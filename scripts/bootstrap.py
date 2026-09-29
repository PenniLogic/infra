"""Idempotent local Postgres/Redis bootstrap with named-port conflict diagnostics.

Single documented command::

    python scripts/bootstrap.py

It creates ``.env`` from ``.env.example`` on first run (generating a development-only
Postgres password), refuses to start unless the publish address is loopback, fails fast
with the conflicting port named when another program already holds it, starts the Compose
project, waits for both container health checks and prints one JSON summary to stdout::

    {"schema": "pennilogic.infra.bootstrap/1", "action": "up", "ok": true, "project": "pennilogic",
     "services": [{"service": "postgres", "healthy": true, "startup_ms": 2345},
                  {"service": "redis", "healthy": true, "startup_ms": 1102}],
     "checks": {...}, "warnings": [], "error": null}

Running it again leaves exactly one healthy stack. Other actions: ``--status`` (read-only),
``--down`` (remove containers and network, keep data) and ``--reset`` (also remove the
named volumes: the only destructive path, always explicit). ``--smoke`` additionally runs
``scripts/smoke_infra.py`` and embeds its separate ``{service, status, latency_ms}`` document
under ``"smoke"``. Human-readable progress goes to stderr; credentials never appear in
either stream. Only resources labelled with this Compose project are ever touched.
"""

import argparse
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke_infra  # noqa: E402  (sibling module; shares the environment contract)


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT / "docker-compose.yml"
ENV_FILE = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"
SCHEMA = "pennilogic.infra.bootstrap/1"
DEFAULT_PROJECT = "pennilogic"
SERVICES = smoke_infra.SERVICES
SERVICE_PORTS = {"postgres": "PENNILOGIC_POSTGRES_PORT", "redis": "PENNILOGIC_REDIS_PORT"}
VOLUMES = ("pgdata", "redisdata")
PROJECT_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
PASSWORD_LINE = re.compile(r"^PENNILOGIC_POSTGRES_PASSWORD=\s*$", re.MULTILINE)
PORT_IN_USE = re.compile(
    r"(?:Bind for \S*?:(\d+) failed|:(\d+): bind: address already in use|"
    r":(\d+): bind: An attempt was made to access a socket)",
)
POLL_SECONDS = 0.5
DOCKER_TIMEOUT = 60
LOCK_WAIT_SECONDS = 600
NAME_CONFLICT = re.compile(r"The container name \"/?([^\"]+)\" is already in use")


class BootstrapError(Exception):
    def __init__(self, kind, message, **details):
        super().__init__(message)
        self.kind, self.details = kind, details


def log(message):
    print(f"bootstrap: {message}", file=sys.stderr, flush=True)


class ProjectLock:
    """Serialize bootstrap invocations per Compose project on this machine.

    Compose itself is not atomic: two simultaneous `up` runs of one project race on
    container names and both fail. The lock lives in the temp directory, so concurrent
    invocations wait for each other instead of colliding.
    """

    def __init__(self, project, wait_seconds=LOCK_WAIT_SECONDS):
        self.path = Path(tempfile.gettempdir()) / f"pennilogic-bootstrap-{project}.lock"
        self.wait_seconds, self.handle = wait_seconds, None

    def __enter__(self):
        self.handle = open(self.path, "a+", encoding="utf-8")
        deadline = time.monotonic() + self.wait_seconds
        announced = False
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() > deadline:
                    self.handle.close()
                    raise BootstrapError(
                        "locked", f"Another bootstrap of this project has held {self.path} for over"
                        f" {self.wait_seconds}s; wait for it or remove the stale lock file.",
                    ) from None
                if not announced:
                    log("another bootstrap of this project is running; waiting for it to finish")
                    announced = True
                time.sleep(POLL_SECONDS)

    def __exit__(self, *exc_info):
        try:
            if os.name == "nt":
                import msvcrt
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
        return False


def parse_timestamp(value):
    """Parse the timestamp formats Docker emits: RFC 3339 (``StartedAt``) and Go's
    ``2006-01-02 15:04:05.999999999 -0700 MST`` (health-log entries), with nanoseconds."""
    value = value.strip()
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})(?:\s+\w+)?", value)
    if not match:
        raise ValueError(f"unrecognised timestamp {value!r}")
    date, clock, fraction, zone = match.groups()
    micro = (fraction or "0")[:6].ljust(6, "0")
    zone = "+00:00" if zone == "Z" else (zone if ":" in zone else zone[:3] + ":" + zone[3:])
    return datetime.fromisoformat(f"{date}T{clock}.{micro}{zone}")


def parse_json_records(text):
    """Accept both a JSON array and JSON Lines, as different Compose versions print them."""
    text = text.strip()
    if not text:
        return []
    try:
        loaded = json.loads(text)
        return loaded if isinstance(loaded, list) else [loaded]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


# --- environment file -------------------------------------------------------------------------

def ensure_env_file(env_file, example=ENV_EXAMPLE):
    """Create ``env_file`` from the example with a generated password. Returns True if created."""
    env_file = Path(env_file)
    if env_file.exists():
        return False
    if not Path(example).is_file():
        raise BootstrapError("missing_example", f"{example} is missing; restore it from the repository.")
    template = Path(example).read_text(encoding="utf-8")
    if not PASSWORD_LINE.search(template):
        raise BootstrapError(
            "invalid_example", f"{example} has no blank PENNILOGIC_POSTGRES_PASSWORD= line to fill in.",
        )
    content = PASSWORD_LINE.sub(
        "PENNILOGIC_POSTGRES_PASSWORD=" + secrets.token_urlsafe(24), template, count=1,
    )
    env_file.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(env_file, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    return True


def resolve_project(explicit, settings):
    project = explicit or settings.get("COMPOSE_PROJECT_NAME") or DEFAULT_PROJECT
    if not PROJECT_NAME.match(project):
        raise BootstrapError(
            "invalid_project",
            f"Compose project name {project!r} must be lowercase letters, digits, '-' or '_' and start"
            " with a letter or digit.",
        )
    return project


def validate_settings(settings, allow_non_loopback=False, require_password=True):
    ports = {}
    for service, key in SERVICE_PORTS.items():
        try:
            ports[service] = smoke_infra.port_of(settings, key)
        except ValueError as error:
            raise BootstrapError("invalid_port", str(error)) from error
    if ports["postgres"] == ports["redis"]:
        raise BootstrapError(
            "invalid_port",
            f"PENNILOGIC_POSTGRES_PORT and PENNILOGIC_REDIS_PORT are both {ports['postgres']};"
            " give each service its own port in .env.",
        )
    address = settings["PENNILOGIC_BIND_ADDRESS"]
    if not is_loopback(address) and not allow_non_loopback:
        raise BootstrapError(
            "non_loopback_bind",
            f"PENNILOGIC_BIND_ADDRESS={address} would publish the development services beyond this"
            " machine. The stack binds to the loopback interface only by default; keep 127.0.0.1, or"
            " pass --allow-non-loopback if you really intend to expose development credentials to"
            " your network.",
        )
    if require_password and not settings["PENNILOGIC_POSTGRES_PASSWORD"]:
        raise BootstrapError(
            "missing_password",
            "PENNILOGIC_POSTGRES_PASSWORD is blank. Set any development-only value in .env, or delete"
            " .env and re-run so a random one is generated. Nothing was started.",
        )
    return ports


def is_loopback(address):
    if address == "localhost":
        return True
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


# --- docker wrappers ----------------------------------------------------------------------------

class Compose:
    def __init__(self, project, env_file, environ, secret_values, verbose=False, compose_file=COMPOSE_FILE):
        self.project, self.env_file, self.environ = project, Path(env_file), dict(environ)
        self.secret_values, self.verbose, self.compose_file = tuple(secret_values), verbose, compose_file

    def redact(self, text):
        return smoke_infra.redact(text, self.secret_values)

    def docker(self, *args, timeout=DOCKER_TIMEOUT):
        command = ["docker", *args]
        try:
            result = subprocess.run(
                command, cwd=ROOT, env=self.environ, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=timeout, check=False,
            )
        except FileNotFoundError as error:
            raise BootstrapError("docker_missing", "The `docker` command is not installed or not on PATH.") from error
        except subprocess.TimeoutExpired as error:
            raise BootstrapError(
                "docker_timeout", f"`{' '.join(command[:3])}` did not finish within {timeout}s.",
            ) from error
        if self.verbose and result.stderr.strip():
            log(self.redact(result.stderr.rstrip()))
        return result

    def compose(self, *args, timeout=DOCKER_TIMEOUT, check=True):
        base = ["compose", "--project-name", self.project, "-f", str(self.compose_file)]
        if self.env_file.is_file():
            base += ["--env-file", str(self.env_file)]
        result = self.docker(*base, *args, timeout=timeout)
        if check and result.returncode:
            raise BootstrapError(
                "compose_failed",
                f"`docker compose {args[0]}` failed (exit {result.returncode}):\n{self.redact(result.stderr.strip())}",
                stderr=self.redact(result.stderr),
            )
        return result

    def engine_version(self):
        result = self.docker("version", "--format", "{{.Server.Version}}", timeout=30)
        if result.returncode or not result.stdout.strip():
            raise BootstrapError(
                "docker_unavailable",
                "Docker Engine is not reachable. Start Docker Desktop (or the docker service) and re-run.\n"
                + self.redact(result.stderr.strip()),
            )
        return result.stdout.strip()

    def ps(self, all_states=False):
        args = ["ps", "--format", "json"] + (["--all"] if all_states else [])
        return parse_json_records(self.compose(*args).stdout)

    def inspect(self, container_ids):
        if not container_ids:
            return []
        result = self.docker("inspect", *container_ids)
        if result.returncode:
            return []
        return json.loads(result.stdout)

    def volumes(self):
        result = self.docker(
            "volume", "ls", "--filter", f"label=com.docker.compose.project={self.project}",
            "--format", "{{.Name}}",
        )
        return sorted(line.strip() for line in result.stdout.splitlines() if line.strip())

    def logs(self):
        return self.compose("logs", "--no-color", check=False).stdout

    def published_ports(self):
        """Map host port -> description for every running container on this engine."""
        result = self.docker(
            "ps", "--format", '{{.Names}}\t{{.Label "com.docker.compose.project"}}\t{{.Ports}}',
        )
        holders = {}
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            name, project, ports = parts
            for match in re.finditer(r":(\d+)->", ports):
                where = f" of compose project '{project}'" if project else ""
                holders[int(match.group(1))] = f"Docker container '{name}'{where}"
        return holders


# --- preflight -----------------------------------------------------------------------------------

def is_listening(address, port, timeout=1.0):
    target = {"0.0.0.0": "127.0.0.1", "::": "::1", "": "127.0.0.1"}.get(address, address)
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except OSError:
        return False


def suggest_port(address, port):
    for candidate in (port + 10000, port + 20000, port + 30000):
        if candidate <= 65535 and not is_listening(address, candidate):
            return candidate
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def owned_ports(records):
    """Service -> published host port for this project's running containers."""
    owned = {}
    for record in records:
        if record.get("State") != "running":
            continue
        for publisher in record.get("Publishers") or []:
            if publisher.get("PublishedPort"):
                owned.setdefault(record.get("Service"), set()).add(int(publisher["PublishedPort"]))
    return owned


def find_port_conflicts(settings, ports, own_records, holders=None):
    """Return conflicts for ports needed by services that are not already ours."""
    address, owned, conflicts = settings["PENNILOGIC_BIND_ADDRESS"], owned_ports(own_records), []
    for service, port in ports.items():
        if port in owned.get(service, set()) or not is_listening(address, port):
            continue
        holder = (holders or {}).get(port) or (
            "a process outside Docker (Windows: `netstat -ano | findstr :%d` then `tasklist /FI \"PID eq <pid>\"`;"
            " Linux/macOS: `ss -ltnp 'sport = :%d'` or `lsof -iTCP:%d -sTCP:LISTEN`)" % (port, port, port)
        )
        conflicts.append({
            "service": service, "port": port, "address": address, "holder": holder,
            "variable": SERVICE_PORTS[service], "suggested_port": suggest_port(address, port),
        })
    return conflicts


def conflict_error(conflicts):
    lines = []
    for item in conflicts:
        lines.append(
            f"Port conflict: service \"{item['service']}\" needs {item['address']}:{item['port']}, but port"
            f" {item['port']} is already in use by {item['holder']}.\n"
            f"  Fix: set {item['variable']}={item['suggested_port']} in .env (a verified free port) and"
            " re-run, or stop the conflicting service."
        )
    lines.append("Nothing was started.")
    return BootstrapError(
        "port_conflict", "\n".join(lines), ports=[item["port"] for item in conflicts], conflicts=conflicts,
    )


def compose_port_failure(stderr):
    ports = sorted({int(p) for match in PORT_IN_USE.finditer(stderr) for p in match.groups() if p})
    if not ports:
        return None
    named = ", ".join(str(p) for p in ports)
    return BootstrapError(
        "port_conflict",
        f"Docker could not bind host port(s) {named}: another program took the port between the preflight"
        f" check and the start, or Windows reserves that range. Set the matching PENNILOGIC_*_PORT in .env"
        f" to a free port and re-run.\n{stderr.strip()}",
        ports=ports,
    )


# --- readiness ------------------------------------------------------------------------------------

HEALTH_LOG_CAPACITY = 5  # Docker keeps only the most recent health probes per container


def derive_startup_ms(state):
    """Milliseconds from container start to its first successful health probe, if still logged."""
    health = state.get("Health") or {}
    entries = sorted(health.get("Log") or [], key=lambda entry: entry.get("Start", ""))
    successes = [entry for entry in entries if entry.get("ExitCode") == 0]
    if not successes or not state.get("StartedAt"):
        return None
    if entries[0].get("ExitCode") == 0 and len(entries) >= HEALTH_LOG_CAPACITY:
        return None  # the first success may have rotated out of the log; unknown rather than wrong
    try:
        delta = parse_timestamp(successes[0]["End"]) - parse_timestamp(state["StartedAt"])
    except (KeyError, ValueError):
        return None
    return max(0, int(delta.total_seconds() * 1000))


def service_records(compose, records, observed_ms=None):
    """One contract record per service: {service, healthy, startup_ms}.

    ``startup_ms`` comes from Docker's health log (container start to first successful probe);
    when that log no longer holds the first success, the wall-clock time this run observed
    is used, and ``None`` means unknown.
    """
    by_service = {record.get("Service"): record for record in records}
    # `compose ps` prints short (12-char) IDs while `docker inspect` returns full IDs.
    inspected = compose.inspect([record["ID"] for record in records if record.get("ID")])
    states = {}
    for record in records:
        short = record.get("ID") or "\0"
        states[short] = next((item["State"] for item in inspected if item.get("Id", "").startswith(short)), {})
    output = []
    for service in SERVICES:
        record = by_service.get(service) or {}
        healthy = record.get("State") == "running" and record.get("Health") == "healthy"
        startup_ms = None
        if healthy:
            startup_ms = derive_startup_ms(states.get(record.get("ID"), {}))
            if startup_ms is None:
                startup_ms = (observed_ms or {}).get(service)
        output.append({"service": service, "healthy": healthy, "startup_ms": startup_ms})
    return output


def wait_healthy(compose, deadline):
    observed, started = {}, time.monotonic()
    while True:
        records = compose.ps()
        by_service = {record.get("Service"): record for record in records}
        problems = []
        for service in SERVICES:
            record = by_service.get(service)
            if record is None:
                continue
            if record.get("State") in ("exited", "dead") or record.get("Health") == "unhealthy":
                problems.append(f"{service}: state={record.get('State')} health={record.get('Health') or 'n/a'}")
            elif record.get("Health") == "healthy" and service not in observed:
                observed[service] = int((time.monotonic() - started) * 1000)
        if problems:
            raise BootstrapError(
                "unhealthy", "The stack did not become healthy:\n  " + "\n  ".join(problems)
                + "\n" + diagnostics(compose, records),
            )
        if len(observed) == len(SERVICES):
            return records, observed
        if time.monotonic() > deadline:
            waiting = ", ".join(f"{s}: {by_service.get(s, {}).get('Health') or by_service.get(s, {}).get('State') or 'absent'}"
                                for s in SERVICES if s not in observed)
            raise BootstrapError(
                "timeout", f"Timed out waiting for health checks ({waiting}).\n" + diagnostics(compose, records),
            )
        time.sleep(POLL_SECONDS)


def diagnostics(compose, records):
    lines = []
    for item in compose.inspect([record["ID"] for record in records if record.get("ID")]):
        health = (item.get("State") or {}).get("Health") or {}
        last = (health.get("Log") or [{}])[-1]
        name = item.get("Name", "").lstrip("/")
        lines.append(f"{name}: status={item['State'].get('Status')} health={health.get('Status', 'n/a')}"
                     f" last_probe={compose.redact((last.get('Output') or '').strip())[:200]!r}")
    tail = compose.redact(compose.logs()).splitlines()[-15:]
    return "Container state:\n  " + "\n  ".join(lines) + "\nLast log lines:\n  " + "\n  ".join(tail)


def stack_checks(compose):
    containers = compose.ps(all_states=True)
    counts = {service: sum(1 for r in containers if r.get("Service") == service) for service in SERVICES}
    volumes = compose.volumes()
    expected = sorted(f"{compose.project}_{name}" for name in VOLUMES)
    return {
        "single_stack": all(count == 1 for count in counts.values()) and len(containers) == len(SERVICES)
        and volumes == expected,
        "containers": counts,
        "orphan_containers": len(containers) - sum(counts.values()),
        "volumes": volumes,
    }


MIN_SCANNED_SECRET_LENGTH = 8


def logs_free_of_credentials(compose):
    """False if any configured secret appears verbatim in the container logs.

    Values shorter than MIN_SCANNED_SECRET_LENGTH are not scanned: they would match
    ordinary log text by chance, and the generated development password is far longer.
    """
    text = compose.logs()
    return not any(len(value) >= MIN_SCANNED_SECRET_LENGTH and value in text for value in compose.secret_values)


# --- actions -----------------------------------------------------------------------------------------

def action_up(compose, settings, ports, args):
    warnings = []
    volumes_before = compose.volumes()
    if args.env_created and volumes_before:
        warnings.append(
            f"Data volumes {', '.join(volumes_before)} already existed before this first start, so the"
            " freshly generated PENNILOGIC_POSTGRES_PASSWORD will not match the password stored in that"
            " Postgres data. If connections fail with authentication errors, run"
            " `python scripts/bootstrap.py --reset` (destroys that development data) and start again."
        )
    before = compose.ps(all_states=True)
    conflicts = find_port_conflicts(settings, ports, before, compose.published_ports())
    if conflicts:
        raise conflict_error(conflicts)
    log(f"starting compose project '{compose.project}' on {settings['PENNILOGIC_BIND_ADDRESS']}"
        f" (postgres:{ports['postgres']}, redis:{ports['redis']})")
    started = time.monotonic()
    result = compose.compose("up", "--detach", "--remove-orphans", timeout=max(args.timeout, 600), check=False)
    if result.returncode:
        stderr = compose.redact(result.stderr)
        conflict = compose_port_failure(stderr)
        if conflict is None and NAME_CONFLICT.search(stderr):
            conflict = BootstrapError(
                "compose_failed",
                "Docker reports a container-name conflict for this project, which happens when another"
                " `docker compose up` of the same project ran at the same time. Re-run `python scripts/bootstrap.py`"
                f" once the other run has finished.\n{stderr.strip()}",
            )
        raise conflict or BootstrapError(
            "compose_failed", f"`docker compose up` failed (exit {result.returncode}):\n{stderr.strip()}",
        )
    records, observed = wait_healthy(compose, started + args.timeout)
    services = service_records(compose, records, observed)
    checks = stack_checks(compose)
    checks["logs_free_of_credentials"] = logs_free_of_credentials(compose)
    summary = {"services": services, "checks": checks, "warnings": warnings,
               "elapsed_ms": int((time.monotonic() - started) * 1000)}
    if not checks["single_stack"]:
        raise BootstrapError(
            "not_single_stack", f"Expected exactly one container per service and volumes {VOLUMES}; found {checks}.",
            summary=summary,
        )
    if not checks["logs_free_of_credentials"]:
        raise BootstrapError(
            "credential_in_logs", "A configured credential value appears in the container logs (value withheld).",
            summary=summary,
        )
    for record in services:
        log(f"{record['service']}: healthy in {record['startup_ms']} ms")
    return summary


def action_status(compose):
    records = compose.ps(all_states=True)
    services = service_records(compose, records)
    checks = stack_checks(compose)
    ok = all(record["healthy"] for record in services) and checks["single_stack"]
    for record in services:
        log(f"{record['service']}: {'healthy' if record['healthy'] else 'not healthy'}"
            + (f" (startup {record['startup_ms']} ms)" if record["startup_ms"] is not None else ""))
    return {"services": services, "checks": checks, "warnings": [], "ok": ok}


def action_down(compose, destroy_volumes):
    if destroy_volumes:
        log(f"DESTROYING containers, network and data volumes of compose project '{compose.project}'")
    else:
        log(f"removing containers and network of compose project '{compose.project}'; data volumes are kept")
    args = ["down", "--remove-orphans"] + (["--volumes"] if destroy_volumes else [])
    compose.compose(*args, timeout=180)
    remaining_containers = compose.ps(all_states=True)
    remaining_volumes = compose.volumes()
    ok = not remaining_containers and (not remaining_volumes if destroy_volumes else True)
    services = [{"service": service, "healthy": False, "startup_ms": None} for service in SERVICES]
    checks = {"containers_remaining": len(remaining_containers), "volumes_remaining": remaining_volumes}
    if not ok:
        raise BootstrapError(
            "teardown_incomplete", f"Teardown left resources behind: {checks}",
            summary={"services": services, "checks": checks, "warnings": []},
        )
    log("done" + ("" if destroy_volumes else f"; kept volumes {', '.join(remaining_volumes) or '(none)'}"))
    return {"services": services, "checks": checks, "warnings": [], "ok": True}


# --- entry point ---------------------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--status", action="store_true", help="report health without starting anything")
    action.add_argument("--down", action="store_true", help="remove containers and network; keep data volumes")
    action.add_argument("--reset", action="store_true",
                        help="remove containers, network AND named volumes (destroys development data)")
    parser.add_argument("--smoke", action="store_true",
                        help="after the stack is healthy, run scripts/smoke_infra.py and embed its result")
    parser.add_argument("--project", help="Compose project name (default: COMPOSE_PROJECT_NAME or 'pennilogic')")
    parser.add_argument("--env-file", type=Path, default=ENV_FILE, help="environment file (default: .env)")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="seconds to wait for both health checks (default 120)")
    parser.add_argument("--summary-file", type=Path, help="also write the JSON summary to this file")
    parser.add_argument("--allow-non-loopback", action="store_true",
                        help="permit a PENNILOGIC_BIND_ADDRESS that is not a loopback address")
    parser.add_argument("--verbose", action="store_true", help="show docker/compose stderr while running")
    return parser


def emit(summary, summary_file):
    text = json.dumps(summary, indent=2)
    if summary_file:
        summary_file.parent.mkdir(parents=True, exist_ok=True)
        summary_file.write_text(text + "\n", encoding="utf-8")
    print(text, flush=True)


def main(argv=None):
    args = build_parser().parse_args(argv)
    action = "status" if args.status else "down" if args.down else "reset" if args.reset else "up"
    summary = {"schema": SCHEMA, "action": action, "ok": False, "project": None,
               "services": [{"service": s, "healthy": False, "startup_ms": None} for s in SERVICES],
               "checks": {}, "warnings": [], "error": None}
    compose = None
    try:
        args.env_file = Path(args.env_file).expanduser().resolve()
        if args.summary_file:
            args.summary_file = Path(args.summary_file).expanduser().resolve()
        args.env_created = action == "up" and ensure_env_file(args.env_file)
        if args.env_created:
            log(f"created {args.env_file} from {ENV_EXAMPLE.name} with a generated development password")
        settings = smoke_infra.load_settings(args.env_file)
        ports = validate_settings(settings, args.allow_non_loopback, require_password=action == "up")
        project = resolve_project(args.project, settings)
        summary["project"] = project
        compose = Compose(project, args.env_file, os.environ, smoke_infra.secret_values(settings), args.verbose)
        compose.engine_version()
        if action == "status":
            summary.update(action_status(compose))
        else:
            with ProjectLock(project):
                if action == "up":
                    summary.update(action_up(compose, settings, ports, args))
                    summary["ok"] = True
                    if args.smoke:
                        smoke = smoke_infra.run(settings, timeout=min(args.timeout, 10.0))
                        for record in smoke["services"]:
                            note = "" if record["detail"] is None else f" - {record['detail']}"
                            log(f"smoke {record['service']}: {record['status']} ({record['latency_ms']} ms){note}")
                        summary["smoke"] = smoke
                        if not smoke["ok"]:
                            raise BootstrapError("smoke_failed", "The smoke probe failed; see the smoke records.")
                else:
                    summary.update(action_down(compose, destroy_volumes=action == "reset"))
    except BootstrapError as error:
        summary.update(error.details.pop("summary", {}))
        message = compose.redact(str(error)) if compose else str(error)
        summary["ok"] = False
        summary["error"] = {"kind": error.kind, "message": message, **error.details}
        log(message)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        message = compose.redact(str(error)) if compose else str(error)
        summary["ok"] = False
        summary["error"] = {"kind": "io_error", "message": f"{type(error).__name__}: {message}"}
        log(message)
    except KeyboardInterrupt:
        summary["error"] = {"kind": "interrupted", "message": "Interrupted."}
        emit(summary, args.summary_file)
        return 130
    emit(summary, args.summary_file)
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
