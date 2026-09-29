"""Idempotent local Postgres/Redis bootstrap with named-port conflict diagnostics.

Single documented command::

    python scripts/bootstrap.py

It creates ``.env`` from ``.env.example`` on first run (generating a development-only
Postgres password), refuses to start unless the publish address is loopback, exits within a
few seconds with the conflicting port named when another program already holds it, starts
the Compose project, waits for both container health checks and prints one JSON summary to
stdout::

    {"schema": "pennilogic.infra.bootstrap/1", "action": "up", "ok": true, "project": "pennilogic",
     "services": [{"service": "postgres", "healthy": true, "startup_ms": 2345, "startup_source": "health_log"},
                  {"service": "redis", "healthy": true, "startup_ms": 1102, "startup_source": "health_log"}],
     "checks": {...}, "warnings": [], "error": null}

Running it again leaves exactly one healthy stack. Other actions: ``--status`` (read-only),
``--down`` (remove containers and network, keep data) and ``--reset`` (also remove the
named volumes: the only destructive path, always explicit). ``--smoke`` additionally runs
``scripts/smoke_infra.py`` and embeds its separate ``{service, status, latency_ms}`` document
under ``"smoke"``. Human-readable progress goes to stderr; credentials never appear in
either stream. Only resources labelled with this Compose project are ever touched.

``startup_ms`` is the container's own start-to-first-healthy-probe time read from Docker's
health log (``startup_source: "health_log"``); a container that was already running and
healthy before this invocation reports ``0`` (``"already_running"``); when the health log
has rotated the value is ``null`` (``"unknown"``). It is never this script's own wait time.
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
import stat
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
PASSWORD_LINE = re.compile(r"^PENNILOGIC_POSTGRES_PASSWORD=[ \t]*$", re.MULTILINE)
# Daemon wording differs by platform: Linux/macOS "address already in use", Windows
# "Only one usage of each socket address" (port held) or "An attempt was made to access a
# socket" (excluded port range), plus the older "Bind for <ip>:<port> failed" form.
PORT_IN_USE = re.compile(
    r"(?:Bind for \S*?:(\d+) failed|"
    r":(\d+): bind: address already in use|"
    r":(\d+): bind: Only one usage of each socket address|"
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
    container names and both fail. The lock is an OS file lock (``flock`` on POSIX,
    ``msvcrt.locking`` on Windows) on a zero-byte per-project file in a per-user directory
    under the system temp directory. It is released automatically when the holding process
    exits, so it can never be stale.

    The lock file is deliberately **never unlinked**: on POSIX a waiter polls the inode it
    opened, so unlinking on release would let a newcomer lock a fresh inode while the waiter
    later succeeds on the old one, and two bootstraps would run at once. Independently of
    that, an acquirer re-checks that the inode it locked is still the one at the path.
    """

    def __init__(self, project, wait_seconds=LOCK_WAIT_SECONDS):
        # Per-user directory so another local account cannot pre-create the lock file (POSIX /tmp).
        owner = f"-{os.getuid()}" if hasattr(os, "getuid") else ""
        self.directory = Path(tempfile.gettempdir()) / f"pennilogic-bootstrap-locks{owner}"
        self.path = self.directory / f"{project}.lock"
        self.wait_seconds, self.handle = wait_seconds, None

    def _try_lock(self):
        """Return True when the lock on the currently opened file is held and still authoritative."""
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        import fcntl
        fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            current = os.stat(self.path)
        except FileNotFoundError:
            current = None
        held = os.fstat(self.handle.fileno())
        if current is None or (current.st_ino, current.st_dev) != (held.st_ino, held.st_dev):
            # The file was replaced or removed under us: this lock protects nothing. Reopen.
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
            self.handle = open(self.path, "a+", encoding="utf-8")
            return False
        return True

    def __enter__(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if hasattr(os, "getuid"):
            info = os.stat(self.directory)
            if info.st_uid != os.getuid() or stat.S_ISLNK(os.lstat(self.directory).st_mode):
                raise BootstrapError(
                    "locked", f"Lock directory {self.directory} is not owned by this user or is a symlink;"
                    " refusing to use it. Remove it or set TMPDIR to a private directory.",
                )
            if stat.S_IMODE(info.st_mode) & 0o077:
                os.chmod(self.directory, 0o700)
        self.handle = open(self.path, "a+", encoding="utf-8")
        deadline = time.monotonic() + self.wait_seconds
        announced = False
        while True:
            try:
                if self._try_lock():
                    return self
            except OSError:
                if time.monotonic() > deadline:
                    self.handle.close()
                    raise BootstrapError(
                        "locked", f"Another bootstrap of this project has been running for over"
                        f" {self.wait_seconds}s (lock {self.path}). Wait for it to finish, or find and"
                        " stop that bootstrap process; the lock is released when it exits.",
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
    """Create ``env_file`` from the example with a generated password. Returns True if created.

    The file is created exclusively (``O_EXCL``) with mode 0600 where the platform honours
    it (POSIX; on Windows the directory ACL applies). If another invocation created it in
    the meantime, that file is kept and False is returned.
    """
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
    try:
        descriptor = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
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
    """Check ports, publish address and credentials; return {service: port}.

    Returns the validated ports. Also used by ``--status`` (``require_password=False``).
    """
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
    if address == "localhost":
        raise BootstrapError(
            "non_loopback_bind",
            "PENNILOGIC_BIND_ADDRESS=localhost is not accepted: Docker publishes to IP addresses only."
            " Use 127.0.0.1 (the default) or ::1.",
        )
    if not is_loopback(address):
        if not allow_non_loopback:
            raise BootstrapError(
                "non_loopback_bind",
                f"PENNILOGIC_BIND_ADDRESS={address} would publish the development services beyond this"
                " machine. The stack binds to the loopback interface only by default; keep 127.0.0.1, or"
                " pass --allow-non-loopback if you really intend to expose the development Postgres and"
                " Redis to your network (Redis then also needs PENNILOGIC_REDIS_PASSWORD set).",
            )
        if not settings["PENNILOGIC_REDIS_PASSWORD"]:
            raise BootstrapError(
                "non_loopback_bind",
                f"PENNILOGIC_BIND_ADDRESS={address} with --allow-non-loopback would expose Redis to your"
                " network with no authentication at all (PENNILOGIC_REDIS_PASSWORD is blank). Set a"
                " development-only PENNILOGIC_REDIS_PASSWORD in .env first, or keep the loopback default."
                " Nothing was started.",
            )
    if require_password and not settings["PENNILOGIC_POSTGRES_PASSWORD"]:
        raise BootstrapError(
            "missing_password",
            "PENNILOGIC_POSTGRES_PASSWORD is blank. Set any development-only value in .env, or delete"
            " .env and re-run so a random one is generated. Nothing was started.",
        )
    return ports


def is_loopback(address):
    """True for loopback IP literals (127.0.0.0/8, ::1, IPv4-mapped loopback); hostnames are not accepted."""
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


def conflict_error(conflicts, warnings=()):
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
        summary={"warnings": list(warnings)},
    )


def compose_port_failure(stderr):
    ports = sorted({int(p) for match in PORT_IN_USE.finditer(stderr) for p in match.groups() if p})
    if not ports:
        return None
    named = ", ".join(str(p) for p in ports)
    return BootstrapError(
        "port_conflict",
        f"Port conflict: Docker could not bind host port(s) {named}. Another program holds the port"
        " (it may only be bound, not listening, so the preflight check could not see it) or it is in"
        " a reserved range. Set the matching PENNILOGIC_*_PORT in .env to a free port and re-run."
        f"\n{stderr.strip()}",
        ports=ports,
    )


def rollback_partial_start(compose, had_containers_before):
    """After a failed `up`, undo what this run created; data volumes are always kept.

    Only a stack that did not exist before this run is removed. If the project already had
    containers (a failed re-run, or a concurrent run's stack), nothing is touched and the
    message says so. Returns a sentence for the error message. Never raises: the original
    failure must not be masked by a follow-up error.
    """
    try:
        volumes = compose.volumes()
    except BootstrapError:
        volumes = []
    kept = f" Data volumes {', '.join(volumes)} were kept." if volumes else ""
    if had_containers_before:
        return (
            "This run's rollback did not touch the project's containers because some already existed before"
            " it started (Compose itself may have recreated a container whose configuration changed). Run"
            " `python scripts/bootstrap.py --status` to inspect them and re-run once the cause is fixed;"
            " the re-run converges to one healthy stack." + kept
        )
    try:
        result = compose.compose("down", "--remove-orphans", timeout=180, check=False)
        remaining = compose.ps(all_states=True) if result.returncode == 0 else None
    except BootstrapError:
        result, remaining = None, None
    if result is not None and result.returncode == 0 and not remaining:
        return "The partially created containers and network were removed again; nothing is running." + kept
    return (
        "Warning: the partially created stack could not be fully removed; run `python scripts/bootstrap.py"
        " --down` (or re-run after fixing the cause) to converge." + kept
    )


# --- readiness ------------------------------------------------------------------------------------

HEALTH_LOG_CAPACITY = 5  # Docker keeps only the most recent health probes per container
SOURCE_HEALTH_LOG, SOURCE_ALREADY_RUNNING, SOURCE_UNKNOWN = "health_log", "already_running", "unknown"


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


def service_records(compose, records, already_running=()):
    """One contract record per service: {service, healthy, startup_ms, startup_source}.

    ``startup_ms`` is the container's own start-to-first-healthy-probe time from Docker's
    health log (``health_log``). A container that was already running and healthy before this
    invocation (its ID is in ``already_running``) reports ``0`` (``already_running``). When the
    health log has rotated past the first success the value is ``None`` (``unknown``). This
    script's own polling latency is never reported as startup time.
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
        startup_ms, source = None, SOURCE_UNKNOWN
        if healthy and record.get("ID") in already_running:
            startup_ms, source = 0, SOURCE_ALREADY_RUNNING
        elif healthy:
            startup_ms = derive_startup_ms(states.get(record.get("ID"), {}))
            source = SOURCE_HEALTH_LOG if startup_ms is not None else SOURCE_UNKNOWN
        output.append({"service": service, "healthy": healthy, "startup_ms": startup_ms, "startup_source": source})
    return output


def healthy_ids(records):
    return {r.get("ID") for r in records if r.get("State") == "running" and r.get("Health") == "healthy"}


def wait_healthy(compose, deadline):
    """Poll until both services report healthy; raise on exit/unhealthy or when ``deadline`` passes."""
    while True:
        records = compose.ps()
        by_service = {record.get("Service"): record for record in records}
        problems, healthy = [], set()
        for service in SERVICES:
            record = by_service.get(service)
            if record is None:
                continue
            if record.get("State") in ("exited", "dead") or record.get("Health") == "unhealthy":
                problems.append(f"{service}: state={record.get('State')} health={record.get('Health') or 'n/a'}")
            elif record.get("Health") == "healthy":
                healthy.add(service)
        if problems:
            raise BootstrapError(
                "unhealthy", "The stack did not become healthy:\n  " + "\n  ".join(problems)
                + "\n" + diagnostics(compose, records),
            )
        if len(healthy) == len(SERVICES):
            return records
        if time.monotonic() > deadline:
            waiting = ", ".join(f"{s}: {by_service.get(s, {}).get('Health') or by_service.get(s, {}).get('State') or 'absent'}"
                                for s in SERVICES if s not in healthy)
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

def stale_volume_warning(compose, env_created):
    """Warn when a freshly generated password cannot match data already in this project's volumes."""
    volumes = compose.volumes()
    if not (env_created and volumes):
        return None
    return (
        f"Data volumes {', '.join(volumes)} already existed before this first start, so the freshly"
        " generated PENNILOGIC_POSTGRES_PASSWORD will not match the password stored in that Postgres"
        " data. If connections fail with authentication errors, run `python scripts/bootstrap.py --reset`"
        " (destroys that development data) and start again."
    )


def action_up(compose, settings, ports, args):
    warnings = []
    stale = stale_volume_warning(compose, args.env_created)
    if stale:
        warnings.append(stale)
        log("warning: " + stale)
    before = compose.ps(all_states=True)
    conflicts = find_port_conflicts(settings, ports, before, compose.published_ports())
    if conflicts:
        raise conflict_error(conflicts, warnings)
    already_running = healthy_ids(before)
    log(f"starting compose project '{compose.project}' on {settings['PENNILOGIC_BIND_ADDRESS']}"
        f" (postgres:{ports['postgres']}, redis:{ports['redis']})")
    started = time.monotonic()
    # `up` may pull both images on a clean machine; that time is not counted against --timeout.
    result = compose.compose("up", "--detach", "--remove-orphans", timeout=max(args.timeout, 600), check=False)
    if result.returncode:
        stderr = compose.redact(result.stderr)
        name_conflict = bool(NAME_CONFLICT.search(stderr))
        error = compose_port_failure(stderr)
        if error is None and name_conflict:
            error = BootstrapError(
                "compose_failed",
                "Docker reports a container-name conflict for this project, which happens when another"
                " `docker compose up` of the same project ran at the same time. Re-run `python scripts/bootstrap.py`"
                f" once the other run has finished.\n{stderr.strip()}",
            )
        if error is None:
            error = BootstrapError(
                "compose_failed", f"`docker compose up` failed (exit {result.returncode}):\n{stderr.strip()}",
            )
        # Compose may already have created a network, volumes and some containers (Redis can even be
        # running). Leave no half-started stack behind when the project was empty before this run;
        # an existing stack (failed re-run) or another run's containers (name conflict) are left alone.
        # Volumes are never removed.
        outcome = rollback_partial_start(compose, had_containers_before=bool(before) or name_conflict)
        error.args = (f"{error.args[0]}\n{outcome}",)
        error.details["rollback"] = outcome
        error.details["summary"] = {"warnings": warnings}
        raise error
    health_deadline = time.monotonic() + args.timeout
    try:
        records = wait_healthy(compose, health_deadline)
    except BootstrapError as error:
        error.details.setdefault("summary", {})["warnings"] = warnings
        raise
    services = service_records(compose, records, already_running)
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
        log(f"{record['service']}: " + describe_startup(record))
    return summary


def describe_startup(record):
    if record["startup_source"] == SOURCE_ALREADY_RUNNING:
        return "healthy (already running before this run)"
    if record["startup_ms"] is None:
        return "healthy (startup time no longer in Docker's health log)"
    return f"healthy in {record['startup_ms']} ms (from Docker's health log)"


def action_status(compose):
    records = compose.ps(all_states=True)
    services = service_records(compose, records)
    checks = stack_checks(compose)
    ok = all(record["healthy"] for record in services) and checks["single_stack"]
    for record in services:
        log(f"{record['service']}: " + (describe_startup(record) if record["healthy"] else "not healthy"))
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
    services = empty_services()
    checks = {"containers_remaining": len(remaining_containers), "volumes_remaining": remaining_volumes}
    if not ok:
        raise BootstrapError(
            "teardown_incomplete", f"Teardown left resources behind: {checks}",
            summary={"services": services, "checks": checks, "warnings": []},
        )
    log("done" + ("" if destroy_volumes else f"; kept volumes {', '.join(remaining_volumes) or '(none)'}"))
    return {"services": services, "checks": checks, "warnings": [], "ok": True}


def empty_services():
    return [{"service": s, "healthy": False, "startup_ms": None, "startup_source": SOURCE_UNKNOWN} for s in SERVICES]


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
                        help="seconds to wait for both health checks after `docker compose up` returns;"
                             " image pulls are not counted (default 120)")
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


def run_up(compose, settings, ports, args, summary):
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


def main(argv=None):
    args = build_parser().parse_args(argv)
    action = "status" if args.status else "down" if args.down else "reset" if args.reset else "up"
    summary = {"schema": SCHEMA, "action": action, "ok": False, "project": None,
               "services": empty_services(), "checks": {}, "warnings": [], "error": None}
    compose = None
    try:
        args.env_file = Path(args.env_file).expanduser().resolve()
        if args.summary_file:
            args.summary_file = Path(args.summary_file).expanduser().resolve()
        args.env_created = False
        # Settings are read once before the lock so the project name is known; `up` re-reads them
        # under the lock after possibly creating .env, so concurrent first runs share one file.
        settings = smoke_infra.load_settings(args.env_file)
        project = resolve_project(args.project, settings)
        summary["project"] = project
        if action == "status":
            ports = validate_settings(settings, args.allow_non_loopback, require_password=False)
            compose = Compose(project, args.env_file, os.environ, smoke_infra.secret_values(settings), args.verbose)
            compose.engine_version()
            summary.update(action_status(compose))
        else:
            with ProjectLock(project):
                if action == "up":
                    args.env_created = ensure_env_file(args.env_file)
                    if args.env_created:
                        log(f"created {args.env_file} from {ENV_EXAMPLE.name} with a generated development password")
                    settings = smoke_infra.load_settings(args.env_file)
                ports = validate_settings(settings, args.allow_non_loopback, require_password=action == "up")
                compose = Compose(project, args.env_file, os.environ, smoke_infra.secret_values(settings), args.verbose)
                compose.engine_version()
                if action == "up":
                    run_up(compose, settings, ports, args, summary)
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
