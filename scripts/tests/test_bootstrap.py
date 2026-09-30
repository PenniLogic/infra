"""Docker-free tests for scripts/bootstrap.py: env generation, validation, port diagnostics, envelope,
and the timeout regression for a `docker` command whose child outlives it (infra#37)."""

import gc
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import support
import bootstrap
import smoke_infra as smoke


def settings_for(**overrides):
    values = dict(smoke.DEFAULTS)
    values["PENNILOGIC_POSTGRES_PASSWORD"] = "dev-only"
    values.update(overrides)
    return values


class EnvFileTests(unittest.TestCase):
    def test_creates_env_with_generated_password_exactly_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            example = Path(tmp) / ".env.example"
            shutil.copy(bootstrap.ENV_EXAMPLE, example)
            target = Path(tmp) / "sub" / ".env"
            self.assertTrue(bootstrap.ensure_env_file(target, example))
            first = target.read_text(encoding="utf-8")
            values = smoke.parse_env_file(target)
            self.assertGreaterEqual(len(values["PENNILOGIC_POSTGRES_PASSWORD"]), 24)
            self.assertNotIn("PENNILOGIC_POSTGRES_PASSWORD=\n", first)
            self.assertEqual("", values["PENNILOGIC_REDIS_PASSWORD"], "redis stays unauthenticated by default")
            self.assertEqual("5432", values["PENNILOGIC_POSTGRES_PORT"])
            self.assertIn("# PenniLogic local development environment", first, "the documented contract is kept")
            self.assertFalse(bootstrap.ensure_env_file(target, example))
            self.assertEqual(first, target.read_text(encoding="utf-8"), "second run must not rewrite .env")
            if os.name != "nt":
                self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))

    def test_missing_or_invalid_example_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(bootstrap.BootstrapError) as ctx:
                bootstrap.ensure_env_file(Path(tmp) / ".env", Path(tmp) / "absent.example")
            self.assertEqual("missing_example", ctx.exception.kind)
            bad = Path(tmp) / "bad.example"
            bad.write_text("PENNILOGIC_POSTGRES_PASSWORD=preset\n", encoding="utf-8")
            with self.assertRaises(bootstrap.BootstrapError) as ctx:
                bootstrap.ensure_env_file(Path(tmp) / ".env", bad)
            self.assertEqual("invalid_example", ctx.exception.kind)

    def test_committed_example_has_no_credential(self):
        values = smoke.parse_env_file(bootstrap.ENV_EXAMPLE)
        for key in smoke.SECRET_KEYS:
            self.assertEqual("", values[key], f"{key} must be blank in the committed example")
        for key in smoke.DEFAULTS:
            self.assertIn(key, values, "every published variable is documented in .env.example")


class ValidationTests(unittest.TestCase):
    def test_loopback_addresses_are_accepted(self):
        for address in ("127.0.0.1", "127.0.0.5", "::1", "::ffff:127.0.0.1"):
            with self.subTest(address=address):
                ports = bootstrap.validate_settings(settings_for(PENNILOGIC_BIND_ADDRESS=address))
                self.assertEqual({"postgres": 5432, "redis": 6379}, ports)

    def test_localhost_is_refused_with_a_hint(self):
        # Compose publishes to IP literals only; accepting "localhost" would fail later inside Docker.
        with self.assertRaises(bootstrap.BootstrapError) as ctx:
            bootstrap.validate_settings(settings_for(PENNILOGIC_BIND_ADDRESS="localhost"))
        self.assertEqual("non_loopback_bind", ctx.exception.kind)
        self.assertIn("127.0.0.1", str(ctx.exception))
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_settings(settings_for(PENNILOGIC_BIND_ADDRESS="localhost"), allow_non_loopback=True)

    def test_non_loopback_is_refused_unless_explicitly_allowed(self):
        for address in ("0.0.0.0", "::", "192.168.1.20", "example.com", "", "127.1", "0177.0.0.1", "127.0.0.1 "):
            with self.subTest(address=address):
                with self.assertRaises(bootstrap.BootstrapError) as ctx:
                    bootstrap.validate_settings(settings_for(PENNILOGIC_BIND_ADDRESS=address))
                self.assertEqual("non_loopback_bind", ctx.exception.kind)
                self.assertIn("--allow-non-loopback", str(ctx.exception))
        bootstrap.validate_settings(
            settings_for(PENNILOGIC_BIND_ADDRESS="0.0.0.0", PENNILOGIC_REDIS_PASSWORD="dev-redis-pw"),
            allow_non_loopback=True,
        )

    def test_non_loopback_with_unauthenticated_redis_is_refused_even_when_allowed(self):
        with self.assertRaises(bootstrap.BootstrapError) as ctx:
            bootstrap.validate_settings(settings_for(PENNILOGIC_BIND_ADDRESS="0.0.0.0"), allow_non_loopback=True)
        self.assertEqual("non_loopback_bind", ctx.exception.kind)
        self.assertIn("no authentication", str(ctx.exception))
        self.assertIn("PENNILOGIC_REDIS_PASSWORD", str(ctx.exception))
        self.assertIn("Nothing was started", str(ctx.exception))

    def test_blank_password_is_refused_for_up_only(self):
        with self.assertRaises(bootstrap.BootstrapError) as ctx:
            bootstrap.validate_settings(settings_for(PENNILOGIC_POSTGRES_PASSWORD=""))
        self.assertEqual("missing_password", ctx.exception.kind)
        self.assertIn("Nothing was started", str(ctx.exception))
        bootstrap.validate_settings(settings_for(PENNILOGIC_POSTGRES_PASSWORD=""), require_password=False)

    def test_invalid_or_colliding_ports_are_refused(self):
        with self.assertRaises(bootstrap.BootstrapError) as ctx:
            bootstrap.validate_settings(settings_for(PENNILOGIC_REDIS_PORT="70000"))
        self.assertEqual("invalid_port", ctx.exception.kind)
        with self.assertRaises(bootstrap.BootstrapError) as ctx:
            bootstrap.validate_settings(settings_for(PENNILOGIC_REDIS_PORT="5432"))
        self.assertIn("both 5432", str(ctx.exception))

    def test_project_name_resolution_and_validation(self):
        self.assertEqual("pennilogic", bootstrap.resolve_project(None, {}))
        self.assertEqual("from-env", bootstrap.resolve_project(None, {"COMPOSE_PROJECT_NAME": "from-env"}))
        self.assertEqual("explicit", bootstrap.resolve_project("explicit", {"COMPOSE_PROJECT_NAME": "from-env"}))
        self.assertEqual("pennilogic", bootstrap.resolve_project(None, {"COMPOSE_PROJECT_NAME": ""}))
        for bad in ("Upper", "-lead", "sp ace", "dot.name"):
            with self.subTest(bad=bad), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.resolve_project(bad, {})


class PortConflictTests(unittest.TestCase):
    def test_decoy_listener_yields_named_actionable_conflict(self):
        decoy = socket.socket()
        decoy.bind(("127.0.0.1", 0))
        decoy.listen(1)
        port = decoy.getsockname()[1]
        try:
            settings = settings_for(PENNILOGIC_POSTGRES_PORT=str(port), PENNILOGIC_REDIS_PORT=str(support.free_port()))
            ports = bootstrap.validate_settings(settings)
            conflicts = bootstrap.find_port_conflicts(settings, ports, own_records=[], holders={})
        finally:
            decoy.close()
        self.assertEqual(1, len(conflicts), conflicts)
        conflict = conflicts[0]
        self.assertEqual(("postgres", port, "127.0.0.1", "PENNILOGIC_POSTGRES_PORT"),
                         (conflict["service"], conflict["port"], conflict["address"], conflict["variable"]))
        self.assertIn("outside Docker", conflict["holder"])
        self.assertIn(f":{port}", conflict["holder"], "the diagnostic command names the port")
        self.assertNotEqual(port, conflict["suggested_port"])
        error = bootstrap.conflict_error(conflicts)
        self.assertEqual("port_conflict", error.kind)
        self.assertEqual([port], error.details["ports"])
        message = str(error)
        self.assertIn(f"port {port} is already in use", message)
        self.assertIn(f"PENNILOGIC_POSTGRES_PORT={conflict['suggested_port']}", message)
        self.assertIn("Nothing was started.", message)

    def test_own_running_container_on_the_port_is_not_a_conflict(self):
        decoy = socket.socket()
        decoy.bind(("127.0.0.1", 0))
        decoy.listen(1)
        port = decoy.getsockname()[1]
        try:
            settings = settings_for(PENNILOGIC_POSTGRES_PORT=str(port), PENNILOGIC_REDIS_PORT=str(support.free_port()))
            own = [{"Service": "postgres", "State": "running", "ID": "abc",
                    "Publishers": [{"URL": "127.0.0.1", "TargetPort": 5432, "PublishedPort": port, "Protocol": "tcp"}]}]
            conflicts = bootstrap.find_port_conflicts(settings, bootstrap.validate_settings(settings), own)
            self.assertEqual([], conflicts)
            stopped = [dict(own[0], State="exited")]
            self.assertEqual(1, len(bootstrap.find_port_conflicts(settings, bootstrap.validate_settings(settings), stopped)))
        finally:
            decoy.close()

    def test_docker_holder_is_named(self):
        decoy = socket.socket()
        decoy.bind(("127.0.0.1", 0))
        decoy.listen(1)
        port = decoy.getsockname()[1]
        try:
            settings = settings_for(PENNILOGIC_REDIS_PORT=str(port), PENNILOGIC_POSTGRES_PORT=str(support.free_port()))
            holders = {port: "Docker container 'other-redis' of compose project 'other'"}
            conflicts = bootstrap.find_port_conflicts(settings, bootstrap.validate_settings(settings), [], holders)
        finally:
            decoy.close()
        self.assertEqual("redis", conflicts[0]["service"])
        self.assertIn("other-redis", conflicts[0]["holder"])

    def test_free_ports_produce_no_conflict(self):
        settings = settings_for(PENNILOGIC_POSTGRES_PORT=str(support.free_port()),
                                PENNILOGIC_REDIS_PORT=str(support.free_port()))
        self.assertEqual([], bootstrap.find_port_conflicts(settings, bootstrap.validate_settings(settings), []))

    def test_compose_bind_failures_are_translated_to_named_ports(self):
        samples = {
            # Docker Engine 29.x on Linux (verified in moby tags docker-v29.0.0 .. docker-v29.8.1):
            # daemon/libnetwork/portallocator/osallocator_linux.go:222, bindTCPOrUDP:
            #   fmt.Errorf("failed to bind host port %s/%s: %w", addr, proto, err)   # addr is a netip.AddrPort
            # No "for", no container part; propagated unwrapped by the bridge driver.
            "Error response from daemon: failed to set up container networking: driver failed programming external "
            "connectivity on endpoint pennilogic-postgres-1 (abc123): failed to bind host port 127.0.0.1:57005/tcp: "
            "address already in use": [57005],
            # Same daemon, IPv6 host (netip.AddrPort brackets it) and UDP:
            "failed to bind host port [::1]:16379/udp: address already in use": [16379],
            # Docker Engine 28.0.4 on GitHub's ubuntu-24.04 runner, captured verbatim from PR #40's CI
            # (https://github.com/PenniLogic/infra/actions/runs/36617966906). Source: moby v28.0.4 (still v28.5.2)
            # libnetwork/drivers/bridge/port_mapping_linux.go, bindTCPOrUDP:
            #   fmt.Errorf("failed to bind host port for %s: %w", cfg, err)
            # where %s is PortBinding.String() = host-ip:host-port:container-ip:container-port/proto.
            # The HOST port (57005) must be captured, not the container port (5432).
            "Error response from daemon: failed to set up container networking: driver failed programming external "
            "connectivity on endpoint pennilogic-test-eab256a3-bind-postgres-1 "
            "(3e5c6aee731e5fd6c4ab2ec8877a8d011b9f8ee28e6bed4e21196627c7fdcef4): failed to bind host port for "
            "127.0.0.1:57005:172.19.0.2:5432/tcp: address already in use": [57005],
            # Same daemon, IPv6 host address (PortBinding.String() brackets it):
            "failed to bind host port for [::1]:16379:172.19.0.3:6379/tcp: address already in use": [16379],
            # Same file, published-port-range sibling: fmt.Errorf("failed to bind host port %d for %s: %w", ...):
            "failed to bind host port 57005 for 127.0.0.1:57005-57010:172.19.0.2:5432/tcp: address already in use": [57005],
            # Docker Desktop for Windows 29.7.2, captured verbatim from a failed `compose up`:
            "Error response from daemon: ports are not available: exposing port TCP 127.0.0.1:55726 -> 127.0.0.1:0: "
            "listen tcp4 127.0.0.1:55726: bind: Only one usage of each socket address (protocol/network address/port)"
            " is normally permitted.": [55726],
            # Docker Engine < 28 on Linux / macOS:
            "Error response from daemon: Ports are not available: exposing port TCP 127.0.0.1:6379 -> 127.0.0.1:0: "
            "listen tcp 127.0.0.1:6379: bind: address already in use": [6379],
            # Windows excluded port range:
            "listen tcp 127.0.0.1:5432: bind: An attempt was made to access a socket in a way forbidden by its "
            "access permissions.": [5432],
            # Older daemon wording:
            "Error response from daemon: driver failed programming external connectivity on endpoint x: "
            "Bind for 127.0.0.1:5432 failed: port is already allocated": [5432],
        }
        for stderr, ports in samples.items():
            with self.subTest(stderr=stderr[-70:]):
                error = bootstrap.compose_port_failure(stderr)
                self.assertIsNotNone(error, stderr)
                self.assertEqual(("port_conflict", ports), (error.kind, error.details["ports"]))
                self.assertIn(f"port(s) {ports[0]}", str(error))
                self.assertIn("PENNILOGIC_*_PORT", str(error))
        self.assertIsNone(bootstrap.compose_port_failure("some unrelated failure"))
        # A bind failure for a different reason must not be misreported as a port conflict (both wordings).
        self.assertIsNone(bootstrap.compose_port_failure(
            "failed to bind host port for 127.0.0.1:57005:172.19.0.2:5432/tcp: permission denied"))
        self.assertIsNone(bootstrap.compose_port_failure(
            "failed to bind host port 127.0.0.1:57005/tcp: permission denied"))

    def test_conflict_error_carries_earlier_warnings(self):
        conflicts = [{"service": "postgres", "port": 5432, "address": "127.0.0.1", "holder": "x",
                      "variable": "PENNILOGIC_POSTGRES_PORT", "suggested_port": 15432}]
        error = bootstrap.conflict_error(conflicts, warnings=["stale volume warning"])
        self.assertEqual(["stale volume warning"], error.details["summary"]["warnings"])

    def test_rollback_after_failed_up_reports_outcome_and_keeps_volumes(self):
        class FakeCompose:
            project = "p"

            def __init__(self, down_ok=True):
                self.calls, self.down_ok = [], down_ok

            def compose(self, *args, **kwargs):
                self.calls.append(args)
                return type("R", (), {"returncode": 0 if self.down_ok else 1})()

            def ps(self, all_states=False):
                if not self.down_ok:
                    raise bootstrap.BootstrapError("compose_failed", "ps failed")
                return []

            def volumes(self):
                return ["p_pgdata", "p_redisdata"]

        fake = FakeCompose()
        outcome = bootstrap.rollback_partial_start(fake, had_containers_before=False)
        self.assertEqual([("down", "--remove-orphans")], fake.calls, "never `--volumes` on rollback")
        self.assertIn("removed again", outcome)
        self.assertIn("p_pgdata, p_redisdata were kept", outcome)
        untouched = FakeCompose()
        outcome = bootstrap.rollback_partial_start(untouched, had_containers_before=True)
        self.assertEqual([], untouched.calls, "an existing stack is never torn down by a failed re-run")
        self.assertIn("did not touch", outcome)
        broken = FakeCompose(down_ok=False)
        outcome = bootstrap.rollback_partial_start(broken, had_containers_before=False)
        self.assertIn("could not be fully removed", outcome, "a failing rollback never raises over the original error")


class ReadinessTests(unittest.TestCase):
    def test_project_lock_is_exclusive_and_released(self):
        with bootstrap.ProjectLock("pennilogic-unit-lock", wait_seconds=1) as held:
            self.assertTrue(held.path.is_file())
            with self.assertRaises(bootstrap.BootstrapError) as ctx:
                with bootstrap.ProjectLock("pennilogic-unit-lock", wait_seconds=1):
                    pass
            self.assertEqual("locked", ctx.exception.kind)
        self.assertTrue(held.path.is_file(), "the lock file is deliberately kept: unlinking breaks POSIX waiters")
        with bootstrap.ProjectLock("pennilogic-unit-lock", wait_seconds=1):
            pass  # released by the first context manager

    @unittest.skipIf(os.name == "nt", "POSIX flock inode semantics; Windows locks are handle-based")
    def test_project_lock_three_overlapping_holders_never_overlap(self):
        # Regression for the round-2 finding: with the lock file unlinked on release, a waiter polling
        # the old inode and a newcomer locking a fresh inode could both hold the lock at once.
        program = r"""
import sys, time, json, os
sys.path.insert(0, sys.argv[1]); import bootstrap
project, out = sys.argv[2], sys.argv[3]
with bootstrap.ProjectLock(project, wait_seconds=60):
    start = time.monotonic(); time.sleep(0.6); end = time.monotonic()
    with open(out, "a") as f: f.write(json.dumps({"pid": os.getpid(), "start": start, "end": end}) + "\n")
"""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "holders.jsonl"
            project = f"pennilogic-unit-lock-{os.getpid()}"
            procs = []
            for _ in range(2):
                procs.append(subprocess.Popen([sys.executable, "-c", program, str(support.SCRIPTS), project, str(out)]))
                time.sleep(0.15)
            time.sleep(0.4)  # A is inside, B is polling: now the release/newcomer race window opens
            procs.append(subprocess.Popen([sys.executable, "-c", program, str(support.SCRIPTS), project, str(out)]))
            for process in procs:
                self.assertEqual(0, process.wait(timeout=60))
            intervals = sorted((json.loads(line) for line in out.read_text().splitlines()), key=lambda r: r["start"])
        self.assertEqual(3, len(intervals))
        for earlier, later in zip(intervals, intervals[1:]):
            self.assertGreaterEqual(later["start"], earlier["end"],
                                    f"lock holders overlapped: {earlier} then {later}")

    def test_startup_ms_is_derived_from_first_successful_probe(self):
        state = {"StartedAt": "2026-09-29T10:00:00.000000000Z", "Health": {"Log": [
            {"Start": "2026-09-29T10:00:01Z", "End": "2026-09-29T10:00:01.100000000Z", "ExitCode": 1},
            {"Start": "2026-09-29T10:00:02Z", "End": "2026-09-29T10:00:02.250000000Z", "ExitCode": 0},
            {"Start": "2026-09-29T10:00:07Z", "End": "2026-09-29T10:00:07.050000000Z", "ExitCode": 0},
        ]}}
        self.assertEqual(2250, bootstrap.derive_startup_ms(state))

    def test_timestamps_in_both_docker_formats_are_parsed(self):
        rfc = bootstrap.parse_timestamp("2026-09-29T15:58:49.002386497Z")
        go = bootstrap.parse_timestamp("2026-09-29 15:58:50.394255128 +0000 UTC")
        self.assertEqual(1391869, int((go - rfc).total_seconds() * 1_000_000))
        offset = bootstrap.parse_timestamp("2026-09-29 17:58:50.5 +0200 CEST")
        self.assertEqual(go.replace(microsecond=0), offset.replace(microsecond=0))
        with self.assertRaises(ValueError):
            bootstrap.parse_timestamp("yesterday")
        real = {"StartedAt": "2026-09-29T15:58:49.002386497Z", "Health": {"Log": [
            {"Start": "2026-09-29 15:58:50.394255128 +0000 UTC", "End": "2026-09-29 15:58:50.494255128 +0000 UTC",
             "ExitCode": 0}]}}
        self.assertEqual(1491, bootstrap.derive_startup_ms(real))

    def test_startup_ms_unknown_when_log_rotated_or_no_success(self):
        full = {"StartedAt": "2026-09-29T10:00:00Z", "Health": {"Log": [
            {"Start": f"2026-09-29T10:00:{s:02d}Z", "End": f"2026-09-29T10:00:{s:02d}.5Z", "ExitCode": 0}
            for s in range(10, 35, 5)]}}
        self.assertIsNone(bootstrap.derive_startup_ms(full))
        failing = {"StartedAt": "2026-09-29T10:00:00Z", "Health": {"Log": [
            {"Start": "2026-09-29T10:00:01Z", "End": "2026-09-29T10:00:01.1Z", "ExitCode": 1}]}}
        self.assertIsNone(bootstrap.derive_startup_ms(failing))
        self.assertIsNone(bootstrap.derive_startup_ms({}))

    def test_json_records_accept_array_and_lines(self):
        self.assertEqual([{"a": 1}, {"b": 2}], bootstrap.parse_json_records('[{"a": 1}, {"b": 2}]'))
        self.assertEqual([{"a": 1}, {"b": 2}], bootstrap.parse_json_records('{"a": 1}\n{"b": 2}\n'))
        self.assertEqual([], bootstrap.parse_json_records("  \n"))

    def test_owned_ports_only_counts_running_publishers(self):
        records = [
            {"Service": "postgres", "State": "running", "Publishers": [{"PublishedPort": 15432}, {"PublishedPort": 0}]},
            {"Service": "redis", "State": "exited", "Publishers": [{"PublishedPort": 16379}]},
        ]
        self.assertEqual({"postgres": {15432}}, bootstrap.owned_ports(records))

    def test_log_scan_detects_real_secret_but_ignores_trivial_values(self):
        class FakeCompose:
            def __init__(self, secrets, text):
                self.secret_values, self.text = secrets, text

            def logs(self):
                return self.text

        leaked = "generated-development-secret-123"
        self.assertFalse(bootstrap.logs_free_of_credentials(FakeCompose((leaked,), "credential value " + leaked + "\n")))
        self.assertTrue(bootstrap.logs_free_of_credentials(FakeCompose((leaked,), "database system is ready\n")))
        self.assertTrue(bootstrap.logs_free_of_credentials(FakeCompose(("x", "ready"), "database system is ready\n")),
                        "one-character or dictionary-word values would match any log by chance")

    def test_service_records_report_provenance_and_never_poll_latency(self):
        class FakeCompose:
            def inspect(self, ids):
                # docker inspect returns full IDs while compose ps gives 12-char prefixes
                return [{"Id": "pg-id" + "0" * 59, "State": {"StartedAt": "2026-09-29T10:00:00Z", "Health": {"Log": [
                    {"Start": "2026-09-29T10:00:01Z", "End": "2026-09-29T10:00:01.5Z", "ExitCode": 0}]}}},
                        {"Id": "redis-id" + "0" * 56, "State": {"StartedAt": "2026-09-29T10:00:00Z", "Health": {"Log": [
                            {"Start": f"2026-09-29T10:00:{s:02d}Z", "End": f"2026-09-29T10:00:{s:02d}.5Z", "ExitCode": 0}
                            for s in range(10, 35, 5)]}}}]  # rotated: five successes, first one gone

        records = [{"Service": "postgres", "State": "running", "Health": "healthy", "ID": "pg-id"},
                   {"Service": "redis", "State": "running", "Health": "healthy", "ID": "redis-id"}]
        fresh = bootstrap.service_records(FakeCompose(), records)
        self.assertEqual([
            {"service": "postgres", "healthy": True, "startup_ms": 1500, "startup_source": "health_log"},
            {"service": "redis", "healthy": True, "startup_ms": None, "startup_source": "unknown"},
        ], fresh, "rotated health log yields null, never this run's own wait time")
        rerun = bootstrap.service_records(FakeCompose(), records, already_running={"pg-id", "redis-id"})
        self.assertEqual([
            {"service": "postgres", "healthy": True, "startup_ms": 0, "startup_source": "already_running"},
            {"service": "redis", "healthy": True, "startup_ms": 0, "startup_source": "already_running"},
        ], rerun)
        stopped = [dict(records[0], State="exited", Health="")]
        self.assertEqual([
            {"service": "postgres", "healthy": False, "startup_ms": None, "startup_source": "unknown"},
            {"service": "redis", "healthy": False, "startup_ms": None, "startup_source": "unknown"},
        ], bootstrap.service_records(FakeCompose(), stopped))
        self.assertEqual({"pg-id", "redis-id"}, bootstrap.healthy_ids(records))
        self.assertEqual(set(), bootstrap.healthy_ids(stopped))


FAKE_DOCKER = r'''"""Harmless stand-in for docker.exe (infra#37 regression fixture; never touches Docker).

argv: <stdio: inherit|redirect> <state dir> <lifetime seconds>. Like docker.exe starting
docker-compose.exe, it starts a child process that either inherits this process's stdout/stderr
(the bootstrap's captured pipes) or has its own, and both outlive the bootstrap's timeout. The
child records its PID in <state>/child.pid and keeps <state>/held.txt open while it lives (on
Windows that file cannot be deleted until the child is gone).
"""
import subprocess
import sys
import time

stdio, state, lifetime = sys.argv[1], sys.argv[2], sys.argv[3]
child_code = (
    "import os, sys, time\n"
    "state, lifetime = sys.argv[1], float(sys.argv[2])\n"
    "with open(os.path.join(state, 'held.txt'), 'w') as held:\n"
    "    with open(os.path.join(state, 'child.pid'), 'w') as handle:\n"
    "        handle.write(str(os.getpid()))\n"
    "    time.sleep(lifetime)\n"
)
streams = ({"stdout": sys.stdout, "stderr": sys.stderr} if stdio == "inherit"
           else {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL})
child = subprocess.Popen([sys.executable, "-c", child_code, state, lifetime], **streams)
print(f"fake docker: started child {child.pid} ({stdio})", flush=True)
time.sleep(float(lifetime))
'''


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    _k32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    _k32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _k32.GetProcessHandleCount.argtypes = (wintypes.HANDLE, wintypes.LPDWORD)
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _SYNCHRONIZE, _PROCESS_TERMINATE, _PROCESS_QUERY_LIMITED_INFORMATION, _WAIT_OBJECT_0 = 0x100000, 0x1, 0x1000, 0

    def own_handle_count():
        count = wintypes.DWORD()
        _k32.GetProcessHandleCount(_k32.GetCurrentProcess(), ctypes.byref(count))
        return count.value


def wait_for_exit(pid, seconds):
    """True once the process has fully exited (Windows: its process object is signaled, which happens
    only after the kernel has released the process's handles; `GetExitCodeProcess` turns non-running
    milliseconds earlier and would let a following unlink race the handle rundown)."""
    if os.name != "nt":
        deadline = time.monotonic() + seconds
        while True:  # at least one check, so a zero wait still answers
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)
    handle = _k32.OpenProcess(_SYNCHRONIZE | _PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return True  # no such process object any more: torn down completely
    try:
        return _k32.WaitForSingleObject(handle, int(seconds * 1000)) == _WAIT_OBJECT_0
    finally:
        _k32.CloseHandle(handle)


def stop_process(pid):
    """Fixture hygiene only: stop a test child that outlived its test and wait for its exit
    (never used by the bootstrap). Returns True once the process is gone."""
    if os.name != "nt":
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return True  # an open file never blocks the directory removal on POSIX; no wait needed
    handle = _k32.OpenProcess(_SYNCHRONIZE | _PROCESS_TERMINATE, False, pid)
    if not handle:
        return True
    try:
        _k32.TerminateProcess(handle, 1)
        return _k32.WaitForSingleObject(handle, 2000) == _WAIT_OBJECT_0
    finally:
        _k32.CloseHandle(handle)


class DockerCommandTests(unittest.TestCase):
    """`Compose.docker()` with a harmless fake docker (infra#37).

    A timed-out `docker` command must raise `docker_timeout` about `timeout + TEARDOWN_SECONDS` after
    it started (a healthy Windows teardown takes ~0.1 s; the bound below adds half a second of slack
    for the start-up and wait overhead measured when a tree does not exit) even when the command
    started a child that outlives it, as docker.exe's compose plugin does on Windows. There the whole
    tree is owned by a job object and the child must be gone when the error is raised. On POSIX only
    docker itself is killed (unchanged by infra#37): the child is left to the operating system, no
    ownership is claimed in the error, and this test stops it. The fixture directory is removed
    without `ignore_errors`: a child that still held a file in it would fail the test loudly instead
    of leaving the directory behind.
    """

    TIMEOUT, LIFETIME = 2.0, 20.0  # seconds; the fake and its child outlive TIMEOUT + TEARDOWN_SECONDS widely
    TEARDOWN_SLACK = 0.5  # seconds of start-up/wait overhead tolerated on top of TIMEOUT + TEARDOWN_SECONDS
    TREE_EXITED = "Its whole process tree was terminated and has exited (2 processes, output released)."

    def setUp(self):
        self.state = Path(tempfile.mkdtemp(prefix="pennilogic-fake-docker-"))
        self.addCleanup(shutil.rmtree, self.state)
        self.addCleanup(self.stop_child)
        self.fake = self.state / "fake_docker.py"
        self.fake.write_text(FAKE_DOCKER, encoding="utf-8")
        environ = {k: v for k, v in os.environ.items() if not k.startswith("PENNILOGIC_")}
        environ.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"})
        self.compose = bootstrap.Compose("pennilogic-unit-fake", self.state / ".env", environ, (),
                                         docker_command=(sys.executable, str(self.fake)))

    def child_pid(self):
        pid_file = self.state / "child.pid"
        return int(pid_file.read_text()) if pid_file.is_file() else None

    def stop_child(self):
        pid = self.child_pid()
        if pid and not wait_for_exit(pid, 0):
            self.assertTrue(stop_process(pid), f"fixture child {pid} could not be stopped")

    def wait_until(self, predicate, seconds):
        deadline = time.monotonic() + seconds
        while not predicate() and time.monotonic() < deadline:
            time.sleep(0.05)
        return predicate()

    def test_missing_docker_is_reported(self):
        compose = bootstrap.Compose("p", self.state / ".env", os.environ, (),
                                    docker_command=("pennilogic-no-such-docker",))
        with self.assertRaises(bootstrap.BootstrapError) as ctx:
            compose.docker("version")
        self.assertEqual("docker_missing", ctx.exception.kind)

    def test_timed_out_docker_returns_within_bound_whatever_its_child_does_with_the_pipes(self):
        bound = self.TIMEOUT + bootstrap.TEARDOWN_SECONDS + self.TEARDOWN_SLACK
        for stdio in ("inherit", "redirect"):
            with self.subTest(stdio=stdio):
                for leftover in ("child.pid", "held.txt"):
                    (self.state / leftover).unlink(missing_ok=True)
                started = time.monotonic()
                with self.assertRaises(bootstrap.BootstrapError) as ctx:
                    self.compose.docker(stdio, str(self.state), str(self.LIFETIME), timeout=self.TIMEOUT)
                elapsed = time.monotonic() - started
                error = ctx.exception
                self.assertEqual("docker_timeout", error.kind)
                self.assertIn(f"did not finish within {self.TIMEOUT}s", str(error))
                self.assertLess(elapsed, bound,
                                f"a child that {stdio}s the output pipes delayed the timeout return to {elapsed:.2f}s")
                pid = self.child_pid()
                self.assertIsNotNone(pid, "the fake docker did not start its child within the timeout; the machine"
                                          f" was too slow to start two interpreters in {self.TIMEOUT}s")
                if os.name == "nt":
                    self.assertTrue(wait_for_exit(pid, 2.0),
                                    f"the child {pid} of the timed-out command survived ({stdio})")
                    (self.state / "held.txt").unlink()  # PermissionError here would mean the child still held it
                    self.assertEqual(self.TREE_EXITED, error.details.get("cleanup"))
                    self.assertIn(error.details["cleanup"], str(error))
                else:
                    self.assertNotIn("cleanup", error.details, "POSIX makes no ownership claim (unchanged path)")
                    self.stop_child()

    @unittest.skipIf(os.name != "nt", "Windows job objects")
    def test_failed_job_assignment_fails_closed_and_stops_the_command(self):
        refusal = bootstrap.ProcessOwnershipError(13, "AssignProcessToJobObject failed: Access is denied.", None, 5)
        started = time.monotonic()
        with mock.patch.object(bootstrap.WindowsJob, "assign", side_effect=refusal):
            with self.assertRaises(bootstrap.BootstrapError) as ctx:
                self.compose.docker("redirect", str(self.state), str(self.LIFETIME), timeout=self.TIMEOUT)
        elapsed = time.monotonic() - started
        self.assertEqual("io_error", ctx.exception.kind)
        self.assertIn("refused to own the process tree", str(ctx.exception))
        self.assertIn("AssignProcessToJobObject failed: Access is denied", str(ctx.exception))
        self.assertIn("had already been started and was terminated immediately", str(ctx.exception))
        self.assertNotIn("was not started", str(ctx.exception))
        self.assertLess(elapsed, self.TIMEOUT, "the command must be stopped at once, not run out its timeout")
        self.assertIsNone(self.child_pid(), "the command was terminated before it could start anything")

    @unittest.skipIf(os.name != "nt", "Windows job objects")
    def test_refused_job_creation_fails_closed_before_anything_starts(self):
        refusal = bootstrap.ProcessOwnershipError(13, "CreateJobObject failed: Access is denied.", None, 5)
        with mock.patch.object(bootstrap.WindowsJob, "__init__", side_effect=refusal):
            with self.assertRaises(bootstrap.BootstrapError) as ctx:
                self.compose.docker("redirect", str(self.state), str(self.LIFETIME), timeout=self.TIMEOUT)
        self.assertEqual("io_error", ctx.exception.kind)
        self.assertIn("CreateJobObject failed: Access is denied", str(ctx.exception))
        self.assertIn("The command was not started.", str(ctx.exception))
        self.assertNotIn("terminated", str(ctx.exception))
        self.assertEqual({"fake_docker.py"}, {p.name for p in self.state.iterdir()},
                         "nothing ran, so the fake docker wrote nothing")

    @unittest.skipIf(os.name != "nt", "Windows job objects")
    def test_failing_cleanup_keeps_the_timeout_primary_and_kill_on_close_still_applies(self):
        with mock.patch.object(bootstrap, "terminate_tree", side_effect=RuntimeError("probe: cleanup broke")):
            with self.assertRaises(bootstrap.BootstrapError) as ctx:
                self.compose.docker("redirect", str(self.state), str(self.LIFETIME), timeout=self.TIMEOUT)
        error = ctx.exception
        self.assertEqual("docker_timeout", error.kind, "a failing cleanup never replaces the timeout error")
        self.assertIn(f"did not finish within {self.TIMEOUT}s", str(error))
        self.assertIn("could not be cleaned up (RuntimeError: probe: cleanup broke)", error.details["cleanup"])
        self.assertIn("terminated without confirmation", error.details["cleanup"])
        pid = self.child_pid()
        self.assertIsNotNone(pid)
        self.assertTrue(wait_for_exit(pid, 2.0), "closing the job object must still terminate the child")

    @unittest.skipIf(os.name != "nt", "Windows job objects")
    def test_refused_termination_with_failing_kill_releases_the_pinned_handles(self):
        # Reliability finding R3: when TerminateJobObject is refused and the fallback kill raises, the
        # SYNCHRONIZE pins taken before the kill must still be closed (two handles leaked per event before).
        sleeper = "import time; time.sleep(30)"

        def one_round():
            with bootstrap.WindowsJob() as job:
                process = subprocess.Popen([sys.executable, "-c", sleeper],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                job.assign(process.pid)
                self.assertTrue(self.wait_until(lambda: job.active_processes() == 1, 10.0))
                with mock.patch.object(bootstrap.WindowsJob, "terminate", return_value=False), \
                        mock.patch.object(subprocess.Popen, "kill", side_effect=OSError("probe: kill refused")):
                    with self.assertRaises(OSError):
                        bootstrap.terminate_tree(job, process, time.monotonic() + 1.0)
                # leaving the block closes the job: kill-on-close ends the sleeper
            process.wait(timeout=bootstrap.TEARDOWN_SECONDS)
            del process  # the Popen's own process handle goes with it
            gc.collect()

        one_round()  # warm-up: lazily created interpreter/mock objects settle before the baseline
        before = own_handle_count()
        for _ in range(5):
            one_round()
        after = own_handle_count()
        self.assertLessEqual(after, before, f"process handle count grew from {before} to {after} over five"
                                            " refused-termination rounds (the leak was +2 per round)")

    @unittest.skipIf(os.name != "nt", "Windows job objects")
    def test_interrupt_inside_the_unowned_window_kills_the_started_command(self):
        # Reliability finding R2: between Popen returning and the assignment the command is unowned;
        # an interrupt there must not leave it behind. The command records its PID, the interrupt is
        # raised in place of the assignment once that PID is known.
        pid_file = self.state / "self.pid"
        code = f"import os, time; open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(30)"
        compose = bootstrap.Compose("p", self.state / ".env", os.environ, (), docker_command=(sys.executable, "-c"))

        def interrupted_assign(job, pid):
            self.assertTrue(self.wait_until(lambda: pid_file.is_file() and pid_file.read_text(), 10.0))
            raise KeyboardInterrupt

        with mock.patch.object(bootstrap.WindowsJob, "assign", interrupted_assign):
            with self.assertRaises(KeyboardInterrupt):
                compose.docker(code, timeout=self.TIMEOUT)
        pid = int(pid_file.read_text())
        self.assertTrue(wait_for_exit(pid, 2.0), f"the unowned command {pid} survived the interrupt")

    @unittest.skipIf(os.name != "nt", "Windows job objects")
    def test_command_that_exits_before_it_can_be_owned_is_reported_with_its_result(self):
        # Windows refuses to assign an exited process; a command that failed within microseconds must not
        # be turned into an ownership error. The delayed assignment stands in for that window.
        original = bootstrap.WindowsJob.assign

        def late_assign(job, pid):
            time.sleep(1.0)
            return original(job, pid)

        compose = bootstrap.Compose("p", self.state / ".env", os.environ, (), docker_command=(sys.executable, "-c"))
        with mock.patch.object(bootstrap.WindowsJob, "assign", late_assign):
            result = compose.docker("import sys; print('done'); sys.exit(3)")
        self.assertEqual((3, "done\n"), (result.returncode, result.stdout))

    @unittest.skipIf(os.name != "nt", "Windows job objects")
    def test_windows_job_owns_the_whole_tree_and_terminates_it(self):
        tree = ("import subprocess, sys, time;"
                " subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); time.sleep(30)")
        with bootstrap.WindowsJob() as job:
            process = subprocess.Popen([sys.executable, "-c", tree],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                job.assign(process.pid)  # works nested when the test runner itself is inside a job
                self.assertTrue(self.wait_until(lambda: len(job.process_ids() or []) == 2, 10.0),
                                f"child and grandchild are both members of the job: {job.process_ids()}")
                members = job.process_ids()
                self.assertIn(process.pid, members)
                grandchild = next(pid for pid in members if pid != process.pid)
                self.assertTrue(job.terminate())
                self.assertIsNotNone(process.wait(timeout=bootstrap.TEARDOWN_SECONDS))
                self.assertTrue(wait_for_exit(grandchild, bootstrap.TEARDOWN_SECONDS),
                                "the grandchild's process object must be signaled, not just the accounting")
                self.assertEqual(0, job.active_processes())
                self.assertEqual([], job.process_ids())
            finally:
                process.kill()
        self.assertIsNone(job.handle, "the job handle is closed with the context")

    @unittest.skipIf(os.name != "nt", "Windows job objects")
    def test_process_exits_awaits_the_process_objects_not_the_job_accounting(self):
        # The job's counter reads 0 well before a terminated process has released its handles; the
        # "has exited" claim must come from the process objects (a held file is deletable right after).
        held = self.state / "held-by-tree.txt"
        code = f"import time; f = open({str(held)!r}, 'w'); time.sleep(30)"
        with bootstrap.WindowsJob() as job:
            process = subprocess.Popen([sys.executable, "-c", code],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            job.assign(process.pid)
            self.assertTrue(self.wait_until(held.exists, 10.0))
            exits = bootstrap.ProcessExits()
            exits.add(job.process_ids())
            self.assertEqual(1, exits.seen)
            self.assertTrue(job.terminate())
            self.assertEqual(1, exits.wait(bootstrap.TEARDOWN_SECONDS))
            exits.close()
            held.unlink()  # PermissionError here would mean "exited" was claimed before the handle rundown
            process.wait(timeout=bootstrap.TEARDOWN_SECONDS)
        still_referenced = bootstrap.ProcessExits()
        still_referenced.add([process.pid])  # the Popen still holds a handle: the object exists and is signaled
        self.assertEqual((1, 0, 0), (len(still_referenced.handles), len(still_referenced.gone),
                                     len(still_referenced.unopenable)))
        self.assertEqual(1, still_referenced.wait(0))
        still_referenced.close()
        finished = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"], capture_output=True,
                                  text=True, check=True)
        gc.collect()  # the run()'s Popen and its process handle are gone: nothing of ours keeps the object alive
        released = bootstrap.ProcessExits()
        released.add([int(finished.stdout)])  # counts as exited, never as unopenable
        # Usually the PID is `gone` (OpenProcess fails with ERROR_INVALID_PARAMETER). But an unrelated component
        # on the host (endpoint protection, an ETW/WMI consumer) may still hold a handle to the just-exited
        # child: its object then outlives it, OpenProcess succeeds and the PID lands in `handles` instead (about
        # 1/300 without synthetic load, about half the rounds under a synthetic handle-holding load; infra#47).
        # The bootstrap relies on neither classification, only on what holds in both: a released PID is never
        # `unopenable`, and `wait` counts it as exited (a `gone` PID by definition, a pinned one because its
        # object is signaled). A process still running would be pinned but not signaled and fail the wait.
        classified = (len(released.handles), len(released.gone), len(released.unopenable))
        self.assertEqual(0, len(released.unopenable), classified)
        self.assertEqual(1, released.wait(0), classified)
        released.close()  # drops the pin taken in the `handles` case


class CommandLineEnvelopeTests(unittest.TestCase):
    """Refusals that happen before Docker is consulted, checked through the real CLI."""

    def run_cli(self, *args, env_extra):
        env = {k: v for k, v in os.environ.items() if not k.startswith("PENNILOGIC_")}
        env.update(env_extra)
        return support.run_script("bootstrap.py", *args, env=env, timeout=120)

    def test_non_loopback_refusal_emits_json_error_and_summary_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary_file = Path(tmp) / "out" / "summary.json"
            result = self.run_cli(
                "--project", "pennilogic-unit-test", "--env-file", str(Path(tmp) / ".env"),
                "--summary-file", str(summary_file),
                env_extra={"PENNILOGIC_BIND_ADDRESS": "0.0.0.0"},
            )
            self.assertEqual(1, result.returncode, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual(summary, json.loads(summary_file.read_text(encoding="utf-8")))
            generated = smoke.parse_env_file(Path(tmp) / ".env")
        self.assertEqual(bootstrap.SCHEMA, summary["schema"])
        self.assertEqual(("up", False, "non_loopback_bind"), (summary["action"], summary["ok"], summary["error"]["kind"]))
        self.assertEqual([{"service": "postgres", "healthy": False, "startup_ms": None, "startup_source": "unknown"},
                          {"service": "redis", "healthy": False, "startup_ms": None, "startup_source": "unknown"}],
                         summary["services"])
        self.assertIn("PENNILOGIC_BIND_ADDRESS=0.0.0.0", result.stderr)
        self.assertNotIn(generated["PENNILOGIC_POSTGRES_PASSWORD"], result.stdout + result.stderr,
                         "the generated password never reaches either stream")

    def test_status_with_invalid_project_does_not_create_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            result = self.run_cli("--status", "--project", "Bad Name", "--env-file", str(env_file), env_extra={})
            self.assertFalse(env_file.exists(), "--status must not create .env")
        self.assertEqual(1, result.returncode)
        self.assertEqual("invalid_project", json.loads(result.stdout)["error"]["kind"])
        self.assertEqual("status", json.loads(result.stdout)["action"])


if __name__ == "__main__":
    unittest.main()
