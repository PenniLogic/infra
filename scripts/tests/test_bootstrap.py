"""Docker-free tests for scripts/bootstrap.py: env generation, validation, port diagnostics, envelope."""

import json
import os
from pathlib import Path
import shutil
import socket
import stat
import tempfile
import unittest

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
            # Docker Desktop for Windows 29.7.2, captured verbatim from a failed `compose up`:
            "Error response from daemon: ports are not available: exposing port TCP 127.0.0.1:55726 -> 127.0.0.1:0: "
            "listen tcp4 127.0.0.1:55726: bind: Only one usage of each socket address (protocol/network address/port)"
            " is normally permitted.": [55726],
            # Linux / macOS wording:
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
            with self.subTest(stderr=stderr[:60]):
                error = bootstrap.compose_port_failure(stderr)
                self.assertIsNotNone(error, stderr)
                self.assertEqual(("port_conflict", ports), (error.kind, error.details["ports"]))
                self.assertIn(f"port(s) {ports[0]}", str(error))
                self.assertIn("PENNILOGIC_*_PORT", str(error))
        self.assertIsNone(bootstrap.compose_port_failure("some unrelated failure"))

    def test_conflict_error_carries_earlier_warnings(self):
        conflicts = [{"service": "postgres", "port": 5432, "address": "127.0.0.1", "holder": "x",
                      "variable": "PENNILOGIC_POSTGRES_PORT", "suggested_port": 15432}]
        error = bootstrap.conflict_error(conflicts, warnings=["stale volume warning"])
        self.assertEqual(["stale volume warning"], error.details["summary"]["warnings"])

    def test_rollback_after_failed_up_reports_outcome_and_keeps_volumes(self):
        class FakeCompose:
            project = "p"

            def __init__(self):
                self.calls = []

            def compose(self, *args, **kwargs):
                self.calls.append(args)
                return type("R", (), {"returncode": 0})()

            def ps(self, all_states=False):
                return []

            def volumes(self):
                return ["p_pgdata", "p_redisdata"]

        fake = FakeCompose()
        outcome = bootstrap.rollback_partial_start(fake)
        self.assertEqual([("down", "--remove-orphans")], fake.calls, "never `--volumes` on rollback")
        self.assertIn("removed again", outcome)
        self.assertIn("p_pgdata, p_redisdata were kept", outcome)


class ReadinessTests(unittest.TestCase):
    def test_project_lock_is_exclusive_and_released(self):
        with bootstrap.ProjectLock("pennilogic-unit-lock", wait_seconds=1) as held:
            self.assertTrue(held.path.is_file())
            with self.assertRaises(bootstrap.BootstrapError) as ctx:
                with bootstrap.ProjectLock("pennilogic-unit-lock", wait_seconds=1):
                    pass
            self.assertEqual("locked", ctx.exception.kind)
        with bootstrap.ProjectLock("pennilogic-unit-lock", wait_seconds=1):
            pass  # released by the first context manager

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
