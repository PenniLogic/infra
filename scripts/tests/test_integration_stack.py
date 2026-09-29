"""Integration tests that run the real Compose stack in uniquely named, self-owned projects.

They need a reachable Docker Engine and are skipped (with the reason) otherwise, or when
``PENNILOGIC_SKIP_DOCKER_TESTS=1``. Every project created here is removed with ``--reset``
in ``tearDownClass``; nothing outside those projects is ever touched. Ports are chosen from
the currently free loopback ports, so the machine's own Postgres/Redis stay untouched.
"""

import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

import support
import smoke_infra as smoke

COMPOSE_FILE = support.ROOT / "docker-compose.yml"


def docker(*args, timeout=120):
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, check=False,
    )


def docker_available():
    if os.environ.get("PENNILOGIC_SKIP_DOCKER_TESTS") == "1":
        return "PENNILOGIC_SKIP_DOCKER_TESTS=1"
    try:
        result = docker("version", "--format", "{{.Server.Version}}", timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"docker not runnable: {error}"
    if result.returncode or not result.stdout.strip():
        return "Docker Engine not reachable: " + result.stderr.strip()[:200]
    return None


def project_containers(project):
    result = docker("ps", "-a", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{.ID}} {{.Names}}")
    return sorted(line for line in result.stdout.splitlines() if line.strip())


def project_volumes(project):
    result = docker("volume", "ls", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{.Name}}")
    return sorted(line for line in result.stdout.splitlines() if line.strip())


def redis_command(port, *parts):
    with smoke._connect("127.0.0.1", port, 5.0) as sock:
        reader = smoke._Reader(sock)
        sock.sendall(smoke._resp_command(*parts))
        line = reader.read_line()
        if line.startswith(b"$"):
            length = int(line[1:])
            return None if length < 0 else reader.read_exact(length + 2)[:-2].decode()
        return line[1:].decode()


DOCKER_SKIP_REASON = docker_available()


@unittest.skipIf(DOCKER_SKIP_REASON is not None, DOCKER_SKIP_REASON or "")
class StackLifecycleTests(unittest.TestCase):
    """Ordered lifecycle of one owned project (unittest runs methods alphabetically)."""

    @classmethod
    def setUpClass(cls):
        cls.project = f"pennilogic-test-{secrets.token_hex(4)}"
        cls.tmp = Path(tempfile.mkdtemp(prefix="pennilogic-infra-test-"))
        cls.env_file = cls.tmp / ".env"
        cls.pg_port, cls.redis_port = support.free_port(), support.free_port()
        while cls.redis_port == cls.pg_port:
            cls.redis_port = support.free_port()
        cls.env = {k: v for k, v in os.environ.items() if not k.startswith("PENNILOGIC_") and k != "COMPOSE_PROJECT_NAME"}
        cls.env.update({"PENNILOGIC_POSTGRES_PORT": str(cls.pg_port), "PENNILOGIC_REDIS_PORT": str(cls.redis_port)})
        cls.first_ids = None

    @classmethod
    def tearDownClass(cls):
        for suffix in ("", "-conflict", "-bind", "-race"):
            env_file = {"": cls.env_file, "-conflict": cls.tmp / "conflict.env", "-bind": cls.tmp / "bind.env",
                        "-race": cls.tmp / "race.env"}[suffix]
            support.run_script("bootstrap.py", "--reset", "--project", cls.project + suffix, "--env-file", env_file,
                               env=cls.env, timeout=300)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def bootstrap(self, *args, timeout=420):
        return support.run_script("bootstrap.py", "--project", self.project, "--env-file", self.env_file,
                                  "--timeout", "180", *args, env=self.env, timeout=timeout)

    def summary(self, result):
        self.assertTrue(result.stdout.strip(), f"no JSON on stdout; stderr:\n{result.stderr}")
        summary = json.loads(result.stdout)
        self.assertLessEqual({"schema", "action", "ok", "project", "services", "checks", "warnings", "error"},
                             set(summary))
        self.assertEqual("pennilogic.infra.bootstrap/1", summary["schema"])
        for record in summary["services"]:
            self.assertEqual({"service", "healthy", "startup_ms", "startup_source"}, set(record))
            self.assertIn(record["startup_source"], ("health_log", "already_running", "unknown"))
        return summary

    def compose_logs(self):
        return docker("compose", "--project-name", self.project, "-f", str(COMPOSE_FILE), "--env-file",
                      str(self.env_file), "logs", "--no-color").stdout

    def password(self):
        return smoke.parse_env_file(self.env_file)["PENNILOGIC_POSTGRES_PASSWORD"]

    def test_01_fresh_stack_becomes_healthy_with_smoke_and_artifact(self):
        summary_file = self.tmp / "artifacts" / "bootstrap.json"
        result = self.bootstrap("--smoke", "--summary-file", summary_file)
        self.assertEqual(0, result.returncode, result.stderr)
        summary = self.summary(result)
        self.assertTrue(summary["ok"], summary)
        self.assertEqual(summary, json.loads(summary_file.read_text(encoding="utf-8")))
        self.assertEqual(self.project, summary["project"])
        for record in summary["services"]:
            self.assertTrue(record["healthy"], record)
            self.assertEqual("health_log", record["startup_source"], record)
            self.assertIsInstance(record["startup_ms"], int)
            self.assertGreater(record["startup_ms"], 0)
        self.assertTrue(summary["checks"]["single_stack"], summary["checks"])
        self.assertEqual({"postgres": 1, "redis": 1}, summary["checks"]["containers"])
        self.assertEqual([f"{self.project}_pgdata", f"{self.project}_redisdata"], summary["checks"]["volumes"])
        self.assertTrue(summary["checks"]["logs_free_of_credentials"])
        self.assertEqual([], summary["warnings"])
        smoke_doc = summary["smoke"]
        self.assertEqual("pennilogic.infra.smoke/1", smoke_doc["schema"])
        self.assertTrue(smoke_doc["ok"], smoke_doc)
        for record in smoke_doc["services"]:
            self.assertEqual({"service", "status", "latency_ms", "detail"}, set(record))
            self.assertEqual("ok", record["status"], record)
            self.assertIsInstance(record["latency_ms"], int)
        self.assertTrue(self.env_file.is_file(), ".env is generated on first run")
        password = self.password()
        self.assertGreaterEqual(len(password), 24)
        self.assertNotIn(password, result.stdout + result.stderr, "credential in bootstrap output")
        self.assertNotIn(password, self.compose_logs(), "credential in container startup output")
        self.assertEqual(2, len(project_containers(self.project)))
        for name in project_containers(self.project):
            self.assertIn(f"{self.project}-", name, "containers are project-scoped, not fixed names")
        type(self).first_ids = project_containers(self.project)

    def test_02_second_run_is_idempotent(self):
        result = self.bootstrap("--smoke")
        self.assertEqual(0, result.returncode, result.stderr)
        summary = self.summary(result)
        self.assertTrue(summary["ok"], summary)
        self.assertTrue(summary["checks"]["single_stack"])
        self.assertEqual(self.first_ids, project_containers(self.project), "running containers were replaced")
        self.assertEqual(2, len(project_volumes(self.project)))
        self.assertTrue(summary["smoke"]["ok"])
        for record in summary["services"]:
            self.assertEqual((0, "already_running"), (record["startup_ms"], record["startup_source"]),
                             "an already healthy container reports 0, never this run's own wait time")

    def test_03_down_keeps_data_and_recreate_restores_it(self):
        self.assertEqual("OK", redis_command(self.redis_port, "SET", "pennilogic:test:persist", "kept"))
        result = self.bootstrap("--down")
        self.assertEqual(0, result.returncode, result.stderr)
        summary = self.summary(result)
        self.assertEqual(("down", True), (summary["action"], summary["ok"]))
        self.assertEqual([], project_containers(self.project))
        self.assertEqual(2, len(project_volumes(self.project)), "--down must keep the named volumes")
        self.assertEqual(2, len(summary["checks"]["volumes_remaining"]))
        result = self.bootstrap()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(self.summary(result)["ok"])
        self.assertEqual("kept", redis_command(self.redis_port, "GET", "pennilogic:test:persist"))
        self.assertEqual("ok", smoke.probe("postgres", smoke.load_settings(self.env_file, self.env), 5.0)["status"])

    def test_04_existing_volume_with_other_credentials_is_named_not_wiped(self):
        old_password = self.password()
        self.env_file.unlink()
        result = self.bootstrap()
        self.assertEqual(0, result.returncode, result.stderr)
        summary = self.summary(result)
        self.assertTrue(summary["ok"], "health is credential-agnostic; the start itself succeeds")
        self.assertTrue(any("already existed" in w and "--reset" in w for w in summary["warnings"]), summary["warnings"])
        self.assertNotEqual(old_password, self.password())
        self.assertEqual(2, len(project_volumes(self.project)), "existing data must never be wiped implicitly")
        probe = smoke.probe("postgres", smoke.load_settings(self.env_file, self.env), 5.0)
        self.assertEqual("error", probe["status"], probe)
        self.assertIn("28P01", probe["detail"])
        self.assertIn("--reset", probe["detail"])
        self.assertNotIn(self.password(), json.dumps(probe))
        self.assertNotIn(old_password, json.dumps(probe))

    def test_05_reset_removes_everything_and_recreate_needs_no_manual_step(self):
        result = self.bootstrap("--reset")
        self.assertEqual(0, result.returncode, result.stderr)
        summary = self.summary(result)
        self.assertEqual(("reset", True), (summary["action"], summary["ok"]))
        self.assertEqual([], project_containers(self.project))
        self.assertEqual([], project_volumes(self.project))
        self.assertEqual({"containers_remaining": 0, "volumes_remaining": []}, summary["checks"])
        result = self.bootstrap("--smoke")
        self.assertEqual(0, result.returncode, result.stderr)
        summary = self.summary(result)
        self.assertTrue(summary["ok"], summary)
        self.assertTrue(summary["smoke"]["ok"], summary["smoke"])
        self.assertEqual([], summary["warnings"])
        self.assertIsNone(redis_command(self.redis_port, "GET", "pennilogic:test:persist"), "reset destroyed data")

    def test_06_occupied_postgres_port_fails_fast_naming_the_port(self):
        decoy = socket.socket()
        decoy.bind(("127.0.0.1", 0))
        decoy.listen(1)
        port = decoy.getsockname()[1]
        project = self.project + "-conflict"
        env = dict(self.env, PENNILOGIC_POSTGRES_PORT=str(port), PENNILOGIC_REDIS_PORT=str(support.free_port()))
        started = time.monotonic()
        try:
            result = support.run_script("bootstrap.py", "--project", project, "--env-file", self.tmp / "conflict.env",
                                        env=env, timeout=180)
        finally:
            decoy.close()
        elapsed = time.monotonic() - started
        self.assertEqual(1, result.returncode)
        self.assertLess(elapsed, 90, "the conflict must be reported promptly, not after a hang")
        summary = json.loads(result.stdout)
        self.assertEqual("port_conflict", summary["error"]["kind"])
        self.assertEqual([port], summary["error"]["ports"])
        self.assertIn(f"port {port} is already in use", result.stderr)
        self.assertIn('service "postgres"', result.stderr)
        self.assertIn("PENNILOGIC_POSTGRES_PORT=", result.stderr)
        self.assertIn("Nothing was started.", result.stderr)
        self.assertEqual([], project_containers(project), "no container may be created on a conflict")
        self.assertEqual([], project_volumes(project))

    def test_07_status_is_read_only(self):
        before = project_containers(self.project)
        result = self.bootstrap("--status")
        self.assertEqual(0, result.returncode, result.stderr)
        summary = self.summary(result)
        self.assertEqual(("status", True), (summary["action"], summary["ok"]))
        self.assertTrue(all(record["healthy"] for record in summary["services"]))
        for record in summary["services"]:
            self.assertIn(record["startup_source"], ("health_log", "unknown"), "status never guesses")
        self.assertEqual(before, project_containers(self.project))

    def test_08_docker_bind_failure_after_preflight_is_named_and_rolled_back(self):
        # A socket that is bound but not listening refuses connections, so the preflight cannot see it,
        # but Docker cannot bind the port either: this is the post-preflight race the code must translate.
        decoy = socket.socket()
        decoy.bind(("127.0.0.1", 0))
        port = decoy.getsockname()[1]
        project = self.project + "-bind"
        env = dict(self.env, PENNILOGIC_POSTGRES_PORT=str(port), PENNILOGIC_REDIS_PORT=str(support.free_port()))
        try:
            result = support.run_script("bootstrap.py", "--project", project, "--env-file", self.tmp / "bind.env",
                                        "--timeout", "60", env=env, timeout=300)
        finally:
            decoy.close()
        self.assertEqual(1, result.returncode)
        summary = json.loads(result.stdout)
        self.assertEqual("port_conflict", summary["error"]["kind"], result.stderr)
        self.assertEqual([port], summary["error"]["ports"])
        self.assertIn(f"port(s) {port}", result.stderr)
        self.assertIn("removed again", summary["error"]["rollback"])
        self.assertEqual([], project_containers(project), "no half-started container may remain")
        self.assertEqual([], docker("network", "ls", "--filter", f"label=com.docker.compose.project={project}",
                                    "--format", "{{.Name}}").stdout.split())
        self.assertEqual(2, len(project_volumes(project)), "rollback never removes data volumes")

    def test_09_two_simultaneous_first_runs_share_one_env_and_one_stack(self):
        project = self.project + "-race"
        env_file = self.tmp / "race.env"
        env = dict(self.env, PENNILOGIC_POSTGRES_PORT=str(support.free_port()), PENNILOGIC_REDIS_PORT=str(support.free_port()))
        args = [sys.executable, str(support.SCRIPTS / "bootstrap.py"), "--project", project, "--env-file", str(env_file),
                "--timeout", "180"]
        environment = dict(env, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        first = subprocess.Popen(args, cwd=support.ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, encoding="utf-8", errors="replace")
        second = subprocess.Popen(args, cwd=support.ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, encoding="utf-8", errors="replace")
        outputs = [process.communicate(timeout=420) for process in (first, second)]
        codes = (first.returncode, second.returncode)
        self.assertEqual((0, 0), codes, [o[1][-800:] for o in outputs])
        summaries = [json.loads(o[0]) for o in outputs]
        self.assertTrue(all(s["ok"] and s["checks"]["single_stack"] for s in summaries), summaries)
        self.assertEqual(2, len(project_containers(project)))
        self.assertEqual(2, len(project_volumes(project)))
        self.assertTrue(any("waiting for it to finish" in o[1] for o in outputs), "one run must wait on the lock")
        sources = sorted(r["startup_source"] for s in summaries for r in s["services"])
        self.assertEqual(["already_running", "already_running", "health_log", "health_log"], sources)
        password = smoke.parse_env_file(env_file)["PENNILOGIC_POSTGRES_PASSWORD"]
        self.assertEqual("ok", smoke.probe("postgres", smoke.load_settings(env_file, env), 5.0)["status"],
                         "both runs used the single generated password")
        self.assertNotIn(password, "".join(o[0] + o[1] for o in outputs))


if __name__ == "__main__":
    unittest.main()
