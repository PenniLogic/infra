"""Single QA-gate entry point (PenniLogic/infra#28, E25-F01): subcommand dispatch and exit codes 0/1/2.

Each negative has a passing control and exactly one mutation, and asserts the exact static rule code.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
import qa_gates
import qa_gates_support as qs


SCRIPT = Path(qa_gates.__file__).resolve()


class CliTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.manifest = self.root / "manifest.json"
        self.manifest.write_bytes(qs.encode(qs.manifest_document()))
        self.ledger = self.root / "ledger.json"
        self.ledger.write_bytes(qs.encode(qs.ledger_document()))

    def run_main(self, *arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = qa_gates.main(list(arguments), clock=lambda: qs.TODAY, ticket_port=qs.FakeTicketPort())
        return code, output.getvalue()

    def quarantine(self, outcome):
        attempt = self.root / "attempt.xml"
        attempt.write_bytes(qs.junit_xml(qs.cases(("test_case", outcome))))
        code, output = self.run_main("quarantine", "--job", qs.JOB, "--run-id", qs.RUN, "--attempt", str(attempt),
                                     "--ledger", str(self.ledger), "--manifest", str(self.manifest),
                                     "--base-ledger", str(self.ledger), "--base-manifest", str(self.manifest))
        return code, json.loads(output)

    def test_quarantine_subcommand_exit_codes(self):
        self.assertEqual(self.quarantine("passed")[0], 0)
        code, report = self.quarantine("failed")
        self.assertEqual((code, report["decision"]), (1, "fail"))
        self.assertIn("QG-REAL-FAILURE", {finding["rule"] for finding in report["findings"]})

    def test_retry_subcommand_exit_codes(self):
        workflows = self.root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        path = workflows / "ci.yml"

        def check(command):
            document = {"jobs": {"ci": {"runs-on": "ubuntu-24.04", "steps": [{"run": command}]}}}
            path.write_bytes(json.dumps(document).encode("utf-8"))
            code, output = self.run_main("retry", "--root", str(self.root), "--manifest", str(self.manifest),
                                         "--workflow", ".github/workflows/ci.yml")
            return code, json.loads(output)

        self.assertEqual(check("pytest --reruns 1")[0], 0)
        code, report = check("pytest --reruns 2")
        self.assertEqual((code, [finding["rule"] for finding in report["findings"]]),
                         (1, ["RETRY-ATTEMPT-HIDDEN", "RETRY-LIMIT-EXCEEDED", "RETRY-MANIFEST-JOB-UNCHECKED"]))

    def test_policy_subcommand_reports_the_pin(self):
        code, output = self.run_main("policy")
        report = json.loads(output)
        self.assertEqual((code, report["decision"]), (0, "pass"))
        self.assertEqual((report["policy"]["retry_limit"], report["policy"]["money_path_retry_limit"]), (1, 0))
        self.assertEqual(json.loads(self.run_main("policy", "extra")[1])["reason"], "USAGE")
        self.assertEqual(self.run_main("policy", "extra")[0], 2)

    def test_missing_or_unknown_subcommand_is_usage(self):
        self.assertEqual(self.run_main("policy")[0], 0)
        for arguments in ((), ("unknown",), ("--job", qs.JOB)):
            with self.subTest(arguments=arguments):
                code, output = self.run_main(*arguments)
                self.assertEqual((code, json.loads(output)),
                                 (2, {"schema": qa_gates.REPORT_SCHEMA, "decision": "refused", "reason": "USAGE"}))

    def test_missing_input_is_exit_two(self):
        self.assertEqual(self.quarantine("passed")[0], 0)
        code, output = self.run_main("quarantine", "--job", qs.JOB, "--run-id", qs.RUN, "--attempt",
                                     str(self.root / "missing.xml"), "--ledger", str(self.ledger),
                                     "--manifest", str(self.manifest), "--base-ledger", str(self.ledger),
                                     "--base-manifest", str(self.manifest))
        self.assertEqual((code, json.loads(output)["reason"]), (2, "INPUT-UNREADABLE"))

    def test_help_exits_zero(self):
        code, output = self.run_main("--help")
        self.assertEqual(code, 0)
        self.assertIn("qa_gates.py retry", output)

    def test_runs_as_a_script(self):
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        completed = subprocess.run([sys.executable, "-B", str(SCRIPT), "policy"], capture_output=True, timeout=60,
                                   env=environment, cwd=self.root, check=False)
        self.assertEqual((completed.returncode, completed.stderr), (0, b""))
        self.assertEqual(json.loads(completed.stdout)["decision"], "pass")


class HeadInputTests(unittest.TestCase):
    """Review round 3, ADVSEC-R3-03: the head ledger, manifest and root are named explicitly, so a gate run from a
    base checkout evaluates the head files and never its own checkout's copies."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.base = self.root / "base" / "scripts"
        self.base.mkdir(parents=True)
        for path in SCRIPT.parent.glob("qa_gates*.py"):
            (self.base / path.name).write_bytes(path.read_bytes())
        # Copy the configuration tree as it is: the merged SAST and DAST slice of infra#28 added the directory
        # scripts/qa-gates/rules, and a per-entry file copy raised IsADirectoryError on it.
        shutil.copytree(SCRIPT.parent / "qa-gates", self.base / "qa-gates")
        self.head = self.root / "head"
        self.head.mkdir()
        self.base_manifest = self.head / "base-manifest.json"
        self.base_manifest.write_bytes(qs.encode(qs.manifest_document()))
        relaxed = qs.manifest_document()
        relaxed["rules"][1]["tags"] = []  # the security rule loses its tag in the head
        self.manifest = self.head / "manifest.json"
        self.manifest.write_bytes(qs.encode(relaxed))
        self.ledger = self.head / "ledger.json"
        self.ledger.write_bytes(qs.encode(qs.ledger_document()))
        self.attempt = self.head / "attempt.xml"
        self.attempt.write_bytes(qs.junit_xml(qs.cases(("test_case", "passed"), classname=qs.SECURITY)))

    def gate(self, *arguments):
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        completed = subprocess.run([sys.executable, "-B", str(self.base / "qa_gates.py"), *map(str, arguments)],
                                   capture_output=True, timeout=60, env=environment, cwd=self.head, check=False)
        return completed.returncode, json.loads(completed.stdout)

    def test_quarantine_from_a_base_checkout_reads_the_named_head_files(self):
        common = ("quarantine", "--job", qs.JOB, "--run-id", qs.RUN, "--attempt", self.attempt,
                  "--base-ledger", self.ledger, "--base-manifest", self.base_manifest)
        control = self.gate(*common, "--ledger", self.ledger, "--manifest", self.base_manifest)
        self.assertEqual((control[0], control[1]["decision"]), (0, "pass"))
        code, report = self.gate(*common, "--ledger", self.ledger, "--manifest", self.manifest)
        self.assertEqual((code, {finding["rule"] for finding in report["findings"]}), (1, {"QG-MANIFEST-RELAXED"}))
        for missing in (("--ledger", self.ledger), ("--manifest", self.manifest)):
            with self.subTest(missing=missing[0]):
                self.assertEqual(self.gate(*common, *missing), (2, {"schema": "pennilogic.qa-gates.quarantine-report/1",
                                                                     "decision": "refused", "reason": "USAGE",
                                                                     "test": None}))

    def test_rate_and_retry_require_the_head_inputs(self):
        attempt = f"{qs.JOB}={self.attempt}"
        rate = ("rate", "--attempt", attempt, "--attempt", f"{qs.MONEY_JOB}={self.attempt}",
                "--base-ledger", self.ledger)
        self.assertEqual(self.gate(*rate, "--ledger", self.ledger, "--manifest", self.base_manifest)[0], 0)
        for missing in (("--ledger", self.ledger), ("--manifest", self.base_manifest)):
            with self.subTest(rate=missing[0]):
                self.assertEqual(self.gate(*rate, *missing)[1]["reason"], "USAGE")
        workflows = self.head / ".github" / "workflows"
        workflows.mkdir(parents=True)
        document = {"jobs": {"ci": {"steps": [{"run": "pytest --reruns 5"}]}, "money": {"steps": [{"run": "x"}]}}}
        (workflows / "ci.yml").write_text(json.dumps(document))
        retry = ("retry", "--workflow", ".github/workflows/ci.yml")
        code, report = self.gate(*retry, "--root", ".", "--manifest", self.base_manifest)
        self.assertEqual((code, report["checked"][0]["re_executions"]), (1, 5))
        for missing in (("--root", "."), ("--manifest", self.base_manifest)):
            with self.subTest(retry=missing[0]):
                self.assertEqual(self.gate(*retry, *missing)[1]["reason"], "USAGE")


if __name__ == "__main__":
    unittest.main()
