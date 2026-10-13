"""Single QA-gate entry point (PenniLogic/infra#28, E25-F01): subcommand dispatch and exit codes 0/1/2.

Each negative has a passing control and exactly one mutation, and asserts the exact static rule code.
"""

import contextlib
import io
import json
import os
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
