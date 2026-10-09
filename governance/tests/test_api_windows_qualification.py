"""Canonical Windows routing and synthetic outcome controls, not API target execution."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import conformance_support as support


generator = support.generator
CI = ".github/workflows/ci.yml"
SPEC = importlib.util.spec_from_file_location("windows_qualification", support.GOVERNANCE / "templates/qualify_windows.py")
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)
MARKER = "PRIVATE-FIXTURE-PAYLOAD-DO-NOT-PRINT"


def api_checker():
    namespace = {"__file__": str(support.GOVERNANCE.parent / "scripts/check_repository.py"),
                 "__name__": "generated_api_checker_fixture"}
    exec(compile(generator.checker("api"), "generated API checker", "exec"), namespace)
    return namespace["validate_workflow"]


class ApiWindowsWorkflowTests(unittest.TestCase):
    def test_parallel_owning_suites_and_always_running_required_native_result(self):
        workflow = json.loads(generator.workflow("api"))
        jobs = workflow["jobs"]
        self.assertEqual({"ci", "windows", "ci-result"}, set(jobs))
        self.assertEqual("Linux qualification", jobs["ci"]["name"])
        self.assertNotIn("needs", jobs["ci"])
        self.assertNotIn("needs", jobs["windows"])
        self.assertEqual("windows-2025", jobs["windows"]["runs-on"])
        self.assertEqual(generator.tool_steps(generator.profile_for("api")), jobs["windows"]["steps"][:4])
        windows = jobs["windows"]["steps"][-1]["run"]
        preparation = generator.profile_for("api")["commands"][:7]
        self.assertEqual([command.replace("/", "\\") for command in preparation] + ["python scripts\\qualify_windows.py"],
                         windows.splitlines()[::2])
        self.assertEqual(["if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"] * 8, windows.splitlines()[1::2])
        self.assertNotIn("--tests", windows)
        self.assertNotIn("integrationTest", windows)
        self.assertEqual("CI", jobs["ci-result"]["name"])
        self.assertEqual(["ci", "windows"], jobs["ci-result"]["needs"])
        self.assertEqual("always()", jobs["ci-result"]["if"])
        self.assertEqual({"contents": "read"}, workflow["permissions"])
        self.assertEqual(1, sum(job["name"] == "CI" for job in jobs.values()))
        for name in generator.PROFILES["repositories"]:
            if name != "api":
                self.assertNotIn("API_CI_SHA256", generator.checker(name))
        self.assertNotIn("windows", json.loads(generator.workflow("api", setup=True))["jobs"])

    def test_api_only_exact_binding_refuses_any_job_gate_permission_or_handoff_drift(self):
        validate = api_checker()
        original = json.loads(generator.workflow("api"))
        validate(CI, generator.encoded(original).encode("utf-8"))
        mutations = (
            lambda value: value["jobs"].pop("windows"),
            lambda value: value["jobs"].pop("ci-result"),
            lambda value: value["jobs"]["ci-result"].pop("if"),
            lambda value: value["jobs"]["ci-result"].update(needs=["ci"]),
            lambda value: value["jobs"]["ci-result"]["steps"][0].update(run="true"),
            lambda value: value["jobs"]["windows"].update({"runs-on": "windows-latest"}),
            lambda value: value["jobs"]["windows"]["steps"][-1].update(run="echo skipped"),
            lambda value: value["jobs"]["windows"]["steps"][0].update(uses="actions/checkout@" + "a" * 40),
            lambda value: value.update(permissions={"contents": "write"}),
            lambda value: value["jobs"]["ci"]["steps"][-1].pop("env"),
        )
        for mutation in mutations:
            changed = copy.deepcopy(original)
            mutation(changed)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "API CI must match"):
                validate(CI, generator.encoded(changed).encode("utf-8"))
        for name in generator.PROFILES["repositories"]:
            if name == "api":
                continue
            namespace = {"__file__": str(support.GOVERNANCE.parent / "scripts/check_repository.py")}
            exec(compile(generator.checker(name), "non-API checker", "exec"), namespace)
            with self.subTest(repository=name), self.assertRaises(ValueError):
                namespace["validate_workflow"](CI, generator.workflow("api").encode("utf-8"))

    def test_native_aggregator_accepts_only_two_explicit_successes(self):
        bash = shutil.which("bash")
        self.assertIsNotNone(bash, "Bash is required for the actual native CI result script")
        with tempfile.TemporaryDirectory(prefix="native-ci-result-") as temporary:
            root = Path(temporary)
            path = root / "result.sh"
            for repo in ("api", "infra"):
                script = generator.ci_result_job(repo)["steps"][0]["run"]
                path.write_text(script + "\n", encoding="utf-8", newline="\n")
                for linux, windows in itertools.product(("success", "failure", "cancelled", "skipped", "", None), repeat=2):
                    environment = support.defects.probe_environment()
                    for key, value in (("LINUX_RESULT", linux), ("WINDOWS_RESULT", windows)):
                        environment.pop(key, None)
                        if value is not None:
                            environment[key] = value
                    result = subprocess.run([bash, "--noprofile", "--norc", "-e", str(path)], cwd=root,
                                            env=environment, capture_output=True, check=False, timeout=10)
                    with self.subTest(repo=repo, linux=linux, windows=windows):
                        self.assertEqual(0 if linux == windows == "success" else 1, result.returncode)
                        self.assertNotIn(MARKER.encode(), result.stdout + result.stderr)

    def test_windows_powershell_stops_at_each_failed_native_command(self):
        source = generator.api_windows_job(generator.profile_for("api"))["steps"][-1]["run"]
        support.assert_powershell_failure_boundaries(self, source, 8)


class WindowsOutcomeTests(unittest.TestCase):
    def python_report(self, target_status="ok", target=None):
        target = qualification.PYTHON_TARGET if target is None else target
        return (
            f"{target.rsplit('.', 1)[-1]} ({target}) ... {target_status}\n"
            f"test_other (test_fixture.OtherTest.test_other) ... skipped '{MARKER}'\n"
            "\nRan 2 tests in 0.001s\n\nOK (skipped=1)\n"
        )

    def write_junit(self, root, status="passed", name=qualification.KOTLIN_METHOD):
        directory = root / qualification.JUNIT
        directory.mkdir(parents=True)
        suite = ET.Element("testsuite", tests="1", failures=str(int(status == "failure")),
                           errors=str(int(status == "error")), skipped=str(int(status == "skipped")))
        case = ET.SubElement(suite, "testcase", classname=qualification.KOTLIN_CLASS, name=name)
        if status != "passed":
            ET.SubElement(case, status, message=MARKER).text = MARKER
        (directory / "TEST-fixture.xml").write_bytes(ET.tostring(suite))

    def exercise(self, root, python=None, task="> Task :test", status="passed",
                 name=qualification.KOTLIN_METHOD, exit_code=0):
        def run(command, **options):
            self.assertEqual([sys.executable, str(root / "scripts" / "quality.py"), "test"], command)
            self.assertEqual(root, options["cwd"])
            options["stdout"].write((task + "\n" + MARKER + "\n").encode() + b"\xff\n")
            options["stderr"].write((python if python is not None else self.python_report()).encode())
            self.write_junit(root, status, name)
            return subprocess.CompletedProcess(command, exit_code)
        output = io.StringIO()
        with mock.patch.object(qualification.subprocess, "run", side_effect=run) as child, contextlib.redirect_stdout(output):
            try:
                qualification.qualify(root)
            finally:
                self.assertEqual(1, child.call_count)
                self.assertNotIn(MARKER, output.getvalue())
                if task not in ("> Task :test", "> Task :test FAILED"):
                    self.assertNotIn('"suite": "junit:test"', output.getvalue())
        return [json.loads(line) for line in output.getvalue().splitlines() if line.startswith("{")]

    def test_normal_command_emits_each_exact_hashed_outcome_and_both_fixed_target_identities(self):
        with tempfile.TemporaryDirectory(prefix="windows-outcomes-") as temporary:
            records = self.exercise(Path(temporary))
        outcomes = [record for record in records if record["event"] == "test_outcome"]
        self.assertEqual(3, len(outcomes))
        self.assertEqual(3, len({record["id_sha256"] for record in outcomes}))
        self.assertEqual({
            hashlib.sha256(identity.encode("utf-8")).hexdigest() for identity in (
                qualification.PYTHON_TARGET, "test_fixture.OtherTest.test_other",
                qualification.KOTLIN_CLASS + "\0" + qualification.KOTLIN_METHOD,
            )
        }, {record["id_sha256"] for record in outcomes})
        self.assertEqual({"passed", "skipped"}, {record["outcome"] for record in outcomes})
        self.assertEqual({qualification.PYTHON_TARGET, qualification.KOTLIN_CLASS + "." + qualification.KOTLIN_METHOD},
                         {record["required_test"] for record in outcomes if "required_test" in record})
        self.assertEqual({"event": "windows_qualification", "ok": True, "python_tests": 2, "junit_tests": 1}, records[-1])

    def test_target_skips_absence_cached_results_and_command_failure_refuse(self):
        cases = (
            {"python": self.python_report("skipped 'no privilege'")},
            {"python": self.python_report(target="test_fixture.OtherTest.test_not_the_target")},
            {"status": "skipped"}, {"status": "failure"}, {"name": "not the target()"},
            {"task": "> Task :test UP-TO-DATE"}, {"task": "> Task :test FROM-CACHE"},
            {"task": "> Task :test NO-SOURCE"}, {"task": "> Task :test SKIPPED"}, {"task": ""},
            {"task": "> Task :test FAILED"}, {"task": "> Task :test\n> Task :test"},
            {"exit_code": 9}, {"python": ""}, {"python": self.python_report().replace("Ran 2", "Ran 3")},
            {"python": self.python_report().replace(f"skipped '{MARKER}'", "FAIL")},
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="windows-outcome-refusal-") as temporary:
                with self.assertRaises(qualification.Refused):
                    self.exercise(Path(temporary), **case)

    def test_preexisting_results_refuse_before_any_process_or_repair(self):
        with tempfile.TemporaryDirectory(prefix="windows-stale-result-") as temporary:
            root = Path(temporary)
            self.write_junit(root)
            before = (root / qualification.JUNIT / "TEST-fixture.xml").read_bytes()
            with mock.patch.object(qualification.subprocess, "run") as child:
                with self.assertRaisesRegex(qualification.Refused, "preexisting"):
                    qualification.qualify(root)
                child.assert_not_called()
            self.assertEqual(before, (root / qualification.JUNIT / "TEST-fixture.xml").read_bytes())

    def test_real_unittest_verbose_output_with_docstrings_and_platform_skips_is_parsed_without_payloads(self):
        with tempfile.TemporaryDirectory(prefix="windows-real-unittest-format-") as temporary:
            root = Path(temporary)
            (root / "test_example.py").write_text(
                "import unittest\n\nclass Example(unittest.TestCase):\n"
                "    def test_pass(self):\n"
                f"        '''{MARKER}'''\n"
                "        self.assertTrue(True)\n"
                f"    @unittest.skip('{MARKER}')\n"
                "    def test_skip(self):\n        self.fail()\n", encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", str(root), "-v"],
                env=support.defects.probe_environment(), capture_output=True, check=False, timeout=15,
            )
            self.assertEqual(0, result.returncode)
            records = qualification.python_outcomes(result.stderr)
        self.assertEqual(["passed", "skipped"], [record["outcome"] for record in records])
        self.assertNotIn(MARKER, json.dumps(records))

    def test_python_inventory_is_complete_unique_and_independent_of_diagnostic_encoding(self):
        valid = self.python_report().encode("utf-8")
        records = qualification.python_outcomes(valid.replace(MARKER.encode("utf-8"), b"\xe9\xff"))
        self.assertEqual(["passed", "skipped"], [record["outcome"] for record in records])
        first = valid.splitlines()[0]
        cases = (
            valid + b"Ran 2 tests in 0.001s\n",
            first + b"\n" + first + b"\nRan 2 tests in 0.001s\n",
            valid.replace(b"Ran 2 tests in 0.001s", b""),
            valid.replace(b"Ran 2", b"Ran 0"),
            valid.replace(b" ... ok", b" ... unknown"),
            valid.replace(b"test_other (", b"test_wrong ("),
        )
        for data in cases:
            with self.subTest(data=data), self.assertRaises(qualification.Refused):
                qualification.python_outcomes(data)

    def test_junit_inventory_refuses_malformed_counts_missing_identities_and_duplicate_cases(self):
        mutations = (
            lambda suite: suite.set("tests", "2"),
            lambda suite: suite.set("failures", "1"),
            lambda suite: suite.attrib.pop("skipped"),
            lambda suite: suite.find("testcase").attrib.pop("classname"),
            lambda suite: suite.find("testcase").attrib.pop("name"),
            lambda suite: (suite.append(copy.deepcopy(suite.find("testcase"))), suite.set("tests", "2")),
            lambda suite: (ET.SubElement(suite.find("testcase"), "failure"),
                           ET.SubElement(suite.find("testcase"), "skipped")),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="windows-junit-refusal-") as temporary:
                root = Path(temporary)
                self.write_junit(root)
                path = root / qualification.JUNIT / "TEST-fixture.xml"
                suite = ET.parse(path).getroot()
                mutation(suite)
                path.write_bytes(ET.tostring(suite))
                with self.assertRaises(qualification.Refused):
                    qualification.junit_outcomes(root)

    def test_process_and_report_errors_and_non_windows_execution_fail_with_static_codes(self):
        for error in (OSError(MARKER), ValueError(MARKER), ET.ParseError(MARKER)):
            stderr = io.StringIO()
            with mock.patch.object(qualification.sys, "platform", "win32"), \
                    mock.patch.object(qualification, "qualify", side_effect=error), \
                    contextlib.redirect_stderr(stderr):
                self.assertEqual(1, qualification.main())
            self.assertEqual({"event": "windows_qualification_refused", "code": "process-or-report-error"},
                             json.loads(stderr.getvalue()))
            self.assertNotIn(MARKER, stderr.getvalue())
        stderr = io.StringIO()
        with mock.patch.object(qualification.sys, "platform", "linux"), \
                mock.patch.object(qualification, "qualify") as child, contextlib.redirect_stderr(stderr):
            self.assertEqual(1, qualification.main())
            child.assert_not_called()
        self.assertEqual("windows-owning-suites-require-windows", json.loads(stderr.getvalue())["code"])


if __name__ == "__main__":
    unittest.main()
