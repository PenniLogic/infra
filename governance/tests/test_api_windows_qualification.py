"""Canonical Windows routing and synthetic outcome controls, not API target execution."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import conformance_support as support
from conformance import generator as generator_module
import qualify as infra_qualification


generator = support.generator
CI = ".github/workflows/ci.yml"
SPEC = importlib.util.spec_from_file_location("windows_qualification", support.GOVERNANCE / "templates/qualify_windows.py")
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)
MARKER = "PRIVATE-FIXTURE-PAYLOAD-DO-NOT-PRINT"
INPUT_PREPARATION = "python -I -S -B scripts\\money_client_interop.py prepare"


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
        self.assertEqual([command.replace("/", "\\") for command in preparation]
                         + [INPUT_PREPARATION, "python scripts\\qualify_windows.py"],
                         windows.splitlines()[::2])
        self.assertEqual(["if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"] * 9, windows.splitlines()[1::2])
        self.assertNotIn("--node", windows)
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
        support.assert_powershell_failure_boundaries(self, source, 9)

    def test_input_preparation_omission_stub_reordering_and_missing_guard_are_refused(self):
        validate = api_checker()
        original = json.loads(generator.workflow("api"))
        commands = original["jobs"]["windows"]["steps"][-1]["run"].splitlines()[::2]
        self.assertEqual(INPUT_PREPARATION, commands[-2])
        changed_commands = (
            commands[:-2] + commands[-1:],
            commands[:-2] + ["python -c \"pass\"", commands[-1]],
            commands[:-2] + [commands[-1], commands[-2]],
            [commands[-2]] + commands[:-2] + commands[-1:],
            commands[:-2] + [INPUT_PREPARATION + " --node ignored", commands[-1]],
        )
        scripts = [generator.powershell_commands(changed) for changed in changed_commands]
        scripts.append(original["jobs"]["windows"]["steps"][-1]["run"].replace(
            INPUT_PREPARATION + "\nif ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }", INPUT_PREPARATION,
        ))
        for script in scripts:
            changed = copy.deepcopy(original)
            changed["jobs"]["windows"]["steps"][-1]["run"] = script
            with self.subTest(script=script), self.assertRaisesRegex(ValueError, "API CI must match"):
                validate(CI, generator.encoded(changed).encode("utf-8"))

    def test_input_preparation_preserves_accepted_other_workflows_profiles_and_qualifier(self):
        accepted = "6b1e4baf403f25e6c4c695a5676e995f1ecb259e"
        with tempfile.TemporaryDirectory(prefix="api-windows-accepted-") as temporary:
            root = Path(temporary)
            for name in ("generate.py", "repository-profiles.json"):
                (root / name).write_text(
                    support.git(support.GOVERNANCE.parent, "show", f"{accepted}:governance/{name}"),
                    encoding="utf-8", newline="\n",
                )
            previous = generator_module.load(root / "generate.py", name="api_windows_accepted_generator")
            android_commands = previous.PROFILES["repositories"]["android"]["commands"]
            self.assertEqual([
                "python scripts/check_repository.py",
                "python -m pip install -r scripts/privacy_traffic/requirements.txt",
                "python scripts/quality_gates.py ci",
                "python scripts/quality_gates.py self-test",
                "python scripts/privacy_traffic_harness.py self-test",
                "python scripts/check_privacy_components.py",
                'python -m unittest discover -s scripts/tests -p "test_*.py"',
            ], android_commands)
            android_commands[4] = "python scripts/privacy_traffic_harness.py self-test --all-scripts"
            android_commands.pop()
            self.assertEqual(previous.PROFILES, generator.PROFILES)
            for name in generator.PROFILES["repositories"]:
                for setup in (False, True):
                    expected = previous.workflow(name, setup=setup)
                    if name == "api" and not setup:
                        document = json.loads(expected)
                        step = document["jobs"]["windows"]["steps"][-1]
                        qualifier = "python scripts\\qualify_windows.py"
                        self.assertEqual(1, step["run"].count(qualifier))
                        step["run"] = step["run"].replace(
                            qualifier, generator.powershell_commands([INPUT_PREPARATION]) + "\n" + qualifier,
                        )
                        expected = previous.encoded(document)
                    with self.subTest(repository=name, setup=setup):
                        self.assertEqual(expected, generator.workflow(name, setup=setup))
        qualifier_source = "5795155323e7ff9899fb8cf2846ab6646fb0f141"
        accepted_qualifier = "f85f50f41b31a32838e9d4326947bb437140446a"
        self.assertEqual(
            support.git(support.GOVERNANCE.parent, "show", f"{qualifier_source}:governance/templates/qualify_windows.py"),
            support.git(support.GOVERNANCE.parent, "show", f"{accepted_qualifier}:governance/templates/qualify_windows.py"),
        )
        current_source = "f85d4cd7f7d5a1c14669d8040f282437ceb5ef7f"
        current_qualifier = support.git(
            support.GOVERNANCE.parent, "show", f"{current_source}:governance/templates/qualify_windows.py",
        )
        self.assertEqual(
            current_qualifier,
            (support.GOVERNANCE / "templates/qualify_windows.py").read_text(encoding="utf-8"),
        )
        self.assertEqual(current_qualifier, generator.artifacts("api")["scripts/qualify_windows.py"])


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
            report = python if python is not None else self.python_report()
            options["stderr"].write(report if isinstance(report, bytes) else report.encode())
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

    def real_admissions(self, body, *, diagnostic=b"", description=None, decorator="",
                        other_body=None, allowed_skip=True, expected_exit=0,
                        expected_tail=b"OK (skipped=1)", accepted=False, infra_accepted=None):
        if infra_accepted is None:
            infra_accepted = accepted
        module, class_name, method = qualification.PYTHON_TARGET.rsplit(".", 2)
        other = f"{module}.{class_name}.test_other"
        source = f"import sys\nimport unittest\n\nclass {class_name}(unittest.TestCase):\n"
        if decorator:
            source += f"    @unittest.{decorator}\n"
        source += f"    def {method}(self):\n"
        if description is not None:
            source += f"        {description!r}\n"
        source += f"        sys.stderr.buffer.write({diagnostic!r})\n        {body}\n"
        source += "    def test_other(self):\n"
        source += other_body or f"        self.skipTest('{MARKER}')\n"
        with tempfile.TemporaryDirectory(prefix="qualification-real-outcomes-") as temporary:
            root = Path(temporary)
            tests = root / "governance" / "tests"
            tests.mkdir(parents=True)
            (tests / (module + ".py")).write_text(source, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", str(tests), "-v"],
                cwd=root, env=support.defects.probe_environment(),
                capture_output=True, check=False, timeout=15,
            )
            self.assertEqual(expected_exit, result.returncode)
            self.assertEqual(expected_tail, result.stderr.splitlines()[-1])
            with self.subTest(caller="api"):
                if accepted:
                    records = self.exercise(root, python=result.stderr, exit_code=result.returncode)
                    self.assertTrue(records[-1]["ok"])
                else:
                    with self.assertRaises(qualification.Refused):
                        self.exercise(root, python=result.stderr, exit_code=result.returncode)
            output = io.StringIO()
            with self.subTest(caller="infra"), mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.dict(sys.modules), mock.patch.object(sys, "path", sys.path[:]), \
                    mock.patch.object(infra_qualification, "versions", return_value={"image_version": "synthetic"}), \
                    mock.patch.object(infra_qualification, "source_inventory", return_value=(
                        "a" * 40, "b" * 40, [{"path_sha256": "c" * 64, "mode": "100644", "git_blob": "d" * 40}],
                    )), \
                    mock.patch.object(infra_qualification, "REQUIRED", {"governance": {qualification.PYTHON_TARGET, other}}), \
                    mock.patch.object(infra_qualification, "SKIPS", {
                        sys.platform: {"governance": {other} if allowed_skip else set()},
                    }), \
                    contextlib.redirect_stdout(output):
                if infra_accepted:
                    infra_qualification.qualify(root, "governance")
                    records = [json.loads(line) for line in output.getvalue().splitlines()]
                    self.assertEqual(
                        {"event": "infra_qualification", "suite": "governance", "ok": True,
                         "tests": 2, "skipped": int(allowed_skip)},
                        records[-1],
                    )
                else:
                    with self.assertRaises(infra_qualification.Refused):
                        infra_qualification.qualify(root, "governance")
                    self.assertNotIn('"event": "infra_qualification"', output.getvalue())
                self.assertNotIn(MARKER, output.getvalue())

    def test_real_skip_and_expected_failure_cannot_be_replaced_by_diagnostic_statuses_in_either_admission(self):
        diagnostics = (b"", b"synthetic diagnostic\nok\n", b"ok\n", b"synthetic ... ok\n",
                       b"ok\nunterminated diagnostic ", b"\xff\nok\n")
        for body, decorator, tail in (
            (f"self.skipTest('{MARKER}')", "", b"OK (skipped=2)"),
            (f"self.fail('{MARKER}')", "expectedFailure", b"OK (skipped=1, expected failures=1)"),
        ):
            for description, diagnostic in itertools.product((None, MARKER), diagnostics):
                with self.subTest(decorator=decorator, docstring=description is not None, diagnostic=diagnostic):
                    self.real_admissions(body, decorator=decorator, description=description,
                                         diagnostic=diagnostic, expected_tail=tail)

    def test_real_passing_docstrings_and_applicable_skips_pass_but_interleaving_and_failures_refuse(self):
        for description in (None, MARKER, "ok", "description ... ok"):
            with self.subTest(description=description):
                self.real_admissions("self.assertTrue(True)", description=description, accepted=True)
        for diagnostic in (b"", b"synthetic diagnostic\nok\n", b"ok\n", b"synthetic ... ok\n"):
            with self.subTest(diagnostic=diagnostic):
                if diagnostic:
                    self.real_admissions("self.assertTrue(True)", diagnostic=diagnostic, infra_accepted=True)
                self.real_admissions(f"self.fail('{MARKER}')", diagnostic=diagnostic,
                                     expected_exit=1, expected_tail=b"FAILED (failures=1, skipped=1)")

    def test_real_diagnostics_cannot_swap_per_id_outcomes_even_when_terminal_counts_match(self):
        for diagnostic in (False, True):
            other = (f"        sys.stderr.buffer.write(b\"synthetic diagnostic\\nskipped '{MARKER}'\\ntail \")\n"
                     if diagnostic else "")
            other += "        self.assertTrue(True)\n"
            with self.subTest(diagnostic=diagnostic):
                self.real_admissions(
                    f"self.skipTest('{MARKER}')", other_body=other,
                    diagnostic=b"synthetic diagnostic\nok\ntail " if diagnostic else b"",
                )

    def test_real_first_prefix_and_later_status_diagnostics_refuse_with_one_passing_control(self):
        other = "        self.assertTrue(True)\n"
        for description in (None, MARKER):
            with self.subTest(docstring=description is not None, control="both-passing"):
                self.real_admissions("self.assertTrue(True)", other_body=other, allowed_skip=False,
                                     description=description, expected_tail=b"OK", accepted=True)
            for body, decorator, tail in (
                (f"self.skipTest('{MARKER}')", "", b"OK (skipped=1)"),
                (f"self.fail('{MARKER}')", "expectedFailure", b"OK (expected failures=1)"),
            ):
                for diagnostic in (b"", b"ok\n", b"synthetic diagnostic\nok\n"):
                    with self.subTest(decorator=decorator, docstring=description is not None, diagnostic=diagnostic):
                        self.real_admissions(
                            body, decorator=decorator, diagnostic=diagnostic, description=description,
                            other_body=other, allowed_skip=False, expected_tail=tail,
                        )

    def test_python_inventory_is_complete_unique_and_independent_of_diagnostic_encoding(self):
        valid = self.python_report().encode("utf-8")
        records = qualification.python_outcomes(valid.replace(MARKER.encode("utf-8"), b"\xe9\xff"))
        self.assertEqual(["passed", "skipped"], [record["outcome"] for record in records])
        first = valid.splitlines()[0]
        cases = (
            valid + b"Ran 2 tests in 0.001s\n",
            valid + b"ok\n",
            valid + b"diagnostic ... skipped 'platform'\n",
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


class WindowsRefusalDiagnosticTests(unittest.TestCase):
    def capture_refusal(self, root, runner, code="ambiguous-python-outcome", expected_exit=1):
        streams, captured, open_at_publication = {}, {}, []

        class PublicOutput(io.StringIO):
            def write(self, text):
                if '"event": "windows_qualification_diagnostic"' in text:
                    open_at_publication.append(all(not stream.closed for stream in streams.values()))
                return super().write(text)

        def run(command, **options):
            self.assertEqual([sys.executable, str(root / "scripts" / "quality.py"), "test"], command)
            streams.update({name: options[name] for name in ("stdout", "stderr")})
            result = runner(command, **options)
            for name, stream in streams.items():
                stream.flush()
                stream.seek(0)
                captured[name] = stream.read()
            return result

        output = PublicOutput()
        with mock.patch.object(qualification.subprocess, "run", side_effect=run) as child, \
                mock.patch.object(qualification, "junit_outcomes") as junit, \
                contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(qualification.Refused, "^" + code + "$"):
                qualification.qualify(root)
            self.assertEqual(1, child.call_count)
            junit.assert_not_called()
        public = output.getvalue()
        self.assertNotIn(MARKER, public)
        self.assertNotIn("\x1b", public)
        self.assertNotIn("\\u001b", public)
        self.assertNotIn(str(root), public)
        self.assertTrue(all(stream.closed for stream in streams.values()))
        records = [json.loads(line) for line in public.splitlines() if line.startswith("{")]
        self.assertEqual(expected_exit, records[0]["exit_code"])
        self.assertEqual(
            ["windows_owning_suite_command", "windows_qualification_diagnostic"],
            [record["event"] for record in records],
        )
        diagnostic = records[-1]
        self.assertEqual([True], open_at_publication)
        self.assertIs(diagnostic["diagnostic_only"], True)
        self.assertIs(diagnostic["inventory_complete"], False)
        self.assertEqual(records[0]["exit_code"], diagnostic["exit_code"])
        self.assertLess(len(json.dumps(diagnostic).encode("utf-8")), 4096)
        self.assertEqual(code, diagnostic["parser"]["code"])
        for name, data in captured.items():
            self.assertEqual(
                {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
                diagnostic[name],
            )
        return diagnostic, captured

    def real_refusal(self, body, exit_code, negative):
        identity = "test_diagnostic.DiagnosticCases.test_a_primary"
        real_run = subprocess.run
        with tempfile.TemporaryDirectory(prefix="windows-real-refusal-") as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "tests").mkdir()
            (root / "scripts" / "quality.py").write_text(
                "from pathlib import Path\nimport subprocess\nimport sys\n"
                "assert sys.argv[1:] == ['test']\n"
                "root = Path(__file__).resolve().parents[1]\n"
                "raise SystemExit(subprocess.run([sys.executable, '-m', 'unittest', 'discover',\n"
                "    '-s', str(root / 'tests'), '-v'], check=False).returncode)\n",
                encoding="utf-8",
            )
            (root / "tests" / "test_diagnostic.py").write_text(
                "import subprocess\nimport sys\nimport unittest\n\n"
                f"PAYLOAD = {MARKER!r} + '\\x1b[31m'\n"
                "class DiagnosticCases(unittest.TestCase):\n"
                "    def test_a_primary(self):\n"
                "        print(PAYLOAD)\n"
                f"        {body}\n"
                "    @unittest.skip(PAYLOAD)\n"
                "    def test_b_skip(self):\n"
                "        self.fail(PAYLOAD)\n",
                encoding="utf-8",
            )

            def run(command, **options):
                result = real_run(command, **options, env=support.defects.probe_environment(), timeout=15)
                self.assertEqual(exit_code, result.returncode)
                return result

            diagnostic, captured = self.capture_refusal(root, run, expected_exit=exit_code)
        self.assertEqual(exit_code, diagnostic["exit_code"])
        self.assertIn(b"Ran 2 tests", captured["stderr"])
        self.assertIn(MARKER.encode("utf-8"), captured["stdout"])
        self.assertIn(MARKER.encode("utf-8"), captured["stderr"])
        parser = diagnostic["parser"]
        self.assertIs(parser["count_summary_seen"], False)
        self.assertIs(parser["terminal_summary_seen"], True)
        self.assertIs(parser["negative_prefix_truncated"], False)
        self.assertNotIn(identity, json.dumps(diagnostic))
        hashed = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        if negative is None:
            self.assertEqual(b"OK (skipped=1)", captured["stderr"].splitlines()[-1])
            self.assertEqual("case-status", parser["boundary"])
            self.assertEqual(hashed, parser["pending_id_sha256"])
            self.assertEqual([], parser["negative_prefix"])
            self.assertEqual(0, parser["negative_prefix_count"])
        else:
            self.assertTrue(captured["stderr"].splitlines()[-1].startswith(b"FAILED ("))
            self.assertEqual("before-count-summary", parser["boundary"])
            self.assertIsNone(parser["pending_id_sha256"])
            expected = {"id_sha256": hashed, "outcome": negative}
            if negative == "error":
                detail = parser["negative_prefix"][0]["error"]
                self.assertEqual({"exception", "source_frames", "incomplete", "truncated"}, set(detail))
                expected["error"] = detail
            self.assertEqual([expected], parser["negative_prefix"])
            self.assertEqual(1, parser["negative_prefix_count"])
        return diagnostic, captured

    def exception_report(self, root, entries, reports, terminal=True):
        data = "".join(
            f"{name.rsplit('.', 1)[-1]} ({name}) ... {status}\n" for name, status in entries
        )
        for name, body in reports:
            data += ("=" * 70 + f"\nERROR: {name.rsplit('.', 1)[-1]} ({name})\n"
                     + "-" * 70 + "\nTraceback (most recent call last):\n" + body + "\n")
        if terminal:
            data += "-" * 70 + f"\nRan {len(entries)} tests in 0.001s\n\nFAILED (errors=1)\n"
        return data.encode("utf-8")

    def report_refusal(self, root, data, exit_code=1):
        def run(command, **options):
            options["stderr"].write(data)
            return subprocess.CompletedProcess(command, exit_code)

        return self.capture_refusal(root, run, expected_exit=exit_code)[0]

    def test_real_process_exception_reports_keep_only_allowlisted_classes_and_hashed_frames(self):
        for body, expected in (
            ("raise PermissionError(PAYLOAD)", "PermissionError"),
            ("raise subprocess.TimeoutExpired(PAYLOAD, 1)", "subprocess.TimeoutExpired"),
            ("raise subprocess.CalledProcessError(1, PAYLOAD)", "subprocess.CalledProcessError"),
            ("raise type('PrivateFixtureException', (Exception,), {})(PAYLOAD)", "unclassified"),
            ("raise RuntimeError(PAYLOAD) from ValueError(PAYLOAD)", "unclassified"),
        ):
            with self.subTest(exception=expected):
                diagnostic, _ = self.real_refusal(body, 1, "error")
                detail = diagnostic["parser"]["negative_prefix"][0]["error"]
                self.assertEqual(expected, detail["exception"])
                self.assertIs(detail["incomplete"], expected == "unclassified")
                self.assertIs(detail["truncated"], False)
                if expected != "unclassified":
                    self.assertEqual([{
                        "path_sha256": hashlib.sha256(b"tests/test_diagnostic.py").hexdigest(), "line": 9,
                    }], detail["source_frames"])
                self.assertNotIn("PrivateFixtureException", json.dumps(diagnostic))

    def test_error_report_metadata_is_associated_by_exact_negative_error_identity(self):
        first, second, passed, failed = [f"test_fixture.Cases.test_{name}" for name in ("a", "b", "c", "d")]
        with tempfile.TemporaryDirectory(prefix="windows-error-association-") as temporary:
            root = Path(temporary)
            reports = [
                (name, f'  File "{root / "tests" / filename}", line {line}, in private_function\n'
                 f"    raise {exception}('{MARKER}')\n{exception}: {MARKER}\n")
                for name, filename, line, exception in (
                    (second, "second.py", 23, "PermissionError"),
                    (passed, "passed.py", 31, "RuntimeError"),
                    (failed, "failed.py", 41, "ValueError"),
                    (first, "first.py", 17, "subprocess.TimeoutExpired"),
                )
            ]
            diagnostic = self.report_refusal(root, self.exception_report(
                root, [(first, "ERROR"), (second, "ERROR"), (passed, "ok"), (failed, "FAIL")], reports,
            ))
        prefix = diagnostic["parser"]["negative_prefix"]
        self.assertEqual([hashlib.sha256(name.encode()).hexdigest() for name in (first, second, failed)],
                         [record["id_sha256"] for record in prefix])
        self.assertEqual(["subprocess.TimeoutExpired", "PermissionError"],
                         [record["error"]["exception"] for record in prefix[:2]])
        for record, filename, line in ((prefix[0], "first.py", 17), (prefix[1], "second.py", 23)):
            self.assertEqual([{
                "path_sha256": hashlib.sha256(f"tests/{filename}".encode()).hexdigest(), "line": line,
            }], record["error"]["source_frames"])
            self.assertIs(record["error"]["incomplete"], False)
        self.assertNotIn("error", prefix[-1])
        self.assertNotIn("private_function", json.dumps(diagnostic))

    def test_unclassified_or_malformed_error_reports_cannot_borrow_later_exception_text(self):
        name = "test_fixture.Cases.test_error"
        other = "test_fixture.Cases.test_unreported"
        with tempfile.TemporaryDirectory(prefix="windows-error-unknowns-") as temporary:
            root = Path(temporary)
            frame = f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
            good = frame + f"RuntimeError: {MARKER}\n"
            unknown = frame + f"PrivateFixtureException: {MARKER}\nRuntimeError: quoted\n"
            valid = self.exception_report(root, [(name, "ERROR")], [(name, good)])
            variants = {
                "unreported-id": self.exception_report(root, [(name, "ERROR")], [(other, good)]),
                "duplicate-id": self.exception_report(root, [(name, "ERROR")], [(name, good), (name, good)]),
                "unknown-before-allowlisted-quote": self.exception_report(root, [(name, "ERROR")], [(name, unknown)]),
                "missing-traceback": valid.replace(b"Traceback (most recent call last):\n", b""),
                "missing-terminal": self.exception_report(root, [(name, "ERROR")], [(name, good)], terminal=False),
                "no-frames": self.exception_report(root, [(name, "ERROR")], [(name, "RuntimeError: hidden\n")]),
                "mismatched-method": valid.replace(b"ERROR: test_error (", b"ERROR: test_wrong ("),
                "wrong-status": valid.replace(b"ERROR: test_error (", b"FAIL: test_error ("),
                "invalid-line": valid.replace(b", line 19,", b", line 0,"),
                "oversized-line": valid.replace(b", line 19,", b", line 999999999,"),
                "path-traversal": valid.replace(b"fixture.py", b"../fixture.py"),
                "path-control": valid.replace(b"fixture.py", b"\x1b[31mfixture.py"),
                "qualified-lookalike": valid.replace(b"RuntimeError: ", b"private.RuntimeError: "),
                "unsupported-chain": self.exception_report(root, [(name, "ERROR")], [(name, good +
                    "\nDuring handling of the above exception, another exception occurred:\n\n"
                    "Traceback (most recent call last):\n" + frame + "PermissionError: private\n")]),
            }
            for label, data in variants.items():
                with self.subTest(report=label):
                    diagnostic = self.report_refusal(root, data)
                    detail = diagnostic["parser"]["negative_prefix"][0]["error"]
                    self.assertEqual("unclassified", detail["exception"])
                    self.assertIs(detail["incomplete"], True)
                    self.assertNotIn("PrivateFixtureException", json.dumps(diagnostic))
                    self.assertNotIn(other, json.dumps(diagnostic))

    def test_error_frames_ignore_external_paths_and_do_not_reparse_exception_messages(self):
        name = "test_fixture.Cases.test_error"
        with tempfile.TemporaryDirectory(prefix="windows-error-frames-") as temporary:
            root = Path(temporary)
            body = (
                f'  File "{root.parent / "outside.py"}", line 2, in external\n'
                f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
                f"RuntimeError: {MARKER}\n"
                f'  File "{root / "quoted.py"}", line 77, in quoted\n'
                "PermissionError: quoted exception text\n"
            )
            diagnostic = self.report_refusal(
                root, self.exception_report(root, [(name, "ERROR")], [(name, body)]),
            )
        detail = diagnostic["parser"]["negative_prefix"][0]["error"]
        self.assertEqual("RuntimeError", detail["exception"])
        self.assertIs(detail["incomplete"], False)
        self.assertEqual([{
            "path_sha256": hashlib.sha256(b"tests/fixture.py").hexdigest(), "line": 19,
        }], detail["source_frames"])
        self.assertNotIn("outside.py", json.dumps(diagnostic))
        self.assertNotIn("quoted.py", json.dumps(diagnostic))

    def test_allowlisted_empty_messages_and_standard_crlf_description_sections_are_supported(self):
        classes = (
            "OSError", "FileNotFoundError", "PermissionError", "TimeoutError", "RuntimeError", "ValueError",
            "subprocess.SubprocessError", "subprocess.TimeoutExpired", "subprocess.CalledProcessError",
        )
        name, second = "test_fixture.Cases.test_error", "test_fixture.Cases.test_second"
        with tempfile.TemporaryDirectory(prefix="windows-error-standard-sections-") as temporary:
            root = Path(temporary)
            frame = f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
            for exception in classes:
                with self.subTest(exception=exception):
                    data = self.exception_report(
                        root, [(name, "ERROR"), (second, "ERROR")],
                        [(name, frame + exception + "\n"), (second, frame + "RuntimeError\n")],
                    )
                    data = data.replace(b")\n" + b"-" * 70, b")\n" + MARKER.encode() + b"\n" + b"-" * 70)
                    diagnostic = self.report_refusal(root, data.replace(b"\n", b"\r\n"))
                    details = [record["error"] for record in diagnostic["parser"]["negative_prefix"]]
                    self.assertEqual([exception, "RuntimeError"], [detail["exception"] for detail in details])
                    self.assertTrue(all(not detail["incomplete"] and not detail["truncated"] for detail in details))
                    self.assertTrue(all(detail["source_frames"] == [{
                        "path_sha256": hashlib.sha256(b"tests/fixture.py").hexdigest(), "line": 19,
                    }] for detail in details))

    def test_error_details_preserve_eight_case_and_public_byte_caps_with_explicit_frame_truncation(self):
        identities = [f"test_fixture.Cases.test_case_{index}" for index in range(12)]
        with tempfile.TemporaryDirectory(prefix="windows-error-limits-") as temporary:
            root = Path(temporary)
            reports = [(name, "".join(
                f'  File "{root / "tests" / f"fixture_{line}.py"}", line {line}, in private\n'
                for line in range(1, 11)
            ) + f"subprocess.CalledProcessError: {MARKER}\n") for name in reversed(identities)]
            diagnostic = self.report_refusal(
                root, self.exception_report(root, [(name, "ERROR") for name in identities], reports),
            )
        parser = diagnostic["parser"]
        self.assertEqual(12, parser["negative_prefix_count"])
        self.assertIs(parser["negative_prefix_truncated"], True)
        self.assertEqual(8, len(parser["negative_prefix"]))
        details = [record["error"] for record in parser["negative_prefix"]]
        self.assertEqual(8, sum(len(detail["source_frames"]) for detail in details))
        self.assertTrue(all(detail["incomplete"] and detail["truncated"] for detail in details))
        self.assertTrue(all(detail["exception"] == "subprocess.CalledProcessError" for detail in details))
        self.assertLess(len(json.dumps(diagnostic).encode()), 4096)

    def test_classified_error_text_with_zero_exit_still_refuses_before_outcome_admission(self):
        name = "test_fixture.Cases.test_error"
        with tempfile.TemporaryDirectory(prefix="windows-error-zero-exit-") as temporary:
            root = Path(temporary)
            body = (f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
                    f"RuntimeError: {MARKER}\n")
            diagnostic = self.report_refusal(
                root, self.exception_report(root, [(name, "ERROR")], [(name, body)]), exit_code=0,
            )
        self.assertEqual("RuntimeError", diagnostic["parser"]["negative_prefix"][0]["error"]["exception"])
        self.assertEqual(0, diagnostic["exit_code"])
        self.assertIs(diagnostic["inventory_complete"], False)
        self.assertIs(diagnostic["diagnostic_only"], True)

    def test_real_unittest_failure_retains_safe_diagnostic_before_capture_closes(self):
        self.real_refusal("self.fail(PAYLOAD)", 1, "failed")

    def test_real_unittest_error_retains_safe_diagnostic_before_capture_closes(self):
        diagnostic, _ = self.real_refusal("raise RuntimeError(PAYLOAD)", 1, "error")
        self.assertEqual({
            "exception": "RuntimeError", "incomplete": False, "truncated": False,
            "source_frames": [{"path_sha256": hashlib.sha256(b"tests/test_diagnostic.py").hexdigest(), "line": 9}],
        }, diagnostic["parser"]["negative_prefix"][0]["error"])

    def test_real_passing_stderr_retains_safe_diagnostic_without_becoming_accepted(self):
        self.real_refusal("print(PAYLOAD, file=sys.stderr)", 0, None)

    def test_negative_prefix_diagnostic_is_bounded_and_never_an_outcome_inventory(self):
        identities = [f"test_fixture.Private.test_case_{index}" for index in range(12)]
        data = b"".join(
            f"{identity.rsplit('.', 1)[-1]} ({identity}) ... FAIL\n".encode("ascii")
            for identity in identities
        )
        data += b"=" * 70 + b"\n" + (MARKER.encode() + b"\xff\x1b[31m\n") * 200
        data += b"Ran 12 tests in 0.001s\n\nFAILED (failures=12)\n"

        def run(command, **options):
            options["stdout"].write((MARKER.encode() + b"\n") * 200)
            options["stderr"].write(data)
            return subprocess.CompletedProcess(command, 1)

        with tempfile.TemporaryDirectory(prefix="windows-bounded-refusal-") as temporary:
            diagnostic, _ = self.capture_refusal(Path(temporary), run)
        parser = diagnostic["parser"]
        self.assertEqual(12, parser["negative_prefix_count"])
        self.assertEqual(8, len(parser["negative_prefix"]))
        self.assertIs(parser["negative_prefix_truncated"], True)
        self.assertEqual(13, parser["line"])
        self.assertEqual(
            [{"id_sha256": hashlib.sha256(identity.encode()).hexdigest(), "outcome": "failed"}
             for identity in identities[:8]],
            parser["negative_prefix"],
        )
        self.assertNotIn("test_fixture", json.dumps(diagnostic))

    def test_every_parser_refusal_keeps_its_static_boundary_without_admitting_partial_data(self):
        case = b"test_one (test_fixture.Private.test_one)"
        passed = case + b" ... ok\n"
        summary = b"Ran 1 test in 0.001s\n"
        cases = (
            (summary + summary, "ambiguous-python-summary", "count-summary", True),
            (case + b"\n" + case + b"\n", "ambiguous-python-case", "case-prefix", False),
            (case + b"\n" + MARKER.encode() + b"\n", "ambiguous-python-outcome", "pending-description", False),
            (b"ok\n", "unbound-python-outcome", "unbound-status", False),
            (passed + MARKER.encode() + b"\n", "ambiguous-python-outcome", "before-count-summary", False),
            (case + b" ... " + MARKER.encode() + b"\n", "ambiguous-python-outcome", "case-status", False),
            (passed + passed, "duplicate-python-case", "duplicate-case", False),
            (passed, "incomplete-python-outcomes", "end-of-stream", False),
            (summary, "incomplete-python-outcomes", "end-of-stream", True),
            (b"", "incomplete-python-outcomes", "end-of-stream", False),
        )
        for data, code, boundary, summary_seen in cases:
            def run(command, **options):
                options["stdout"].write(MARKER.encode())
                options["stderr"].write(data)
                return subprocess.CompletedProcess(command, 1)

            with self.subTest(code=code, boundary=boundary, data_bytes=len(data)), \
                    tempfile.TemporaryDirectory(prefix="windows-parser-boundary-") as temporary:
                diagnostic, _ = self.capture_refusal(Path(temporary), run, code)
                parser = diagnostic["parser"]
                self.assertEqual(boundary, parser["boundary"])
                self.assertIs(summary_seen, parser["count_summary_seen"])
                self.assertIs(parser["terminal_summary_seen"], False)
                self.assertEqual([], parser["negative_prefix"])

    def test_quoted_terminal_summary_is_observation_only_and_never_repairs_refusal(self):
        data = (b"test_one (test_fixture.Private.test_one) ... " + MARKER.encode()
                + b"\nRan 1 test in 0.001s\n\nOK\n")

        def run(command, **options):
            options["stderr"].write(data)
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory(prefix="windows-quoted-summary-") as temporary:
            diagnostic, _ = self.capture_refusal(Path(temporary), run, expected_exit=0)
        self.assertIs(diagnostic["parser"]["terminal_summary_seen"], True)
        self.assertIs(diagnostic["parser"]["count_summary_seen"], False)
        self.assertEqual("case-status", diagnostic["parser"]["boundary"])

    def test_unreadable_summary_count_retains_only_static_parser_diagnostics(self):
        def run(command, **options):
            options["stderr"].write(b"Ran 1 test in 0.001s\n\nOK\n")
            return subprocess.CompletedProcess(command, 1)

        with tempfile.TemporaryDirectory(prefix="windows-summary-refusal-") as temporary, \
                mock.patch.object(qualification, "int", side_effect=ValueError(MARKER), create=True):
            diagnostic, _ = self.capture_refusal(
                Path(temporary), run, "invalid-python-summary-count",
            )
        self.assertEqual("count-summary", diagnostic["parser"]["boundary"])
        self.assertIs(diagnostic["parser"]["count_summary_seen"], False)
        self.assertIs(diagnostic["parser"]["terminal_summary_seen"], True)


if __name__ == "__main__":
    unittest.main()
