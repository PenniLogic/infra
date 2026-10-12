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
from conformance import generator as generator_module, registry as registry_module
import qualify as infra_qualification
from test_api_native_source_fetch import native_owning_script, remove_native_steps
from test_baseline import CONTRACTS_PREVIOUS_SOURCE_TEST_COMMAND, CONTRACTS_SOURCE_TEST_COMMAND


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


def without_absent_lookup(test, records):
    observed = [record for record in records if record["event"] == "windows_shell_lookup_diagnostic"]
    test.assertEqual([{
        "event": "windows_shell_lookup_diagnostic", "diagnostic_only": True,
        "capsule_complete": False, "status": "unavailable", "code": "not-observed",
    }], observed)
    return [record for record in records if record["event"] != "windows_shell_lookup_diagnostic"]


class ApiWindowsWorkflowTests(unittest.TestCase):
    def test_optional_shell_readback_preserves_the_complete_accepted_workflow(self):
        workflow = json.loads(generator.workflow("api"))
        steps = workflow["jobs"]["windows"]["steps"]
        name = "Read approved-shell command boundary"
        self.assertEqual(1, sum(step.get("name") == name for step in steps))
        self.assertEqual(["Run Windows owning suites", name], [step["name"] for step in steps[-2:]])
        reader = steps[-1]
        source = reader["run"]
        self.assertEqual({
            "name": name,
            "if": "always()",
            "shell": "pwsh",
            "working-directory": "${{ github.workspace }}",
            "timeout-minutes": 1,
            "run": source,
        }, reader)
        self.assertEqual(2254, len(source.encode("ascii")))
        self.assertEqual("cb9fa0289b294b06a5ce6c5bfc0b04751a1d38b90a70e08956c6d58354864a62",
                         hashlib.sha256(source.encode("ascii")).hexdigest())
        previous = source
        for current, accepted in (
            ("    pre_record_writer_return = 'not-observed'\n", ""),
            ("[byte[]]::new(8)", "[byte[]]::new(7)"),
            ("if ($count -le 7)", "if ($count -le 6)"),
            (r"\A(?:|E|EU|EUX|ES[01]{3}|ES[01]{3}X|ES[01]{3}CX?)\z",
             r"\A(?:|E|EU|EUX|ES[01]{3}|ES[01]{3}X)\z"),
            ("            if ($value.Contains('C')) { $record.pre_record_writer_return = 'observed' }\n", ""),
            (r"\AES([01])([01])([01])C?X?\z", r"\AES([01])([01])([01])X?\z"),
        ):
            self.assertEqual(1, previous.count(current))
            previous = previous.replace(current, accepted, 1)
        self.assertEqual(2105, len(previous.encode("ascii")))
        self.assertEqual("ae4694d83532deda918500fb7b5d4ec85a61b65d6eb94c428fbcac2af9b9656a",
                         hashlib.sha256(previous.encode("ascii")).hexdigest())
        absence = ("} catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] {\n"
                   "    $record.status = 'not-observed'\n    $exitCode = 0\n")
        self.assertEqual(1, source.count(absence))
        self.assertEqual("aef8bf30c81bf0a9b14409f949c2d94428ce695c8520fac1af38e7476237eda4",
                         hashlib.sha256(previous.replace(absence, "", 1).encode("ascii")).hexdigest())
        self.assertNotIn("hashFiles", generator.workflow("api"))
        self.assertNotIn("\r", source)
        self.assertEqual(30, workflow["jobs"]["windows"]["timeout-minutes"])
        self.assertEqual({"contents": "read"}, workflow["permissions"])
        self.assertNotIn("continue-on-error", steps[-2])
        steps.pop()
        self.assertEqual("fa3a89940050ebbee9b7ddb4942c5e3dfd021c181f84f10e5c64253d21c0148c",
                         hashlib.sha256(generator.encoded(workflow).encode("utf-8")).hexdigest())
        artifacts = generator.artifacts("api")
        self.assertEqual(25, len(artifacts))
        self.assertFalse(any("read_approved_shell_boundary" in path for path in artifacts))
        self.assertEqual("0a073083148e670081eee72612fd9853a1a78100c2a50129ce89a2da9adfe1b3",
                         hashlib.sha256(artifacts["scripts/qualify_windows.py"].encode("utf-8")).hexdigest())

    def test_optional_shell_readback_drift_is_refused_without_policy_widening(self):
        original = json.loads(generator.workflow("api"))
        self.assertEqual("Read approved-shell command boundary", original["jobs"]["windows"]["steps"][-1]["name"])
        self.assertIn("$record.status = 'not-observed'", original["jobs"]["windows"]["steps"][-1]["run"])
        validate = api_checker()
        validate(CI, generator.encoded(original).encode("utf-8"))
        mutations = (
            ("absent-step", lambda job: job["steps"].pop()),
            ("unconditional", lambda job: job["steps"][-1].pop("if")),
            ("hash-files", lambda job: job["steps"][-1].update(
                {"if": "always() && hashFiles('build/diagnostics/api106-approved-shell-boundary.bin') != ''"})),
            ("success-only", lambda job: job["steps"][-1].update(
                {"if": "hashFiles('build/diagnostics/api106-approved-shell-boundary.bin') != ''"})),
            ("broad-path", lambda job: job["steps"][-1].update(
                {"if": "always() && hashFiles('build/diagnostics/*') != ''"})),
            ("wrong-marker", lambda job: job["steps"][-1].update(
                {"if": "always() && hashFiles('build/diagnostics/other.bin') != ''"})),
            ("empty-gate", lambda job: job["steps"][-1].update({"if": ""})),
            ("shell", lambda job: job["steps"][-1].update(shell="powershell")),
            ("cwd", lambda job: job["steps"][-1].update({"working-directory": "scripts"})),
            ("step-cap", lambda job: job["steps"][-1].update({"timeout-minutes": 2})),
            ("job-cap", lambda job: job.update({"timeout-minutes": 31})),
            ("collector-soft-failure", lambda job: job["steps"][-1].update({"continue-on-error": True})),
            ("owner-soft-failure", lambda job: job["steps"][-2].update({"continue-on-error": True})),
            ("reader", lambda job: job["steps"][-1].update(run="exit 0")),
            ("read-bound", lambda job: job["steps"][-1].update(
                run=job["steps"][-1]["run"].replace("[byte[]]::new(8)", "[byte[]]::new(4096)"))),
            ("record-bound", lambda job: job["steps"][-1].update(
                run=job["steps"][-1]["run"].replace("if ($count -le 7)", "if ($count -le 8)"))),
            ("writer-return-after-u", lambda job: job["steps"][-1].update(
                run=job["steps"][-1]["run"].replace("|ES[01]{3}CX?", "|EUCX?|ES[01]{3}CX?"))),
            ("writer-return-absence", lambda job: job["steps"][-1].update(
                run=job["steps"][-1]["run"].replace(
                    "pre_record_writer_return = 'not-observed'", "pre_record_writer_return = 'observed'"))),
            ("output-bound", lambda job: job["steps"][-1].update(
                run=job["steps"][-1]["run"].replace("-gt 1024", "-gt 4096"))),
            ("failure-exit", lambda job: job["steps"][-1].update(
                run=job["steps"][-1]["run"].replace("$exitCode = 2", "$exitCode = 0"))),
            ("absence-fails", lambda job: job["steps"][-1].update(run=job["steps"][-1]["run"].replace(
                "$record.status = 'not-observed'\n    $exitCode = 0",
                "$record.status = 'not-observed'\n    $exitCode = 2"))),
            ("broad-absence-catch", lambda job: job["steps"][-1].update(run=job["steps"][-1]["run"].replace(
                "[IO.FileNotFoundException], [IO.DirectoryNotFoundException]", "[IO.IOException]"))),
            ("missing-parent-fails", lambda job: job["steps"][-1].update(run=job["steps"][-1]["run"].replace(
                ", [IO.DirectoryNotFoundException]", ""))),
            ("absence-checkpoint", lambda job: job["steps"][-1].update(run=job["steps"][-1]["run"].replace(
                "$record.status = 'not-observed'", "$record.status = 'not-observed'\n    $record.checkpoint = 'command-entry'"))),
            ("absence-flags", lambda job: job["steps"][-1].update(run=job["steps"][-1]["run"].replace(
                "$record.status = 'not-observed'", "$record.status = 'not-observed'\n    $record.console_redirected = $false"))),
            ("raw-output", lambda job: job["steps"][-1].update(
                run=job["steps"][-1]["run"] + "\nGet-Content $path")),
            ("reordered", lambda job: job["steps"].insert(-1, job["steps"].pop())),
            ("duplicate", lambda job: job["steps"].append(copy.deepcopy(job["steps"][-1]))),
            ("credential", lambda job: job["steps"][-1].update(env={"GH_TOKEN": "${{ github.token }}"})),
        )
        with tempfile.TemporaryDirectory(prefix="api-shell-readback-drift-") as temporary:
            root = Path(temporary)
            generator.generate("api", root)
            for label, mutation in mutations:
                changed = copy.deepcopy(original)
                mutation(changed["jobs"]["windows"])
                content = generator.encoded(changed).encode("utf-8")
                self.assertNotEqual(generator.encoded(original).encode("utf-8"), content, label)
                (root / CI).write_bytes(content)
                with self.subTest(mutation=label):
                    with self.assertRaisesRegex(ValueError, "API CI must match"):
                        validate(CI, content)
                    with self.assertRaisesRegex(ValueError, "Generated setup differs"):
                        generator.generate("api", root, check=True)
            (root / CI).write_bytes(generator.encoded(original).encode("utf-8"))
            generator.generate("api", root, check=True)
        namespace = {"__file__": str(support.GOVERNANCE.parent / "scripts/check_repository.py")}
        exec(compile(generator.standard_checker("api"), "standard API checker", "exec"), namespace)
        with self.assertRaisesRegex(ValueError, "unreviewed workflow expression"):
            namespace["validate_expressions"]({"working-directory": "${{ github.workspace }}"})
        with self.assertRaisesRegex(ValueError, "conditions are not part"):
            namespace["validate_mappings"]({"if": original["jobs"]["windows"]["steps"][-1]["if"]})
        for name in generator.PROFILES["repositories"]:
            for setup in (False, True):
                if name != "api" or setup:
                    self.assertNotIn("api106-approved-shell-boundary", generator.workflow(name, setup=setup))

    def test_shell_readback_keeps_two_file_historical_workflow_rendering(self):
        sources = {
            "governance/generate.py": (support.GOVERNANCE / "generate.py").read_bytes(),
            "governance/repository-profiles.json": (support.GOVERNANCE / "repository-profiles.json").read_bytes(),
        }
        reads = []
        ref = "a" * 40

        def read_source(command, **options):
            self.assertEqual(["git", "-C", str(support.GOVERNANCE.parent), "show"], command[:-1])
            self.assertTrue(command[-1].startswith(ref + ":"))
            name = command[-1].split(":", 1)[1]
            self.assertIn(name, sources)
            reads.append(name)
            return subprocess.CompletedProcess(command, 0, sources[name], b"")

        rendered = registry_module.render_workflow_at(
            support.GOVERNANCE.parent, ref, "api", run=read_source,
        )
        self.assertEqual(generator.workflow("api").encode("utf-8"), rendered)
        self.assertEqual(list(sources), reads)

    def test_parallel_owning_suites_and_always_running_required_native_result(self):
        workflow = json.loads(generator.workflow("api"))
        jobs = workflow["jobs"]
        self.assertEqual({"ci", "windows", "ci-result"}, set(jobs))
        self.assertEqual("Linux qualification", jobs["ci"]["name"])
        self.assertNotIn("needs", jobs["ci"])
        self.assertNotIn("needs", jobs["windows"])
        self.assertEqual("windows-2025", jobs["windows"]["runs-on"])
        self.assertEqual(generator.tool_steps(generator.profile_for("api")), jobs["windows"]["steps"][:4])
        windows = native_owning_script(generator.workflow("api"), windows=True)
        preparation = list(generator.profile_for("api")["commands"][:7])
        preparation[1] += " --verify-inputs"
        preparation[5] = preparation[5].removesuffix(" --fetch")
        self.assertEqual([command.replace("/", "\\") for command in preparation]
                         + [INPUT_PREPARATION + " --require-prepared",
                            "python scripts\\qualify_windows.py --require-prepared"],
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
            lambda value: next(step for step in value["jobs"]["windows"]["steps"]
                               if step["name"] == "Run Windows owning suites").update(run="echo skipped"),
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
        source = native_owning_script(generator.workflow("api"), windows=True)
        support.assert_powershell_failure_boundaries(self, source, 9)

    def test_input_preparation_omission_stub_reordering_and_missing_guard_are_refused(self):
        validate = api_checker()
        original = json.loads(generator.workflow("api"))
        owning = next(step for step in original["jobs"]["windows"]["steps"]
                      if step["name"] == "Run Windows owning suites")
        commands = owning["run"].splitlines()[::2]
        self.assertEqual(INPUT_PREPARATION + " --require-prepared", commands[-2])
        changed_commands = (
            commands[:-2] + commands[-1:],
            commands[:-2] + ["python -c \"pass\"", commands[-1]],
            commands[:-2] + [commands[-1], commands[-2]],
            [commands[-2]] + commands[:-2] + commands[-1:],
            commands[:-2] + [INPUT_PREPARATION + " --node ignored", commands[-1]],
        )
        scripts = [generator.powershell_commands(changed) for changed in changed_commands]
        scripts.append(owning["run"].replace(
            commands[-2] + "\nif ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }", commands[-2],
        ))
        for script in scripts:
            changed = copy.deepcopy(original)
            next(step for step in changed["jobs"]["windows"]["steps"]
                 if step["name"] == "Run Windows owning suites")["run"] = script
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
            contracts_commands = previous.PROFILES["repositories"]["contracts"]["commands"]
            self.assertEqual(CONTRACTS_PREVIOUS_SOURCE_TEST_COMMAND, contracts_commands[-1])
            contracts_commands[-1] = CONTRACTS_SOURCE_TEST_COMMAND
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
                        actual = generator.workflow(name, setup=setup)
                        if name == "api" and not setup:
                            actual = remove_native_steps(self, actual)
                        self.assertEqual(expected, actual)
        qualifier_source = "5795155323e7ff9899fb8cf2846ab6646fb0f141"
        accepted_qualifier = "f85f50f41b31a32838e9d4326947bb437140446a"
        self.assertEqual(
            support.git(support.GOVERNANCE.parent, "show", f"{qualifier_source}:governance/templates/qualify_windows.py"),
            support.git(support.GOVERNANCE.parent, "show", f"{accepted_qualifier}:governance/templates/qualify_windows.py"),
        )
        historical_source = "f85d4cd7f7d5a1c14669d8040f282437ceb5ef7f"
        historical_accepted = "a40b9018a4b04fa78a5643905ebedc3a1a107db3"
        self.assertEqual(
            support.git(support.GOVERNANCE.parent, "show", f"{historical_source}:governance/templates/qualify_windows.py"),
            support.git(support.GOVERNANCE.parent, "show", f"{historical_accepted}:governance/templates/qualify_windows.py"),
        )
        current_digest = "0a073083148e670081eee72612fd9853a1a78100c2a50129ce89a2da9adfe1b3"
        current_template = (support.GOVERNANCE / "templates/qualify_windows.py").read_bytes()
        current_generated = generator.artifacts("api")["scripts/qualify_windows.py"].encode("utf-8")
        self.assertEqual(current_digest, hashlib.sha256(current_template).hexdigest())
        self.assertEqual(current_digest, hashlib.sha256(current_generated).hexdigest())


class WindowsShellBoundaryReaderTests(unittest.TestCase):
    def setUp(self):
        self.powershell = shutil.which("pwsh")
        self.assertIsNotNone(self.powershell, "PowerShell is required for the emitted boundary reader fixture")
        temporary = tempfile.TemporaryDirectory(prefix="api-shell-boundary-reader-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.marker = self.root / "build" / "diagnostics" / "api106-approved-shell-boundary.bin"
        self.script = self.root / "read.ps1"
        reader = json.loads(generator.workflow("api"))["jobs"]["windows"]["steps"][-1]
        self.assertEqual("Read approved-shell command boundary", reader["name"])
        self.script.write_text(reader["run"], encoding="ascii", newline="\n")

    def assert_boundary(self, status, exit_code, checkpoint=None, redirected=None, writer_return="not-observed"):
        result = subprocess.run(
            [self.powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(self.script)],
            cwd=self.root, env=support.defects.probe_environment(), capture_output=True, check=False, timeout=15,
        )
        self.assertEqual(exit_code, result.returncode, result.stderr)
        self.assertEqual(b"", result.stderr)
        self.assertLessEqual(len(result.stdout), 1024)
        self.assertEqual(1, len(result.stdout.splitlines()))
        self.assertEqual({
            "event": "api106_approved_shell_command_boundary", "diagnostic_only": True,
            "status": status, "checkpoint": checkpoint, "console_redirected": redirected,
            "pre_record_writer_return": writer_return,
        }, json.loads(result.stdout.decode("ascii")))

    def test_all_legacy_shapes_and_only_paired_writer_returns_preserve_checkpoint_and_flags(self):
        self.marker.parent.mkdir(parents=True)
        for payload, checkpoint in (
            (b"", "none-observed"), (b"E", "command-entry"),
            (b"EU", "before-write-output"), (b"EUX", "after-write-output"),
        ):
            with self.subTest(payload=payload):
                self.marker.write_bytes(payload)
                self.assert_boundary("observed-record", 0, checkpoint)
                self.assertEqual(payload, self.marker.read_bytes())
        for flags in itertools.product("01", repeat=3):
            redirected = dict(zip(("stdin", "stdout", "stderr"), (flag == "1" for flag in flags), strict=True))
            for writer_return, suffix in itertools.product(("", "C"), ("", "X")):
                payload = ("ES" + "".join(flags) + writer_return + suffix).encode("ascii")
                with self.subTest(payload=payload):
                    self.marker.write_bytes(payload)
                    self.assert_boundary(
                        "observed-record", 0, "after-write-output" if suffix else "before-write-output",
                        redirected, "observed" if writer_return else "not-observed",
                    )
                    self.assertEqual(payload, self.marker.read_bytes())

    def test_partial_misordered_repeated_and_oversized_records_never_publish_a_prefix(self):
        self.marker.parent.mkdir(parents=True)
        payloads = (
            b"ES", b"ES1", b"ES11", b"C", b"CES111", b"EC", b"ECS111", b"EUC", b"EUCX", b"EUXC",
            b"ESC111", b"ES1C11", b"ES11C1", b"ES111XC", b"ES111CC", b"ES111CCX",
            b"ES111c", b"ES222C", b"EEX", b"ES111X\n", b"ES111C\0", b"ES111CX\n", b"ES111CXC",
            b"\xffES111C", b"ES111C" + MARKER.encode("ascii"),
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.marker.write_bytes(payload)
                self.assert_boundary("oversized-record" if len(payload) >= 8 else "partial-or-invalid-record", 2)
                self.assertEqual(payload, self.marker.read_bytes())

    def test_missing_file_and_parent_are_optional_but_unreadable_data_is_not_an_observation(self):
        self.assert_boundary("not-observed", 0)
        self.marker.parent.mkdir(parents=True)
        self.assert_boundary("not-observed", 0)
        self.marker.mkdir()
        self.assert_boundary("unavailable-read", 2)


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

    def write_junit_cases(self, root, filename, identities, **attributes):
        directory = root / qualification.JUNIT
        directory.mkdir(parents=True, exist_ok=True)
        suite = ET.Element("testsuite", name=MARKER, tests=str(len(identities)),
                           failures="0", errors="0", skipped="0")
        suite.attrib.update(attributes)
        for class_name, name in identities:
            ET.SubElement(suite, "testcase", classname=class_name, name=name)
        data = ET.tostring(suite)
        path = directory / filename
        path.write_bytes(data)
        return path, data

    def exercise(self, root, python=None, task="> Task :test", status="passed",
                 name=qualification.KOTLIN_METHOD, exit_code=0, require_prepared=False):
        def run(command, **options):
            arguments = ["--require-prepared"] if require_prepared else []
            self.assertEqual([sys.executable, str(root / "scripts" / "quality.py"), "test", *arguments], command)
            self.assertEqual(root, options["cwd"])
            options["stdout"].write((task + "\n" + MARKER + "\n").encode() + b"\xff\n")
            report = python if python is not None else self.python_report()
            options["stderr"].write(report if isinstance(report, bytes) else report.encode())
            self.write_junit(root, status, name)
            return subprocess.CompletedProcess(command, exit_code)
        output = io.StringIO()
        with mock.patch.object(qualification.subprocess, "run", side_effect=run) as child, contextlib.redirect_stdout(output):
            try:
                qualification.qualify(root, require_prepared=require_prepared)
            finally:
                self.assertEqual(1, child.call_count)
                self.assertNotIn(MARKER, output.getvalue())
                if task not in ("> Task :test", "> Task :test FAILED"):
                    self.assertNotIn('"suite": "junit:test"', output.getvalue())
        return [json.loads(line) for line in output.getvalue().splitlines() if line.startswith("{")]

    def test_require_prepared_is_only_an_explicit_child_flag_and_keeps_every_qualification_gate(self):
        with mock.patch.object(qualification.sys, "platform", "win32"), \
                mock.patch.object(qualification, "qualify") as qualify:
            self.assertEqual(0, qualification.main(["--require-prepared"]))
            qualify.assert_called_once_with(qualification.ROOT, require_prepared=True)
        with tempfile.TemporaryDirectory(prefix="windows-prepared-outcomes-") as temporary:
            records = self.exercise(Path(temporary), require_prepared=True)
        self.assertEqual({"event": "windows_qualification", "ok": True, "python_tests": 2, "junit_tests": 1}, records[-1])
        self.assertFalse(any(record["event"] == "windows_qualification_diagnostic" for record in records))
        for changes in ({"task": "> Task :test FROM-CACHE"}, {"python": self.python_report("skipped 'unavailable'")},
                        {"exit_code": 1}, {"status": "failure"}, {"python": self.python_report().replace("Ran 2", "Ran 1")}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory(prefix="windows-prepared-refusal-") as temporary:
                with self.assertRaises(qualification.Refused):
                    self.exercise(Path(temporary), require_prepared=True, **changes)

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

    def test_junit_duplicate_same_report_binds_exact_bytes_positions_and_separate_identity_hashes(self):
        identity = (MARKER + ".PrivateClass", "private case \u2603" * 8192)
        with tempfile.TemporaryDirectory(prefix="junit-duplicate-same-") as temporary:
            root = Path(temporary)
            path, data = self.write_junit_cases(root, "TEST-private.xml", [identity, identity])
            self.assertGreater(len(data), 65536)
            native_open, observed = Path.open, {}

            @contextlib.contextmanager
            def open_report(candidate, mode):
                with native_open(candidate, mode) as stream:
                    observed["stream"] = stream
                    observed["reader"] = mock.Mock(wraps=stream)
                    yield observed["reader"]

            with mock.patch.object(Path, "open", autospec=True, side_effect=open_report) as reader, \
                    self.assertRaisesRegex(qualification.Refused, "^duplicate-junit-case$") as caught:
                qualification.junit_outcomes(root)
            reader.assert_called_once_with(path, "rb")
            reads = observed["reader"].read.call_args_list
            self.assertGreater(len(reads), 1)
            self.assertEqual([mock.call(65536)] * len(reads), reads)
            self.assertTrue(observed["stream"].closed)
            diagnostic = getattr(caught.exception, "diagnostic", None)
            self.assertIsInstance(diagnostic, dict)
            report = {
                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "testcase_count": 2, "suite_counts": {"tests": 2, "failures": 0, "errors": 0, "skipped": 0},
                "metadata_complete": True,
            }
            self.assertEqual({
                "code": "duplicate-junit-case",
                "id_sha256": hashlib.sha256("\0".join(identity).encode("utf-8")).hexdigest(),
                "classname_sha256": hashlib.sha256(identity[0].encode("utf-8")).hexdigest(),
                "name_sha256": hashlib.sha256(identity[1].encode("utf-8")).hexdigest(),
                "same_report": True,
                "first": {"report_position": 1, "case_position": 1, "report": report},
                "current": {"report_position": 1, "case_position": 2, "report": report},
                "prefix": {"selected_reports": 1, "completed_reports": 0,
                           "completed_cases": 1, "encountered_cases": 2},
            }, diagnostic)
            self.assertEqual(data, path.read_bytes())
            self.assertNotIn(MARKER, json.dumps(diagnostic))
            self.assertNotIn(str(root), json.dumps(diagnostic))
            maximum = copy.deepcopy(diagnostic)
            for key in ("first", "current"):
                maximum[key].update(report_position=4294967295, case_position=4294967295)
                maximum[key]["report"].update(bytes=4294967295, testcase_count=4294967295)
                maximum[key]["report"]["suite_counts"] = dict.fromkeys(report["suite_counts"], 4294967295)
            maximum["prefix"] = dict.fromkeys(maximum["prefix"], 4294967295)
            envelope = {"event": "windows_qualification_diagnostic", "diagnostic_only": True,
                        "inventory_complete": False, "exit_code": -2147483648, "junit": maximum}
            self.assertLess(len(json.dumps(envelope).encode("ascii")), 4096)

    def test_junit_duplicate_cross_report_preserves_first_location_and_stops_before_later_bad_xml(self):
        duplicate = ("example.PrivateClass", MARKER)
        with tempfile.TemporaryDirectory(prefix="junit-duplicate-cross-") as temporary:
            root = Path(temporary)
            last, current = self.write_junit_cases(
                root, "TEST-z.xml", [("example.CurrentPrefix", "one"), duplicate],
            )
            _, first = self.write_junit_cases(root, "TEST-a.xml", [("example.FirstPrefix", "one"), duplicate])
            self.write_junit_cases(root, "TEST-m.xml", [("example.Middle", "one")])
            (last.parent / "TEST-zz.xml").write_bytes(b"<malformed")
            with self.assertRaisesRegex(qualification.Refused, "^duplicate-junit-case$") as caught:
                qualification.junit_outcomes(root)
            diagnostic = getattr(caught.exception, "diagnostic", None)
            self.assertIsInstance(diagnostic, dict)
            self.assertIs(diagnostic["same_report"], False)
            self.assertEqual((1, 2), (diagnostic["first"]["report_position"], diagnostic["first"]["case_position"]))
            self.assertEqual((3, 2), (diagnostic["current"]["report_position"], diagnostic["current"]["case_position"]))
            for key, data in (("first", first), ("current", current)):
                self.assertEqual(len(data), diagnostic[key]["report"]["bytes"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), diagnostic[key]["report"]["sha256"])
                self.assertEqual(2, diagnostic[key]["report"]["testcase_count"])
            self.assertEqual({"selected_reports": 4, "completed_reports": 2,
                              "completed_cases": 4, "encountered_cases": 5}, diagnostic["prefix"])
        with tempfile.TemporaryDirectory(prefix="junit-identical-reports-") as temporary:
            root = Path(temporary)
            self.write_junit_cases(root, "TEST-a.xml", [duplicate])
            self.write_junit_cases(root, "TEST-b.xml", [duplicate])
            with self.assertRaisesRegex(qualification.Refused, "^duplicate-junit-case$") as caught:
                qualification.junit_outcomes(root)
            diagnostic = caught.exception.diagnostic
            self.assertIs(diagnostic["same_report"], False)
            self.assertEqual(1, diagnostic["first"]["report_position"])
            self.assertEqual(2, diagnostic["current"]["report_position"])
            self.assertEqual(diagnostic["first"]["report"], diagnostic["current"]["report"])

    def test_junit_distinct_pairs_keep_original_ids_and_do_not_scan_other_tasks_or_nested_reports(self):
        identities = [("example.First", "shared"), ("example.Second", "shared"), ("example.First", "other")]
        with tempfile.TemporaryDirectory(prefix="junit-distinct-pairs-") as temporary:
            root = Path(temporary)
            self.write_junit_cases(root, "TEST-b.xml", identities[1:])
            _, first = self.write_junit_cases(root, "TEST-a.xml", identities[:1])
            nested = root / qualification.JUNIT / "nested"
            nested.mkdir()
            (nested / "TEST-hidden.xml").write_bytes(first)
            other = root / "build/test-results/moneyTest"
            other.mkdir()
            (other / "TEST-private.xml").write_bytes(b"<malformed")
            records = qualification.junit_outcomes(root)
            expected = [
                {"event": "test_outcome", "suite": "junit:test",
                 "id_sha256": hashlib.sha256("\0".join(identity).encode("utf-8")).hexdigest(), "outcome": "passed"}
                for identity in identities
            ]
            self.assertEqual(expected, records)
            directory = root / qualification.JUNIT
            (directory / "TEST-a.xml").rename(directory / "TEST-z.xml")
            self.assertEqual({record["id_sha256"] for record in expected},
                             {record["id_sha256"] for record in qualification.junit_outcomes(root)})

    def test_junit_duplicate_main_publishes_only_bounded_private_provenance_and_preserves_nonzero(self):
        for cross_file, exit_code in itertools.product((False, True), (0, 37)):
            with self.subTest(cross_file=cross_file, exit_code=exit_code), \
                    tempfile.TemporaryDirectory(prefix="junit-private-refusal-") as temporary:
                root = Path(temporary)
                identity = (str(root) + MARKER, MARKER + "\u2603" * 30000)

                def run(command, **options):
                    self.assertEqual([sys.executable, str(root / "scripts/quality.py"), "test"], command)
                    self.assertEqual(root, options["cwd"])
                    options["stdout"].write(b"> Task :test\n" + MARKER.encode() + b"\x1b[31m\n")
                    options["stderr"].write(self.python_report().encode())
                    required = (qualification.KOTLIN_CLASS, qualification.KOTLIN_METHOD)
                    if cross_file:
                        self.write_junit_cases(root, "TEST-a.xml", [required, identity])
                        self.write_junit_cases(root, "TEST-b.xml", [identity])
                    else:
                        self.write_junit_cases(root, "TEST-a.xml", [required, identity, identity])
                    return subprocess.CompletedProcess(command, exit_code)

                output, errors = io.StringIO(), io.StringIO()
                with mock.patch.object(qualification.sys, "platform", "win32"), \
                        mock.patch.object(qualification, "ROOT", root), \
                        mock.patch.object(qualification.subprocess, "run", side_effect=run) as child, \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    self.assertEqual(1, qualification.main([]))
                child.assert_called_once()
                public = output.getvalue() + errors.getvalue()
                for private in (MARKER, str(root), "\x1b", "\\u001b", "\u2603", "\\u2603", "<testsuite"):
                    self.assertNotIn(private, public)
                records = [json.loads(line) for line in output.getvalue().splitlines() if line.startswith("{")]
                records = without_absent_lookup(self, records)
                self.assertEqual(["windows_owning_suite_command", "test_outcome", "test_outcome",
                                  "windows_qualification_diagnostic"], [record["event"] for record in records])
                self.assertFalse(any(record.get("suite") == "junit:test" for record in records))
                diagnostic = records[-1]
                self.assertIs(diagnostic["diagnostic_only"], True)
                self.assertIs(diagnostic["inventory_complete"], False)
                self.assertEqual(exit_code, diagnostic["exit_code"])
                self.assertLess(len(json.dumps(diagnostic).encode("ascii")), 4096)
                self.assertEqual("duplicate-junit-case", diagnostic["junit"]["code"])
                self.assertEqual(not cross_file, diagnostic["junit"]["same_report"])
                self.assertEqual({"event": "windows_qualification_refused", "code": "duplicate-junit-case"},
                                 json.loads(errors.getvalue()))

    def test_junit_duplicate_metadata_bounds_and_malformed_later_counts_do_not_change_refusal(self):
        for value, expected in ((0, 0), (4294967295, 4294967295), ("4294967295", 4294967295),
                                (" +1 ", 1), (False, None), (-1, None), (4294967296, None),
                                (None, None), ("", None), (MARKER, None), ("9" * 5000, None)):
            with self.subTest(value_type=type(value).__name__, expected=expected):
                self.assertEqual(expected, qualification.junit_diagnostic_number(value))
        for index, bad_count in enumerate((None, MARKER, "-1", "4294967296", "9" * 5000)):
            with self.subTest(case=index), tempfile.TemporaryDirectory(prefix="junit-count-bound-") as temporary:
                root = Path(temporary)
                path, _ = self.write_junit_cases(root, "TEST-private.xml", [("example.Test", "same")] * 2)
                suite = ET.parse(path).getroot()
                if bad_count is None:
                    suite.attrib.pop("failures")
                else:
                    suite.set("failures", bad_count)
                path.write_bytes(ET.tostring(suite))
                with self.assertRaisesRegex(qualification.Refused, "^duplicate-junit-case$") as caught:
                    qualification.junit_outcomes(root)
                diagnostic = getattr(caught.exception, "diagnostic", None)
                self.assertIsInstance(diagnostic, dict)
                self.assertIsNone(diagnostic["current"]["report"]["suite_counts"]["failures"])
                self.assertIs(diagnostic["current"]["report"]["metadata_complete"], False)
                self.assertLess(len(json.dumps(diagnostic).encode("ascii")), 4096)
                self.assertNotIn(MARKER, json.dumps(diagnostic))

    def test_junit_duplicate_does_not_override_earlier_guards_or_reorder_later_guards(self):
        mutations = (
            (lambda suite: suite.set("tests", "3"), "incomplete-junit-outcomes"),
            (lambda suite: suite.find("testcase").attrib.pop("classname"), "missing-junit-identity"),
            (lambda suite: (ET.SubElement(suite[0], "failure"), ET.SubElement(suite[0], "skipped")),
             "ambiguous-junit-outcome"),
            (lambda suite: (ET.SubElement(suite[1], "failure"), ET.SubElement(suite[1], "skipped")),
             "duplicate-junit-case"),
        )
        for mutate, code in mutations:
            with self.subTest(code=code), tempfile.TemporaryDirectory(prefix="junit-guard-order-") as temporary:
                root = Path(temporary)
                path, _ = self.write_junit_cases(root, "TEST-private.xml", [("example.Test", "same")] * 2)
                suite = ET.parse(path).getroot()
                mutate(suite)
                path.write_bytes(ET.tostring(suite))
                with self.assertRaisesRegex(qualification.Refused, "^" + code + "$") as caught:
                    qualification.junit_outcomes(root)
                self.assertEqual(code == "duplicate-junit-case", hasattr(caught.exception, "diagnostic"))
        with tempfile.TemporaryDirectory(prefix="junit-earlier-count-") as temporary:
            root = Path(temporary)
            self.write_junit_cases(root, "TEST-a.xml", [("example.Test", "same")], failures="1")
            self.write_junit_cases(root, "TEST-b.xml", [("example.Test", "same")])
            with self.assertRaisesRegex(qualification.Refused, "^inconsistent-junit-outcome-counts$"):
                qualification.junit_outcomes(root)

    def test_junit_duplicate_keeps_empty_malformed_file_and_symlink_refusals(self):
        with tempfile.TemporaryDirectory(prefix="junit-report-guards-") as temporary:
            root = Path(temporary)
            directory = root / qualification.JUNIT
            with self.assertRaisesRegex(qualification.Refused, "^missing-ordinary-junit-results$"):
                qualification.junit_outcomes(root)
            directory.mkdir(parents=True)
            with self.assertRaisesRegex(qualification.Refused, "^empty-ordinary-junit-results$"):
                qualification.junit_outcomes(root)
            path, _ = self.write_junit_cases(root, "TEST-private.xml", [("example.Test", "same")] * 2)
            is_symlink = Path.is_symlink
            for link, code in ((directory, "missing-ordinary-junit-results"), (path, "invalid-junit-result-file")):
                with self.subTest(link=link.name), \
                        mock.patch.object(Path, "is_symlink", lambda candidate: candidate == link or is_symlink(candidate)):
                    with self.assertRaisesRegex(qualification.Refused, "^" + code + "$"):
                        qualification.junit_outcomes(root)
            path.write_bytes(b"<malformed")
            with self.assertRaises(ET.ParseError):
                qualification.junit_outcomes(root)

    def test_process_and_report_errors_and_non_windows_execution_fail_with_static_codes(self):
        for error in (OSError(MARKER), ValueError(MARKER), ET.ParseError(MARKER)):
            stderr = io.StringIO()
            with mock.patch.object(qualification.sys, "platform", "win32"), \
                    mock.patch.object(qualification, "qualify", side_effect=error), \
                    contextlib.redirect_stderr(stderr):
                self.assertEqual(1, qualification.main([]))
            self.assertEqual({"event": "windows_qualification_refused", "code": "process-or-report-error"},
                             json.loads(stderr.getvalue()))
            self.assertNotIn(MARKER, stderr.getvalue())
        stderr = io.StringIO()
        with mock.patch.object(qualification.sys, "platform", "linux"), \
                mock.patch.object(qualification, "qualify") as child, contextlib.redirect_stderr(stderr):
            self.assertEqual(1, qualification.main([]))
            child.assert_not_called()
        self.assertEqual("windows-owning-suites-require-windows", json.loads(stderr.getvalue())["code"])


class WindowsShellLookupDiagnosticTests(unittest.TestCase):
    def records(self):
        empty = hashlib.sha256(b"").hexdigest()
        return [
            {"v": 1, "phase": "roots", "status": "observed", "value": "present", "roots": [
                {"i": 0, "kind": "empty", "sha256": empty, "duplicate_of": None},
                {"i": 1, "kind": "unknown", "sha256": "a" * 64, "duplicate_of": None},
                {"i": 2, "kind": "pshome", "sha256": "b" * 64, "duplicate_of": None},
                {"i": 3, "kind": "empty", "sha256": empty, "duplicate_of": 0},
                {"i": 4, "kind": "unknown", "sha256": "a" * 64, "duplicate_of": 1},
            ]},
            {"v": 1, "phase": "observer", "status": "armed"},
            {"v": 1, "phase": "pre", "status": "observed", "ms": 10},
            {"v": 1, "phase": "post", "status": "observed", "ms": 20, "lookup_ms": 10,
             "command_type": 1, "module_kind": "pshome", "module_sha256": "c" * 64},
        ]

    def v2_records(self):
        records = self.records()
        for record in records:
            record["v"] = 2
        records[1]["not_found"] = {"status": "armed"}
        records.insert(3, {"v": 2, "phase": "not-found", "status": "observed", "ms": 15})
        return records

    def encode(self, records):
        return b"".join(json.dumps(record, separators=(",", ":")).encode("ascii") + b"\n" for record in records)

    def write_capsule(self, root, data):
        path = root / qualification.LOOKUP
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
        return path

    def collect(self, data):
        with tempfile.TemporaryDirectory(prefix="lookup-capsule-") as temporary:
            root = Path(temporary)
            before = qualification.lookup_before(root)
            self.assertEqual("absent", before)
            if data is not None:
                self.write_capsule(root, data)
            encoded = qualification.lookup_diagnostic_json(root, before)
        self.assertLessEqual(len(encoded.encode("ascii")) + 1, 4096)
        for private in (MARKER, str(root), "\x1b", "\\u001b"):
            self.assertNotIn(private, encoded)
        result = json.loads(encoded)
        self.assertIs(result["diagnostic_only"], True)
        self.assertNotIn("ok", result)
        if result["status"] in ("refused", "unavailable"):
            self.assertNotIn("records", result)
            self.assertNotIn("a" * 64, encoded)
        return result

    def test_lookup_preserves_every_root_and_phase_fact_losslessly(self):
        records = self.records()
        result = self.collect(self.encode(records))
        self.assertEqual("observed", result["status"])
        self.assertIs(result["capsule_complete"], True)
        observed = copy.deepcopy(result["records"])
        columns = observed[0].pop("root_columns")
        self.assertEqual(["i", "kind", "sha256", "duplicate_of"], columns)
        observed[0]["roots"] = [dict(zip(columns, entry, strict=True)) for entry in observed[0]["roots"]]
        self.assertEqual(records, observed)
        for kind, command, hashed in (("no-command", None, None), ("none", 32, None),
                                     ("unknown", 2, None), ("other", 256, "d" * 64)):
            with self.subTest(kind=kind):
                records[-1].update(module_kind=kind, command_type=command, module_sha256=hashed)
                self.assertEqual(records[-1], self.collect(self.encode(records))["records"][-1])

    def test_lookup_prefixes_absence_empty_and_partial_lines_remain_distinct(self):
        self.assertEqual("not-observed", self.collect(None)["code"])
        empty = self.collect(b"")
        self.assertEqual(("partial", "empty-prefix", []), (empty["status"], empty["code"], empty["records"]))
        for length in (1, 2, 3):
            with self.subTest(length=length):
                result = self.collect(self.encode(self.records()[:length]))
                self.assertEqual("partial", result["status"])
                self.assertEqual("incomplete-prefix", result["code"])
                self.assertIs(result["capsule_complete"], False)
                self.assertEqual(length, len(result["records"]))
        self.assertEqual("partial-line", self.collect(self.encode(self.records())[:-1])["code"])
        records = self.records()
        records[0].update(value="absent", roots=[])
        self.assertEqual("absent", self.collect(self.encode(records))["records"][0]["value"])

    def test_lookup_timing_uses_exact_integer_difference_and_explicit_nulls(self):
        for start, end, elapsed in ((0, 0, 0), (0, 600000, 600000), (600000, 600000, 0),
                                    (None, 0, None), (0, None, None), (None, None, None)):
            with self.subTest(start=start, end=end, elapsed=elapsed):
                records = self.records()
                records[2]["ms"] = start
                records[3].update(ms=end, lookup_ms=elapsed)
                self.assertEqual("observed", self.collect(self.encode(records))["status"])
        for start, end, elapsed in ((10, 20, 9), (10, 20, None), (20, 10, 0), (None, 20, 10),
                                    (10, None, 10), (None, None, 0), (True, 20, 19),
                                    (10, False, 0), (10, 20, True), (-1, 20, 21),
                                    (0, 600001, 600001), (0.0, 20, 20), (10, "20", 10)):
            with self.subTest(start=start, end=end, elapsed=elapsed):
                records = self.records()
                records[2]["ms"] = start
                records[3].update(ms=end, lookup_ms=elapsed)
                self.assertEqual("timing", self.collect(self.encode(records))["code"])

    def test_lookup_rejects_wrong_shapes_types_hashes_and_duplicate_relationships_before_publication(self):
        mutations = (
            lambda r: r[0].update(v=True),
            lambda r: r[0].update(v=2),
            lambda r: r[0].update(phase=MARKER),
            lambda r: r[0].update(extra=MARKER),
            lambda r: r[0].update(value=[]),
            lambda r: r[0].update(value="absent"),
            lambda r: r[0].update(roots=[]),
            lambda r: r[0].update(roots=False),
            lambda r: r[0]["roots"][0].update(i=False),
            lambda r: r[0]["roots"][0].update(i=1),
            lambda r: r[0]["roots"][0].update(kind="unknown"),
            lambda r: r[0]["roots"][1].update(kind=MARKER),
            lambda r: r[0]["roots"][1].update(sha256="A" * 64),
            lambda r: r[0]["roots"][1].update(sha256="a" * 63),
            lambda r: r[0]["roots"][1].update(sha256=MARKER + "\x1b[31m"),
            lambda r: r[0]["roots"][1].update(duplicate_of=0),
            lambda r: r[0]["roots"][3].update(duplicate_of=None),
            lambda r: r[0]["roots"][3].update(duplicate_of=False),
            lambda r: r[0]["roots"][4].update(duplicate_of=4),
            lambda r: r[0]["roots"][4].update(kind="pshome"),
            lambda r: r[1].update(code="unsupported-api"),
            lambda r: r[2].update(extra=MARKER),
            lambda r: r[3].update(command_type=True),
            lambda r: r[3].update(command_type=3),
            lambda r: r[3].update(module_kind="no-command"),
            lambda r: r[3].update(module_kind="none"),
            lambda r: r[3].update(module_kind=[]),
            lambda r: r[3].update(module_sha256=None),
            lambda r: r[3].update(module_sha256="c" * 65),
            lambda r: r[3].update(status="refused", code=MARKER),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                records = self.records()
                mutate(records)
                self.assertEqual("refused", self.collect(self.encode(records))["status"])
        records = self.records()
        records[0]["roots"].extend(copy.deepcopy(records[0]["roots"][1:2]) * 28)
        self.assertEqual("roots", self.collect(self.encode(records))["code"])
        records = self.records()
        records[0]["roots"].append({"i": 5, "kind": "unknown", "sha256": "a" * 64, "duplicate_of": 4})
        self.assertEqual("roots", self.collect(self.encode(records))["code"])

    def test_lookup_refusal_phases_and_impossible_transitions_are_not_normalized(self):
        roots = self.records()[0]
        for status, code in (("unavailable", "existing-hooks"), ("unavailable", "unsupported-api"),
                             ("refused", "install")):
            with self.subTest(observer=code):
                records = [roots, {"v": 1, "phase": "observer", "status": status, "code": code},
                           {"v": 1, "phase": "post", "status": "unavailable", "code": "observer-unavailable"}]
                self.assertEqual("observed", self.collect(self.encode(records))["status"])
        for code in ("input-limit", "encoding", "snapshot"):
            records = [{"v": 1, "phase": "roots", "status": "refused", "code": code},
                       {"v": 1, "phase": "observer", "status": "unavailable", "code": "roots-refused"},
                       {"v": 1, "phase": "post", "status": "unavailable", "code": "observer-unavailable"}]
            self.assertEqual(records, self.collect(self.encode(records))["records"])
        for count, status, codes in (
            (2, "unavailable", ("no-pre", "post-without-pre")),
            (2, "refused", ("callback",)),
            (3, "unavailable", ("no-post", "nested-target")),
            (3, "refused", ("command-type", "module-path-limit", "callback")),
        ):
            for code in codes:
                with self.subTest(pre=count == 3, code=code):
                    records = self.records()[:count] + [{"v": 1, "phase": "post", "status": status, "code": code}]
                    self.assertEqual("observed", self.collect(self.encode(records))["status"])
        invalid = [
            self.records()[1:],
            self.records()[:1] + self.records()[2:],
            self.records()[:2] + self.records()[3:],
            self.records()[:3] + self.records()[2:3],
            self.records()[:1] * 2,
        ]
        for count, code in ((2, "no-post"), (2, "nested-target"), (3, "no-pre"), (3, "post-without-pre"),
                             (3, "observer-unavailable")):
            invalid.append(self.records()[:count] + [{"v": 1, "phase": "post", "status": "unavailable", "code": code}])
        nonarmed = self.records()
        nonarmed[1] = {"v": 1, "phase": "observer", "status": "unavailable", "code": "existing-hooks"}
        invalid.append(nonarmed)
        roots_refused = self.records()
        roots_refused[0] = {"v": 1, "phase": "roots", "status": "refused", "code": "snapshot"}
        invalid.append(roots_refused)
        for index, records in enumerate(invalid):
            with self.subTest(invalid=index):
                self.assertEqual("record-order", self.collect(self.encode(records))["code"])

    def test_lookup_enforces_ascii_json_and_each_input_cap_without_partial_projection(self):
        valid = self.encode(self.records())
        duplicate_nested = valid.replace(b'"i":0', b'"i":0,"i":0', 1)
        for data, code in (
            (valid + b"\n", "record-count"),
            (b"\n", "blank-line"),
            (b"\xef\xbb\xbf" + valid, "encoding"),
            (valid.replace(b"\n", b"\r\n"), "encoding"),
            (valid + b"\x1b[31m\n", "encoding"),
            (b'{"v":1,"v":1}\n', "duplicate-json-key"),
            (duplicate_nested, "duplicate-json-key"),
            (valid[:-1] + b" " * 8192 + b"\n", "file-limit"),
            (self.encode(self.records()[:1])[:-1] + b" " * 6144 + b"\n", "record-limit"),
            (self.encode(self.records()[:2]) + b'{"private":"' + MARKER.encode() + b'"\n', "invalid-json"),
            (b"[" * 2000 + b"broken" + b"]" * 2000 + b"\n", "invalid-json"),
            ('{"v":1}'.encode("utf-16-le") + b"\n", "invalid-json"),
            (b"null\n", "record-shape"),
        ):
            with self.subTest(code=code, bytes=len(data)):
                self.assertEqual(code, self.collect(data)["code"])
        lines = [self.encode([record]) for record in self.records()]
        lines[0] = lines[0][:-1] + b" " * (6144 - len(lines[0])) + b"\n"
        lines[1] = lines[1][:-1] + b" " * (8192 - sum(map(len, lines))) + b"\n"
        self.assertEqual(8192, sum(map(len, lines)))
        self.assertEqual("observed", self.collect(b"".join(lines))["status"])

    def test_lookup_bound_read_stale_file_and_nonregular_reparse_guards(self):
        with tempfile.TemporaryDirectory(prefix="lookup-filesystem-") as temporary:
            root = Path(temporary)
            before = qualification.lookup_before(root)
            path = self.write_capsule(root, b"x" * 10000)
            native_open, observed = qualification.os.fdopen, {}

            @contextlib.contextmanager
            def open_capsule(descriptor, mode, **options):
                with native_open(descriptor, mode, **options) as stream:
                    observed["reader"] = mock.Mock(wraps=stream)
                    observed["stream"] = stream
                    yield observed["reader"]

            with mock.patch.object(qualification.os, "fdopen", side_effect=open_capsule), \
                    mock.patch.object(qualification.os, "open", wraps=qualification.os.open) as reader:
                result = json.loads(qualification.lookup_diagnostic_json(root, before))
            self.assertEqual("file-limit", result["code"])
            reader.assert_called_once()
            self.assertEqual(path, reader.call_args.args[0])
            flags = reader.call_args.args[1]
            for name in ("O_BINARY", "O_NOFOLLOW", "O_NONBLOCK"):
                required = getattr(qualification.os, name, 0)
                self.assertEqual(required, flags & required)
            observed["reader"].read.assert_called_once_with(8193)
            self.assertTrue(observed["stream"].closed)
            stale = qualification.lookup_before(root)
            with mock.patch.object(qualification.os, "open") as reader:
                self.assertEqual("preexisting-capsule", json.loads(qualification.lookup_diagnostic_json(root, stale))["code"])
                reader.assert_not_called()
            for missing in (None, False, MARKER):
                with self.subTest(freshness=type(missing).__name__), \
                        mock.patch.object(qualification.os, "open") as reader:
                    encoded = qualification.lookup_diagnostic_json(root, missing)
                    self.assertEqual("freshness-unavailable", json.loads(encoded)["code"])
                    self.assertNotIn(MARKER, encoded)
                    self.assertNotIn("records", json.loads(encoded))
                    reader.assert_not_called()
            native_lstat = Path.lstat
            for guarded in (root, root / "build", path.parent, path):
                for mode, attributes in ((qualification.stat.S_IFLNK, 0), (qualification.stat.S_IFREG, 0x400)):
                    def lstat(candidate):
                        if candidate == guarded:
                            return mock.Mock(st_mode=mode, st_file_attributes=attributes)
                        return native_lstat(candidate)
                    with self.subTest(part=guarded.name, mode=mode), \
                            mock.patch.object(Path, "lstat", autospec=True, side_effect=lstat), \
                            mock.patch.object(qualification.os, "open") as reader:
                        self.assertEqual("reparse-path", json.loads(qualification.lookup_diagnostic_json(root, before))["code"])
                        reader.assert_not_called()
            path.unlink()
            path.mkdir()
            self.assertEqual("nonregular-path", json.loads(qualification.lookup_diagnostic_json(root, before))["code"])

    def test_lookup_io_and_short_read_failures_do_not_publish_valid_prefixes(self):
        with tempfile.TemporaryDirectory(prefix="lookup-read-errors-") as temporary:
            root = Path(temporary)
            before = qualification.lookup_before(root)
            self.write_capsule(root, self.encode(self.records()))
            with mock.patch.object(qualification.os, "open", side_effect=PermissionError(MARKER)):
                encoded = qualification.lookup_diagnostic_json(root, before)
            self.assertEqual("read-error", json.loads(encoded)["code"])
            self.assertNotIn(MARKER, encoded)
            native_open = qualification.os.fdopen

            @contextlib.contextmanager
            def short_read(descriptor, mode, **options):
                with native_open(descriptor, mode, **options) as stream:
                    reader = mock.Mock(wraps=stream)
                    reader.read.return_value = self.encode(self.records()[:1])
                    yield reader

            with mock.patch.object(qualification.os, "fdopen", side_effect=short_read):
                self.assertEqual("incomplete-read", json.loads(qualification.lookup_diagnostic_json(root, before))["code"])
            with mock.patch.object(qualification.os, "fdopen", side_effect=OSError(MARKER)) as wrap:
                self.assertEqual("read-error", json.loads(qualification.lookup_diagnostic_json(root, before))["code"])
            with self.assertRaises(OSError):
                qualification.os.fstat(wrap.call_args.args[0])
            with mock.patch.object(Path, "lstat", side_effect=PermissionError(MARKER)):
                self.assertEqual("preflight-unavailable", qualification.lookup_before(root))
            native_fstat = qualification.os.fstat
            for field in ("st_ino", "st_size", "st_mtime_ns"):
                calls = []

                def fstat(descriptor):
                    metadata = native_fstat(descriptor)
                    calls.append(metadata)
                    if len(calls) == (1 if field == "st_ino" else 2):
                        values = {key: getattr(metadata, key)
                                  for key in ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns")}
                        values[field] += 1
                        return mock.Mock(**values)
                    return metadata

                with self.subTest(changed=field), mock.patch.object(qualification.os, "fstat", side_effect=fstat):
                    encoded = qualification.lookup_diagnostic_json(root, before)
                self.assertEqual("file-changed", json.loads(encoded)["code"])
                self.assertNotIn("a" * 64, encoded)

    def test_lookup_worst_case_lossless_projection_fits_and_overflow_refuses_without_truncation(self):
        records = self.records()
        records[0]["roots"] = [
            {"i": index, "kind": "unknown", "sha256": hashlib.sha256(str(index).encode("ascii")).hexdigest(),
             "duplicate_of": None} for index in range(32)
        ]
        records[2]["ms"] = 100000
        records[3].update(ms=600000, lookup_ms=500000, command_type=256)
        encoded_input = self.encode(records)
        self.assertLessEqual(len(encoded_input), 8192)
        self.assertTrue(all(len(line) + 1 <= 6144 for line in encoded_input.splitlines()))
        result = self.collect(encoded_input)
        self.assertEqual("observed", result["status"])
        self.assertEqual(32, len(result["records"][0]["roots"]))
        size = len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")) + len(os.linesep)
        self.assertLessEqual(size, 4096)
        with mock.patch.object(qualification, "DIAGNOSTIC_BYTE_LIMIT", size - 1):
            refused = self.collect(encoded_input)
        self.assertEqual("projection-limit", refused["code"])
        self.assertNotIn("records", refused)

    def test_lookup_v2_negative_edge_is_lossless_nonterminal_and_not_command_provenance(self):
        records = self.v2_records()
        for count in (1, 2, 3, 4, 5):
            with self.subTest(records=count):
                result = self.collect(self.encode(records[:count]))
                self.assertEqual("observed" if count == 5 else "partial", result["status"])
                self.assertIs(result["capsule_complete"], count == 5)
                observed = copy.deepcopy(result["records"])
                columns = observed[0].pop("root_columns")
                observed[0]["roots"] = [dict(zip(columns, entry, strict=True)) for entry in observed[0]["roots"]]
                self.assertEqual(records[:count], observed)
        for kind, command, hashed in (("no-command", None, None), ("none", 32, None),
                                     ("unknown", 2, None), ("pshome", 1, "c" * 64),
                                     ("other", 256, "d" * 64)):
            with self.subTest(kind=kind):
                records[-1].update(module_kind=kind, command_type=command, module_sha256=hashed)
                self.assertEqual(records[-1], self.collect(self.encode(records))["records"][-1])
        for version in (1, 2):
            prefix = (self.records() if version == 1 else self.v2_records())[:3]
            prefix[-1]["ms"] = 238
            result = self.collect(self.encode(prefix))
            self.assertEqual(("partial", "incomplete-prefix"), (result["status"], result["code"]))
            self.assertFalse(any(record["phase"] == "not-found" for record in result["records"]))
            self.assertEqual(version == 2, "not_found" in result["records"][1])

    def test_lookup_v2_negative_hook_availability_is_independent_and_exact(self):
        for availability in ({"status": "armed"}, {"status": "unavailable", "code": "existing-hook"},
                             {"status": "unavailable", "code": "unsupported-api"},
                             {"status": "refused", "code": "install"}):
            records = self.v2_records()
            records.pop(3)
            records[1]["not_found"] = availability
            with self.subTest(availability=availability):
                result = self.collect(self.encode(records))
                self.assertEqual(records[1:], result["records"][1:])
                self.assertIs(result["capsule_complete"], True)
                if availability["status"] != "armed":
                    records.insert(3, self.v2_records()[3])
                    self.assertEqual("record-order", self.collect(self.encode(records))["code"])
        for status, code in (("unavailable", "existing-hooks"), ("unavailable", "unsupported-api"),
                             ("refused", "install"), ("unavailable", "roots-refused")):
            records = self.v2_records()[:1]
            if code == "roots-refused":
                records[0] = {"v": 2, "phase": "roots", "status": "refused", "code": "snapshot"}
            records += [
                {"v": 2, "phase": "observer", "status": status, "code": code,
                 "not_found": {"status": "unavailable", "code": "observer-unavailable"}},
                {"v": 2, "phase": "post", "status": "unavailable", "code": "observer-unavailable"},
            ]
            with self.subTest(parent=code):
                self.assertEqual(records[1:], self.collect(self.encode(records))["records"][1:])
                records[1]["not_found"] = {"status": "armed"}
                self.assertEqual("record-order", self.collect(self.encode(records))["code"])
        for availability in (None, False, [], {"status": True}, {"status": "armed", "code": "install"},
                             {"status": "observed"}, {"status": "unavailable", "code": "existing-hooks"},
                             {"status": "refused", "code": MARKER}, {"status": "armed", "extra": MARKER}):
            records = self.v2_records()
            records[1]["not_found"] = availability
            with self.subTest(invalid=availability):
                self.assertEqual("record-shape", self.collect(self.encode(records))["code"])
        records = self.v2_records()
        records[1]["not_found"] = {"status": "unavailable", "code": "observer-unavailable"}
        self.assertEqual("record-order", self.collect(self.encode(records))["code"])

    def test_lookup_v2_requires_one_version_and_preserves_v1_shapes_and_record_cap(self):
        for records in (self.records(), self.v2_records()):
            for index in range(len(records)):
                for version in (True, 0, 3, 2 if records[0]["v"] == 1 else 1):
                    changed = copy.deepcopy(records)
                    changed[index]["v"] = version
                    with self.subTest(index=index, version=version, count=len(records)):
                        self.assertEqual("refused", self.collect(self.encode(changed))["status"])
        v1 = self.records()
        v1[1]["not_found"] = {"status": "armed"}
        self.assertEqual("record-shape", self.collect(self.encode(v1))["code"])
        v1 = self.records()
        v1.insert(3, {**self.v2_records()[3], "v": 1})
        self.assertEqual("record-count", self.collect(self.encode(v1))["code"])
        self.assertEqual("record-shape", self.collect(self.encode(v1[:4]))["code"])
        v2 = self.v2_records()
        del v2[1]["not_found"]
        self.assertEqual("record-shape", self.collect(self.encode(v2))["code"])
        for data in (self.encode(self.records()) + b"\n", self.encode(self.records()) + b"{bad\n"):
            self.assertEqual("record-count", self.collect(data)["code"])
        self.assertEqual("record-count", self.collect(self.encode(self.v2_records()) + b"\n")["code"])

    def test_lookup_v2_negative_boundary_samples_are_nullable_exact_and_monotonic(self):
        for start, negative, end, elapsed in (
            (0, 0, 0, 0), (0, 600000, 600000, 600000), (600000, 600000, 600000, 0),
            (None, 0, 600000, None), (0, None, 600000, 600000), (0, 600000, None, None),
            (None, None, 0, None), (None, 0, None, None), (0, None, None, None),
            (None, None, None, None),
        ):
            records = self.v2_records()
            records[2]["ms"], records[3]["ms"] = start, negative
            records[4].update(ms=end, lookup_ms=elapsed)
            with self.subTest(valid=(start, negative, end, elapsed)):
                self.assertEqual("observed", self.collect(self.encode(records))["status"])
        for start, negative, end, elapsed in (
            (20, 10, 30, 10), (10, 30, 20, 10), (None, 30, 20, None),
            (20, None, 10, 0), (10, 15, 20, 5), (None, 15, 20, 10),
            (10, True, 20, 10), (10, -1, 20, 10), (10, 600001, 20, 10),
            (10, 15.0, 20, 10), (10, "15", 20, 10), (10, [], 20, 10),
        ):
            records = self.v2_records()
            records[2]["ms"], records[3]["ms"] = start, negative
            records[4].update(ms=end, lookup_ms=elapsed)
            with self.subTest(invalid=(start, negative, end, elapsed)):
                self.assertEqual("timing", self.collect(self.encode(records))["code"])
        records = self.v2_records()[:4]
        records[3]["ms"] = 9
        self.assertEqual("timing", self.collect(self.encode(records))["code"])

    def test_lookup_v2_duplicate_late_missing_and_impossible_phases_refuse_without_prefix(self):
        records = self.v2_records()
        for positions in ((0, 1, 3), (0, 1, 3, 4), (0, 1, 2, 4, 3), (0, 1, 2, 3, 3),
                          (0, 1, 2, 2, 3), (0, 1, 2, 4, 4), (0, 1, 1), (0, 2, 3)):
            with self.subTest(positions=positions):
                self.assertEqual("record-order", self.collect(self.encode([records[i] for i in positions]))["code"])
        for length, status, codes in (
            (2, "unavailable", ("no-pre", "post-without-pre")), (2, "refused", ("callback",)),
            (3, "unavailable", ("no-post", "nested-target")),
            (4, "unavailable", ("no-post", "nested-target")),
            (3, "refused", ("command-type", "module-path-limit", "callback")),
            (4, "refused", ("command-type", "module-path-limit", "callback")),
        ):
            for code in codes:
                terminal = {"v": 2, "phase": "post", "status": status, "code": code}
                data = records[:length] + [terminal]
                with self.subTest(length=length, code=code):
                    result = self.collect(self.encode(data))
                    self.assertEqual(terminal, result["records"][-1])
                    self.assertIs(result["capsule_complete"], True)
        for code in ("no-pre", "post-without-pre", "observer-unavailable"):
            data = records[:4] + [{"v": 2, "phase": "post", "status": "unavailable", "code": code}]
            self.assertEqual("record-order", self.collect(self.encode(data))["code"])
        for mutate in (lambda r: r[3].update(extra=MARKER),
                       lambda r: r[3].update(status="unavailable", code="no-post"),
                       lambda r: r[3].update(phase=MARKER),
                       lambda r: r[3].pop("ms"),
                       lambda r: r[-1].update(status="unavailable", code="not-found-without-pre")):
            data = copy.deepcopy(records)
            mutate(data)
            self.assertEqual("record-shape", self.collect(self.encode(data))["code"])
        data = records[:2] + [
            {"v": 2, "phase": "post", "status": "unavailable", "code": "not-found-without-pre"},
        ]
        result = self.collect(self.encode(data))
        self.assertEqual(("refused", "record-shape"), (result["status"], result["code"]))
        self.assertIs(result["capsule_complete"], False)
        self.assertNotIn("records", result)

    def test_lookup_v2_whole_input_and_caps_are_checked_before_any_projection(self):
        valid = self.encode(self.v2_records())
        for data, code in (
            (valid[:-1], "partial-line"),
            (valid.replace(b'"not_found":{"status":"armed"}',
                           b'"not_found":{"status":"armed","status":"armed"}'), "duplicate-json-key"),
            (valid.replace(b'"phase":"not-found"', b'"phase":"not-found","phase":"not-found"'),
             "duplicate-json-key"),
            (valid.replace(b'"ms":15', b'"ms":15,"private":"' + MARKER.encode() + b'"'), "record-shape"),
            (valid.replace(b'"ms":15', b'"ms":15,"private":"' + MARKER.encode() + b'\x1b"'), "encoding"),
            (self.encode(self.v2_records()[:4]) + b'{"private":"' + MARKER.encode() + b'"\n', "invalid-json"),
            (valid[:-1] + b" " * 8192 + b"\n", "file-limit"),
            (self.encode(self.v2_records()[:1])[:-1] + b" " * 6144 + b"\n", "record-limit"),
        ):
            with self.subTest(code=code):
                self.assertEqual(code, self.collect(data)["code"])
        lines = [self.encode([record]) for record in self.v2_records()]
        lines[0] = lines[0][:-1] + b" " * (6144 - len(lines[0])) + b"\n"
        lines[1] = lines[1][:-1] + b" " * (8192 - sum(map(len, lines))) + b"\n"
        self.assertEqual(8192, sum(map(len, lines)))
        self.assertEqual("observed", self.collect(b"".join(lines))["status"])

    def test_lookup_v2_worst_case_availability_prefixes_and_negative_edge_fit_public_cap(self):
        records = self.v2_records()
        records[0]["roots"] = [
            {"i": index, "kind": "unknown", "sha256": hashlib.sha256(str(index).encode("ascii")).hexdigest(),
             "duplicate_of": None} for index in range(32)
        ]
        records[2]["ms"] = 100000
        records[3]["ms"] = 600000
        records[4].update(ms=600000, lookup_ms=500000, command_type=256)
        shapes = [records[:count] for count in range(1, 6)]
        for availability in ({"status": "unavailable", "code": "existing-hook"},
                             {"status": "unavailable", "code": "unsupported-api"},
                             {"status": "refused", "code": "install"}):
            data = copy.deepcopy(records)
            data.pop(3)
            data[1]["not_found"] = availability
            shapes.extend(data[:count] for count in range(2, 5))
        for length, status, codes in (
            (2, "unavailable", ("no-pre", "post-without-pre")), (2, "refused", ("callback",)),
            (3, "unavailable", ("no-post", "nested-target")), (4, "unavailable", ("no-post", "nested-target")),
            (3, "refused", ("command-type", "module-path-limit", "callback")),
            (4, "refused", ("command-type", "module-path-limit", "callback")),
        ):
            shapes.extend(records[:length] + [{"v": 2, "phase": "post", "status": status, "code": code}]
                          for code in codes)
        sizes = []
        for data in shapes:
            encoded = self.encode(data)
            self.assertLessEqual(len(encoded), 8192)
            self.assertTrue(all(len(line) + 1 <= 6144 for line in encoded.splitlines()))
            result = self.collect(encoded)
            self.assertNotEqual("refused", result["status"])
            self.assertEqual(32, len(result["records"][0]["roots"]))
            columns = result["records"][0]["root_columns"]
            self.assertEqual(data[0]["roots"], [
                dict(zip(columns, entry, strict=True)) for entry in result["records"][0]["roots"]
            ])
            self.assertEqual(data[1:], result["records"][1:])
            sizes.append(len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")) + 2)
        self.assertEqual(sizes[4], max(sizes))
        self.assertLessEqual(max(sizes), 4096)
        with mock.patch.object(qualification, "DIAGNOSTIC_BYTE_LIMIT", sizes[4] - 3):
            refused = self.collect(self.encode(records))
        self.assertEqual("projection-limit", refused["code"])
        self.assertNotIn("records", refused)

    def test_lookup_collection_settles_after_child_and_cannot_mask_owning_or_qualification_failure(self):
        fixtures = WindowsOutcomeTests()
        for data in (None, b"", self.encode(self.records()[:3]), self.encode(self.records()),
                     self.encode(self.v2_records()[:4]), self.encode(self.v2_records()), b"invalid\n"):
            for failure in ("none", "owning", "python", "duplicate"):
                with self.subTest(capsule_bytes=None if data is None else len(data), failure=failure), \
                        tempfile.TemporaryDirectory(prefix="lookup-owning-flow-") as temporary:
                    root = Path(temporary)
                    output, errors = io.StringIO(), io.StringIO()

                    def run(command, **options):
                        self.assertEqual([sys.executable, str(root / "scripts" / "quality.py"), "test"], command)
                        self.assertEqual(root, options["cwd"])
                        self.assertNotIn("windows_shell_lookup_diagnostic", output.getvalue())
                        options["stdout"].write(b"> Task :test\n")
                        options["stderr"].write((b"invalid\n" if failure == "python" else fixtures.python_report().encode()))
                        if failure == "duplicate":
                            fixtures.write_junit_cases(root, "TEST-fixture.xml", [("example.Class", "same")] * 2)
                        else:
                            fixtures.write_junit(root)
                        if data is not None:
                            self.write_capsule(root, data)
                        return subprocess.CompletedProcess(command, 37 if failure == "owning" else 0)

                    with mock.patch.object(qualification.sys, "platform", "win32"), \
                            mock.patch.object(qualification, "ROOT", root), \
                            mock.patch.object(qualification.subprocess, "run", side_effect=run) as child, \
                            contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                        self.assertEqual(0 if failure == "none" else 1, qualification.main([]))
                    child.assert_called_once()
                    records = [json.loads(line) for line in output.getvalue().splitlines() if line.startswith("{")]
                    self.assertEqual("windows_owning_suite_command", records[0]["event"])
                    self.assertEqual("windows_shell_lookup_diagnostic", records[1]["event"])
                    self.assertEqual(1, sum(record["event"] == "windows_shell_lookup_diagnostic" for record in records))
                    if failure == "none":
                        self.assertEqual("windows_qualification", records[-1]["event"])
                        self.assertIs(records[-1]["ok"], True)
                    else:
                        code = {"owning": "owning-suite-command-failed", "python": "incomplete-python-outcomes",
                                "duplicate": "duplicate-junit-case"}[failure]
                        self.assertEqual(code, json.loads(errors.getvalue())["code"])
                        self.assertFalse(any(record["event"] == "windows_qualification" for record in records))
                        if failure == "duplicate":
                            self.assertFalse(any(record.get("suite") == "junit:test" for record in records))

    def test_lookup_observation_does_not_bypass_preflight_and_retains_spawn_failure(self):
        fixtures = WindowsOutcomeTests()
        with tempfile.TemporaryDirectory(prefix="lookup-preflight-") as temporary:
            root = Path(temporary)
            fixtures.write_junit(root)
            with mock.patch.object(qualification, "lookup_before") as before, \
                    mock.patch.object(qualification, "lookup_diagnostic_json") as read, \
                    mock.patch.object(qualification.subprocess, "run") as child:
                with self.assertRaisesRegex(qualification.Refused, "^preexisting-ordinary-junit-results$"):
                    qualification.qualify(root)
                before.assert_not_called()
                read.assert_not_called()
                child.assert_not_called()
        with tempfile.TemporaryDirectory(prefix="lookup-spawn-failure-") as temporary:
            output, errors = io.StringIO(), io.StringIO()
            with mock.patch.object(qualification.sys, "platform", "win32"), \
                    mock.patch.object(qualification, "ROOT", Path(temporary)), \
                    mock.patch.object(qualification.subprocess, "run", side_effect=OSError(MARKER)), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(1, qualification.main([]))
            self.assertEqual("process-or-report-error", json.loads(errors.getvalue())["code"])
            self.assertNotIn(MARKER, output.getvalue() + errors.getvalue())
            records = [json.loads(line) for line in output.getvalue().splitlines() if line.startswith("{")]
            self.assertEqual(["windows_shell_lookup_diagnostic"], [record["event"] for record in records])
            self.assertEqual("not-observed", records[0]["code"])

    def test_lookup_preexisting_capsule_is_not_read_after_owning_failure(self):
        fixtures = WindowsOutcomeTests()
        with tempfile.TemporaryDirectory(prefix="lookup-stale-owning-failure-") as temporary:
            root = Path(temporary)
            data = self.encode(self.records())
            path = self.write_capsule(root, data)
            output, errors = io.StringIO(), io.StringIO()

            def run(command, **options):
                options["stdout"].write(b"> Task :test\n")
                options["stderr"].write(fixtures.python_report().encode())
                fixtures.write_junit(root)
                return subprocess.CompletedProcess(command, 37)

            with mock.patch.object(qualification.sys, "platform", "win32"), \
                    mock.patch.object(qualification, "ROOT", root), \
                    mock.patch.object(qualification.subprocess, "run", side_effect=run) as child, \
                    mock.patch.object(qualification, "lookup_records") as parse, \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(1, qualification.main([]))
                child.assert_called_once()
                parse.assert_not_called()
            self.assertEqual(data, path.read_bytes())
            records = [json.loads(line) for line in output.getvalue().splitlines() if line.startswith("{")]
            self.assertEqual(37, records[0]["exit_code"])
            self.assertEqual({"event": "windows_shell_lookup_diagnostic", "diagnostic_only": True,
                              "capsule_complete": False, "status": "refused", "code": "preexisting-capsule"}, records[1])
            self.assertEqual("owning-suite-command-failed", json.loads(errors.getvalue())["code"])
            self.assertNotIn("a" * 64, output.getvalue())
            self.assertFalse(any(record["event"] == "windows_qualification" for record in records))


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
        records = without_absent_lookup(self, records)
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

    def real_refusal(self, body, exit_code, negative, process_state=None, job_state=None, capture_state=None):
        identity = "test_diagnostic.DiagnosticCases.test_a_primary"
        real_run = subprocess.run
        with tempfile.TemporaryDirectory(prefix="windows-real-refusal-") as temporary:
            root = Path(temporary).resolve()
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
                fields = {"exception", "source_frames", "incomplete", "truncated"}
                if process_state is not None:
                    fields.add("process_budget_state")
                    self.assertEqual(process_state, detail.get("process_budget_state"))
                if job_state is not None:
                    fields.add("process_budget_job_state")
                    self.assertEqual(job_state, detail.get("process_budget_job_state"))
                if capture_state is not None:
                    fields.add("process_budget_capture_state")
                    self.assertEqual(capture_state, detail.get("process_budget_capture_state"))
                self.assertEqual(fields, set(detail))
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

    def budget_state(self, **changes):
        return {
            "capture_readers": 1, "capture_readers_alive": 1, "elapsed_ms": 10000,
            "process_running": True, "returncode": None,
            "schema": "pennilogic.process-budget-state/1", "setup_ms": 12,
            "status": "observed", "wait_ms": 9988, **changes,
        }

    def budget_note(self, state):
        return "process_budget_state=" + json.dumps(state, sort_keys=True, separators=(",", ":"))

    def job_state(self, accounting=None, members=None):
        return {
            "schema": "pennilogic.process-budget-job-state/1",
            "accounting": {"status": "observed", "total_assigned": 2, "active": 2}
            if accounting is None else accounting,
            "members": {"status": "observed", "listed": 2, "bootstrap": 1,
                        "system_approved_shell": 1, "other": 0, "unclassified": 0}
            if members is None else members,
        }

    def job_note(self, state):
        return "process_budget_job_state=" + json.dumps(state, sort_keys=True, separators=(",", ":"))

    def capture_state(self, mode="separate", **changes):
        streams = {
            name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in (("stdout", b"inner-out"), ("stderr", b"" if mode == "merged" else b"inner-err"))
        }
        return {
            "schema": "pennilogic.process-budget-capture-state/1", "status": "observed",
            "scope": "snapshot", "complete": False, "mode": mode, **streams, **changes,
        }

    def capture_note(self, state):
        return "process_budget_capture_state=" + json.dumps(state, sort_keys=True, separators=(",", ":"))

    def test_real_capture_notes_transport_inner_snapshots_without_repairing_budget_refusal(self):
        unavailable = {"schema": "pennilogic.process-budget-capture-state/1", "status": "unavailable"}
        legacy, job = self.budget_state(), self.job_state()
        for state, include_job in itertools.product(
            (self.capture_state(), self.capture_state("merged"), unavailable), (False, True),
        ):
            note, final = self.capture_note(state), self.budget_note(legacy)
            notes = [note] + ([self.job_note(job)] if include_job else []) + [final]
            with self.subTest(state=state, job=include_job):
                diagnostic, captured = self.real_refusal(
                    "error = type('BudgetExceeded', (TimeoutError,), {})(PAYLOAD); "
                    + "; ".join(f"error.add_note({value!r})" for value in notes) + "; raise error",
                    1, "error", process_state=legacy, job_state=job if include_job else None, capture_state=state,
                )
                lines = captured["stderr"].splitlines()
                for value in notes:
                    self.assertEqual(1, lines.count(value.encode("ascii")))
                start = lines.index(note.encode("ascii"))
                self.assertEqual([value.encode("ascii") for value in notes], lines[start:start + len(notes)])
                detail = diagnostic["parser"]["negative_prefix"][0]["error"]
                self.assertEqual("unclassified", detail["exception"])
                self.assertIs(detail["incomplete"], True)
                self.assertIs(detail["truncated"], False)
                self.assertNotIn("BudgetExceeded", json.dumps(diagnostic))
                for name in ("stdout", "stderr"):
                    if state["status"] == "observed":
                        self.assertNotEqual(diagnostic[name], state[name])
                self.assertNotIn("inner-out", json.dumps(diagnostic))
                self.assertNotIn("inner-err", json.dumps(diagnostic))

    def test_capture_snapshot_modes_counts_and_completeness_keep_exact_bounds(self):
        empty = {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        maximum = {"bytes": 18446744073709551615, "sha256": "f" * 64}
        unavailable = {"schema": "pennilogic.process-budget-capture-state/1", "status": "unavailable"}
        states = [unavailable]
        for mode in ("merged", "separate"):
            for stdout, stderr in itertools.product((empty, maximum), repeat=2):
                if mode == "merged" and stderr != empty:
                    continue
                states.append(self.capture_state(mode, stdout=stdout, stderr=stderr))
        self.assertEqual(106, len(self.capture_note(unavailable).encode("ascii")))
        self.assertEqual(389, len(self.capture_note(self.capture_state(stdout=maximum, stderr=maximum)).encode("ascii")))
        name, legacy, job = "test_fixture.Cases.test_error", self.budget_state(), self.job_state()
        with tempfile.TemporaryDirectory(prefix="windows-capture-state-counts-") as temporary:
            root = Path(temporary)
            for state in states:
                with self.subTest(state=state):
                    original = copy.deepcopy(state)
                    note = self.capture_note(state)
                    self.assertEqual(state, qualification.process_budget_capture_note(note.encode("ascii")))
                    body = (f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
                            f"RuntimeError: {MARKER}\n{note}\n{self.job_note(job)}\n{self.budget_note(legacy)}\n")
                    diagnostic = self.report_refusal(
                        root, self.exception_report(root, [(name, "ERROR")], [(name, body)]), exit_code=0,
                    )
                    detail = diagnostic["parser"]["negative_prefix"][0]["error"]
                    self.assertEqual(state, detail["process_budget_capture_state"])
                    self.assertEqual(legacy, detail["process_budget_state"])
                    self.assertEqual(job, detail["process_budget_job_state"])
                    self.assertEqual(original, state)
                    self.assertEqual("RuntimeError", detail["exception"])
                    self.assertIs(detail["incomplete"], True)
                    self.assertIs(detail["truncated"], False)
                    self.assertIs(diagnostic["inventory_complete"], False)

    def test_malformed_capture_notes_preserve_independently_valid_older_metadata(self):
        state, legacy, job = self.capture_state(), self.budget_state(), self.job_state()
        unavailable = {"schema": "pennilogic.process-budget-capture-state/1", "status": "unavailable"}
        invalid = [None, [], True, 1, MARKER]
        invalid.extend({key: value for key, value in state.items() if key != missing} for missing in state)
        invalid.extend((
            {**state, "extra": MARKER}, {**state, "schema": "pennilogic.process-budget-capture-state/2"},
            {**state, "status": "unavailable"}, {**unavailable, "mode": "separate"},
        ))
        for key, values in (
            ("complete", (True, 0, 1, None, "false", [], {})),
            ("mode", ("", "combined", None, True, 0, [], {})),
            ("scope", ("complete", None, True, [], {})),
            ("status", ("partial", "unsupported", None, True, [], {})),
        ):
            invalid.extend({**state, key: value} for value in values)
        for name in ("stdout", "stderr"):
            invalid.extend({**state, name: value} for value in (None, [], True, 1, MARKER))
            invalid.extend({**state, name: {key: value for key, value in state[name].items() if key != missing}}
                           for missing in state[name])
            invalid.append({**state, name: {**state[name], "extra": MARKER}})
            invalid.extend({**state, name: {**state[name], "bytes": value}}
                           for value in (True, False, -1, 18446744073709551616, 1.0, None, [], {}, "9"))
            invalid.extend({**state, name: {**state[name], "sha256": value}} for value in (
                None, [], {}, True, 64, "F" * 64, "g" * 64, "f" * 63, "f" * 65, "f" * 63 + "\n", MARKER,
            ))
            invalid.append({**state, name: {"bytes": 0, "sha256": "f" * 64}})
        invalid.append({**state, "mode": "merged"})
        note = self.capture_note(state)
        notes = [self.capture_note(value) for value in invalid]
        notes.extend((
            note.replace('"bytes":9', '"bytes":9,"bytes":9', 1),
            note.replace('"status":"observed"', '"status":"observed","status":"observed"'),
            note.replace('"complete":false', '"complete": false'),
            note.replace('"snapshot"', '"snap\\u0073hot"'),
            note.replace('"bytes":9', '"bytes":NaN', 1),
            note.replace('"bytes":9', '"bytes":Infinity', 1),
            note.replace('"bytes":9', '"bytes":1e1000', 1),
            "process_budget_capture_state=" + json.dumps(state, separators=(",", ":")),
            'process_budget_capture_state={"schema":"' + MARKER + '\u00e9"}',
            self.capture_note({**state, "schema": MARKER + "\u00e9"}),
            "process_budget_capture_state={", note + " " * 512,
        ))
        name = "test_fixture.Cases.test_error"
        with tempfile.TemporaryDirectory(prefix="windows-capture-state-invalid-") as temporary:
            root = Path(temporary)
            for index, candidate in enumerate(notes):
                with self.subTest(candidate=index):
                    body = (f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
                            f"RuntimeError: {MARKER}\n{candidate}\n{self.job_note(job)}\n{self.budget_note(legacy)}\n")
                    diagnostic = self.report_refusal(root, self.exception_report(root, [(name, "ERROR")], [(name, body)]))
                    detail = diagnostic["parser"]["negative_prefix"][0]["error"]
                    self.assertEqual(unavailable, detail["process_budget_capture_state"])
                    self.assertEqual(job, detail["process_budget_job_state"])
                    self.assertEqual(legacy, detail["process_budget_state"])
                    self.assertIs(detail["incomplete"], True)
                    self.assertIs(detail["truncated"], False)

    def test_capture_note_full_byte_bound_precedes_decoding(self):
        note = self.capture_note(self.capture_state()).encode("ascii")
        unavailable = {"schema": "pennilogic.process-budget-capture-state/1", "status": "unavailable"}
        for length, calls in ((512, 1), (513, 0)):
            candidate = note + b" " * (length - len(note))
            with self.subTest(bytes=length), mock.patch.object(qualification.json, "loads", wraps=json.loads) as loads:
                self.assertEqual(unavailable, qualification.process_budget_capture_note(candidate))
                self.assertEqual(calls, loads.call_count)
        for candidate in (b"", b"wrong_prefix={}", note + b"\xff"):
            with self.subTest(candidate=candidate), mock.patch.object(qualification.json, "loads") as loads:
                self.assertEqual(unavailable, qualification.process_budget_capture_note(candidate))
                loads.assert_not_called()

    def test_capture_note_requires_contiguous_tail_without_changing_older_note_rules(self):
        state, legacy, job = self.capture_state(), self.budget_state(), self.job_state()
        unavailable = {"schema": "pennilogic.process-budget-capture-state/1", "status": "unavailable"}
        job_unavailable = self.job_state(accounting={"status": "unavailable"}, members={"status": "unavailable"})
        legacy_unavailable = {"schema": "pennilogic.process-budget-state/1", "status": "unavailable"}
        note, middle, final = self.capture_note(state), self.job_note(job), self.budget_note(legacy)
        name = "test_fixture.Cases.test_error"
        with tempfile.TemporaryDirectory(prefix="windows-capture-state-order-") as temporary:
            root = Path(temporary)
            frame = f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
            for label, body, expected_job, expected_legacy in (
                ("duplicate", f"RuntimeError\n{note}\n{note}\n{middle}\n{final}\n", job, legacy),
                ("before-exception", f"{note}\nRuntimeError\n{middle}\n{final}\n", job, legacy),
                ("blank-before-job", f"RuntimeError\n{note}\n\n{middle}\n{final}\n", job, legacy),
                ("content-before-job", f"RuntimeError\n{note}\n{MARKER}\n{middle}\n{final}\n", job, legacy),
                ("blank-before-v1", f"RuntimeError\n{note}\n\n{final}\n", None, legacy),
                ("between-job-v1", f"RuntimeError\n{middle}\n{note}\n{final}\n", job_unavailable, legacy),
                ("after-v1", f"RuntimeError\n{middle}\n{final}\n{note}\n", job_unavailable, legacy_unavailable),
                ("duplicate-job", f"RuntimeError\n{note}\n{middle}\n{middle}\n{final}\n", job_unavailable, legacy),
                ("duplicate-v1", f"RuntimeError\n{note}\n{final}\n{final}\n", None, legacy_unavailable),
                ("missing-v1", f"RuntimeError\n{note}\n{middle}\n", job_unavailable, None),
            ):
                with self.subTest(report=label):
                    detail = self.report_refusal(
                        root, self.exception_report(root, [(name, "ERROR")], [(name, frame + body)]),
                    )["parser"]["negative_prefix"][0]["error"]
                    self.assertEqual(unavailable, detail["process_budget_capture_state"])
                    self.assertEqual(expected_job, detail.get("process_budget_job_state"))
                    self.assertEqual(expected_legacy, detail.get("process_budget_state"))
                    self.assertIs(detail["incomplete"], True)
            for malformed_job, malformed_v1 in ((True, False), (False, True)):
                with self.subTest(job=malformed_job, v1=malformed_v1):
                    body = (frame + f"RuntimeError\n{note}\n"
                            + ("process_budget_job_state={}" if malformed_job else middle) + "\n"
                            + ("process_budget_state={}" if malformed_v1 else final) + "\n")
                    detail = self.report_refusal(
                        root, self.exception_report(root, [(name, "ERROR")], [(name, body)]),
                    )["parser"]["negative_prefix"][0]["error"]
                    self.assertEqual(state, detail["process_budget_capture_state"])
                    self.assertEqual(job_unavailable if malformed_job else job, detail["process_budget_job_state"])
                    self.assertEqual(legacy_unavailable if malformed_v1 else legacy, detail["process_budget_state"])
            for suffix in ("", note + "\n"):
                report = self.exception_report(
                    root, [(name, "ERROR")], [(name, frame + f"RuntimeError\n{middle}\n{final}\n")],
                )
                detail = self.report_refusal(root, report + suffix.encode("ascii"))["parser"]["negative_prefix"][0]["error"]
                self.assertNotIn("process_budget_capture_state", detail)
                self.assertEqual(job, detail["process_budget_job_state"])
                self.assertEqual(legacy, detail["process_budget_state"])
                self.assertIs(detail["incomplete"], False)

    def test_capture_notes_cannot_cross_error_identities_or_broken_reports(self):
        first, second, passed, failed = [f"test_fixture.Cases.test_{name}" for name in ("a", "b", "c", "d")]
        state, job, legacy = self.capture_state(), self.job_state(), self.budget_state()
        note, middle, final = self.capture_note(state), self.job_note(job), self.budget_note(legacy)
        with tempfile.TemporaryDirectory(prefix="windows-capture-state-identity-") as temporary:
            root = Path(temporary)
            frame = f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
            body = frame + f"RuntimeError\n{note}\n{middle}\n{final}\n"
            report = self.exception_report(
                root, [(first, "ERROR"), (second, "ERROR"), (passed, "ok"), (failed, "FAIL")],
                [(passed, body), (second, body), (failed, body), (first, frame + f"RuntimeError\n{middle}\n{final}\n")],
            )
            prefix = self.report_refusal(root, report)["parser"]["negative_prefix"]
            self.assertNotIn("process_budget_capture_state", prefix[0]["error"])
            self.assertEqual(state, prefix[1]["error"]["process_budget_capture_state"])
            self.assertNotIn("error", prefix[2])
            good = self.exception_report(root, [(first, "ERROR")], [(first, body)])
            for label, candidate in (
                ("duplicate-error", self.exception_report(root, [(first, "ERROR")], [(first, body), (first, body)])),
                ("unclosed", self.exception_report(root, [(first, "ERROR")], [(first, body)], terminal=False)),
                ("missing-traceback", good.replace(b"Traceback (most recent call last):\n", b"")),
                ("missing-frames", good.replace(frame.encode(), b"")),
                ("missing-exception", good.replace(b"RuntimeError\n", b"")),
                ("mismatched-method", good.replace(b"ERROR: test_a (", b"ERROR: test_wrong (")),
                ("wrong-status", good.replace(b"ERROR: test_a (", b"FAIL: test_a (")),
                ("chain", good.replace(body.encode(), (body + "During handling of the above exception, "
                    "another exception occurred:\nTraceback (most recent call last):\n" + frame + "ValueError\n").encode())),
            ):
                with self.subTest(report=label):
                    detail = self.report_refusal(root, candidate)["parser"]["negative_prefix"][0]["error"]
                    self.assertNotEqual(state, detail.get("process_budget_capture_state"))
                    self.assertIs(detail["incomplete"], True)
            detail = self.report_refusal(root, good.replace(b"\n", b"\r\n"))["parser"]["negative_prefix"][0]["error"]
            self.assertEqual(state, detail["process_budget_capture_state"])
            self.assertEqual(job, detail["process_budget_job_state"])
            self.assertEqual(legacy, detail["process_budget_state"])

    def test_capture_snapshots_shed_globally_before_job_or_v1_metadata(self):
        stream = {"bytes": 18446744073709551615, "sha256": "f" * 64}
        state = self.capture_state(stdout=stream, stderr=stream)
        job = self.job_state(accounting={"status": "observed", "total_assigned": 4294967295, "active": 16},
                             members={"status": "observed", "listed": 16, "bootstrap": 1,
                                      "system_approved_shell": 1, "other": 14, "unclassified": 0})
        legacy = self.budget_state(process_running=False, returncode=4294967295, capture_readers=2,
                                   capture_readers_alive=2, elapsed_ms=86400000, setup_ms=43200000, wait_ms=43200000)
        with tempfile.TemporaryDirectory(prefix="windows-capture-state-size-") as temporary:
            root = Path(temporary)
            for (count, frames), include_job in itertools.product(((1, 1), (5, 1), (12, 10)), (False, True)):
                with self.subTest(cases=count, job=include_job):
                    names = [f"test_fixture.Cases.test_case_{index}" for index in range(count)]
                    diagnostics = []
                    for include_capture in (False, True):
                        reports = [(name, "".join(
                            f'  File "{root / "tests" / f"fixture_{line}.py"}", line {line}, in private\n'
                            for line in range(1, frames + 1)
                        ) + f"BudgetExceeded: {MARKER}\n"
                            + (self.capture_note(state) + "\n" if include_capture else "")
                            + (self.job_note(job) + "\n" if include_job else "")
                            + self.budget_note(legacy) + "\n") for name in reversed(names)]
                        diagnostics.append(self.report_refusal(
                            root, self.exception_report(root, [(name, "ERROR") for name in names], reports),
                        ))
                    previous, current = [item["parser"]["negative_prefix"] for item in diagnostics]
                    self.assertEqual([item["id_sha256"] for item in previous],
                                     [item["id_sha256"] for item in current])
                    details = [item["error"] for item in current]
                    for field in ("source_frames", "process_budget_job_state", "process_budget_state"):
                        self.assertEqual([item["error"].get(field) for item in previous],
                                         [item.get(field) for item in details])
                    if count == 1:
                        self.assertEqual(state, details[0]["process_budget_capture_state"])
                        self.assertIs(details[0]["truncated"], False)
                    else:
                        self.assertTrue(any(item.get("process_budget_capture_state") != state for item in details))
                        self.assertTrue(all(item["incomplete"] and item["truncated"]
                                            for item in details if item.get("process_budget_capture_state") != state))
                    if any(item.get("process_budget_state") != legacy or
                           (include_job and item.get("process_budget_job_state") != job) for item in details):
                        self.assertTrue(all("process_budget_capture_state" not in item for item in details))
                    self.assertLess(len(json.dumps(diagnostics[-1]).encode("utf-8")), 4096)
                    self.assertEqual(count, diagnostics[-1]["parser"]["negative_prefix_count"])
                    self.assertLessEqual(len(current), 8)
                    self.assertLessEqual(sum(len(item["source_frames"]) for item in details), 8)

    def test_real_job_note_pair_retains_v1_and_unclassified_budget_refusal(self):
        legacy = self.budget_state()
        partial = self.job_state()
        partial["members"].update(status="partial", system_approved_shell=0, unclassified=1)
        states = (
            self.job_state(), partial,
            self.job_state(accounting={"status": "unavailable"}, members={"status": "unavailable"}),
            self.job_state(accounting={"status": "unsupported"}, members={"status": "unsupported"}),
            self.job_state(members={"status": "oversized"}),
        )
        for state in states:
            note, final = self.job_note(state), self.budget_note(legacy)
            with self.subTest(state=state):
                self.assertLessEqual(len(note.encode("ascii")), 512)
                diagnostic, captured = self.real_refusal(
                    "error = type('BudgetExceeded', (TimeoutError,), {})(PAYLOAD); "
                    f"error.add_note({note!r}); error.add_note({final!r}); raise error",
                    1, "error", process_state=legacy, job_state=state,
                )
                lines = captured["stderr"].splitlines()
                self.assertEqual(1, lines.count(note.encode("ascii")))
                self.assertEqual(1, lines.count(final.encode("ascii")))
                self.assertEqual(final.encode("ascii"), lines[lines.index(note.encode("ascii")) + 1])
                detail = diagnostic["parser"]["negative_prefix"][0]["error"]
                self.assertEqual("unclassified", detail["exception"])
                self.assertIs(detail["incomplete"], True)
                self.assertIs(detail["truncated"], False)
                self.assertNotIn("BudgetExceeded", json.dumps(diagnostic))

    def test_job_counts_normalize_only_observed_non_atomic_active_disagreement(self):
        name, legacy = "test_fixture.Cases.test_error", self.budget_state()
        empty = self.job_state(accounting={"status": "observed", "total_assigned": 0, "active": 0},
                               members={"status": "observed", "listed": 0, "bootstrap": 0,
                                        "system_approved_shell": 0, "other": 0, "unclassified": 0})
        maximum = self.job_state(
            accounting={"status": "observed", "total_assigned": 4294967295, "active": 16},
            members={"status": "observed", "listed": 16, "bootstrap": 1,
                     "system_approved_shell": 1, "other": 14, "unclassified": 0},
        )
        partial = self.job_state()
        partial["members"]["status"] = "partial"
        cases = [(empty, "observed", False), (maximum, "observed", False), (partial, "partial", True)]
        for active in (1, 2, 3, 4294967295):
            cases.append((self.job_state(accounting={
                "status": "observed", "total_assigned": 4294967295, "active": active,
            }), "observed" if active == 2 else "partial", active != 2))
        for status in ("unavailable", "unsupported"):
            cases.append((self.job_state(accounting={"status": status}), "observed", True))
        for status in ("unavailable", "unsupported", "oversized"):
            cases.append((self.job_state(members={"status": status}), status, True))
        with tempfile.TemporaryDirectory(prefix="windows-job-state-counts-") as temporary:
            root = Path(temporary)
            for state, status, incomplete in cases:
                with self.subTest(state=state):
                    original = copy.deepcopy(state)
                    body = (f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
                            f"RuntimeError: {MARKER}\n{self.job_note(state)}\n{self.budget_note(legacy)}\n")
                    diagnostic = self.report_refusal(
                        root, self.exception_report(root, [(name, "ERROR")], [(name, body)]), exit_code=0,
                    )
                    expected = copy.deepcopy(state)
                    expected["members"]["status"] = status
                    detail = diagnostic["parser"]["negative_prefix"][0]["error"]
                    self.assertEqual(expected, detail["process_budget_job_state"])
                    self.assertEqual(legacy, detail["process_budget_state"])
                    self.assertEqual(original, state)
                    self.assertEqual("RuntimeError", detail["exception"])
                    self.assertIs(detail["incomplete"], incomplete)
                    self.assertIs(detail["truncated"], False)

    def test_malformed_job_notes_are_unavailable_without_invalidating_final_v1(self):
        state, legacy = self.job_state(), self.budget_state()
        unavailable = self.job_state(accounting={"status": "unavailable"}, members={"status": "unavailable"})
        invalid = [{key: value for key, value in state.items() if key != missing} for missing in state]
        invalid.extend(({**state, "extra": MARKER}, {**state, "schema": "pennilogic.process-budget-job-state/2"}))
        for part in ("accounting", "members"):
            invalid.extend({**state, part: value} for value in (None, [], True, 1, MARKER))
            invalid.extend({**state, part: {key: value for key, value in state[part].items() if key != missing}}
                           for missing in state[part])
            invalid.append({**state, part: {**state[part], "extra": MARKER}})
            invalid.extend({**state, part: {**state[part], "status": value}}
                           for value in (None, True, [], {}, MARKER, "unavailable", "unsupported", "oversized"))
            for key in set(state[part]) - {"status"}:
                limit = 4294967295 if part == "accounting" else 16
                invalid.extend({**state, part: {**state[part], key: value}}
                               for value in (True, False, -1, limit + 1, 1.0, None, [], {}, "1"))
        invalid.extend((
            self.job_state(accounting={"status": "observed", "total_assigned": 1, "active": 2}),
            self.job_state(accounting={"status": "oversized"}),
            self.job_state(members={**state["members"], "status": "partial", "listed": 3}),
            self.job_state(members={**state["members"], "listed": 3, "bootstrap": 2}),
            self.job_state(members={**state["members"], "system_approved_shell": 0, "unclassified": 1}),
            self.job_state(members={"status": "partial"}),
        ))
        note = self.job_note(state)
        notes = [self.job_note(value) for value in invalid]
        notes.extend((
            note.replace('"active":2', '"active":2,"active":2'),
            note.replace('"listed":2', '"listed":2,"listed":2'),
            note.replace('{"accounting":', '{"schema":"' + state["schema"] + '","accounting":', 1),
            note.replace('"active":2', '"active":NaN'),
            note.replace('"listed":2', '"listed":Infinity'),
            note.replace('"active":2', '"active":1e1000'),
            note.replace('"active":2', '"active": 2'),
            "process_budget_job_state=" + json.dumps(state, separators=(",", ":")),
            'process_budget_job_state={"schema":"' + MARKER + '\u00e9"}',
            self.job_note({**state, "schema": MARKER + "\u00e9"}),
            "process_budget_job_state=[]", "process_budget_job_state=null", "process_budget_job_state={",
            note + " " * 512,
        ))
        name = "test_fixture.Cases.test_error"
        with tempfile.TemporaryDirectory(prefix="windows-job-state-invalid-") as temporary:
            root = Path(temporary)
            for index, candidate in enumerate(notes):
                with self.subTest(candidate=index):
                    body = (f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
                            f"RuntimeError: {MARKER}\n{candidate}\n{self.budget_note(legacy)}\n")
                    diagnostic = self.report_refusal(
                        root, self.exception_report(root, [(name, "ERROR")], [(name, body)]),
                    )
                    detail = diagnostic["parser"]["negative_prefix"][0]["error"]
                    self.assertEqual(unavailable, detail["process_budget_job_state"])
                    self.assertEqual(legacy, detail["process_budget_state"])
                    self.assertIs(detail["incomplete"], True)
                    self.assertIs(detail["truncated"], False)

    def test_job_note_byte_bound_includes_prefix_and_precedes_json_decoding(self):
        note = self.job_note(self.job_state()).encode("ascii")
        unavailable = self.job_state(accounting={"status": "unavailable"}, members={"status": "unavailable"})
        for length, calls in ((512, 1), (513, 0)):
            candidate = note + b" " * (length - len(note))
            with self.subTest(bytes=length), mock.patch.object(qualification.json, "loads", wraps=json.loads) as loads:
                self.assertEqual(unavailable, qualification.process_budget_job_note(candidate))
                self.assertEqual(calls, loads.call_count)
        for candidate in (b"", b"wrong_prefix={}", note + b"\xff"):
            with self.subTest(candidate=candidate), mock.patch.object(qualification.json, "loads") as loads:
                self.assertEqual(unavailable, qualification.process_budget_job_note(candidate))
                loads.assert_not_called()

    def test_job_note_order_duplicates_and_absence_preserve_independent_legacy_rules(self):
        state, legacy = self.job_state(), self.budget_state()
        unavailable = self.job_state(accounting={"status": "unavailable"}, members={"status": "unavailable"})
        legacy_unavailable = {"schema": "pennilogic.process-budget-state/1", "status": "unavailable"}
        note, final = self.job_note(state), self.budget_note(legacy)
        name = "test_fixture.Cases.test_error"
        with tempfile.TemporaryDirectory(prefix="windows-job-state-order-") as temporary:
            root = Path(temporary)
            frame = f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
            variants = (
                ("duplicate-job", f"RuntimeError\n{note}\n{note}\n{final}\n", legacy),
                ("before-exception", f"{note}\nRuntimeError\n{final}\n", legacy),
                ("blank-between", f"RuntimeError\n{note}\n\n{final}\n", legacy),
                ("content-between", f"RuntimeError\n{note}\n{MARKER}\n{final}\n", legacy),
                ("after-v1", f"RuntimeError\n{final}\n{note}\n", legacy_unavailable),
                ("duplicate-v1", f"RuntimeError\n{final}\n{note}\n{final}\n", legacy_unavailable),
                ("missing-v1", f"RuntimeError\n{note}\n", None),
            )
            for label, body, expected_legacy in variants:
                with self.subTest(report=label):
                    diagnostic = self.report_refusal(
                        root, self.exception_report(root, [(name, "ERROR")], [(name, frame + body)]),
                    )
                    detail = diagnostic["parser"]["negative_prefix"][0]["error"]
                    self.assertEqual(unavailable, detail["process_budget_job_state"])
                    self.assertEqual(expected_legacy, detail.get("process_budget_state"))
                    self.assertIs(detail["incomplete"], True)
            body = frame + f"RuntimeError\n{note}\nprocess_budget_state={{}}\n"
            detail = self.report_refusal(
                root, self.exception_report(root, [(name, "ERROR")], [(name, body)]),
            )["parser"]["negative_prefix"][0]["error"]
            self.assertEqual(state, detail["process_budget_job_state"])
            self.assertEqual(legacy_unavailable, detail["process_budget_state"])
            self.assertIs(detail["incomplete"], True)
            for suffix in ("", note + "\n"):
                report = self.exception_report(
                    root, [(name, "ERROR")], [(name, frame + f"RuntimeError\n{final}\n")],
                )
                detail = self.report_refusal(root, report + suffix.encode("ascii"))["parser"]["negative_prefix"][0]["error"]
                self.assertNotIn("process_budget_job_state", detail)
                self.assertEqual(legacy, detail["process_budget_state"])
                self.assertIs(detail["incomplete"], False)

    def test_job_notes_cannot_cross_error_identities_or_invalid_report_envelopes(self):
        first, second, passed, failed = [f"test_fixture.Cases.test_{name}" for name in ("a", "b", "c", "d")]
        state, legacy = self.job_state(), self.budget_state()
        note, final = self.job_note(state), self.budget_note(legacy)
        with tempfile.TemporaryDirectory(prefix="windows-job-state-identity-") as temporary:
            root = Path(temporary)
            frame = f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
            body = frame + f"RuntimeError\n{note}\n{final}\n"
            data = self.exception_report(
                root, [(first, "ERROR"), (second, "ERROR"), (passed, "ok"), (failed, "FAIL")],
                [(passed, body), (second, body), (failed, body), (first, frame + f"RuntimeError\n{final}\n")],
            )
            prefix = self.report_refusal(root, data)["parser"]["negative_prefix"]
            self.assertNotIn("process_budget_job_state", prefix[0]["error"])
            self.assertEqual(state, prefix[1]["error"]["process_budget_job_state"])
            self.assertNotIn("error", prefix[2])
            good = self.exception_report(root, [(first, "ERROR")], [(first, body)])
            for label, report in (
                ("duplicate-error", self.exception_report(root, [(first, "ERROR")], [(first, body), (first, body)])),
                ("unclosed", self.exception_report(root, [(first, "ERROR")], [(first, body)], terminal=False)),
                ("missing-traceback", good.replace(b"Traceback (most recent call last):\n", b"")),
                ("missing-frames", good.replace(frame.encode(), b"")),
                ("mismatched-method", good.replace(b"ERROR: test_a (", b"ERROR: test_wrong (")),
                ("wrong-status", good.replace(b"ERROR: test_a (", b"FAIL: test_a (")),
                ("chain", good.replace(body.encode(), (body + "During handling of the above exception, "
                    "another exception occurred:\nTraceback (most recent call last):\n" + frame + "ValueError\n").encode())),
            ):
                with self.subTest(report=label):
                    detail = self.report_refusal(root, report)["parser"]["negative_prefix"][0]["error"]
                    self.assertNotEqual(state, detail.get("process_budget_job_state"))
                    self.assertIs(detail["incomplete"], True)
            detail = self.report_refusal(root, good.replace(b"\n", b"\r\n"))["parser"]["negative_prefix"][0]["error"]
            self.assertEqual(state, detail["process_budget_job_state"])
            self.assertEqual(legacy, detail["process_budget_state"])

    def test_job_notes_shed_before_v1_without_removing_identities_or_frames(self):
        state = self.job_state(accounting={"status": "observed", "total_assigned": 4294967295, "active": 16},
                               members={"status": "observed", "listed": 16, "bootstrap": 1,
                                        "system_approved_shell": 1, "other": 14, "unclassified": 0})
        legacy = self.budget_state(process_running=False, returncode=4294967295, capture_readers=2,
                                   capture_readers_alive=2, elapsed_ms=86400000, setup_ms=43200000, wait_ms=43200000)
        with tempfile.TemporaryDirectory(prefix="windows-job-state-size-") as temporary:
            root = Path(temporary)
            for count, frames in ((5, 1), (12, 10)):
                with self.subTest(cases=count):
                    names = [f"test_fixture.Cases.test_case_{index}" for index in range(count)]
                    entries = [(name, "ERROR") for name in names]
                    diagnostics = []
                    for include_job in (False, True):
                        reports = [(name, "".join(
                            f'  File "{root / "tests" / f"fixture_{line}.py"}", line {line}, in private\n'
                            for line in range(1, frames + 1)
                        ) + f"subprocess.CalledProcessError: {MARKER}\n"
                            + (self.job_note(state) + "\n" if include_job else "")
                            + self.budget_note(legacy) + "\n") for name in reversed(names)]
                        diagnostics.append(self.report_refusal(root, self.exception_report(root, entries, reports)))
                    previous, current = [item["parser"]["negative_prefix"] for item in diagnostics]
                    self.assertEqual([item["id_sha256"] for item in previous],
                                     [item["id_sha256"] for item in current])
                    self.assertEqual([item["error"]["source_frames"] for item in previous],
                                     [item["error"]["source_frames"] for item in current])
                    self.assertEqual([item["error"].get("process_budget_state") for item in previous],
                                     [item["error"].get("process_budget_state") for item in current])
                    details = [item["error"] for item in current]
                    self.assertTrue(any(item.get("process_budget_job_state") != state for item in details))
                    self.assertTrue(all(item["incomplete"] and item["truncated"]
                                        for item in details if item.get("process_budget_job_state") != state))
                    self.assertLess(len(json.dumps(diagnostics[-1]).encode("utf-8")), 4096)
                    self.assertEqual(count, diagnostics[-1]["parser"]["negative_prefix_count"])
                    if count == 5:
                        self.assertTrue(all(item["process_budget_state"] == legacy for item in details))
                    else:
                        self.assertEqual(8, len(current))
                        self.assertEqual(8, sum(len(item["source_frames"]) for item in details))
                        self.assertIs(diagnostics[-1]["parser"]["negative_prefix_truncated"], True)
                        self.assertTrue(any(item.get("process_budget_state") != legacy for item in details))
                        self.assertTrue(all("process_budget_job_state" not in item for item in details))

    def test_real_exception_notes_transport_observed_and_unavailable_without_classifying_budget_error(self):
        unavailable = {"schema": "pennilogic.process-budget-state/1", "status": "unavailable"}
        for state in (self.budget_state(), self.budget_state(process_running=False, returncode=0), unavailable):
            note = self.budget_note(state)
            with self.subTest(state=state):
                self.assertLessEqual(len(note.encode("ascii")), 384)
                diagnostic, captured = self.real_refusal(
                    "error = type('BudgetExceeded', (TimeoutError,), {})(PAYLOAD); "
                    f"error.add_note({note!r}); raise error", 1, "error", process_state=state,
                )
                self.assertIn(note.encode("ascii"), captured["stderr"])
                detail = diagnostic["parser"]["negative_prefix"][0]["error"]
                self.assertEqual("unclassified", detail["exception"])
                self.assertIs(detail["incomplete"], True)
                self.assertIs(detail["truncated"], False)
                self.assertEqual([{
                    "path_sha256": hashlib.sha256(b"tests/test_diagnostic.py").hexdigest(), "line": 9,
                }], detail["source_frames"])
                self.assertNotIn("BudgetExceeded", json.dumps(diagnostic))

    def test_process_state_transport_accepts_only_exact_bounded_integer_endpoints(self):
        name = "test_fixture.Cases.test_error"
        states = (
            self.budget_state(capture_readers=0, capture_readers_alive=0, elapsed_ms=0, setup_ms=0, wait_ms=0),
            self.budget_state(process_running=False, returncode=-2147483648),
            self.budget_state(process_running=False, returncode=4294967295, capture_readers=2,
                              capture_readers_alive=2, elapsed_ms=86400000, setup_ms=86400000, wait_ms=0),
        )
        with tempfile.TemporaryDirectory(prefix="windows-budget-state-limits-") as temporary:
            root = Path(temporary)
            for state in states:
                with self.subTest(state=state):
                    body = (f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
                            f"RuntimeError: {MARKER}\n{self.budget_note(state)}\n")
                    diagnostic = self.report_refusal(
                        root, self.exception_report(root, [(name, "ERROR")], [(name, body)]), exit_code=0,
                    )
                    detail = diagnostic["parser"]["negative_prefix"][0]["error"]
                    self.assertEqual(state, detail["process_budget_state"])
                    self.assertEqual("RuntimeError", detail["exception"])
                    self.assertIs(detail["incomplete"], False)
                    self.assertIs(diagnostic["inventory_complete"], False)

    def test_malformed_process_state_notes_are_unavailable_not_outcomes_or_raw_diagnostics(self):
        name = "test_fixture.Cases.test_error"
        unavailable = {"schema": "pennilogic.process-budget-state/1", "status": "unavailable"}
        state = self.budget_state()
        note = self.budget_note(state)
        invalid = [self.budget_note({key: value for key, value in state.items() if key != missing})
                   for missing in state]
        for key in ("capture_readers", "capture_readers_alive", "elapsed_ms", "setup_ms", "wait_ms"):
            invalid.extend(self.budget_note(self.budget_state(**{key: value}))
                           for value in (True, False, -1, 86400001, 1.0, None, [], {}))
        invalid.extend(self.budget_note(self.budget_state(**changes)) for changes in (
            {"extra": MARKER}, {"schema": "pennilogic.process-budget-state/2"}, {"status": "unknown"},
            {"process_running": 1}, {"process_running": None}, {"returncode": 0},
            {"process_running": False}, {"process_running": False, "returncode": True},
            {"process_running": False, "returncode": -2147483649},
            {"process_running": False, "returncode": 4294967296},
            {"capture_readers": 0}, {"capture_readers": 3}, {"capture_readers_alive": 3},
            {"elapsed_ms": 9999}, {"setup_ms": 13}, {"wait_ms": 9987},
            {"schema": MARKER + "\u00e9"}, {"schema": unavailable["schema"], "status": "unavailable"},
        ))
        invalid.extend((
            note.replace('{"capture_readers":1', '{"capture_readers":1,"capture_readers":1'),
            note.replace('"returncode":null', '"returncode":NaN'),
            note.replace('"returncode":null', '"returncode":Infinity'),
            note.replace('"wait_ms":9988', '"wait_ms":1e1000'),
            "process_budget_state=[]", "process_budget_state=null", "process_budget_state={",
            note + " " * 384, note + "\n" + note, note + "\n" + MARKER,
            note.replace('"status":', '"status": '), self.budget_note({"schema": unavailable["schema"]}),
            self.budget_note({**unavailable, "extra": MARKER}),
            "process_budget_state=" + '{"schema":"' + MARKER + "\u00e9" + '"}',
        ))
        with tempfile.TemporaryDirectory(prefix="windows-budget-state-invalid-") as temporary:
            root = Path(temporary)
            for index, candidate in enumerate(invalid):
                with self.subTest(candidate=index):
                    body = (f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
                            f"RuntimeError: {MARKER}\n{candidate}\n")
                    diagnostic = self.report_refusal(
                        root, self.exception_report(root, [(name, "ERROR")], [(name, body)]),
                    )
                    detail = diagnostic["parser"]["negative_prefix"][0]["error"]
                    self.assertEqual(unavailable, detail["process_budget_state"])
                    self.assertEqual("RuntimeError", detail["exception"])
                    self.assertIs(detail["incomplete"], True)
                    self.assertIs(detail["truncated"], False)

    def test_process_state_notes_cannot_cross_identity_or_malformed_report_boundaries(self):
        first, second, passed, failed = [f"test_fixture.Cases.test_{name}" for name in ("a", "b", "c", "d")]
        state = self.budget_state()
        note = self.budget_note(state)
        with tempfile.TemporaryDirectory(prefix="windows-budget-state-association-") as temporary:
            root = Path(temporary)
            frame = f'  File "{root / "tests" / "fixture.py"}", line 19, in test_error\n'
            body = frame + "RuntimeError\n" + note + "\n"
            data = self.exception_report(
                root, [(first, "ERROR"), (second, "ERROR"), (passed, "ok"), (failed, "FAIL")],
                [(passed, body), (second, body), (failed, body), (first, frame + "RuntimeError\n")],
            )
            prefix = self.report_refusal(root, data)["parser"]["negative_prefix"]
            self.assertNotIn("process_budget_state", prefix[0]["error"])
            self.assertEqual(state, prefix[1]["error"]["process_budget_state"])
            self.assertNotIn("error", prefix[2])
            good = self.exception_report(root, [(first, "ERROR")], [(first, body)])
            for label, report in (
                ("duplicate", self.exception_report(root, [(first, "ERROR")], [(first, body), (first, body)])),
                ("unclosed", self.exception_report(root, [(first, "ERROR")], [(first, body)], terminal=False)),
                ("before-exception", good.replace(body.encode(), (frame + note + "\nRuntimeError\n").encode())),
                ("chain", good.replace(body.encode(), (body + "During handling of the above exception, "
                    "another exception occurred:\nTraceback (most recent call last):\n" + frame + "ValueError\n").encode())),
                ("missing-traceback", good.replace(b"Traceback (most recent call last):\n", b"")),
                ("mismatched-method", good.replace(b"ERROR: test_a (", b"ERROR: test_wrong (")),
            ):
                with self.subTest(report=label):
                    detail = self.report_refusal(root, report)["parser"]["negative_prefix"][0]["error"]
                    self.assertNotEqual(state, detail.get("process_budget_state"))
                    self.assertIs(detail["incomplete"], True)
            absent = self.exception_report(root, [(first, "ERROR")], [(first, frame + "RuntimeError\n")])
            detail = self.report_refusal(root, absent + note.encode() + b"\n")["parser"]["negative_prefix"][0]["error"]
            self.assertNotIn("process_budget_state", detail)
            self.assertIs(detail["incomplete"], False)

    def test_process_state_notes_preserve_existing_public_byte_case_and_frame_caps(self):
        identities = [f"test_fixture.Cases.test_case_{index}" for index in range(12)]
        state = self.budget_state(process_running=False, returncode=4294967295, capture_readers=2,
                                  capture_readers_alive=2, elapsed_ms=86400000, setup_ms=43200000, wait_ms=43200000)
        note = self.budget_note(state)
        with tempfile.TemporaryDirectory(prefix="windows-budget-state-public-limit-") as temporary:
            root = Path(temporary)
            reports = [(name, "".join(
                f'  File "{root / "tests" / f"fixture_{line}.py"}", line {line}, in private\n'
                for line in range(1, 11)
            ) + f"subprocess.CalledProcessError: {MARKER}\n{note}\n") for name in reversed(identities)]
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
        self.assertTrue(any(detail.get("process_budget_state") == state for detail in details))
        self.assertTrue(any(detail.get("process_budget_state") != state for detail in details))
        self.assertLess(len(json.dumps(diagnostic).encode()), 4096)

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

    def test_real_refusal_resolves_owned_root_alias_before_attributing_frames(self):
        original_temporary = tempfile.TemporaryDirectory

        @contextlib.contextmanager
        def aliased_temporary(*args, **kwargs):
            with original_temporary(*args, **kwargs) as temporary:
                root = Path(temporary).resolve()
                (root / "alias").mkdir()
                alias = root / "alias" / ".."
                self.assertNotEqual(str(root), str(alias))
                self.assertTrue(root.samefile(alias))
                yield str(alias)
            self.assertFalse(root.exists())

        with mock.patch.object(tempfile, "TemporaryDirectory", side_effect=aliased_temporary):
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
