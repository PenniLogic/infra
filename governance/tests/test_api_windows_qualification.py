"""Canonical Windows routing and synthetic outcome controls, not API target execution."""

import ast
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
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import conformance_support as support
from conformance import generator as generator_module, registry as registry_module
import qualify as infra_qualification
from test_api_native_source_fetch import (
    OBSERVER_COMMAND, OBSERVER_CONDITION, OBSERVER_RUNTIME_ENV, native_owning_script, remove_native_steps,
    remove_observer_pair, remove_observer_runtime, remove_shell_focus, SHELL_FOCUS_CONDITION, SHELL_FOCUS_INPUT,
)
from test_baseline import CONTRACTS_PREVIOUS_SOURCE_TEST_COMMAND, CONTRACTS_SOURCE_TEST_COMMAND


generator = support.generator
CI = ".github/workflows/ci.yml"
SPEC = importlib.util.spec_from_file_location("windows_qualification", support.GOVERNANCE / "templates/qualify_windows.py")
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)
MARKER = "PRIVATE-FIXTURE-PAYLOAD-DO-NOT-PRINT"
INPUT_PREPARATION = "python -I -S -B scripts\\money_client_interop.py prepare"
INFRA_SECURITY_SOURCE = "1e16ccc161d1bd964e3c0c438d9e3bac2c95f8e1"


def api_checker():
    namespace = {"__file__": str(support.GOVERNANCE.parent / "scripts/check_repository.py"),
                 "__name__": "generated_api_checker_fixture"}
    exec(compile(generator.checker("api"), "generated API checker", "exec"), namespace)
    return namespace["validate_workflow"]


def use_physical_interpreter(test):
    """The production path check refuses links, so fixtures bind the resolved interpreter on every platform."""
    physical = os.path.realpath(sys.executable)
    if physical != sys.executable:
        patch = mock.patch.object(sys, "executable", physical)
        patch.start()
        test.addCleanup(patch.stop)


def without_absent_lookup(test, records):
    observed = [record for record in records if record["event"] == "windows_shell_lookup_diagnostic"]
    test.assertEqual([{
        "event": "windows_shell_lookup_diagnostic", "diagnostic_only": True,
        "capsule_complete": False, "status": "unavailable", "code": "not-observed",
    }], observed)
    return [record for record in records if record["event"] != "windows_shell_lookup_diagnostic"]


class ApiWindowsWorkflowTests(unittest.TestCase):
    def test_optional_shell_readback_preserves_the_complete_accepted_workflow(self):
        workflow = remove_observer_pair(self, json.loads(generator.workflow("api")))
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
        self.assertEqual((support.GOVERNANCE / "templates/qualify_windows.py").read_bytes(),
                         artifacts["scripts/qualify_windows.py"].encode("utf-8"))

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
            ("owner-soft-failure", lambda job: job["steps"][-3].update({"continue-on-error": True})),
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
        workflow = remove_observer_runtime(self, remove_shell_focus(self, json.loads(generator.workflow("api"))))
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
                            OBSERVER_COMMAND],
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
            lambda value: next(step for step in value["jobs"]["windows"]["steps"]
                               if step["name"] == "Checkout").update(uses="actions/checkout@" + "a" * 40),
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
            for repo in ("api",):
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

    def test_infra_native_aggregator_accepts_only_three_explicit_successes(self):
        bash = shutil.which("bash")
        self.assertIsNotNone(bash, "Bash is required for the actual native CI result script")
        fields = ("LINUX_RESULT", "WINDOWS_GOVERNANCE_RESULT", "WINDOWS_SCRIPTS_RESULT")
        successful = dict.fromkeys(fields, "success")
        cases = [successful]
        for field in fields:
            cases.extend({**successful, field: value}
                         for value in ("failure", "cancelled", "skipped", "", None, "SUCCESS", "unknown", "success\n"))
        with tempfile.TemporaryDirectory(prefix="infra-native-ci-result-") as temporary:
            root = Path(temporary)
            path = root / "result.sh"
            path.write_text(generator.ci_result_job("infra")["steps"][0]["run"] + "\n",
                            encoding="utf-8", newline="\n")
            for values in cases:
                environment = support.defects.probe_environment()
                for field, value in values.items():
                    environment.pop(field, None)
                    if value is not None:
                        environment[field] = value
                result = subprocess.run([bash, "--noprofile", "--norc", "-e", str(path)], cwd=root,
                                        env=environment, capture_output=True, check=False, timeout=10)
                with self.subTest(values=values):
                    self.assertEqual(0 if values == successful else 1, result.returncode)
                    self.assertEqual(b"", result.stdout)
                    self.assertEqual(b"" if values == successful else
                                     b"::error::Infra CI requires successful Linux and Windows qualification.\n",
                                     result.stderr)

    def test_windows_powershell_stops_at_each_failed_native_command(self):
        source = native_owning_script(generator.workflow("api"), windows=True)
        support.assert_powershell_failure_boundaries(self, "$env:PENNILOGIC_API106_OBSERVER_PAIR = 'false'\n" + source, 9)

    def test_observer_pair_is_typed_explicit_and_preserves_every_default_workflow_byte(self):
        current = json.loads(generator.workflow("api"))
        without = remove_observer_pair(self, copy.deepcopy(current))
        self.assertEqual("51bf74f97dbb427e68c4db320ebd69bf9daadcc116c9ca628fcbd33f2349fceb",
                         hashlib.sha256(generator.encoded(without).encode("utf-8")).hexdigest())
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                if repo != "api" or setup:
                    self.assertNotIn("api106_observer_pair", generator.workflow(repo, setup=setup))
        validate = api_checker()
        mutations = (
            lambda value: value["on"]["workflow_dispatch"]["inputs"]["api106_observer_pair"].update(type="string"),
            lambda value: value["on"]["workflow_dispatch"]["inputs"]["api106_observer_pair"].update(default=True),
            lambda value: value["jobs"]["windows"]["steps"][-3].pop("env"),
            lambda value: value["jobs"]["windows"]["steps"][-3]["env"].update(PENNILOGIC_API106_OBSERVER_PAIR="true"),
            lambda value: value["jobs"]["windows"]["steps"][-2].pop("if"),
            lambda value: value["jobs"]["windows"]["steps"][-2].update({"if": "${{ " + OBSERVER_CONDITION + " }}"}),
            lambda value: value["jobs"]["windows"]["steps"][-2].update({"continue-on-error": True}),
            lambda value: value["jobs"]["windows"]["steps"][-2].update({"timeout-minutes": 2}),
            lambda value: value["jobs"]["windows"]["steps"][-1].update({"if": "always()"}),
        )
        for mutation in mutations:
            changed = copy.deepcopy(current)
            mutation(changed)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "API CI must match"):
                validate(CI, generator.encoded(changed).encode("utf-8"))

    def test_checkout_git_selection_and_serialization_are_exact_checker_inputs(self):
        original = json.loads(generator.workflow("api"))
        validate = api_checker()
        validate(CI, generator.encoded(original).encode("utf-8"))
        for before, after in (
            (" | Select-Object -First 1", ""),
            ("Select-Object -First 1", "Select-Object -Last 1"),
            ("Select-Object -First 1", "Sort-Object Source | Select-Object -First 1"),
            ('"path=$git`nsha256=$hash`n"', '"path=$git $git`nsha256=$hash $hash`n"'),
        ):
            changed = copy.deepcopy(original)
            selection = changed["jobs"]["windows"]["steps"][0]
            self.assertEqual(1, selection["run"].count(before))
            selection["run"] = selection["run"].replace(before, after, 1)
            with self.subTest(drift=after), self.assertRaisesRegex(ValueError, "API CI must match"):
                validate(CI, generator.encoded(changed).encode("utf-8"))

    def test_input_preparation_omission_stub_reordering_and_missing_guard_are_refused(self):
        validate = api_checker()
        original = json.loads(generator.workflow("api"))
        projected = remove_observer_runtime(self, copy.deepcopy(original))
        owning = next(step for step in projected["jobs"]["windows"]["steps"]
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
                    elif name == "infra" and not setup:
                        document = json.loads(expected)
                        reviewed = json.loads(support.git(
                            support.GOVERNANCE.parent, "show", f"{INFRA_SECURITY_SOURCE}:{CI}",
                        ))
                        self.assertEqual({"ci", "windows", "ci-result"}, set(reviewed["jobs"]))
                        for job_name in ("ci", "windows"):
                            steps = document["jobs"][job_name]["steps"]
                            self.assertEqual(["Checkout", "Python", "Node"],
                                             [step["name"] for step in steps[:3]])
                            self.assertEqual("Install uv", steps[3]["name"])
                            preparation = reviewed["jobs"][job_name]["steps"][3]
                            self.assertEqual({"name", "run"}, set(preparation))
                            self.assertEqual("Prepare security tools", preparation["name"])
                            steps.insert(3, preparation)
                        windows = document["jobs"].pop("windows")
                        old_commands = windows["steps"][-1]["run"].splitlines()
                        self.assertEqual([
                            "python scripts\\check_repository.py",
                            "python governance\\generate.py --repository infra --check",
                            "python governance\\qualify.py -- python -m unittest discover -s governance\\tests",
                            "python governance\\qualify.py -- python -m unittest discover -s scripts\\tests",
                        ], old_commands[::2])
                        self.assertEqual(["if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"] * 4,
                                         old_commands[1::2])
                        for suite, position in (("governance", 4), ("scripts", 6)):
                            split = copy.deepcopy(windows)
                            split["name"] = "Windows " + suite + " qualification"
                            split["steps"][-1] = {
                                "name": "Run Windows " + suite + " suite",
                                "run": "\n".join(old_commands[:4] + old_commands[position:position + 2]),
                            }
                            document["jobs"]["windows-" + suite] = split
                        aggregate = document["jobs"]["ci-result"]
                        aggregate["needs"] = ["ci", "windows-governance", "windows-scripts"]
                        aggregate["steps"][0] = {
                            "name": "Require all qualification results",
                            "env": {
                                "LINUX_RESULT": "${{ needs.ci.result }}",
                                "WINDOWS_GOVERNANCE_RESULT": "${{ needs.windows-governance.result }}",
                                "WINDOWS_SCRIPTS_RESULT": "${{ needs.windows-scripts.result }}",
                            },
                            "run": 'if [ "${LINUX_RESULT-}" != success ] || '
                                   '[ "${WINDOWS_GOVERNANCE_RESULT-}" != success ] || '
                                   '[ "${WINDOWS_SCRIPTS_RESULT-}" != success ]; then\n'
                                   '  echo "::error::Infra CI requires successful Linux and Windows qualification." >&2\n'
                                   '  exit 1\nfi',
                        }
                        document["jobs"]["ci-result"] = document["jobs"].pop("ci-result")
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
        accepted_digest = "0a073083148e670081eee72612fd9853a1a78100c2a50129ce89a2da9adfe1b3"
        accepted_template = subprocess.run(
            ["git", "--no-pager", "show",
             "0f5f7b7ce4baa8206add295ce0adee03292a5b20:governance/templates/qualify_windows.py"],
            cwd=support.GOVERNANCE.parent, capture_output=True, check=True, timeout=30,
        ).stdout
        self.assertEqual(accepted_digest, hashlib.sha256(accepted_template).hexdigest())
        current_template = (support.GOVERNANCE / "templates/qualify_windows.py").read_bytes()
        current_generated = generator.artifacts("api")["scripts/qualify_windows.py"].encode("utf-8")
        self.assertEqual(current_template, current_generated)


class WindowsShellFocusTests(unittest.TestCase):
    def setUp(self):
        no_spawn = mock.patch.object(subprocess, "Popen", side_effect=AssertionError("No live target in source controls"))
        no_spawn.start()
        self.addCleanup(no_spawn.stop)
        self.fixture = WindowsObserverPairDiagnosticTests()
        self.addCleanup(self.fixture.doCleanups)

    def record(self, **changes):
        return {"v": 1, "event": "api106_shell_focus_target", "target": qualification.SHELL_FOCUS_TARGET,
                "tests_run": 1, "elapsed_ns": 1, "failures": 0, "errors": 0, "skipped": 0,
                "expectedFailures": 0, "unexpectedSuccesses": 0, "exception": None, **changes}

    def result(self, code=0, **changes):
        return subprocess.CompletedProcess([], code, json.dumps(
            self.record(**changes), sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n", b"")

    @contextlib.contextmanager
    def parent(self, result=None, *, lookup_data=None, controls=False):
        with tempfile.TemporaryDirectory(prefix="focus-synthetic-owner-") as temporary:
            root = Path(temporary)
            (root / "build").mkdir()
            budget = self.fixture.budget()
            environment = {"PATH": "synthetic-approved", "CI": "true"}
            command = [sys.executable, "-I", "-S", "-B", "-c", "synthetic-never-executed"]

            def run(*args, **kwargs):
                (root / qualification.OBSERVER_FILES["required-boundary"][0]).write_bytes(b"ES111CX")
                if lookup_data is not None:
                    WindowsShellLookupDiagnosticTests().write_capsule(root, lookup_data)
                return result if result is not None else self.result()

            budget.run.side_effect = run
            with contextlib.ExitStack() as stack:
                for name, value in (
                    ("observer_context", "a" * 64), ("shell_focus_sources", {"synthetic": {"bytes": 1, "sha256": "b" * 64}}),
                    ("observer_budget_module", budget), ("shell_focus_runtime", (environment, {"synthetic_only": True})),
                    ("shell_focus_command", command),
                ):
                    stack.enter_context(mock.patch.object(qualification, name, return_value=value))
                if not controls:
                    stack.enter_context(mock.patch.object(qualification, "shell_focus_controls", return_value=True))
                yield root, budget, command, environment

    def invoke(self, root, **options):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = qualification.shell_focus(root, **options)
        public = output.getvalue()
        self.assertEqual(1, len(public.splitlines()))
        self.assertLessEqual(len(public.encode("ascii")), 16384)
        self.assertNotIn(MARKER, public)
        self.assertNotIn(str(root), public)
        self.assertNotIn("Traceback", public)
        report = json.loads(public)
        self.assertIs(report["diagnostic_only"], True)
        self.assertIs(report["native_qualification"], False)
        self.assertIs(report["physical_cleanup_attestation"], False)
        return code, report

    def test_focus_workflow_has_one_fixed_manual_typed_default_off_job_and_exact_required_jobs(self):
        current = json.loads(generator.workflow("api"))
        self.assertEqual(SHELL_FOCUS_INPUT, current["on"]["workflow_dispatch"]["inputs"]["api106_shell_focus"])
        previous = remove_shell_focus(self, copy.deepcopy(current))
        for name in ("ci", "windows", "ci-result"):
            self.assertEqual(generator.encoded(previous["jobs"][name]), generator.encoded(current["jobs"][name]))
        job = current["jobs"]["api106-shell-focus"]
        self.assertEqual("${{ " + SHELL_FOCUS_CONDITION + " }}", job["if"])
        self.assertNotIn("needs", job)
        self.assertNotIn("continue-on-error", job)
        self.assertEqual("windows-2025", job["runs-on"])
        self.assertEqual(30, job["timeout-minutes"])
        self.assertEqual("3.14.8", next(step for step in job["steps"] if step["name"] == "Python")["with"]["python-version"])
        self.assertEqual(current["jobs"]["windows"]["steps"][1], job["steps"][1])
        owner = job["steps"][-1]
        self.assertEqual("Run isolated approved-shell diagnostic", owner["name"])
        self.assertIn("-I -S -B scripts\\qualify_windows.py --require-prepared --api106-shell-focus", owner["run"])
        self.assertNotIn("--api106-observer-pair", owner["run"])
        self.assertNotIn("elseif", owner["run"])
        self.assertNotIn("continue-on-error", json.dumps(job))
        self.assertEqual({"PENNILOGIC_API106_SHELL_FOCUS": job["if"], **OBSERVER_RUNTIME_ENV}, owner["env"])
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                if repo != "api" or setup:
                    self.assertNotIn("api106_shell_focus", generator.workflow(repo, setup=setup))
        checker = api_checker()
        for mutation in (
            lambda v: v["on"]["workflow_dispatch"]["inputs"]["api106_shell_focus"].update(default=True),
            lambda v: v["on"]["workflow_dispatch"]["inputs"]["api106_shell_focus"].update(type="string"),
            lambda v: v["jobs"]["api106-shell-focus"].update({"if": "${{ inputs.api106_shell_focus }}"}),
            lambda v: v["jobs"]["api106-shell-focus"].update({"continue-on-error": True}),
            lambda v: v["jobs"]["api106-shell-focus"]["steps"][-1].update(run="echo bypass"),
        ):
            value = copy.deepcopy(current)
            mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                checker(CI, generator.encoded(value).encode("ascii"))

    def test_fixed_parent_invocation_keeps_default_ownership_and_reports_real_allowance(self):
        lookup = WindowsShellLookupDiagnosticTests()
        with self.parent(lookup_data=lookup.encode(lookup.v2_records())) as (root, budget, command, environment):
            code, report = self.invoke(root, require_prepared=True)
            budget.run.assert_called_once_with(command, root, 150, capture=True, separate=True, env=environment)
            self.assertEqual(0, code)
            self.assertEqual("passed", report["status"])
            self.assertEqual("passed", report["target_status"])
            self.assertEqual("complete-observed", report["lookup_evidence"])
            self.assertEqual("helper-settled", report["owner_release"])
            self.assertEqual(150, report["work_seconds"])
            self.assertEqual(10, report["single_cleanup_seconds"])
            self.assertIs(report["hard_end_to_end_deadline"], False)
            self.assertIs(report["synchronous_calls_preempted"], False)
            self.assertEqual("shipped-default-false", report["inherit_tree"])
            self.assertIsInstance(report["owned_call_elapsed_ns"], int)
            self.assertGreaterEqual(report["owned_call_elapsed_ns"], 0)
            self.assertEqual("after-write-output", report["carriers"]["boundary"]["checkpoint"])
            self.assertEqual("observed", report["carriers"]["lookup"]["status"])
            self.assertIs(report["carriers"]["lookup"]["capsule_complete"], True)
        tree = ast.parse((support.GOVERNANCE / "templates/qualify_windows.py").read_bytes())
        handler = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "shell_focus")
        calls = [node for node in ast.walk(handler) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                 and (node.func.value.id, node.func.attr) == ("budget", "run")]
        self.assertEqual(1, len(calls))
        self.assertEqual(150, ast.literal_eval(calls[0].args[2]))
        self.assertEqual(["capture", "separate", "env"], [item.arg for item in calls[0].keywords])
        self.assertEqual((270, 300), (qualification.OBSERVER_COMMAND_SECONDS, qualification.OBSERVER_CLOSED_SECONDS))

    def test_target_result_requires_exact_one_case_and_failures_errors_skips_fail_closed(self):
        for field in ("failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses"):
            budget = self.fixture.budget()
            exception = qualification.shell_focus_exception(AssertionError(MARKER), budget)
            result = self.result(1, **{field: 1, "exception": exception if field in ("failures", "errors") else None})
            with self.subTest(outcome=field), self.parent(result) as (root, owner, _, _):
                code, report = self.invoke(root, require_prepared=True)
                self.assertEqual(1, code)
                self.assertEqual("failed", report["status"])
                self.assertEqual("failed", report["target_status"])
                self.assertEqual("inconclusive", report["lookup_evidence"])
                self.assertEqual(1, report["target"][field])
                self.assertEqual("helper-settled", report["owner_release"])
                owner.run.assert_called_once()
        for changes in ({"tests_run": 0}, {"tests_run": 2}, {"tests_run": True},
                        {"target": MARKER}, {"errors": 1}, {"skipped": -1}, {"elapsed_ns": True},
                        {"skipped": 1, "errors": 1}, {"elapsed_ns": 150_000_000_001}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                qualification.shell_focus_result(self.result(**changes))

    def test_missing_lookup_is_inconclusive_without_relabeling_passing_child(self):
        with self.parent() as (root, budget, _, _):
            code, report = self.invoke(root, require_prepared=True)
            budget.run.assert_called_once()
            self.assertEqual(self.record(), report["target"])
            self.assertEqual("not-observed", report["carriers"]["lookup"]["code"])
            self.assertEqual(1, code, json.dumps(report, sort_keys=True))
            self.assertEqual("inconclusive", report["status"])
            self.assertEqual("passed", report["target_status"])
            self.assertEqual("inconclusive", report["lookup_evidence"])
            self.assertEqual("helper-settled", report["owner_release"])
            self.assertIsNone(report["error"])

    def test_complete_available_lookup_preserves_observed_absence_and_optional_negative_edge(self):
        lookup = WindowsShellLookupDiagnosticTests()
        no_negative = lookup.v2_records()
        no_negative.pop(3)
        absent_roots = lookup.v2_records()
        absent_roots[0].update(value="absent", roots=[])
        no_command, no_module, zero_samples = (lookup.v2_records() for _ in range(3))
        no_command[-1].update(command_type=None, module_kind="no-command", module_sha256=None)
        no_module[-1].update(module_kind="none", module_sha256=None)
        for record in zero_samples[2:]:
            record["ms"] = 0
        zero_samples[-1]["lookup_ms"] = 0
        for name, records in (
            ("v1-observed", lookup.records()), ("v2-observed", lookup.v2_records()),
            ("no-negative-event", no_negative), ("observed-absent-roots", absent_roots),
            ("observed-no-command", no_command), ("observed-no-module", no_module),
            ("observed-zero-samples", zero_samples),
        ):
            with self.subTest(case=name), self.parent(lookup_data=lookup.encode(records)) as (root, _, _, _):
                code, report = self.invoke(root, require_prepared=True)
                self.assertEqual((0, "passed", "passed", "complete-observed"),
                                 (code, report["status"], report["target_status"], report["lookup_evidence"]))
                self.assertEqual(self.record(), report["target"])
                self.assertEqual(json.loads(qualification.lookup_diagnostic_json(root, "absent")),
                                 report["carriers"]["lookup"])

    def test_empty_and_every_available_lookup_prefix_are_inconclusive(self):
        lookup = WindowsShellLookupDiagnosticTests()
        no_negative = lookup.v2_records()
        no_negative.pop(3)
        for name, records in (("v1", lookup.records()), ("v2", lookup.v2_records()), ("v2-no-negative", no_negative)):
            for count in range(len(records)):
                with self.subTest(case=f"{name}-prefix-{count}"), \
                        self.parent(lookup_data=lookup.encode(records[:count])) as (root, _, _, _):
                    code, report = self.invoke(root, require_prepared=True)
                    projection = report["carriers"]["lookup"]
                    self.assertEqual((1, "inconclusive", "passed", "inconclusive"),
                                     (code, report["status"], report["target_status"], report["lookup_evidence"]))
                    self.assertEqual(self.record(), report["target"])
                    self.assertEqual("partial", projection["status"])
                    self.assertIs(projection["capsule_complete"], False)
                    self.assertEqual(count, len(projection["records"]))
                    self.assertEqual("incomplete-prefix" if count else "empty-prefix", projection["code"])
                    self.assertEqual(json.loads(qualification.lookup_diagnostic_json(root, "absent")), projection)

    def test_unavailable_or_refused_lookup_phases_and_their_prefixes_never_turn_green(self):
        lookup = WindowsShellLookupDiagnosticTests()
        for version, original in ((1, lookup.records()), (2, lookup.v2_records())):
            cases = []
            for status, code in (("unavailable", "existing-hooks"), ("unavailable", "unsupported-api"),
                                 ("refused", "install")):
                observer = {"v": version, "phase": "observer", "status": status, "code": code}
                if version == 2:
                    observer["not_found"] = {"status": "unavailable", "code": "observer-unavailable"}
                cases.append(("observer-" + code, [
                    original[0], observer,
                    {"v": version, "phase": "post", "status": "unavailable", "code": "observer-unavailable"},
                ]))
            for code in ("input-limit", "encoding", "snapshot"):
                observer = {"v": version, "phase": "observer", "status": "unavailable", "code": "roots-refused"}
                if version == 2:
                    observer["not_found"] = {"status": "unavailable", "code": "observer-unavailable"}
                cases.append(("roots-" + code, [
                    {"v": version, "phase": "roots", "status": "refused", "code": code}, observer,
                    {"v": version, "phase": "post", "status": "unavailable", "code": "observer-unavailable"},
                ]))
            for count, status, codes in (
                (2, "unavailable", ("no-pre", "post-without-pre")), (2, "refused", ("callback",)),
                (3, "unavailable", ("no-post", "nested-target")),
                (3, "refused", ("command-type", "module-path-limit", "callback")),
            ) + (() if version == 1 else (
                (4, "unavailable", ("no-post", "nested-target")),
                (4, "refused", ("command-type", "module-path-limit", "callback")),
            )):
                for code in codes:
                    cases.append((f"post-{count}-{code}", original[:count] + [
                        {"v": version, "phase": "post", "status": status, "code": code},
                    ]))
            if version == 2:
                for status, code in (("unavailable", "existing-hook"), ("unavailable", "unsupported-api"),
                                     ("refused", "install")):
                    records = copy.deepcopy(original)
                    records.pop(3)
                    records[1]["not_found"] = {"status": status, "code": code}
                    cases.append(("negative-hook-" + code, records))
            for name, records in cases:
                for count in range(1, len(records) + 1):
                    prefix = records[:count]
                    refused = any(record["status"] == "refused"
                                  or record.get("not_found", {}).get("status") == "refused" for record in prefix)
                    evidence = "refused" if refused else "inconclusive"
                    with self.subTest(case=f"v{version}-{name}-prefix-{count}"), \
                            self.parent(lookup_data=lookup.encode(prefix)) as (root, _, _, _):
                        code, report = self.invoke(root, require_prepared=True)
                        self.assertEqual((1, "failed" if refused else "inconclusive", "passed", evidence),
                                         (code, report["status"], report["target_status"], report["lookup_evidence"]))
                        self.assertEqual(self.record(), report["target"])
                        projection = report["carriers"]["lookup"]
                        self.assertNotEqual("refused", projection["status"])
                        self.assertEqual(json.loads(qualification.lookup_diagnostic_json(root, "absent")), projection)
                        self.assertEqual(prefix[1:], projection["records"][1:])
                        self.assertIs(projection["capsule_complete"], prefix[-1]["phase"] == "post")

    def test_terminal_observed_lookup_with_unavailable_timing_or_provenance_is_inconclusive(self):
        lookup = WindowsShellLookupDiagnosticTests()
        cases = []
        for name, start, negative, end, elapsed in (
            ("missing-pre-time", None, 15, 20, None),
            ("missing-negative-time", 10, None, 20, 10),
            ("missing-post-time", 10, 15, None, None),
            ("all-times-unavailable", None, None, None, None),
        ):
            records = lookup.v2_records()
            records[2]["ms"], records[3]["ms"] = start, negative
            records[-1].update(ms=end, lookup_ms=elapsed)
            cases.append((name, records))
        unknown_module = lookup.v2_records()
        unknown_module[-1].update(module_kind="unknown", module_sha256=None)
        cases.append(("module-path-unavailable", unknown_module))
        for name, records in cases:
            with self.subTest(case=name), self.parent(lookup_data=lookup.encode(records)) as (root, _, _, _):
                code, report = self.invoke(root, require_prepared=True)
                projection = report["carriers"]["lookup"]
                self.assertEqual((1, "inconclusive", "passed", "inconclusive"),
                                 (code, report["status"], report["target_status"], report["lookup_evidence"]))
                self.assertEqual(self.record(), report["target"])
                self.assertEqual("observed", projection["status"])
                self.assertIs(projection["capsule_complete"], True)
                self.assertEqual(records[1:], projection["records"][1:])

    def test_lookup_parse_refusal_and_read_error_preserve_child_pass_without_success(self):
        lookup = WindowsShellLookupDiagnosticTests()
        valid = lookup.encode(lookup.v2_records())
        for name, data, error in (
            ("malformed", b"{bad\n", "invalid-json"),
            ("duplicate-version-in-five-record-header", valid.replace(b'"v":2', b'"v":2,"v":2', 1), "record-count"),
            ("duplicate-nested", valid.replace(b'"not_found":{"status":"armed"}',
                                              b'"not_found":{"status":"armed","status":"armed"}'), "duplicate-json-key"),
            ("partial-line", valid[:-1], "partial-line"),
            ("record-shape", valid.replace(b'"ms":15', b'"ms":15,"private":"' + MARKER.encode() + b'"'), "record-shape"),
            ("file-limit", b"x" * 8193, "file-limit"),
        ):
            with self.subTest(case=name), self.parent(lookup_data=data) as (root, _, _, _):
                code, report = self.invoke(root, require_prepared=True)
                self.assertEqual((1, "failed", "passed", "refused"),
                                 (code, report["status"], report["target_status"], report["lookup_evidence"]))
                self.assertEqual(self.record(), report["target"])
                self.assertEqual(error, report["carriers"]["lookup"]["code"])
                self.assertNotIn("records", report["carriers"]["lookup"])
        with self.parent(lookup_data=valid) as (root, _, _, _):
            original = qualification.diagnostic_bytes

            def read(path, relative, limit):
                if relative == qualification.LOOKUP:
                    raise PermissionError(MARKER)
                return original(path, relative, limit)

            with mock.patch.object(qualification, "diagnostic_bytes", side_effect=read):
                code, report = self.invoke(root, require_prepared=True)
                projection = json.loads(qualification.lookup_diagnostic_json(root, "absent"))
            self.assertEqual((1, "failed", "passed", "refused"),
                             (code, report["status"], report["target_status"], report["lookup_evidence"]))
            self.assertEqual(self.record(), report["target"])
            self.assertEqual(projection, report["carriers"]["lookup"])
            self.assertEqual(("unavailable", "read-error"), (projection["status"], projection["code"]))

    def test_lookup_evidence_never_supersedes_real_child_or_owner_failures(self):
        lookup = WindowsShellLookupDiagnosticTests()
        for evidence, data in (("inconclusive", lookup.encode(lookup.v2_records()[:4])),
                               ("complete-observed", lookup.encode(lookup.v2_records()))):
            for outcome in ("failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses"):
                exception = qualification.shell_focus_exception(AssertionError(MARKER), self.fixture.budget())
                result = self.result(1, **{
                    outcome: 1, "exception": exception if outcome in ("failures", "errors") else None,
                })
                with self.subTest(case=f"child-{outcome}-{evidence}"), \
                        self.parent(result, lookup_data=data) as (root, _, _, _):
                    code, report = self.invoke(root, require_prepared=True)
                    self.assertEqual((1, "failed", "failed", evidence),
                                     (code, report["status"], report["target_status"], report["lookup_evidence"]))
                    self.assertEqual(json.loads(result.stdout), report["target"])
            for fault in ("output", "timeout"):
                with self.subTest(case=f"owner-{fault}-{evidence}"), \
                        self.parent(lookup_data=data) as (root, budget, _, _):
                    run = budget.run.side_effect
                    error = budget.OutputExceeded() if fault == "output" else budget.BudgetExceeded()

                    def fail(*args, **kwargs):
                        run(*args, **kwargs)
                        raise error

                    budget.run.side_effect = fail
                    code, report = self.invoke(root, require_prepared=True)
                    self.assertEqual((1, "failed", "unavailable", evidence),
                                     (code, report["status"], report["target_status"], report["lookup_evidence"]))
                    self.assertIsNone(report["target"])
                    self.assertEqual("output-budget-exceeded" if fault == "output" else "work-budget-exceeded",
                                     report["error"]["kind"])

    def test_output_projection_rejects_raw_oversized_duplicate_or_nonexact_child_output(self):
        original = self.result()
        outputs = (
            MARKER.encode(), b"x" * 4097 + b"\n", original.stdout * 2,
            original.stdout.replace(b'"tests_run":1', b'"tests_run":1,"tests_run":1'),
            original.stdout[:-1], original.stdout + b"\x1b", b'{"v":true}\n',
        )
        for output in outputs:
            result = subprocess.CompletedProcess([], 0, output, b"")
            with self.subTest(size=len(output)), self.parent(result) as (root, _, _, _):
                code, report = self.invoke(root, require_prepared=True)
                self.assertEqual(1, code)
                self.assertEqual("failed", report["status"])
                self.assertEqual("unavailable", report["target_status"])
                self.assertIsNone(report["target"])
                self.assertEqual("helper-settled", report["owner_release"])
        with self.parent(subprocess.CompletedProcess([], 0, original.stdout, MARKER.encode())) as (root, _, _, _):
            code, report = self.invoke(root, require_prepared=True)
            self.assertEqual(1, code)
            self.assertEqual("failed", report["status"])
            self.assertEqual("unavailable", report["target_status"])
            self.assertIsNone(report["target"])

    def test_output_then_work_exception_and_cleanup_supersession_keep_real_unknown_settlement(self):
        for fault in ("output", "timeout", "assignment", "capture", "cleanup", "interrupt"):
            with self.subTest(fault=fault), self.parent() as (root, budget, _, _):
                error = budget.OutputExceeded() if fault == "output" else (
                    budget.BudgetExceeded() if fault == "timeout" else
                    KeyboardInterrupt(MARKER) if fault == "interrupt" else OSError(MARKER))
                if fault == "cleanup":
                    error.__cause__ = budget.OutputExceeded()
                budget.run.side_effect = error
                with mock.patch.object(qualification, "diagnostic_bytes", side_effect=FileNotFoundError) as reader:
                    code, report = self.invoke(root, require_prepared=True)
                self.assertEqual(1, code)
                self.assertIsNone(report["target"])
                self.assertEqual("unavailable", report["error"]["capture"]["status"])
                self.assertIsNone(report["error"]["capture_from_chain_index"])
                self.assertEqual("helper-settled" if fault in ("output", "timeout") else "unconfirmed",
                                 report["owner_release"])
                if fault not in ("output", "timeout"):
                    reader.assert_not_called()
                    self.assertIsNone(report["carriers"])
                    self.assertEqual("unavailable", report["lookup_evidence"])
                self.assertEqual("output-budget-exceeded" if fault == "output" else (
                    "work-budget-exceeded" if fault == "timeout" else
                    "unexpected-error" if fault == "interrupt" else "process-capture-or-cleanup-error"),
                    report["error"]["kind"])
                if fault == "cleanup":
                    self.assertEqual(["process-capture-or-cleanup-error", "output-budget-exceeded"],
                                     report["error"]["chain"])

    def test_available_capture_cause_is_preserved_without_raw_messages_and_cycles_are_bounded(self):
        budget = self.fixture.budget()
        capture = {"schema": "pennilogic.process-budget-capture-state/1", "status": "observed", "scope": "snapshot",
                   "complete": False, "mode": "separate",
                   "stdout": {"bytes": 1, "sha256": hashlib.sha256(b"x").hexdigest()},
                   "stderr": {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}}
        budget.capture_observation.return_value = "process_budget_capture_state=" + json.dumps(
            capture, sort_keys=True, separators=(",", ":"))
        primary = budget.BudgetExceeded()
        error = OSError(MARKER)
        error.__context__ = primary
        projected = qualification.shell_focus_exception(error, budget)
        qualification.shell_focus_exception_shape(projected)
        self.assertEqual(capture, projected["capture"])
        self.assertEqual(1, projected["capture_from_chain_index"])
        primary.__cause__ = error
        projected = qualification.shell_focus_exception(error, budget)
        self.assertEqual(2, len(projected["chain"]))
        self.assertIs(projected["chain_truncated"], True)
        self.assertNotIn(MARKER, json.dumps(projected))
        for mutate in (
            lambda v: v.update(kind=MARKER),
            lambda v: v.update(code=MARKER),
            lambda v: v.update(chain=[MARKER]),
            lambda v: v.update(capture={"raw": MARKER}),
            lambda v: v.update(capture_from_chain_index=0),
            lambda v: v.update(capture_from_chain_index=True),
        ):
            value = copy.deepcopy(projected)
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                qualification.shell_focus_exception_shape(value)

    def test_fresh_output_area_refuses_all_existing_objects_without_deleting_anything(self):
        for kind in ("directory", "file"):
            with self.subTest(kind=kind), self.parent() as (root, budget, _, _):
                path = root / "build" / "diagnostics"
                if kind == "directory":
                    path.mkdir()
                    marker = path / "required-suite-evidence"
                    marker.write_text(MARKER)
                else:
                    marker = path
                    path.write_text(MARKER)
                code, report = self.invoke(root, require_prepared=True)
                self.assertEqual(1, code)
                self.assertEqual("not-started", report["owner_release"])
                self.assertIsNone(report["owned_call_elapsed_ns"])
                self.assertEqual(MARKER, marker.read_text())
                budget.run.assert_not_called()
        with self.parent() as (root, budget, _, _):
            real = Path.lstat

            def reparse(path, *args, **options):
                value = real(path, *args, **options)
                return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=0x400) if path == root / "build" else value

            with mock.patch.object(Path, "lstat", autospec=True, side_effect=reparse):
                code, _ = self.invoke(root, require_prepared=True)
            self.assertEqual(1, code)
            budget.run.assert_not_called()

    def test_missing_preparation_and_wrong_helper_fail_before_any_owner_call(self):
        with self.parent() as (root, budget, _, _):
            code, report = self.invoke(root)
            self.assertEqual(1, code)
            self.assertEqual("not-started", report["owner_release"])
            self.assertEqual("focus-requires-prepared", report["error"]["code"])
            budget.run.assert_not_called()
        with tempfile.TemporaryDirectory(prefix="focus-pinned-source-") as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "scripts" / "process_budget.py").write_text("raise RuntimeError('must not import')")
            with self.assertRaisesRegex(ValueError, "observer-budget-source"):
                qualification.observer_budget_module(root)
        self.assertEqual((33441, "eca36677c55d7addb00660532fd1aafa4343db752bb014641c667530ada83525"),
                         qualification.SHELL_FOCUS_SOURCES["scripts/process_budget.py"])
        self.assertEqual(4, len(qualification.SHELL_FOCUS_SOURCES))
        self.assertIsNone(qualification.shell_focus_exception(qualification.Refused(MARKER), None)["code"])

    def test_common_and_focus_pins_agree_with_exact_reviewed_source_closure(self):
        expected = {
            "scripts/tests/test_money_mutation.py": (248547, "987aeb75eb219d2cd5a927f89eb84a0e2f9c67f834ab419f45a8d02d383f390e"),
            "scripts/money_mutation.py": (24847, "b4e9ca3218d16af605537714b365962d94f40265d092bb5302538e7efb7de000"),
            "scripts/quality.py": (33687, "725fac94b7c4496a265260503f5492acdc28d45e7690254f1328e596a11b42cd"),
            "scripts/process_budget.py": (33441, "eca36677c55d7addb00660532fd1aafa4343db752bb014641c667530ada83525"),
        }
        self.assertEqual(expected, qualification.SHELL_FOCUS_SOURCES)
        self.assertEqual(expected["scripts/process_budget.py"],
                         (qualification.OBSERVER_BUDGET_BYTES, qualification.OBSERVER_BUDGET_SHA256))

    def test_common_loader_refuses_obsolete_sizes_and_modified_bytes_before_import(self):
        size = qualification.OBSERVER_BUDGET_BYTES
        with tempfile.TemporaryDirectory(prefix="observer-pinned-source-") as temporary:
            root = Path(temporary)
            path = root / "scripts" / "process_budget.py"
            path.parent.mkdir()
            prefix = b"raise AssertionError('unverified helper must not import')\n"
            for label, length in (("obsolete", 30820), ("short", size - 1),
                                  ("same-size-mismatch", size), ("oversize", size + 1)):
                with self.subTest(case=label), mock.patch.object(qualification, "ModuleType") as module:
                    path.write_bytes(prefix + b" " * (length - len(prefix)))
                    with self.assertRaisesRegex(ValueError, "observer-budget-source"):
                        qualification.observer_budget_module(root)
                    module.assert_not_called()

    def test_focus_source_reader_refuses_obsolete_or_modified_mutation_bytes(self):
        name = "scripts/tests/test_money_mutation.py"
        size, _ = qualification.SHELL_FOCUS_SOURCES[name]
        with tempfile.TemporaryDirectory(prefix="focus-pinned-mutation-") as temporary:
            root = Path(temporary)
            path = root / name
            path.parent.mkdir(parents=True)
            prefix = b"raise AssertionError('source reader must not execute the target')\n"
            for label, length in (("obsolete", 235983), ("short", size - 1),
                                  ("same-size-mismatch", size), ("oversize", size + 1)):
                with self.subTest(case=label):
                    path.write_bytes(prefix + b" " * (length - len(prefix)))
                    with self.assertRaisesRegex(ValueError, "focus-source-binding"):
                        qualification.shell_focus_sources(root)

    def test_source_closure_is_exact_and_fixed_child_binds_controller_without_execution(self):
        with tempfile.TemporaryDirectory(prefix="focus-synthetic-source-") as temporary:
            root = Path(temporary)
            path = root / "scripts" / "qualify_windows.py"
            path.parent.mkdir()
            data = b"raise RuntimeError('synthetic controller, never execute')\n"
            path.write_bytes(data)
            temporary = root / "private-temp"
            temporary.mkdir()
            command = qualification.shell_focus_command(root, {"TEMP": str(temporary)})
            self.assertEqual([sys.executable, "-I", "-S", "-B", "-X"], command[:5])
            self.assertEqual(["pycache_prefix=" + str(temporary / "api106-python-cache"), "-c"], command[5:7])
            self.assertEqual(8, len(command))
            self.assertIn(hashlib.sha256(data).hexdigest(), command[-1])
            self.assertIn("n['shell_focus_child'](p.parents[1])", command[-1])
            self.assertNotIn("powershell.exe", command[-1])
            self.assertEqual([], list((temporary / "api106-python-cache").iterdir()))
            with self.assertRaises(FileExistsError):
                qualification.shell_focus_command(root, {"TEMP": str(temporary)})
            pins = {"scripts/qualify_windows.py": (len(data), hashlib.sha256(data).hexdigest())}
            with mock.patch.object(qualification, "SHELL_FOCUS_SOURCES", pins):
                self.assertEqual({"scripts/qualify_windows.py": {
                    "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}}, qualification.shell_focus_sources(root))
                path.write_bytes(data.replace(b"never", b"NEVER"))
                with self.assertRaisesRegex(ValueError, "focus-source-binding"):
                    qualification.shell_focus_sources(root)

    def test_child_runs_one_synthetic_original_identity_first_and_keeps_seam_none(self):
        calls = []

        def only(case):
            calls.append(case.id())

        name = qualification.SHELL_FOCUS_TARGET.rsplit(".", 1)[1]
        case = type("ProcessBudgetTest", (unittest.TestCase,), {"__module__": "test_money_mutation", name: only})
        module = SimpleNamespace(ProcessBudgetTest=case, APPROVED_SHELL_PAIR_ENCLOSURE=None,
                                 process_budget=self.fixture.budget())
        raw = io.BytesIO()
        output = io.TextIOWrapper(raw, encoding="ascii", newline="\r\n", write_through=True)
        with mock.patch.object(qualification, "shell_focus_module", return_value=module), \
                mock.patch.object(qualification, "shell_focus_sources"), contextlib.redirect_stdout(output):
            self.assertEqual(0, qualification.shell_focus_child(Path("synthetic-only")))
        self.assertEqual([qualification.SHELL_FOCUS_TARGET], calls)
        self.assertNotIn(b"\r", raw.getvalue())
        record, passed = qualification.shell_focus_result(subprocess.CompletedProcess(
            [], 0, raw.getvalue(), b""))
        output.close()
        self.assertTrue(passed)
        self.assertEqual(1, record["tests_run"])
        for count in (0, 2):
            with self.subTest(count=count), mock.patch.object(qualification, "shell_focus_module", return_value=module), \
                    mock.patch.object(unittest.TestLoader, "loadTestsFromName",
                                      return_value=unittest.TestSuite([case(name) for _ in range(count)])):
                with self.assertRaisesRegex(ValueError, "focus-target-count"):
                    qualification.shell_focus_child(Path("synthetic-only"))

    def test_original_module_import_and_seam_are_verified_without_running_the_api_target(self):
        with tempfile.TemporaryDirectory(prefix="focus-inert-import-") as temporary:
            root = Path(temporary)

            def module():
                value = ModuleType("test_money_mutation")
                value.__file__ = str(root / "scripts" / "tests" / "test_money_mutation.py")
                value.SCRIPTS, value.APPROVED_SHELL_PAIR_ENCLOSURE = root / "scripts", None
                for name, relative in (("mutation", "money_mutation.py"), ("quality", "quality.py"),
                                       ("process_budget", "process_budget.py")):
                    setattr(value, name, SimpleNamespace(__file__=str(root / "scripts" / relative)))
                return value

            for mutation in (None, "seam", "identity", "scripts", "import"):
                value = module()
                if mutation == "seam":
                    value.APPROVED_SHELL_PAIR_ENCLOSURE = mock.Mock()
                elif mutation == "identity":
                    value.__name__ = "wrong_module"
                elif mutation == "scripts":
                    value.SCRIPTS = root
                elif mutation == "import":
                    value.quality.__file__ = str(root / "other.py")
                spec = mock.Mock(name="inert_spec")
                spec.name = "test_money_mutation"
                with self.subTest(mutation=mutation), mock.patch.dict(sys.modules, {}, clear=False), \
                        mock.patch.object(qualification, "shell_focus_sources"), \
                        mock.patch.object(importlib.util, "spec_from_file_location", return_value=spec), \
                        mock.patch.object(importlib.util, "module_from_spec", return_value=value):
                    sys.modules.pop("test_money_mutation", None)
                    if mutation is None:
                        self.assertIs(value, qualification.shell_focus_module(root))
                        with self.assertRaisesRegex(ValueError, "focus-preexisting-test-module"):
                            qualification.shell_focus_module(root)
                    else:
                        with self.assertRaises(ValueError):
                            qualification.shell_focus_module(root)

    def test_focus_runtime_requires_observed_patch_and_its_own_manual_job_identity(self):
        for fault in (None, "vs2026-image", "job", "event", "selection", "observed-version", "selected-version", "image"):
            with self.subTest(fault=fault), self.fixture.runtime_fixture() as (root, budget, environment):
                environment.update(GITHUB_JOB="api106-shell-focus", PENNILOGIC_API106_SHELL_FOCUS="true",
                                   PENNILOGIC_API106_PYTHON_VERSION="3.14.8", ImageOS="win25", ImageVersion="20261012.1.0")
                if fault == "vs2026-image":
                    environment["ImageOS"] = "win25-vs2026"
                if fault in ("job", "event", "selection", "selected-version", "image"):
                    field, value = {
                        "job": ("GITHUB_JOB", "windows"), "event": ("GITHUB_EVENT_NAME", "push"),
                        "selection": ("PENNILOGIC_API106_SHELL_FOCUS", "True"),
                        "selected-version": ("PENNILOGIC_API106_PYTHON_VERSION", "3.14.3"),
                        "image": ("ImageVersion", MARKER),
                    }[fault]
                    environment[field] = value
                selected = {"python": environment["PENNILOGIC_API106_PYTHON"],
                            "git": environment["PENNILOGIC_API106_GIT"],
                            "java": str(Path(environment["JAVA_HOME"]) / "bin" / "java.exe")}
                budget.resolve_command.side_effect = lambda command, unused: [selected[command[0]]]
                with mock.patch.dict(qualification.os.environ, environment, clear=True), \
                        mock.patch.object(qualification.sys, "version_info", (3, 14, 3) if fault == "observed-version" else (3, 14, 8)):
                    if fault not in (None, "vs2026-image"):
                        with self.assertRaises(ValueError):
                            qualification.shell_focus_runtime(root, budget)
                        continue
                    _, report = qualification.shell_focus_runtime(root, budget)
                    self.assertEqual("3.14.8", report["python_version"])
                    self.assertEqual("runner-metadata-only", report["image_evidence"])
                    self.assertEqual({"python", "cmd", "powershell"}, set(report["images"]))
                    self.assertEqual("unavailable", report["historical_image_equivalence"])
                    self.assertEqual("not-claimed", report["whole_checkout_equivalence"])
                    self.assertNotIn(str(root), json.dumps(report))
                    self.assertNotIn(environment["PENNILOGIC_API106_PYTHON"], json.dumps(report))
                    with self.assertRaisesRegex(ValueError, "observer-job-context"):
                        qualification.observer_context(root)
                    with self.assertRaises(FileExistsError):
                        qualification.shell_focus_runtime(root, budget)
                    self.assertEqual(1, len(list(Path(environment["RUNNER_TEMP"]).glob("api106-shell-focus-*"))))

    def test_fixed_cli_is_mutually_exclusive_and_cannot_enter_required_or_pair_routes(self):
        with mock.patch.object(qualification.sys, "platform", "win32"), \
                mock.patch.object(qualification, "shell_focus", return_value=1) as focus, \
                mock.patch.object(qualification, "qualify") as ordinary, \
                mock.patch.object(qualification, "collect_observer_diagnostics") as pair, \
                mock.patch.object(qualification.sys, "argv", ["qualify_windows.py", "--require-prepared", "--api106-shell-focus"]):
            self.assertEqual(1, qualification.main())
            focus.assert_called_once_with(qualification.ROOT, require_prepared=True)
            ordinary.assert_not_called()
            pair.assert_not_called()
        for option in ("--api106-observer-pair", "--collect-api106-observer-pair", "--tests", "--budget"):
            with self.subTest(option=option), mock.patch.object(qualification.sys, "argv", [
                "qualify_windows.py", "--api106-shell-focus", option,
            ]), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                qualification.main()
            self.assertEqual(2, error.exception.code)

    def test_full_focus_projection_preserves_bounded_lookup_without_admitting_bad_carriers(self):
        lookup = WindowsShellLookupDiagnosticTests()
        records = lookup.v2_records()
        records[0]["roots"] = [
            {"i": index, "kind": "unknown", "sha256": hashlib.sha256(str(index).encode("ascii")).hexdigest(),
             "duplicate_of": None} for index in range(32)
        ]
        records[2]["ms"], records[3]["ms"] = 100000, 600000
        records[4].update(ms=600000, lookup_ms=500000, command_type=256)
        for data, expected in ((lookup.encode(records), 0), (MARKER.encode(), 1)):
            with self.subTest(valid=expected == 0), self.parent() as (root, budget, _, _):
                run = budget.run.side_effect

                def completion(*args, **kwargs):
                    result = run(*args, **kwargs)
                    lookup.write_capsule(root, data)
                    return result

                budget.run.side_effect = completion
                code, report = self.invoke(root, require_prepared=True)
                self.assertEqual(expected, code)
                if expected == 0:
                    self.assertEqual(32, len(report["carriers"]["lookup"]["records"][0]["roots"]))
                    self.assertEqual("observed", report["carriers"]["lookup"]["status"])
                else:
                    self.assertEqual("refused", report["carriers"]["lookup"]["status"])
                    self.assertNotIn("records", report["carriers"]["lookup"])

    def test_synthetic_child_failures_errors_skips_and_expected_outcomes_never_return_zero(self):
        for outcome in ("failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses"):
            def body(case):
                if outcome in ("failures", "expectedFailures"):
                    case.fail(MARKER)
                elif outcome == "errors":
                    raise OSError(MARKER)
                elif outcome == "skipped":
                    raise unittest.SkipTest(MARKER)

            if outcome in ("expectedFailures", "unexpectedSuccesses"):
                body = unittest.expectedFailure(body)
            name = qualification.SHELL_FOCUS_TARGET.rsplit(".", 1)[1]
            case = type("ProcessBudgetTest", (unittest.TestCase,), {"__module__": "test_money_mutation", name: body})
            module = SimpleNamespace(ProcessBudgetTest=case, APPROVED_SHELL_PAIR_ENCLOSURE=None,
                                     process_budget=self.fixture.budget())
            raw = io.BytesIO()
            with self.subTest(outcome=outcome), mock.patch.object(qualification, "shell_focus_module", return_value=module), \
                    mock.patch.object(qualification, "shell_focus_sources"), \
                    mock.patch.object(qualification.sys, "stdout", SimpleNamespace(buffer=raw)):
                self.assertEqual(1, qualification.shell_focus_child(Path("synthetic-only")))
            self.assertNotIn(MARKER.encode(), raw.getvalue())
            record, passed = qualification.shell_focus_result(subprocess.CompletedProcess([], 1, raw.getvalue(), b""))
            self.assertFalse(passed)
            self.assertEqual(1, record[outcome])
            self.assertEqual(1, record["tests_run"])

    def test_child_record_short_write_and_flush_failure_cannot_return_a_passing_result(self):
        name = qualification.SHELL_FOCUS_TARGET.rsplit(".", 1)[1]
        case = type("ProcessBudgetTest", (unittest.TestCase,), {
            "__module__": "test_money_mutation", name: lambda unused: None,
        })
        module = SimpleNamespace(ProcessBudgetTest=case, APPROVED_SHELL_PAIR_ENCLOSURE=None,
                                 process_budget=self.fixture.budget())
        for fault in ("short-write", "flush"):
            output = mock.Mock()
            output.write.side_effect = (lambda data: len(data) - 1) if fault == "short-write" else len
            if fault == "flush":
                output.flush.side_effect = OSError(MARKER)
            with self.subTest(fault=fault), mock.patch.object(qualification, "shell_focus_module", return_value=module), \
                    mock.patch.object(qualification, "shell_focus_sources"), \
                    mock.patch.object(qualification.sys, "stdout", SimpleNamespace(buffer=output)), \
                    self.assertRaises((ValueError, OSError)):
                qualification.shell_focus_child(Path("synthetic-only"))
            data, = output.write.call_args.args
            self.assertLessEqual(len(data), 4096)
            self.assertTrue(data.endswith(b"\n"))
            self.assertNotIn(b"\r", data)
            self.assertNotIn(MARKER.encode(), data)


class WindowsShellControlTests(unittest.TestCase):
    def setUp(self):
        use_physical_interpreter(self)
        spawn = mock.patch.object(subprocess, "Popen", side_effect=AssertionError("No live shell in source controls"))
        spawn.start()
        self.addCleanup(spawn.stop)
        self.focus = WindowsShellFocusTests()
        self.focus.fixture = WindowsObserverPairDiagnosticTests()
        self.addCleanup(self.focus.fixture.doCleanups)

    def test_runtime_path_refuses_a_link_and_accepts_the_resolved_interpreter(self):
        physical = Path(os.path.realpath(sys.executable))
        self.assertEqual(physical, qualification.observer_runtime_path(str(physical), directory=False))
        self.assertEqual(str(physical), sys.executable)
        with tempfile.TemporaryDirectory(prefix="observer-interpreter-link-") as temporary:
            link = Path(temporary) / physical.name
            try:
                link.symlink_to(physical)
            except (OSError, NotImplementedError):
                self.skipTest("Symbolic links are unavailable on this host")
            with self.assertRaisesRegex(qualification.Refused, "observer-runtime-path"):
                qualification.observer_runtime_path(str(link), directory=False)

    def environment_records(self, environment, *, roots=None):
        modules = str(Path(environment["COMSPEC"]).parent / "WindowsPowerShell" / "v1.0" / "Modules")
        hashed = hashlib.sha256(qualification.shell_focus_module_root_normalized(modules).encode("utf-8")).hexdigest()
        return [{"v": 1, "phase": "pre", "status": "observed", "injected_sha256": hashed,
                 "value": "present", "roots": [[0, "injected", hashed, None]] if roots is None else roots},
                {"v": 1, "phase": "post", "status": "observed"}]

    def write_environment(self, root, environment, *, records=None, tail=b""):
        if records is None:
            records = self.environment_records(environment)
        data = b"".join(json.dumps(row, separators=(",", ":")).encode("ascii") + b"\n" for row in records)
        (root / qualification.SHELL_FOCUS_ENVIRONMENT_CARRIER).write_bytes(data + tail)

    @contextlib.contextmanager
    def fixture(self, *, baseline=None, lookup_data=None):
        lookup = WindowsShellLookupDiagnosticTests()
        if lookup_data is None:
            lookup_data = lookup.encode(lookup.v2_records())
        with self.focus.parent(baseline, lookup_data=lookup_data, controls=True) as (root, budget, command, supplied):
            (root / "scripts").mkdir()
            supplied.update(budget.environment.return_value)
            environment = dict(supplied)
            budget.environment.return_value = environment
            shell = Path(environment["COMSPEC"]).parent / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            manifest = shell.parent / "Modules" / "Microsoft.PowerShell.Utility" / "Microsoft.PowerShell.Utility.psd1"
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes(b"@{ ModuleVersion = '3.1.0.0' }\n")
            runtime = {"context_sha256": "a" * 64, "images": {"powershell": {
                "bytes": shell.stat().st_size, "sha256": hashlib.sha256(shell.read_bytes()).hexdigest(),
            }, "python": {
                "bytes": Path(sys.executable).stat().st_size,
                "sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
            }}}
            qualification.shell_focus_runtime.return_value = (supplied, runtime)
            budget.resolve_command.side_effect = lambda argv, env: [str(shell)]
            baseline_run = budget.run.side_effect

            def run(argv, cwd, seconds, **options):
                if seconds == 150:
                    return baseline_run(argv, cwd, seconds, **options)
                if argv[0] == sys.executable:
                    self.write_environment(root, environment)
                return subprocess.CompletedProcess(argv, 0, "approved-shell\r\n", None)

            budget.run.side_effect = run
            yield SimpleNamespace(root=root, budget=budget, supplied=supplied, environment=environment,
                                  runtime=runtime, shell=shell, manifest=manifest, baseline_command=command)

    def invoke(self, fixture, *, require_prepared=True):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = qualification.shell_focus(fixture.root, require_prepared=require_prepared)
        lines = output.getvalue().splitlines()
        self.assertEqual(2, len(lines))
        baseline, controls = map(json.loads, lines)
        self.assertLessEqual(len(lines[0].encode("ascii")) + len(os.linesep), 16384)
        self.assertLessEqual(len(lines[1].encode("ascii")) + len(os.linesep), 8192)
        self.assertEqual("windows_shell_focus", baseline["event"])
        self.assertEqual("windows_shell_focus_controls", controls["event"])
        self.assertEqual({
            "v", "event", "diagnostic_only", "acceptance", "native_qualification", "physical_cleanup_attestation",
            "status", "baseline_status", "baseline_owner_release", "work_seconds", "single_cleanup_seconds",
            "hard_end_to_end_deadline", "synchronous_calls_preempted", "inherit_tree", "interval_scope",
            "stage_scope", "comparison", "blocked_by", "error", "controls",
        }, set(controls))
        self.assertEqual(list(qualification.SHELL_FOCUS_CONTROLS), [item["label"] for item in controls["controls"]])
        for item in controls["controls"]:
            self.assertEqual({
                "label", "outcome", "phase", "owner_release", "owned_call_elapsed_ns", "returncode",
                "capture", "module", "error", "process_boundary", "environment",
            }, set(item))
        self.assertIs(controls["diagnostic_only"], True)
        for field in ("acceptance", "native_qualification", "physical_cleanup_attestation",
                      "hard_end_to_end_deadline", "synchronous_calls_preempted"):
            self.assertIs(controls[field], False)
        for private in (MARKER, str(fixture.root), str(fixture.shell), str(fixture.manifest), "Traceback"):
            self.assertNotIn(private, output.getvalue())
        return code, baseline, controls

    def test_fixed_absolute_commands_use_only_the_approved_shell_builtin_and_no_lookup_hooks(self):
        with self.fixture() as fixture:
            first, module = qualification.shell_focus_control_command(
                fixture.environment, fixture.runtime, "plain-bare-command")
            self.assertEqual([str(fixture.shell), "-NoProfile", "-NonInteractive", "-Command",
                              "Write-Output 'approved-shell'"], first)
            self.assertIsNone(module)
            with mock.patch.object(qualification, "observer_runtime_bytes",
                                   wraps=qualification.observer_runtime_bytes) as reader:
                second, module = qualification.shell_focus_control_command(
                    fixture.environment, fixture.runtime, "explicit-built-in-utility")
            reader.assert_called_once_with(fixture.shell, 32 * 1024 * 1024)
            self.assertEqual(first[:-1], second[:-1])
            self.assertEqual(
                "if ($PSHOME -ine '" + str(fixture.shell.parent) + "') { exit 1 }; Import-Module -Name '"
                + str(fixture.manifest) + "' -ErrorAction Stop; Write-Output 'approved-shell'", second[-1])
            self.assertEqual({"bytes": fixture.manifest.stat().st_size,
                              "evidence": "metadata-only-no-content-read"}, module)
            for forbidden in ("ExecutionPolicy", "PSModulePath", "CommandNotFoundAction",
                              "PreCommandLookupAction", "PostCommandLookupAction", "pennilogicLookup", "-Force"):
                self.assertNotIn(forbidden, " ".join(first + second))
            fixture.budget.run.assert_not_called()
            with self.assertRaisesRegex(ValueError, "focus-control-result"):
                qualification.shell_focus_control_command(fixture.environment, fixture.runtime, MARKER)

    def test_original_first_only_record_precedes_three_serial_merged_ten_second_controls(self):
        with self.fixture() as fixture, mock.patch.object(qualification.time, "monotonic_ns",
                                                         side_effect=(10, 30, 40, 80, 90, 150, 160, 240)):
            output = io.StringIO()
            run = fixture.budget.run.side_effect

            def observe(*args, **options):
                if args[2] == 10:
                    prior = [json.loads(line) for line in output.getvalue().splitlines()]
                    self.assertEqual(["windows_shell_focus"], [item["event"] for item in prior])
                    self.assertEqual("helper-settled", prior[0]["owner_release"])
                    self.assertEqual(1, prior[0]["target"]["tests_run"])
                return run(*args, **options)

            fixture.budget.run.side_effect = observe
            with contextlib.redirect_stdout(output):
                self.assertEqual(0, qualification.shell_focus(fixture.root, require_prepared=True))
            baseline, controls = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(qualification.SHELL_FOCUS_TARGET, baseline["target"]["target"])
            self.assertEqual(20, baseline["owned_call_elapsed_ns"])
            self.assertEqual([40, 60, 80], [record["owned_call_elapsed_ns"] for record in controls["controls"]])
            self.assertEqual([150, 10, 10, 10], [call.args[2] for call in fixture.budget.run.call_args_list])
            self.assertEqual(["plain-bare-command", "os-module-root-environment", "explicit-built-in-utility"],
                             [record["label"] for record in controls["controls"]])
            self.assertEqual(mock.call(fixture.baseline_command, fixture.root, 150, capture=True,
                                       separate=True, env=fixture.supplied), fixture.budget.run.call_args_list[0])
            for call, label in zip(fixture.budget.run.call_args_list[1:], qualification.SHELL_FOCUS_CONTROLS, strict=True):
                command, _ = qualification.shell_focus_control_command(fixture.environment, fixture.runtime, label)
                self.assertEqual(mock.call(command, fixture.root / "scripts", 10, capture=True,
                                           env=fixture.environment), call)
            fixture.budget.environment.assert_called_once_with(supplied=fixture.supplied)
            self.assertEqual((150, 10), (baseline["work_seconds"], baseline["single_cleanup_seconds"]))
            self.assertEqual((10, 10), (controls["work_seconds"], controls["single_cleanup_seconds"]))
            self.assertEqual(b"ES111CX", (fixture.root / qualification.OBSERVER_FILES["required-boundary"][0]).read_bytes())
            self.assertEqual([fixture.root / qualification.SHELL_FOCUS_ENVIRONMENT_CARRIER],
                             list((fixture.root / qualification.SHELL_FOCUS_CONTROL_DIRECTORY).iterdir()))
            self.assertEqual("passed", controls["status"])
            self.assertNotIn("tests_run", json.dumps(controls))

    def test_passing_controls_cannot_erase_a_nested_baseline_failure_or_incomplete_lookup(self):
        exception = {"kind": "work-budget-exceeded", "code": None, "chain": ["work-budget-exceeded"],
                     "chain_truncated": False, "capture": dict(qualification.PROCESS_BUDGET_CAPTURE_UNAVAILABLE),
                     "capture_from_chain_index": None}
        lookup = WindowsShellLookupDiagnosticTests()
        partial = lookup.encode(lookup.v2_records()[:3])
        for result, status in ((self.focus.result(1, errors=1, exception=exception), "failed"),
                               (self.focus.result(), "inconclusive")):
            with self.subTest(status=status), self.fixture(baseline=result, lookup_data=partial) as fixture:
                code, baseline, controls = self.invoke(fixture)
                self.assertEqual((1, status, "inconclusive"), (code, baseline["status"], baseline["lookup_evidence"]))
                self.assertEqual(json.loads(result.stdout), baseline["target"])
                self.assertIsNone(baseline["error"])
                self.assertEqual("passed", controls["status"])
                self.assertEqual(status, controls["baseline_status"])
                self.assertEqual(4, fixture.budget.run.call_count)

    def test_no_control_after_unstarted_or_unknown_baseline_even_with_a_budget_error_cause(self):
        for fault in ("admission", "creation", "owner", "capture", "cleanup", "interrupt"):
            with self.subTest(fault=fault), self.fixture() as fixture:
                if fault != "admission":
                    error = KeyboardInterrupt(MARKER) if fault == "interrupt" else OSError(MARKER)
                    if fault == "cleanup":
                        error.__cause__ = fixture.budget.BudgetExceeded()
                    fixture.budget.run.side_effect = error
                code, baseline, controls = self.invoke(fixture, require_prepared=fault != "admission")
                self.assertEqual(1, code)
                self.assertEqual("not-run", controls["status"])
                self.assertEqual("baseline-not-confirmed-settled", controls["blocked_by"])
                self.assertEqual(0 if fault == "admission" else 1, fixture.budget.run.call_count)
                fixture.budget.environment.assert_not_called()
                self.assertFalse((fixture.root / qualification.SHELL_FOCUS_CONTROL_DIRECTORY).exists())
                self.assertTrue(all(item["owned_call_elapsed_ns"] is None for item in controls["controls"]))
                self.assertNotEqual("helper-settled", baseline["owner_release"])

    def test_each_control_retains_negative_timeout_output_and_unknown_settlement_without_retry(self):
        for index in (0, 1, 2):
            for fault in ("exit", "empty", "timeout", "output", "creation", "capture", "cleanup", "interrupt"):
                with self.subTest(index=index, fault=fault), self.fixture() as fixture:
                    run, count = fixture.budget.run.side_effect, 0

                    def outcome(*args, **options):
                        nonlocal count
                        result = run(*args, **options)
                        if args[2] != 10:
                            return result
                        selected = count == index
                        count += 1
                        if not selected:
                            return result
                        if fault == "exit":
                            return subprocess.CompletedProcess(args[0], 37, MARKER + str(fixture.root), None)
                        if fault == "empty":
                            return subprocess.CompletedProcess(args[0], 0, "", None)
                        error = (fixture.budget.OutputExceeded() if fault == "output" else
                                 fixture.budget.BudgetExceeded() if fault == "timeout" else
                                 KeyboardInterrupt(MARKER) if fault == "interrupt" else OSError(MARKER))
                        if fault == "cleanup":
                            error.__cause__ = fixture.budget.BudgetExceeded()
                        raise error

                    fixture.budget.run.side_effect = outcome
                    with mock.patch.object(qualification, "shell_focus_environment_evidence",
                                           wraps=qualification.shell_focus_environment_evidence) as carrier_reader:
                        code, baseline, controls = self.invoke(fixture)
                    self.assertEqual((1, "passed", "failed"), (code, baseline["status"], controls["status"]))
                    record = controls["controls"][index]
                    known = fault in ("exit", "empty", "timeout", "output")
                    self.assertEqual(0 if not known and index <= 1 else 1, carrier_reader.call_count)
                    self.assertEqual("helper-settled" if known else "unconfirmed", record["owner_release"])
                    self.assertEqual(4 if known else index + 2, fixture.budget.run.call_count)
                    self.assertIsInstance(record["owned_call_elapsed_ns"], int)
                    self.assertGreaterEqual(record["owned_call_elapsed_ns"], 0)
                    expected = {"exit": "nonzero-exit", "empty": "unexpected-output",
                                "timeout": "work-budget-exceeded", "output": "output-budget-exceeded",
                                "interrupt": "unexpected-error"}.get(fault, "process-capture-or-cleanup-error")
                    self.assertEqual(expected, record["outcome"])
                    if fault == "cleanup":
                        self.assertEqual(["process-capture-or-cleanup-error", "work-budget-exceeded"],
                                         record["error"]["chain"])
                    if fault in ("timeout", "output", "cleanup"):
                        fixture.budget.capture_observation.assert_called_with({}, separate=False)
                    if not known:
                        self.assertTrue(all(row["outcome"] == "not-started" for row in controls["controls"][index + 1:]))
                    if not known and index == 1:
                        self.assertEqual({"status": "unavailable", "code": "owner-not-confirmed-settled",
                                          "pre": None, "post": None}, record["environment"])

    def test_settled_baseline_timeout_and_output_failure_still_allow_only_the_three_controls(self):
        for fault in ("timeout", "output"):
            with self.subTest(fault=fault), self.fixture() as fixture:
                run = fixture.budget.run.side_effect

                def fail_baseline(*args, **options):
                    result = run(*args, **options)
                    if args[2] == 150:
                        raise fixture.budget.BudgetExceeded() if fault == "timeout" else fixture.budget.OutputExceeded()
                    return result

                fixture.budget.run.side_effect = fail_baseline
                code, baseline, controls = self.invoke(fixture)
                self.assertEqual((1, "failed", "passed"), (code, baseline["status"], controls["status"]))
                self.assertEqual("helper-settled", baseline["owner_release"])
                self.assertIsNone(baseline["target"])
                self.assertEqual(4, fixture.budget.run.call_count)

    def test_malformed_merged_results_remain_refused_and_never_hide_a_valid_exit(self):
        results = (
            (True, "approved-shell", None), (None, "", None), (4294967296, "", None),
            (0, b"approved-shell", None), (0, None, None), (37, MARKER, b""),
            (0, "x" * (4 * 1024 * 1024 + 1), None), (0, "\ud800", None),
            (0, "\U0001f642" * (4 * 1024 * 1024), None),
        )
        for index, (exit_code, stdout, stderr) in enumerate(results):
            with self.subTest(index=index), self.fixture() as fixture:
                run = fixture.budget.run.side_effect

                def malformed(*args, **options):
                    result = run(*args, **options)
                    return result if args[2] == 150 else subprocess.CompletedProcess(args[0], exit_code, stdout, stderr)

                fixture.budget.run.side_effect = malformed
                code, _, controls = self.invoke(fixture)
                self.assertEqual((1, "failed"), (code, controls["status"]))
                self.assertEqual(4, fixture.budget.run.call_count)
                for record in controls["controls"]:
                    self.assertEqual("helper-settled", record["owner_release"])
                    self.assertEqual("result", record["phase"])
                    self.assertIsNotNone(record["error"])
                    self.assertEqual(exit_code if type(exit_code) is int and exit_code <= 4294967295 else None,
                                     record["returncode"])
                    self.assertEqual({"status": "unavailable"}, record["capture"])

    def test_capture_hashes_label_decoded_text_and_exception_snapshots_without_raw_streams(self):
        with self.fixture() as fixture:
            run = fixture.budget.run.side_effect
            text = MARKER + str(fixture.root) + "\ufffd\n"

            def negative(*args, **options):
                result = run(*args, **options)
                return result if args[2] == 150 else subprocess.CompletedProcess(args[0], 37, text, None)

            fixture.budget.run.side_effect = negative
            _, _, controls = self.invoke(fixture)
            self.assertTrue(all(record["capture"] == {
                "status": "observed", "scope": "decoded-merged-text", "text_bytes": len(text.encode("utf-8")),
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            } for record in controls["controls"]))
        for valid in (True, False):
            with self.subTest(valid=valid), self.fixture() as fixture:
                capture = {"schema": "pennilogic.process-budget-capture-state/1", "status": "observed",
                           "scope": "snapshot", "complete": False, "mode": "merged",
                           "stdout": {"bytes": 18446744073709551615, "sha256": "a" * 64},
                           "stderr": {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}}
                fixture.budget.capture_observation.return_value = (
                    "process_budget_capture_state=" + json.dumps(capture, sort_keys=True, separators=(",", ":"))
                    if valid else MARKER
                )
                run = fixture.budget.run.side_effect

                def timeout(*args, **options):
                    result = run(*args, **options)
                    if args[2] == 10:
                        raise fixture.budget.BudgetExceeded()
                    return result

                fixture.budget.run.side_effect = timeout
                _, _, controls = self.invoke(fixture)
                for record in controls["controls"]:
                    self.assertEqual(capture if valid else qualification.PROCESS_BUDGET_CAPTURE_UNAVAILABLE,
                                     record["error"]["capture"])
                    self.assertEqual(0 if valid else None, record["error"]["capture_from_chain_index"])
                    self.assertEqual("helper-settled", record["owner_release"])

    def test_exclusive_namespace_collision_and_spent_reentry_never_launch_or_reuse_an_arm(self):
        for kind in ("directory", "file"):
            with self.subTest(kind=kind), self.fixture() as fixture:
                run = fixture.budget.run.side_effect
                directory = fixture.root / qualification.SHELL_FOCUS_CONTROL_DIRECTORY
                marker = directory / "retain" if kind == "directory" else directory

                def collision(*args, **options):
                    result = run(*args, **options)
                    if kind == "directory":
                        directory.mkdir()
                    marker.write_text(MARKER)
                    return result

                fixture.budget.run.side_effect = collision
                code, baseline, controls = self.invoke(fixture)
                self.assertEqual((1, "passed", "failed"), (code, baseline["status"], controls["status"]))
                self.assertEqual(1, fixture.budget.run.call_count)
                self.assertEqual(MARKER, marker.read_text())
        with self.fixture() as fixture:
            _, baseline, _ = self.invoke(fixture)
            fixture.budget.run.reset_mock()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(qualification.shell_focus_controls(
                    fixture.root, fixture.budget, fixture.supplied, baseline))
            fixture.budget.run.assert_not_called()

    def test_source_context_shell_resolution_and_namespace_drift_block_further_controls(self):
        for fault in ("source", "context", "shell-image", "shell-selection", "namespace"):
            with self.subTest(fault=fault), self.fixture() as fixture:
                run = fixture.budget.run.side_effect

                def drift(*args, **options):
                    result = run(*args, **options)
                    if args[2] == 150 and fault == "shell-image":
                        fixture.runtime["images"]["powershell"]["sha256"] = "0" * 64
                    elif args[2] == 150 and fault == "shell-selection":
                        fixture.budget.resolve_command.side_effect = lambda argv, env: [str(fixture.root / "powershell.exe")]
                    elif args[2] == 10:
                        if fault == "source":
                            qualification.shell_focus_sources.side_effect = qualification.Refused("focus-source-binding")
                        elif fault == "context":
                            qualification.observer_context.return_value = "c" * 64
                        elif fault == "namespace":
                            moved = fixture.root / qualification.SHELL_FOCUS_CONTROL_DIRECTORY
                            moved.rename(moved.with_name(moved.name + "-retained"))
                            moved.mkdir()
                    return result

                fixture.budget.run.side_effect = drift
                code, baseline, controls = self.invoke(fixture)
                self.assertEqual((1, "passed", "failed"), (code, baseline["status"], controls["status"]))
                self.assertEqual(1 if fault.startswith("shell-") else 2, fixture.budget.run.call_count)
                self.assertEqual("not-started", controls["controls"][1]["outcome"])

    def test_builtin_is_literal_nonreparse_bounded_and_not_a_caller_module_search(self):
        for fault in ("missing", "directory", "empty", "oversized", "reparse"):
            with self.subTest(fault=fault), self.fixture() as fixture:
                if fault in ("missing", "directory"):
                    fixture.manifest.unlink()
                    if fault == "directory":
                        fixture.manifest.mkdir()
                elif fault == "empty":
                    fixture.manifest.write_bytes(b"")
                elif fault == "oversized":
                    fixture.manifest.write_bytes(b"x" * 65537)
                real = Path.lstat

                def metadata(path, *args, **options):
                    value = real(path, *args, **options)
                    if fault == "reparse" and path == fixture.manifest.parent:
                        return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=0x400)
                    return value

                with mock.patch.object(Path, "lstat", autospec=True, side_effect=metadata):
                    code, baseline, controls = self.invoke(fixture)
                self.assertEqual((1, "passed", "failed"), (code, baseline["status"], controls["status"]))
                self.assertEqual(3, fixture.budget.run.call_count)
                self.assertEqual("passed", controls["controls"][0]["outcome"])
                self.assertEqual("passed", controls["controls"][1]["outcome"])
                self.assertEqual("not-started", controls["controls"][2]["owner_release"])
                self.assertIsNone(controls["controls"][2]["owned_call_elapsed_ns"])
        for name in ("literal'root", "wild[card]"):
            with self.subTest(name=name), self.fixture() as fixture:
                system = Path(fixture.environment["COMSPEC"]).parent / name
                shell = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
                manifest = shell.parent / "Modules" / "Microsoft.PowerShell.Utility" / "Microsoft.PowerShell.Utility.psd1"
                manifest.parent.mkdir(parents=True)
                (system / "cmd.exe").write_bytes(b"inert")
                shell.write_bytes(fixture.shell.read_bytes())
                manifest.write_bytes(fixture.manifest.read_bytes())
                environment = {**fixture.environment, "COMSPEC": str(system / "cmd.exe")}
                if name == "wild[card]":
                    with self.assertRaisesRegex(ValueError, "focus-control-module"):
                        qualification.shell_focus_control_command(environment, fixture.runtime, "explicit-built-in-utility")
                else:
                    command, _ = qualification.shell_focus_control_command(
                        environment, fixture.runtime, "explicit-built-in-utility")
                    self.assertIn(str(manifest).replace("'", "''"), command[-1])
                    self.assertIn(str(shell.parent).replace("'", "''"), command[-1])

    def test_control_namespace_reparse_refuses_before_any_control_call(self):
        with self.fixture() as fixture:
            directory = fixture.root / qualification.SHELL_FOCUS_CONTROL_DIRECTORY
            real = Path.lstat

            def metadata(path, *args, **options):
                value = real(path, *args, **options)
                if path == directory:
                    return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=0x400)
                return value

            with mock.patch.object(Path, "lstat", autospec=True, side_effect=metadata):
                code, _, controls = self.invoke(fixture)
            self.assertEqual((1, "failed"), (code, controls["status"]))
            self.assertEqual(1, fixture.budget.run.call_count)
            self.assertTrue(all(item["outcome"] == "not-started" for item in controls["controls"]))

    def test_environment_bridge_changes_only_child_module_input_with_no_nested_owner_or_rearm(self):
        with self.fixture() as fixture:
            command, module = qualification.shell_focus_control_command(
                fixture.environment, fixture.runtime, "os-module-root-environment")
            self.assertIsNone(module)
            self.assertEqual([sys.executable, "-I", "-S", "-B", "-c"], command[:-1])
            ast.parse(command[-1])
            inherited = {**fixture.environment, "PSModulePath": MARKER, "WinPSModulePath": "unchanged"}
            with mock.patch.dict(os.environ, inherited, clear=True), mock.patch.object(
                    subprocess, "run", return_value=SimpleNamespace(returncode=37)) as start, \
                    self.assertRaises(SystemExit) as stopped:
                actual_parent = dict(os.environ)
                exec(compile(command[-1], "fixed-environment-bridge", "exec"), {})
            self.assertEqual(37, stopped.exception.code)
            argv = start.call_args.args[0]
            self.assertEqual([str(fixture.shell), "-NoProfile", "-NonInteractive", "-Command"], argv[:-1])
            expected = {key: value for key, value in actual_parent.items() if key.upper() != "PSMODULEPATH"}
            expected["PSModulePath"] = str(fixture.shell.parent / "Modules")
            self.assertEqual({"env": expected, "check": False}, start.call_args.kwargs)
            script = argv[-1]
            self.assertEqual(1, script.count("Write-Output 'approved-shell'"))
            self.assertLess(script.index("$stream.Flush($true)"), script.index("Write-Output 'approved-shell'"))
            self.assertLess(script.index("Write-Output 'approved-shell'"), script.index("$phase='post-write'"))
            for forbidden in ("Import-Module", "Get-Command", "CommandNotFoundAction", "PreCommandLookupAction",
                              "PostCommandLookupAction", "Get-Content", "ReadAllBytes", "SetEnvironmentVariable"):
                self.assertNotIn(forbidden, script)
            self.assertIn("[Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process)", script)
            self.assertIn("[IO.FileMode]::CreateNew", script)
            self.assertIn("[IO.FileShare]::None", script)
            self.assertIn("[IO.FileAttributes]::ReparsePoint", script)
            self.assertNotIn(MARKER, command[-1])
            fixture.budget.run.assert_not_called()
            output = io.StringIO()
            with mock.patch.object(subprocess, "run", side_effect=OSError(MARKER)), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as error:
                exec(compile(command[-1], "fixed-environment-bridge", "exec"), {})
            self.assertEqual(70, error.exception.code)
            self.assertEqual("", output.getvalue())

    def test_startup_inserted_roots_order_duplicates_and_strict_comparison_are_observations(self):
        for inserted in (False, True):
            with self.subTest(inserted=inserted), self.fixture() as fixture:
                run = fixture.budget.run.side_effect
                original = self.environment_records(fixture.environment)
                hashed = original[0]["injected_sha256"]
                roots = ([[0, "unknown", "a" * 64, None], [1, "injected", hashed, None],
                          [2, "unknown", "a" * 64, 0], [3, "empty", hashlib.sha256(b"").hexdigest(), None]]
                         if inserted else original[0]["roots"])

                def emit(*args, **options):
                    result = run(*args, **options)
                    if args[2] == 10 and args[0][0] == sys.executable:
                        records = self.environment_records(fixture.environment, roots=roots)
                        self.write_environment(fixture.root, fixture.environment, records=records)
                    return result

                fixture.budget.run.side_effect = emit
                code, baseline, controls = self.invoke(fixture)
                evidence = controls["controls"][1]["environment"]
                self.assertEqual((0, "passed", "observed"), (code, baseline["status"], evidence["status"]))
                self.assertEqual(1, evidence["pre"]["injected"]["count"])
                self.assertEqual(4 if inserted else 1, evidence["pre"]["effective_count"])
                self.assertIs(evidence["pre"]["effective_matches_injected_only"], not inserted)
                self.assertEqual(roots, evidence["pre"]["roots"])
                self.assertEqual({"status": "observed"}, evidence["post"])
                self.assertIsNone(controls["controls"][0]["environment"])
                self.assertIsNone(controls["controls"][2]["environment"])
                self.assertEqual("shipped-bootstrap-to-isolated-python-bridge-to-shell",
                                 controls["controls"][1]["process_boundary"])

    def test_environment_prefix_survives_timeout_and_partial_post_without_upgrading_failure(self):
        for fault in ("missing", "empty", "pre", "partial-post", "timeout", "output", "cleanup"):
            with self.subTest(fault=fault), self.fixture() as fixture:
                run = fixture.budget.run.side_effect

                def emit(*args, **options):
                    result = run(*args, **options)
                    if args[2] == 10 and args[0][0] == sys.executable:
                        path = fixture.root / qualification.SHELL_FOCUS_ENVIRONMENT_CARRIER
                        if fault == "missing":
                            path.unlink()
                        else:
                            self.write_environment(
                                fixture.root, fixture.environment,
                                records=[] if fault == "empty" else self.environment_records(fixture.environment)[:1],
                                tail=b'{"v":1' if fault == "partial-post" else b"")
                        if fault in ("timeout", "output", "cleanup"):
                            error = (fixture.budget.OutputExceeded() if fault == "output" else
                                     fixture.budget.BudgetExceeded() if fault == "timeout" else OSError(MARKER))
                            if fault == "cleanup":
                                error.__cause__ = fixture.budget.BudgetExceeded()
                            raise error
                    return result

                fixture.budget.run.side_effect = emit
                code, baseline, controls = self.invoke(fixture)
                item = controls["controls"][1]
                self.assertEqual((1, "passed", "failed"), (code, baseline["status"], controls["status"]))
                self.assertEqual(3 if fault == "cleanup" else 4, fixture.budget.run.call_count)
                self.assertIsNone(item["environment"]["post"])
                if fault not in ("missing", "empty", "cleanup"):
                    self.assertEqual("observed", item["environment"]["pre"]["status"])
                else:
                    self.assertIsNone(item["environment"]["pre"])
                self.assertEqual({
                    "missing": "inconclusive", "empty": "inconclusive", "pre": "inconclusive",
                    "partial-post": "admission-or-result-refused", "timeout": "work-budget-exceeded",
                    "output": "output-budget-exceeded", "cleanup": "process-capture-or-cleanup-error",
                }[fault], item["outcome"])

    def test_environment_reader_rejects_malformed_unknown_shapes_and_retains_valid_prefix(self):
        with self.fixture() as fixture:
            (fixture.root / qualification.SHELL_FOCUS_CONTROL_DIRECTORY).mkdir(parents=True)
            records = self.environment_records(fixture.environment)
            pre = records[0]
            for label, value in (
                ("injection", {**pre, "injected_sha256": "0" * 64}),
                ("root-count", {**pre, "roots": pre["roots"] * 33}),
                ("root-position", {**pre, "roots": [[True, *pre["roots"][0][1:]]]}),
                ("root-kind", {**pre, "roots": [[0, "user", "a" * 64, None]]}),
                ("injected-label", {**pre, "roots": [[0, "unknown", pre["injected_sha256"], None]]}),
                ("path-text", {**pre, "roots": [[0, "unknown", MARKER, None]]}),
                ("duplicate", {**pre, "roots": [pre["roots"][0], [1, *pre["roots"][0][1:]]]}),
                ("extra", {**pre, "raw_path": MARKER}),
                ("bad-version", {**pre, "v": True}),
                ("absent", {**pre, "value": "absent"}),
                ("type", [pre]),
            ):
                with self.subTest(label=label):
                    self.write_environment(fixture.root, fixture.environment, records=[value])
                    result = qualification.shell_focus_environment_evidence(fixture.root, fixture.environment)
                    self.assertEqual("refused", result["status"])
                    self.assertIsNone(result["pre"])
                    self.assertNotIn(MARKER, json.dumps(result))
            for suffix in (b'{"v":1', b"not-json\n", b'{"v":1,"v":1}\n',
                           b'{"v":1,"phase":"post","status":"observed","raw":"'+MARKER.encode()+b'"}\n'):
                with self.subTest(suffix=suffix[:20]):
                    self.write_environment(fixture.root, fixture.environment, records=records[:1], tail=suffix)
                    result = qualification.shell_focus_environment_evidence(fixture.root, fixture.environment)
                    self.assertEqual("refused", result["status"])
                    self.assertEqual("observed", result["pre"]["status"])
                    self.assertIsNone(result["post"])
                    self.assertNotIn(MARKER, json.dumps(result))

    def test_environment_normalization_is_strict_ascii_fold_not_filesystem_resolution(self):
        for value, expected in (
            (r"C:/Windows/Modules///", r"c:\windows\modules"), ("C:\\\\", "c:\\"),
            (r"C:\Windows\..\Modules", r"c:\windows\..\modules"), (r" C:\Modules ", r" c:\modules "),
            ("", ""), (r"C:\I\u0130\u03a3", r"c:\i\u0130\u03a3"),
            ("C:\\I\\\u0130\u03a3", "c:\\i\\\u0130\u03a3"),
        ):
            with self.subTest(value=value):
                self.assertEqual(expected, qualification.shell_focus_module_root_normalized(value))
        script = qualification.shell_focus_environment_script(Path(r"C:\Windows\PowerShell\powershell.exe"),
                                                              Path(r"C:\Windows\PowerShell\Modules"))
        self.assertIn("[string[]]$roots=@()", script)
        self.assertIn("$normalized=& $normalize $injected", script)
        self.assertIn("$entry=& $normalize $entry", script)
        self.assertIn("$letter=65; $letter -le 90; $letter++", script)
        self.assertIn("$entry.Length -gt 3", script)

    def test_environment_absent_empty_refused_and_impossible_phase_sequences_are_distinct(self):
        with self.fixture() as fixture:
            (fixture.root / qualification.SHELL_FOCUS_CONTROL_DIRECTORY).mkdir(parents=True)
            observed = self.environment_records(fixture.environment)
            cases = [
                ([{**observed[0], "value": "absent", "roots": []}, observed[1]], "observed", 0),
                ([{**observed[0], "roots": [[0, "empty", hashlib.sha256(b"").hexdigest(), None]]}, observed[1]],
                 "observed", 1),
                ([{"v": 1, "phase": "pre", "status": "refused", "code": "input-limit"}], "refused", None),
                ([observed[0], {"v": 1, "phase": "post", "status": "refused", "code": "command-failed"}],
                 "refused", 1),
                ([{"v": 1, "phase": "pre", "status": "refused", "code": "snapshot"}, observed[1]], "refused", None),
                ([{"v": 1, "phase": "pre", "status": "refused", "code": "snapshot"},
                  {"v": 1, "phase": "post", "status": "refused", "code": "command-failed"}], "refused", None),
                ([observed[1]], "refused", None), (observed + [observed[1]], "refused", 1),
            ]
            for records, status, count in cases:
                with self.subTest(records=records):
                    self.write_environment(fixture.root, fixture.environment, records=records)
                    evidence = qualification.shell_focus_environment_evidence(fixture.root, fixture.environment)
                    self.assertEqual(status, evidence["status"])
                    self.assertEqual(count, (evidence["pre"] or {}).get("effective_count"))
                    if count == 0 or records[0].get("roots", [[]])[0:1] == [
                            [0, "empty", hashlib.sha256(b"").hexdigest(), None]]:
                        self.assertIs(evidence["pre"]["effective_matches_injected_only"], False)
                    if records[0].get("status") == "refused":
                        self.assertIsNone(evidence["post"])

    def test_environment_carrier_refusals_missing_reads_and_boundaries_do_not_launch_replacements(self):
        for fault in ("collision", "reparse", "directory", "oversized", "read", "python", "modules"):
            with self.subTest(fault=fault), self.fixture() as fixture:
                run = fixture.budget.run.side_effect
                path = fixture.root / qualification.SHELL_FOCUS_ENVIRONMENT_CARRIER
                reader = qualification.diagnostic_bytes

                def emit(*args, **options):
                    result = run(*args, **options)
                    if args[2] == 10 and args[0][0] == str(fixture.shell):
                        if fault == "collision":
                            path.write_bytes(MARKER.encode())
                        elif fault == "python":
                            fixture.runtime["images"]["python"]["sha256"] = "0" * 64
                        elif fault == "modules":
                            fixture.manifest.unlink()
                            fixture.manifest.parent.rmdir()
                            fixture.manifest.parent.parent.rmdir()
                    if args[2] == 10 and args[0][0] == sys.executable:
                        if fault == "directory":
                            path.unlink()
                            path.mkdir()
                        elif fault == "oversized":
                            path.write_bytes(b"x" * 4097)
                    return result

                def read(root, relative, limit):
                    if relative == qualification.SHELL_FOCUS_ENVIRONMENT_CARRIER:
                        if fault == "reparse":
                            raise qualification.Refused("reparse-path")
                        if fault == "read":
                            raise OSError(MARKER)
                    return reader(root, relative, limit)

                fixture.budget.run.side_effect = emit
                with mock.patch.object(qualification, "diagnostic_bytes", side_effect=read):
                    code, _, controls = self.invoke(fixture)
                self.assertEqual(1, code)
                self.assertEqual(2 if fault in ("collision", "python", "modules") else 4, fixture.budget.run.call_count)
                self.assertNotEqual("passed", controls["controls"][1]["outcome"])

    def test_environment_event_with_maximum_roots_and_failure_chain_fits_original_cap(self):
        with self.fixture() as fixture:
            roots = [[i, "unknown", hashlib.sha256(str(i).encode()).hexdigest(), None] for i in range(32)]
            run = fixture.budget.run.side_effect
            capture = {"schema": "pennilogic.process-budget-capture-state/1", "status": "observed",
                       "scope": "snapshot", "complete": False, "mode": "merged",
                       "stdout": {"bytes": 18446744073709551615, "sha256": "a" * 64},
                       "stderr": {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}}
            fixture.budget.capture_observation.return_value = (
                "process_budget_capture_state=" + json.dumps(capture, sort_keys=True, separators=(",", ":"))
            )

            def fail(*args, **options):
                result = run(*args, **options)
                if args[2] == 150:
                    return result
                if args[0][0] == sys.executable:
                    self.write_environment(fixture.root, fixture.environment,
                                           records=self.environment_records(fixture.environment, roots=roots))
                error = fixture.budget.OutputExceeded()
                current = error
                for unused in range(4):
                    current.__cause__ = OSError(MARKER)
                    current = current.__cause__
                if "Import-Module" in args[0][-1]:
                    admission = qualification.Refused(max(qualification.SHELL_FOCUS_REFUSALS, key=len))
                    admission.__cause__ = error
                    qualification.observer_context.side_effect = admission
                raise error

            fixture.budget.run.side_effect = fail
            code, _, controls = self.invoke(fixture)
            self.assertEqual(1, code)
            self.assertEqual(32, controls["controls"][1]["environment"]["pre"]["effective_count"])
            self.assertEqual(4, fixture.budget.run.call_count)
            self.assertEqual(capture, controls["error"]["capture"])
            for record in controls["controls"]:
                self.assertEqual(capture, record["error"]["capture"])
                self.assertIs(record["error"]["chain_truncated"], True)


class WindowsObserverGitBindingTests(unittest.TestCase):
    def setUp(self):
        self.powershell = shutil.which("pwsh")
        self.assertIsNotNone(self.powershell, "PowerShell is required for the emitted Git binding fixture")
        temporary = tempfile.TemporaryDirectory(prefix="api-git-binding-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.images = [self.root / "Git with spaces [literal]" / name / "git.exe"
                       for name in (Path("bin"), Path("cmd"), Path("mingw64") / "bin")]
        for index, path in enumerate(self.images):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"synthetic Git image {index}, never execute\n".encode("ascii"))
        self.checkout = self.root / "checkout with spaces [literal]"
        (self.checkout / ".git").mkdir(parents=True)
        for name in ("HEAD", "index", "config"):
            (self.checkout / ".git" / name).write_bytes(("synthetic " + name + "\n").encode("ascii"))
        self.output, self.path_output = self.root / "step output", self.root / "step path"
        self.git_calls, self.qualifier_calls = self.root / "git calls", self.root / "qualifier calls"
        self.environment = {name: value for name, value in support.defects.probe_environment().items()
                            if not name.upper().startswith("GIT_")}
        self.environment.update({
            "GITHUB_OUTPUT": str(self.output), "GITHUB_PATH": str(self.path_output),
            "GITHUB_WORKSPACE": str(self.checkout), "GITHUB_SHA": "a" * 40,
            "PENNILOGIC_API106_CHECKOUT": "a" * 40, "PENNILOGIC_API106_OBSERVER_PAIR": "true",
            "PENNILOGIC_API106_PYTHON": str(self.root / "synthetic python.exe"),
            "FIXTURE_GIT_CALLS": str(self.git_calls), "FIXTURE_QUALIFIER_CALLS": str(self.qualifier_calls),
        })
        self.selection = json.loads(generator.workflow("api"))["jobs"]["windows"]["steps"][0]["run"]

    def run_powershell(self, source, environment):
        for path in (self.output, self.path_output, self.git_calls, self.qualifier_calls):
            path.write_bytes(b"")
        script = self.root / "fixture.ps1"
        script.write_text(source, encoding="ascii", newline="\n")
        return subprocess.run(
            [self.powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
            cwd=self.root, env=environment, capture_output=True, check=False, timeout=15,
        )

    def select(self, candidates):
        environment = {**self.environment, "FIXTURE_CANDIDATES": json.dumps(candidates)}
        fixture = r"""function Get-Command {
    [CmdletBinding()]
    param([string]$Name, [System.Management.Automation.CommandTypes]$CommandType)
    if ($Name -cne 'git' -or $CommandType -ne 'Application' -or
        $PSBoundParameters['ErrorAction'] -ne 'Stop') { throw 'unexpected command lookup' }
    $candidates = @(ConvertFrom-Json -InputObject $env:FIXTURE_CANDIDATES)
    if ($candidates.Count -eq 0) { throw 'no application' }
    foreach ($candidate in $candidates) { [pscustomobject]@{ Source = $candidate } }
}
"""
        return self.run_powershell(fixture + self.selection, environment)

    def owning(self, binding, **overrides):
        command = generator.api_observer_command()
        # Only external calls are fixtures; all rendered binding/refusal logic runs unchanged.
        for original, fixture, count in (
            ("& $git @prefix diff --no-ext-diff --no-textconv --quiet HEAD --",
             "Invoke-FixtureGit $git @prefix diff --no-ext-diff --no-textconv --quiet HEAD '--'", 1),
            ("& $git @prefix", "Invoke-FixtureGit $git @prefix", 2),
            ("& $env:PENNILOGIC_API106_PYTHON", "Invoke-FixtureQualifier $env:PENNILOGIC_API106_PYTHON", 1),
        ):
            self.assertEqual(count, command.count(original))
            command = command.replace(original, fixture)
        fixture = r"""function Invoke-FixtureGit {
    if ($args[0] -cne $env:FIXTURE_EXPECTED_GIT) { throw 'unexpected Git image' }
    [IO.File]::AppendAllText($env:FIXTURE_GIT_CALLS, (ConvertTo-Json -Compress -InputObject @($args)) + "`n")
    $global:LASTEXITCODE = 0
    switch ($args[5]) {
        'rev-parse' {
            $env:GITHUB_WORKSPACE
            Join-Path $env:GITHUB_WORKSPACE '.git'
            Join-Path $env:GITHUB_WORKSPACE '.git'
            $env:GITHUB_SHA
            'b' * 40
        }
        'status' {}
        'diff' {}
        default { throw 'unexpected Git command' }
    }
}
function Invoke-FixtureQualifier {
    $record = @{
        argv = @($args); prepared = $env:PENNILOGIC_API106_PREPARED; tree = $env:PENNILOGIC_API106_TREE
        head = $env:PENNILOGIC_API106_HEAD_SHA256; index = $env:PENNILOGIC_API106_INDEX_SHA256
        config = $env:PENNILOGIC_API106_CONFIG_SHA256
    }
    [IO.File]::AppendAllText($env:FIXTURE_QUALIFIER_CALLS, (ConvertTo-Json -Compress $record) + "`n")
    $global:LASTEXITCODE = 0
}
function python {
    [IO.File]::AppendAllText($env:FIXTURE_QUALIFIER_CALLS, (ConvertTo-Json -Compress -InputObject @($args)) + "`n")
    $global:LASTEXITCODE = 0
}
"""
        environment = {
            **self.environment, "PENNILOGIC_API106_GIT": binding["path"],
            "PENNILOGIC_API106_GIT_SHA256": binding["sha256"], "FIXTURE_EXPECTED_GIT": binding["path"],
            **overrides,
        }
        return self.run_powershell(fixture + command, environment)

    def test_first_application_is_one_literal_path_and_digest_accepted_by_same_job_guard(self):
        for order in ((0, 1, 2), (1, 2, 0), (2, 0, 1)):
            with self.subTest(order=order):
                candidates = [str(self.images[index]) for index in order]
                selected = self.images[order[0]]
                digest = hashlib.sha256(selected.read_bytes()).hexdigest()
                result = self.select(candidates)
                self.assertEqual((0, b"", b""), (result.returncode, result.stdout, result.stderr))
                self.assertEqual(f"path={selected}\nsha256={digest}\n".encode(), self.output.read_bytes())
                self.assertEqual((str(selected.parent) + "\n").encode(), self.path_output.read_bytes())
                binding = dict(line.split("=", 1) for line in self.output.read_text(encoding="utf-8").splitlines())
                result = self.owning(binding)
                self.assertEqual((0, b"", b""), (result.returncode, result.stdout, result.stderr))
                prefix = [str(selected), "--no-pager", "--no-optional-locks", "-c", "core.fsmonitor=false"]
                self.assertEqual([
                    prefix + ["rev-parse", "--path-format=absolute", "--show-toplevel", "--absolute-git-dir",
                              "--git-common-dir", "HEAD", "HEAD^{tree}"],
                    prefix + ["status", "--porcelain=v1", "--untracked-files=normal"],
                    prefix + ["diff", "--no-ext-diff", "--no-textconv", "--quiet", "HEAD", "--"],
                ], [json.loads(line) for line in self.git_calls.read_text(encoding="utf-8").splitlines()])
                self.assertEqual([{
                    "argv": [self.environment["PENNILOGIC_API106_PYTHON"], "-I", "-S", "-B",
                             r"scripts\qualify_windows.py", "--require-prepared", "--api106-observer-pair"],
                    "prepared": "verified", "tree": "b" * 40,
                    **{name.lower(): hashlib.sha256((self.checkout / ".git" / name).read_bytes()).hexdigest()
                       for name in ("HEAD", "index", "config")},
                }], [json.loads(line) for line in self.qualifier_calls.read_text(encoding="utf-8").splitlines()])

    def test_selection_refuses_missing_or_invalid_first_application_without_fallback(self):
        valid = str(self.images[0])
        for name, candidates in (
            ("missing", []), ("empty-first", ["", valid]), ("relative-first", ["git.exe", valid]),
            ("wrong-name", [str(self.images[0].with_name("not-git.exe")), valid]),
            ("control-character", [str(self.root / "bad\npath" / "git.exe"), valid]),
            ("missing-image", [str(self.root / "absent" / "git.exe"), valid]),
        ):
            with self.subTest(case=name):
                result = self.select(candidates)
                self.assertEqual(1, result.returncode)
                self.assertEqual(b"", result.stdout)
                self.assertEqual([b"API106 checkout Git selection refused."], result.stderr.splitlines())
                self.assertEqual(b"", self.output.read_bytes())
                self.assertEqual(b"", self.path_output.read_bytes())
                self.assertEqual(b"", self.git_calls.read_bytes())
                self.assertEqual(b"", self.qualifier_calls.read_bytes())

    def test_same_job_guard_refuses_missing_joined_mismatched_or_changed_binding(self):
        selected = self.images[0]
        binding = {"path": str(selected), "sha256": hashlib.sha256(selected.read_bytes()).hexdigest()}
        cases = (
            {"PENNILOGIC_API106_GIT": ""},
            {"PENNILOGIC_API106_GIT": " ".join(map(str, self.images))},
            {"PENNILOGIC_API106_GIT": str(self.root / "absent" / "git.exe")},
            {"PENNILOGIC_API106_GIT_SHA256": ""},
            {"PENNILOGIC_API106_GIT_SHA256": "malformed"},
            {"PENNILOGIC_API106_GIT_SHA256": binding["sha256"] + " " + binding["sha256"]},
            {"PENNILOGIC_API106_GIT_SHA256": "0" * 64},
            {"PENNILOGIC_API106_GIT_SHA256": binding["sha256"].upper()},
            {},
        )
        for index, overrides in enumerate(cases):
            with self.subTest(case=index):
                if not overrides:
                    selected.write_bytes(b"changed synthetic image, never execute\n")
                result = self.owning(binding, **overrides)
                self.assertEqual(1, result.returncode)
                self.assertEqual(b"", result.stdout)
                self.assertEqual([b"API106 same-job source and preparation binding refused."],
                                 result.stderr.splitlines())
                self.assertEqual(b"", self.git_calls.read_bytes())
                self.assertEqual(b"", self.qualifier_calls.read_bytes())

    def test_false_route_ignores_observer_binding_and_keeps_ordinary_qualifier_call(self):
        result = self.owning(
            {"path": "invalid observer image", "sha256": "invalid digest"},
            PENNILOGIC_API106_OBSERVER_PAIR="false", GIT_DIR="invalid observer-only selector",
        )
        self.assertEqual((0, b"", b""), (result.returncode, result.stdout, result.stderr))
        self.assertEqual(b"", self.git_calls.read_bytes())
        self.assertEqual([[r"scripts\qualify_windows.py", "--require-prepared"]],
                         [json.loads(line) for line in self.qualifier_calls.read_text(encoding="utf-8").splitlines()])


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


class WindowsObserverPairDiagnosticTests(unittest.TestCase):
    def setUp(self):
        environment = mock.patch.dict(qualification.os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.runtime_inputs = qualification.observer_runtime_inputs
        inputs = mock.patch.object(qualification, "observer_runtime_inputs",
                                   return_value=({"CI": "true", "JAVA_HOME": "synthetic-jdk"},
                                                 [Path("synthetic-git-directory")]))
        self.runtime_selection = inputs.start()
        self.addCleanup(inputs.stop)

    def encode(self, records):
        return b"".join(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
                        for record in records)

    def pair(self):
        envelope = {"event": "api106_approved_shell_observer_pair", "v": 1, "diagnostic_only": True}
        return [{**envelope, **fields} for fields in (
            {"phase": "begin", "order": "required-then-auxiliary", "enclosing_seconds": 60,
             "cleanup_reserve_seconds": 12, "arm_work_seconds": 10, "arm_cleanup_seconds": 10},
            {"phase": "started", "role": "required"},
            {"phase": "arm", "role": "required", "outcome": "work-budget-exceeded", "elapsed_ms": 10001,
             "returncode": None, "stdout": None},
            {"phase": "started", "role": "auxiliary-no-lookup-delegates"},
            {"phase": "arm", "role": "auxiliary-no-lookup-delegates", "outcome": "passed", "elapsed_ms": 123,
             "returncode": 0, "stdout": {"text_bytes": 15, "sha256": "a" * 64}},
            {"phase": "complete", "required": "work-budget-exceeded", "auxiliary": "passed", "acceptance": False},
        )]

    def enclosure(self):
        envelope = {"event": "api106_approved_shell_enclosure", "v": 1, "diagnostic_only": True}
        return [{**envelope, **fields} for fields in (
            {"phase": "admitted", "binding_sha256": "b" * 64, "sources": 51, "python": "c" * 64,
             "work_seconds": 48, "total_seconds": 60, "cleanup_reserve_seconds": 12},
            {"phase": "armed", "elapsed_ms": 1, "known_live_discovery_members": 1, "suite_job_retained": True},
            {"phase": "body-left", "elapsed_ms": 10126, "known_live_discovery_members": 1, "suite_job_retained": True},
            {"phase": "case-closed", "elapsed_ms": 10128, "known_live_discovery_members": 1, "suite_job_retained": True},
            {"phase": "suite-exit", "exit_code": 1, "tests_run": 541, "tests_discovered": 541, "inventory_complete": True},
            {"phase": "cleanup", "owned_tree_and_control_released": True, "report_close_not_attested_by_this_record": True},
        )]

    def write(self, root, relative, data):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def custody(self, root, *, settle=True, returncode=1):
        records = [{"v": 1, "phase": "prepared", "context_sha256": qualification.observer_context(root),
                    "all_six_absent": True}]
        if settle:
            records.append({"v": 1, "phase": "settled", "status": "exited", "returncode": returncode})
        return self.write(root, qualification.OBSERVER_STATE, self.encode(records))

    def carriers(self, root):
        lookup = WindowsShellLookupDiagnosticTests()
        data = {
            "required-boundary": b"ES111C",
            "required-lookup": lookup.encode(lookup.v2_records()),
            "pair": self.encode(self.pair()),
            "enclosure": self.encode(self.enclosure()),
            "auxiliary-boundary": b"ES111X",
            "auxiliary-lookup": lookup.encode(lookup.v2_records()[:1]),
        }
        for name, (relative, _) in qualification.OBSERVER_FILES.items():
            self.write(root, relative, data[name])

    def collect(self, root):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = qualification.collect_observer_diagnostics(root)
        self.assertNotIn(MARKER, output.getvalue())
        self.assertNotIn(str(root), output.getvalue())
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        for line, record in zip(output.getvalue().splitlines(), records, strict=True):
            self.assertLessEqual(len(line.encode("ascii")) + len(os.linesep), 4096)
            self.assertIs(record["diagnostic_only"], True)
            self.assertIs(record["acceptance"], False)
            self.assertNotIn("ok", record)
        return result, records

    def budget(self, result=None):
        class BudgetExceeded(TimeoutError):
            def __init__(self):
                self.streams = {}

        class OutputExceeded(BudgetExceeded):
            pass

        temporary = tempfile.TemporaryDirectory(prefix="observer-inert-system-")
        self.addCleanup(temporary.cleanup)
        system = Path(temporary.name)
        for path in (system / "cmd.exe", system / "WindowsPowerShell" / "v1.0" / "powershell.exe"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic system image, never execute\n")
        selections = {"python": sys.executable, "git": str(Path("synthetic-git-directory") / "git.exe"),
                      "java": str(Path("synthetic-jdk") / "bin" / "java.exe")}
        return mock.Mock(
            BudgetExceeded=BudgetExceeded, OutputExceeded=OutputExceeded,
            environment=mock.Mock(return_value={"PATH": "synthetic-approved-path", "COMSPEC": str(system / "cmd.exe")}),
            resolve_command=mock.Mock(side_effect=lambda command, environment: [selections[command[0]]]),
            capture_observation=mock.Mock(return_value=(
                'process_budget_capture_state={"schema":"pennilogic.process-budget-capture-state/1","status":"unavailable"}'
            )),
            run=mock.Mock(return_value=result or subprocess.CompletedProcess([], 1, b"", b"")),
        )

    @contextlib.contextmanager
    def precedence_io(self, root, failures=(), reporter_error=OSError):
        original_open, original_record = Path.open, qualification.observer_state_record
        observed = {"events": [], "streams": [], "stdout": io.StringIO(), "stderr": io.StringIO()}
        observed["errors"] = {
            name: reporter_error(MARKER) for name in
            ("owning-failure", "owning-result", "interval", "secondary", "projection")
        } | {name: OSError(MARKER) for name in ("settlement", "close")}

        def record(stream, directory, fields):
            if fields["phase"] == "settled":
                observed["events"].append("settlement")
                if "settlement" in failures:
                    raise observed["errors"]["settlement"]
            original_record(stream, directory, fields)

        def opening(path, *arguments, **options):
            stream = original_open(path, *arguments, **options)
            if path != root / qualification.OBSERVER_STATE:
                return stream
            observed["streams"].append(stream)
            wrapped = mock.Mock(wraps=stream)

            def close():
                observed["events"].append("close")
                stream.close()
                if "close" in failures:
                    raise observed["errors"]["close"]

            wrapped.close.side_effect = close
            return wrapped

        def report(value, **options):
            event = json.loads(value).get("event") if value.startswith("{") else None
            operation = {
                "windows_observer_owning_failure": "owning-failure",
                "windows_owning_suite_command": "owning-result",
                "windows_observer_owning_interval": "interval",
                "windows_observer_secondary_failure": "secondary",
                "windows_qualification_diagnostic": "projection",
                "test_outcome": "projection",
            }.get(event)
            if operation:
                observed["events"].append("report:" + operation)
                if operation in failures:
                    raise observed["errors"][operation]
            observed["stderr" if options.get("file") is sys.stderr else "stdout"].write(value + "\n")

        with mock.patch.object(Path, "open", autospec=True, side_effect=opening), \
                mock.patch.object(qualification, "observer_state_record", side_effect=record), \
                mock.patch("builtins.print", side_effect=report):
            yield observed
        self.assertTrue(all(stream.closed for stream in observed["streams"]))
        public = observed["stdout"].getvalue() + observed["stderr"].getvalue()
        self.assertNotIn(MARKER, public)
        self.assertNotIn(str(root), public)
        self.assertNotIn('"ok": true', public)

    def late_result(self, root, result, elapsed, failures=(), reporter_error=OSError):
        budget = self.budget(result)
        with self.precedence_io(root, failures, reporter_error) as observed, \
                mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                mock.patch.object(qualification.time, "monotonic_ns", side_effect=(0, elapsed)), \
                mock.patch.object(qualification.subprocess, "run") as direct, \
                mock.patch.object(qualification, "junit_outcomes") as junit:
            with self.assertRaises(qualification._ObserverResultRefused) as caught:
                qualification.qualify(root, require_prepared=True, api106_observer_pair=True)
        direct.assert_not_called()
        junit.assert_not_called()
        self.assertEqual(1, budget.run.call_count)
        self.assertEqual(270, budget.run.call_args.args[2])
        self.assertEqual("owning-suite-command-failed", str(caught.exception))
        self.assertIs(result, caught.exception.result)
        self.assertNotIn(MARKER, "\n".join(caught.exception.__notes__))
        self.assertEqual(1, observed["events"].count("settlement"))
        self.assertEqual(1, observed["events"].count("close"))
        self.assertLess(observed["events"].index("close"), observed["events"].index("report:interval"))
        records = [json.loads(line) for line in observed["stdout"].getvalue().splitlines() if line.startswith("{")]
        return caught.exception, observed, records

    @contextlib.contextmanager
    def unused_outer_capture(self, operation):
        streams = [mock.MagicMock(spec=io.BytesIO) for _ in range(2)]
        for stream in streams:
            stream.__enter__.return_value = stream
            getattr(stream, operation).side_effect = OSError(MARKER)

            def close(*unused, stream=stream):
                stream.close()
                return False

            stream.__exit__.side_effect = close
        with mock.patch.object(qualification.tempfile, "TemporaryFile", side_effect=streams) as capture:
            yield
        capture.assert_not_called()
        for stream in streams:
            self.assertEqual([], stream.mock_calls)

    @contextlib.contextmanager
    def runtime_fixture(self):
        with tempfile.TemporaryDirectory(prefix="observer-runtime-source-") as temporary:
            base = Path(temporary)
            root, python, git, java, runner = (
                base / "checkout", base / "python" / "python.exe", base / "git" / "git.exe",
                base / "jdk", base / "runner-temp",
            )
            runner.mkdir()
            for path in (python, git, java / "bin" / "java.exe", java / "bin" / "javac.exe"):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic image, never execute\n")
            (python.parent / "Scripts").mkdir()
            (java / "release").write_bytes(
                b'JAVA_VERSION="21.0.9"\r\nJAVA_RUNTIME_VERSION="21.0.9+10-LTS"\r\nIMPLEMENTOR="Eclipse Adoptium"\r\n')
            for relative in (".git/objects", "build/source-materialization", "build/contracts-money",
                             "build/money-client-interop/inputs", "build/database-admission"):
                (root / relative).mkdir(parents=True, exist_ok=True)
            environment = {
                "GITHUB_ACTIONS": "true", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_REPOSITORY": "PenniLogic/api", "GITHUB_REPOSITORY_ID": "1394134582",
                "GITHUB_REPOSITORY_OWNER_ID": "335295566", "GITHUB_JOB": "windows",
                "GITHUB_SHA": "a" * 40, "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_WORKSPACE": str(root), "RUNNER_TEMP": str(runner), "JAVA_HOME": str(java),
                "PENNILOGIC_API106_CHECKOUT": "a" * 40, "PENNILOGIC_API106_TREE": "b" * 40,
                "PENNILOGIC_API106_PYTHON": str(python),
                "PENNILOGIC_API106_PYTHON_VERSION": ".".join(map(str, sys.version_info[:3])),
                "PENNILOGIC_API106_JAVA": str(java), "PENNILOGIC_API106_JAVA_VERSION": "21.0.9+10",
                "PENNILOGIC_API106_GIT": str(git),
                "PENNILOGIC_API106_GIT_SHA256": hashlib.sha256(git.read_bytes()).hexdigest(),
                "PENNILOGIC_API106_MONEY": "success", "PENNILOGIC_API106_PREPARED": "verified",
                "PENNILOGIC_API106_TEMP": str(runner),
            }
            for name in ("HEAD", "index", "config"):
                data = ("synthetic " + name + "\n").encode("ascii")
                (root / ".git" / name).write_bytes(data)
                environment["PENNILOGIC_API106_" + name.upper() + "_SHA256"] = hashlib.sha256(data).hexdigest()
            budget = self.budget()
            budget.sys = mock.Mock(executable=str(python), base_prefix=str(python.parent))
            with mock.patch.dict(qualification.os.environ, environment, clear=True), \
                    mock.patch.multiple(qualification.sys, executable=str(python), prefix=str(python.parent),
                                        base_prefix=str(python.parent)), \
                    mock.patch.object(qualification.subprocess, "run") as direct:
                yield root, budget, environment
                direct.assert_not_called()
                budget.run.assert_not_called()

    def test_runtime_workflow_uses_same_setup_outputs_and_exact_preparation_chain(self):
        current = json.loads(generator.workflow("api"))
        steps = current["jobs"]["windows"]["steps"]
        self.assertEqual(["Bind API106 checkout Git", "Checkout", "Python", "Node", "JDK"],
                         [step["name"] for step in steps[:5]])
        self.assertEqual("api106_git", steps[0]["id"])
        self.assertEqual("${{ " + OBSERVER_CONDITION + " }}", steps[0]["if"])
        self.assertIn("[IO.File]::AppendAllText($env:GITHUB_PATH,", steps[0]["run"])
        owning = next(step for step in steps if step["name"] == "Run Windows owning suites")
        self.assertEqual({"PENNILOGIC_API106_OBSERVER_PAIR": "${{ " + OBSERVER_CONDITION + " }}",
                          **OBSERVER_RUNTIME_ENV}, owning["env"])
        command = generator.api_observer_command()
        preparation = generator.powershell_commands([
            "python -I -S -B scripts\\prepare_database_admission.py prepare",
            "python -I -S -B scripts\\prepare_database_admission.py verify",
            "python -I -S -B scripts\\money_client_interop.py prepare --require-prepared",
        ])
        self.assertEqual(preparation + "\n" + generator.powershell_commands([command]), owning["run"])
        provider = next(step for step in steps if step["name"] == "Prepare verified Money provider")
        self.assertTrue(provider["run"].endswith(
            "python scripts\\materialize_money_sources.py --verify\nif ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"))
        self.assertIn("& $env:PENNILOGIC_API106_PYTHON -I -S -B scripts\\qualify_windows.py --require-prepared "
                      "--api106-observer-pair", command)
        self.assertTrue(command.endswith(
            "} elseif ($env:PENNILOGIC_API106_OBSERVER_PAIR -ceq 'false') {\n"
            "    python scripts\\qualify_windows.py --require-prepared\n"
            "} else { throw 'API106 observer selection must be a Boolean' }"))
        for forbidden in ("--offline", "resolveDependencies", "quality.py install", "--tests", "continue-on-error"):
            self.assertNotIn(forbidden, command)
        previous = remove_observer_runtime(self, copy.deepcopy(current))
        self.assertEqual(current["jobs"]["ci"], previous["jobs"]["ci"])
        self.assertEqual(current["jobs"]["ci-result"], previous["jobs"]["ci-result"])
        without = remove_observer_pair(self, copy.deepcopy(current))
        self.assertEqual("51bf74f97dbb427e68c4db320ebd69bf9daadcc116c9ca628fcbd33f2349fceb",
                         hashlib.sha256(generator.encoded(without).encode("utf-8")).hexdigest())
        self.assertEqual(30, current["jobs"]["windows"]["timeout-minutes"])

    def test_runtime_workflow_binding_drift_is_not_a_new_expression_allowlist(self):
        current = json.loads(generator.workflow("api"))
        validate = api_checker()
        mutations = [
            lambda steps: steps.pop(0),
            lambda steps: steps[0].pop("if"),
            lambda steps: steps[0].update(run="exit 0"),
            lambda steps: steps.insert(1, steps.pop(0)),
            lambda steps: steps[1].pop("id"),
            lambda steps: steps[2].pop("id"),
            lambda steps: steps[4].pop("id"),
        ]
        for name in OBSERVER_RUNTIME_ENV:
            mutations.append(lambda steps, name=name: steps[-3]["env"].update({name: MARKER}))
        for text in ("$env:PENNILOGIC_API106_PREPARED = 'verified'", "--no-optional-locks",
                     "core.fsmonitor=false", "--git-common-dir", "--no-ext-diff --no-textconv",
                     "$env:PENNILOGIC_API106_INDEX_SHA256", "$env:PENNILOGIC_API106_CONFIG_SHA256"):
            mutations.append(lambda steps, text=text: steps[-3].update(run=steps[-3]["run"].replace(text, MARKER)))
        for mutate in mutations:
            changed = copy.deepcopy(current)
            mutate(changed["jobs"]["windows"]["steps"])
            with self.subTest(mutate=mutate), self.assertRaisesRegex(ValueError, "API CI must match"):
                validate(CI, generator.encoded(changed).encode())
        namespace = {"__file__": str(support.GOVERNANCE.parent / "scripts/check_repository.py")}
        exec(compile(generator.standard_checker("api"), "standard checker", "exec"), namespace)
        for value in OBSERVER_RUNTIME_ENV.values():
            with self.subTest(expression=value), self.assertRaises(ValueError):
                namespace["validate_expressions"]({"env": {"RUNTIME": value}})

    def test_runtime_environment_is_finite_and_adds_only_the_bound_git_parent(self):
        with self.runtime_fixture() as (root, budget, environment):
            injected = {
                name: MARKER for name in (
                    "PATH", "HOME", "USERPROFILE", "TEMP", "TMP", "GRADLE_USER_HOME",
                    "GH_TOKEN", "GITHUB_TOKEN", "PENNILOGIC_NATIVE_SOURCE_TOKEN", "HTTPS_PROXY",
                    "PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS",
                    "GRADLE_OPTS", "JAVA_OPTS", "PSModulePath", "GIT_CONFIG_PARAMETERS", "GIT_DIR",
                )
            }
            with mock.patch.dict(qualification.os.environ, injected):
                supplied, directories = self.runtime_inputs(root, budget)
            self.assertEqual([Path(environment["PENNILOGIC_API106_GIT"]).parent], directories)
            self.assertEqual({"HOME", "USERPROFILE", "TEMP", "TMP", "TMPDIR", "JAVA_HOME", "GRADLE_USER_HOME",
                              "CI", "GITHUB_ACTIONS"}, set(supplied))
            self.assertEqual(("true", "true"), (supplied["CI"], supplied["GITHUB_ACTIONS"]))
            self.assertEqual(environment["PENNILOGIC_API106_JAVA"], supplied["JAVA_HOME"])
            self.assertEqual(supplied["HOME"], supplied["USERPROFILE"])
            self.assertEqual(supplied["TEMP"], supplied["TMP"])
            self.assertEqual(supplied["TEMP"], supplied["TMPDIR"])
            self.assertNotIn(MARKER, json.dumps(supplied))
            for name in ("HOME", "TEMP", "GRADLE_USER_HOME"):
                self.assertTrue(Path(supplied[name]).is_relative_to(Path(environment["RUNNER_TEMP"])))
            self.assertEqual([], list(Path(supplied["HOME"]).iterdir()))
            self.assertEqual([], list(Path(supplied["TEMP"]).iterdir()))
            budget.environment.assert_not_called()

    def test_runtime_jdk_selection_uses_fresh_cache_without_offline_or_sdk_acquisition(self):
        with self.runtime_fixture() as (root, budget, environment):
            supplied, _ = self.runtime_inputs(root, budget)
            cache = Path(supplied["GRADLE_USER_HOME"])
            self.assertEqual(["gradle.properties"], [path.name for path in cache.iterdir()])
            java = environment["PENNILOGIC_API106_JAVA"].replace("\\", "\\\\")
            self.assertEqual(
                "org.gradle.java.installations.auto-detect=false\n"
                "org.gradle.java.installations.auto-download=false\n"
                "org.gradle.java.installations.paths=" + java + "\n",
                (cache / "gradle.properties").read_text(encoding="utf-8"),
            )
            with self.assertRaises(FileExistsError):
                self.runtime_inputs(root, budget)
            self.assertTrue(cache.is_dir())
        for name, value in (("JAVA_VERSION", "17.0.1"), ("IMPLEMENTOR", "unselected-vendor")):
            with self.subTest(field=name), self.runtime_fixture() as (root, budget, environment):
                release = Path(environment["PENNILOGIC_API106_JAVA"]) / "release"
                lines = {"JAVA_VERSION": "21.0.9", "JAVA_RUNTIME_VERSION": "21.0.9+10-LTS",
                         "IMPLEMENTOR": "Eclipse Adoptium"}
                lines[name] = value
                release.write_text("".join(f'{key}="{item}"\n' for key, item in lines.items()), encoding="utf-8")
                with self.assertRaisesRegex(qualification.Refused, "observer-java-selection"):
                    self.runtime_inputs(root, budget)

    def test_runtime_java_refusals_identify_only_the_first_failed_predicate_without_values(self):
        valid = 'JAVA_VERSION="21.0.9"\nJAVA_RUNTIME_VERSION="21.0.9+10-LTS"\nIMPLEMENTOR="Eclipse Adoptium"\n'
        cases = (
            ("home", "home-match", valid, "21.0.9+10"),
            ("comma", "home-single-path", valid, "21.0.9+10"),
            ("home-before-comma", "home-match", valid, "21.0.9+10"),
            ("version-absent", "release-version-single-match", 'IMPLEMENTOR="Eclipse Adoptium"\n', "21.0.9"),
            ("version-major", "release-version-single-match", valid.replace("21.0.9", "17.0.9"), "17.0.9"),
            ("version-malformed", "release-version-single-match", valid.replace("21.0.9", MARKER), MARKER),
            ("version-duplicate", "release-version-single-match", valid + 'JAVA_VERSION="21.0.9"\n', "21.0.9"),
            ("version-malformed-duplicate", "release-version-single-match", valid + 'JAVA_VERSION=' + MARKER + '\n',
             "21.0.9+10"),
            ("version-indented-duplicate", "release-version-single-match", valid + ' JAVA_VERSION="21.0.9"\n',
             "21.0.9+10"),
            ("version-before-vendor", "release-version-single-match", MARKER + "\n", MARKER),
            ("selected-absent", "selected-version-match", valid, None),
            ("selected-mismatch", "selected-version-match", valid, MARKER),
            ("selected-before-vendor", "selected-version-match", valid.replace("Eclipse Adoptium", MARKER), MARKER),
            ("vendor-absent", "release-implementor", valid.replace('IMPLEMENTOR="Eclipse Adoptium"\n', ""), "21.0.9+10"),
            ("vendor-mismatch", "release-implementor", valid.replace("Eclipse Adoptium", MARKER), "21.0.9+10"),
            ("vendor-duplicate", "release-implementor", valid + 'IMPLEMENTOR="Eclipse Adoptium"\n', "21.0.9+10"),
        )
        for label, check, release, selected in cases:
            with self.subTest(case=label), self.runtime_fixture() as (root, budget, environment):
                java = Path(environment["PENNILOGIC_API106_JAVA"])
                if label in ("comma", "home-before-comma"):
                    java = java.with_name("jdk," + MARKER)
                    java.mkdir()
                    qualification.os.environ.update(PENNILOGIC_API106_JAVA=str(java), JAVA_HOME=str(java))
                if label in ("home", "home-before-comma"):
                    other = java.with_name("other-" + MARKER)
                    other.mkdir()
                    qualification.os.environ["JAVA_HOME"] = str(other)
                if selected is None:
                    qualification.os.environ.pop("PENNILOGIC_API106_JAVA_VERSION")
                else:
                    qualification.os.environ["PENNILOGIC_API106_JAVA_VERSION"] = selected
                (java / "release").write_text(release, encoding="utf-8")
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), \
                        self.assertRaises(qualification.Refused) as caught:
                    self.runtime_inputs(root, budget)
                self.assertEqual("observer-java-selection", str(caught.exception))
                self.assertEqual("", output.getvalue())
                expected = [{"event": "windows_observer_java_selection", "diagnostic_only": True,
                             "check": check, "matched": False}]
                if check == "selected-version-match":
                    expected.append({"event": "windows_observer_java_versions", "diagnostic_only": True,
                                     "release_version": "21.0.9", "selected_version": "unavailable"})
                self.assertEqual(expected, [json.loads(line) for line in errors.getvalue().splitlines()])
                for line in errors.getvalue().splitlines():
                    self.assertLessEqual(len(line.encode("ascii")) + 2, 192)
                for private in (MARKER, str(java), str(root), "JAVA_HOME", "JAVA_VERSION", "Eclipse Adoptium"):
                    self.assertNotIn(private, errors.getvalue())
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))
                self.assertFalse((root / qualification.OBSERVER_STATE).exists())
                budget.environment.assert_not_called()

    def test_runtime_java_accepted_release_and_setup_versions_emit_no_selection_record(self):
        for release, runtime, selected in (
            ("21.0.9", "21.0.9+10", "21.0.9+10"),
            ("21.0.9", "21.0.9+10-LTS", "21.0.9+10.0"),
            ("21.0.9+10-LTS", "21.0.9+10-LTS", "21.0.9+10"),
            ("21.0.12.1", "21.0.12.1+1-LTS", "21.0.12+101.0"),
            ("21.0.12.1", "21.0.12.1+1", "21.0.12+101"),
            ("21.0.12.1+1", "21.0.12.1+1-LTS", "21.0.12+101.0"),
            ("21.0.12.2", "21.0.12.2+9-LTS", "21.0.12+209"),
            ("21.0.12", "21.0.12+99", "21.0.12+99.0"),
            ("21.99999.99999.99999", "21.99999.99999.99999+99-LTS", "21.99999.99999+9999999.0"),
        ):
            with self.subTest(release=release, selected=selected), \
                    self.runtime_fixture() as (root, budget, environment):
                java = Path(environment["PENNILOGIC_API106_JAVA"])
                selected_java = java.with_name("jdk with [literal] spaces")
                shutil.copytree(java, selected_java)
                java = selected_java
                qualification.os.environ.update(PENNILOGIC_API106_JAVA=str(java), JAVA_HOME=str(java),
                                                PENNILOGIC_API106_JAVA_VERSION=selected)
                (java / "release").write_bytes(
                    f'JAVA_VERSION="{release}"\r\nJAVA_RUNTIME_VERSION="{runtime}"\r\n'
                    'IMPLEMENTOR="Eclipse Adoptium"\r\n'.encode("ascii"))
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    supplied, directories = self.runtime_inputs(root, budget)
                self.assertEqual(str(java), supplied["JAVA_HOME"])
                self.assertEqual([Path(environment["PENNILOGIC_API106_GIT"]).parent], directories)
                self.assertEqual("", output.getvalue() + errors.getvalue())

    def test_runtime_java_version_mismatch_reports_only_bounded_exact_operands(self):
        cases = (
            ("four-component-release", "21.0.12.1", "21.0.12+101.0", "21.0.12.1", "21.0.12"),
            ("four-component-selected", "21.0.12", "21.0.12.1+1-LTS", "21.0.12", "21.0.12.1"),
            ("patch-mismatch", "21.0.13", "21.0.12+101.0", "21.0.13", "21.0.12"),
            ("bounded-maxima", "21.99999.99999.99999", "21.88888.88888.88888",
             "21.99999.99999.99999", "21.88888.88888.88888"),
            ("oversized-release", "21." + "9" * 4096, "21.0.12", "unavailable", "21.0.12"),
            ("large-release-component", "21.100000", "21.0.12", "unavailable", "21.0.12"),
            ("padded-release", "21.00.12", "21.0.12", "unavailable", "21.0.12"),
            ("oversized-selected", "21.0.12", "21." + "9" * 4096, "21.0.12", "unavailable"),
            ("large-selected-component", "21.0.12", "21.100000", "21.0.12", "unavailable"),
            ("private-selected", "21.0.12", MARKER, "21.0.12", "unavailable"),
            ("control-selected", "21.0.12", "21.0.12\n" + MARKER, "21.0.12", "unavailable"),
            ("unicode-selected", "21.0.12", "21.0.\u0661", "21.0.12", "unavailable"),
            ("other-major", "21.0.12", "17.0.12", "21.0.12", "unavailable"),
            ("private-build-suffix", "21.0.13+1-LTS", "21.0.12+" + MARKER, "21.0.13", "21.0.12"),
        )
        for label, release, selected, left, right in cases:
            with self.subTest(case=label), self.runtime_fixture() as (root, budget, environment):
                java = Path(environment["PENNILOGIC_API106_JAVA"])
                (java / "release").write_text(
                    f'JAVA_VERSION="{release}"\nJAVA_RUNTIME_VERSION="21.0.12.1+2-LTS"\n'
                    f'IMPLEMENTOR="Eclipse Adoptium"\nPRIVATE="{MARKER}"\n',
                    encoding="utf-8")
                qualification.os.environ["PENNILOGIC_API106_JAVA_VERSION"] = selected
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), \
                        self.assertRaises(qualification.Refused) as caught:
                    self.runtime_inputs(root, budget)
                self.assertEqual("observer-java-selection", str(caught.exception))
                self.assertEqual("", output.getvalue())
                self.assertEqual([
                    {"event": "windows_observer_java_selection", "diagnostic_only": True,
                     "check": "selected-version-match", "matched": False},
                    {"event": "windows_observer_java_versions", "diagnostic_only": True,
                     "release_version": left, "selected_version": right},
                ], [json.loads(line) for line in errors.getvalue().splitlines()])
                for line in errors.getvalue().splitlines():
                    self.assertLessEqual(len(line.encode("ascii")) + 2, 192)
                for private in (MARKER, str(root), str(java), "JAVA_HOME", "JAVA_VERSION", "Eclipse Adoptium"):
                    self.assertNotIn(private, errors.getvalue())
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))
                self.assertFalse((root / qualification.OBSERVER_STATE).exists())
                budget.environment.assert_not_called()

    def test_runtime_java_semver_contract_rejects_patch_build_and_release_identity_mismatches(self):
        cases = (
            ("patch", "21.0.12.2", "21.0.12.2+1-LTS", "21.0.12+101.0"),
            ("build", "21.0.12.1", "21.0.12.1+2-LTS", "21.0.12+101.0"),
            ("update", "21.0.13.1", "21.0.13.1+1-LTS", "21.0.12+101.0"),
            ("minor", "21.1.12.1", "21.1.12.1+1-LTS", "21.0.12+101.0"),
            ("major", "21.0.12.1", "21.0.12.1+1-LTS", "17.0.12+101.0"),
            ("runtime-version", "21.0.12.1", "21.0.12.2+1-LTS", "21.0.12+101.0"),
            ("runtime-major", "21.0.12.1", "17.0.12.1+1-LTS", "21.0.12+101.0"),
            ("three-part-build", "21.0.12", "21.0.12+2-LTS", "21.0.12+1.0"),
            ("ambiguous-build-carry", "21.0.12.1", "21.0.12.1+101-LTS", "21.0.12+201.0"),
            ("ambiguous-three-part", "21.0.12", "21.0.12+101-LTS", "21.0.12+101.0"),
            ("zero-build", "21.0.12.1", "21.0.12.1+0-LTS", "21.0.12+100.0"),
            ("zero-patch", "21.0.12.0", "21.0.12.0+1-LTS", "21.0.12+1.0"),
            ("missing-selected-build", "21.0.12", "21.0.12+1-LTS", "21.0.12"),
            ("raw-four-part-label", "21.0.12.1", "21.0.12.1+1-LTS", "21.0.12.1+1-LTS"),
            ("unproved-distribution-build", "21.0.12.1", "21.0.12.1+1-LTS", "21.0.12+101.1"),
            ("release-build-disagrees", "21.0.12.1+2", "21.0.12.1+1-LTS", "21.0.12+101.0"),
            ("noncanonical-release", "21.00.12", "21.0.12+1-LTS", "21.0.12+1.0"),
            ("large-release-component", "21.100000.12", "21.100000.12+1-LTS", "21.100000.12+1.0"),
            ("two-part-release", "21.0", "21.0+1-LTS", "21.0+1"),
        )
        for label, release, runtime, selected in cases:
            with self.subTest(case=label), self.runtime_fixture() as (root, budget, environment):
                java = Path(environment["PENNILOGIC_API106_JAVA"])
                (java / "release").write_text(
                    f'JAVA_VERSION="{release}"\nJAVA_RUNTIME_VERSION="{runtime}"\n'
                    'IMPLEMENTOR="Eclipse Adoptium"\n', encoding="ascii")
                qualification.os.environ["PENNILOGIC_API106_JAVA_VERSION"] = selected
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors), self.assertRaises(qualification.Refused) as caught:
                    self.runtime_inputs(root, budget)
                self.assertEqual("observer-java-selection", str(caught.exception))
                records = [json.loads(line) for line in errors.getvalue().splitlines()]
                self.assertEqual("selected-version-match", records[0]["check"])
                self.assertEqual(2, len(records))
                for line in errors.getvalue().splitlines():
                    self.assertLessEqual(len(line.encode("ascii")) + 2, 192)
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))
                self.assertFalse((root / qualification.OBSERVER_STATE).exists())
                budget.environment.assert_not_called()

    def test_runtime_java_runtime_field_must_be_unique_bounded_and_consistent_before_owner(self):
        valid = 'JAVA_RUNTIME_VERSION="21.0.12.1+1-LTS"\n'
        cases = (
            ("absent", ""),
            ("identical-duplicate", valid + valid),
            ("conflicting-duplicate", valid + valid.replace("+1-", "+2-")),
            ("malformed-duplicate", valid + "JAVA_RUNTIME_VERSION=" + MARKER + "\n"),
            ("indented-duplicate", valid + " " + valid),
            ("unquoted", "JAVA_RUNTIME_VERSION=21.0.12.1+1-LTS\n"),
            ("indented", " " + valid),
            ("space-around-assignment", valid.replace("=", " = ")),
            ("missing-build", valid.replace("+1-LTS", "")),
            ("zero-build", valid.replace("+1-", "+0-")),
            ("padded-build", valid.replace("+1-", "+01-")),
            ("negative-build", valid.replace("+1-", "+-1-")),
            ("hundred-build", valid.replace("+1-", "+100-")),
            ("private", valid.replace("21.0.12.1+1-LTS", MARKER)),
            ("private-suffix", valid.replace("-LTS", "-" + MARKER)),
            ("control", valid.replace("+1-", "+1\x00-")),
            ("embedded-line", valid.replace("+1-", "+1\n" + MARKER + "-")),
            ("unicode-digit", valid.replace("+1-", "+\u0661-")),
            ("unicode-line", valid.replace('"\n', '"\u2028')),
            ("oversized", valid.replace("+1-", "+" + "9" * 4096 + "-")),
            ("trailing-private", valid.rstrip("\n") + MARKER + "\n"),
        )
        for label, field in cases:
            with self.subTest(case=label), self.runtime_fixture() as (root, budget, environment):
                java = Path(environment["PENNILOGIC_API106_JAVA"])
                (java / "release").write_text(
                    'JAVA_VERSION="21.0.12.1"\n' + field + f'IMPLEMENTOR="Eclipse Adoptium"\nPRIVATE="{MARKER}"\n',
                    encoding="utf-8")
                qualification.os.environ["PENNILOGIC_API106_JAVA_VERSION"] = "21.0.12+101.0"
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors), self.assertRaises(qualification.Refused) as caught:
                    self.runtime_inputs(root, budget)
                self.assertEqual("observer-java-selection", str(caught.exception))
                self.assertEqual([
                    {"event": "windows_observer_java_selection", "diagnostic_only": True,
                     "check": "selected-version-match", "matched": False},
                    {"event": "windows_observer_java_versions", "diagnostic_only": True,
                     "release_version": "21.0.12.1", "selected_version": "21.0.12"},
                ], [json.loads(line) for line in errors.getvalue().splitlines()])
                for line in errors.getvalue().splitlines():
                    self.assertLessEqual(len(line.encode("ascii")) + 2, 192)
                for private in (MARKER, str(root), str(java), "JAVA_RUNTIME_VERSION", "Eclipse Adoptium"):
                    self.assertNotIn(private, errors.getvalue())
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))
                self.assertFalse((root / qualification.OBSERVER_STATE).exists())
                budget.environment.assert_not_called()

    def test_runtime_java_selected_metadata_rejects_noncanonical_or_private_values(self):
        cases = (
            "", MARKER, "21.0.12", "21.0.12+0", "21.0.12+0101", "21.0.12+101.00", "21.0.12+101.0.0",
            "21.0.12+101-LTS", "21.0.12+101+" + MARKER, "21.0.12+101." + MARKER,
            "21.0.12+101\n", "21.0.12+101\r", "21.0.12+101\x00", "21.0.12+\u0661",
            "21.0.12+101.\u0660", "21.0.12+101\u2028", "21.0.12+" + "9" * 4096,
        )
        for position, selected in enumerate(cases):
            with self.subTest(case=position), self.runtime_fixture() as (root, budget, environment):
                java = Path(environment["PENNILOGIC_API106_JAVA"])
                (java / "release").write_bytes(
                    b'JAVA_VERSION="21.0.12.1"\nJAVA_RUNTIME_VERSION="21.0.12.1+1-LTS"\n'
                    b'IMPLEMENTOR="Eclipse Adoptium"\n')
                errors = io.StringIO()
                with mock.patch.object(qualification.os, "environ", {
                    **qualification.os.environ, "PENNILOGIC_API106_JAVA_VERSION": selected,
                }), contextlib.redirect_stderr(errors), self.assertRaises(qualification.Refused) as caught:
                    self.runtime_inputs(root, budget)
                self.assertEqual("observer-java-selection", str(caught.exception))
                records = [json.loads(line) for line in errors.getvalue().splitlines()]
                self.assertEqual("selected-version-match", records[0]["check"])
                self.assertEqual(2, len(records))
                for line in errors.getvalue().splitlines():
                    self.assertLessEqual(len(line.encode("ascii")) + 2, 192)
                self.assertNotIn(MARKER, errors.getvalue())
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))
                self.assertFalse((root / qualification.OBSERVER_STATE).exists())
                budget.environment.assert_not_called()

    def test_runtime_java_version_operand_projection_does_not_coerce_or_truncate(self):
        cases = (
            None, True, 21, b"21.0.12", mock.Mock(), "", MARKER, r"C:\private\21.0.12",
            "17.0.12", "210.0.12", "21", "21.0.12.1.1", "21.00.12", "21.0.012", "21.100000",
            "21.0.12+1-LTS", "21.0.12\n", "21.0.12\r\n", "21.0.\u0661", "21.0.12 " + MARKER,
            "21.12345.12345.123456", "21." + "9" * 4096,
        )
        for position, value in enumerate(cases):
            with self.subTest(case=position):
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors), self.assertRaises(qualification.Refused) as caught:
                    qualification.observer_java_require(False, "selected-version-match", versions=(value, value))
                self.assertEqual("observer-java-selection", str(caught.exception))
                records = [json.loads(line) for line in errors.getvalue().splitlines()]
                self.assertEqual([
                    {"event": "windows_observer_java_selection", "diagnostic_only": True,
                     "check": "selected-version-match", "matched": False},
                    {"event": "windows_observer_java_versions", "diagnostic_only": True,
                     "release_version": "unavailable", "selected_version": "unavailable"},
                ], records)
                for line in errors.getvalue().splitlines():
                    self.assertLessEqual(len(line.encode("ascii")) + 2, 192)
                self.assertNotIn(MARKER, errors.getvalue())
                self.assertEqual("unavailable", qualification.observer_java_version_operand(value))
                if isinstance(value, mock.Mock):
                    self.assertEqual([], value.mock_calls)

    def test_runtime_java_diagnostic_reporting_failure_preserves_the_primary_refusal(self):
        for error_type, fail_secondary in itertools.product((OSError, ValueError), (False, True)):
            with self.subTest(error=error_type.__name__, fail_secondary=fail_secondary), \
                    self.runtime_fixture() as (root, budget, environment):
                qualification.os.environ["PENNILOGIC_API106_JAVA_VERSION"] = MARKER
                errors, attempted, native_print = io.StringIO(), [], print

                def report(value, *args, **kwargs):
                    record = json.loads(value)
                    attempted.append(record["event"])
                    if record["event"] == "windows_observer_java_selection" or fail_secondary:
                        raise error_type(MARKER)
                    return native_print(value, *args, **kwargs)

                with contextlib.redirect_stderr(errors), mock.patch("builtins.print", side_effect=report), \
                        self.assertRaises(qualification.Refused) as caught:
                    self.runtime_inputs(root, budget)
                self.assertEqual("observer-java-selection", str(caught.exception))
                self.assertEqual(["windows_observer_java_selection", "windows_observer_secondary_failure"], attempted)
                self.assertIn("java-selection-report-unavailable", "\n".join(caught.exception.__notes__))
                self.assertNotIn(MARKER, errors.getvalue() + "\n".join(caught.exception.__notes__))
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))
                self.assertFalse((root / qualification.OBSERVER_STATE).exists())
                budget.environment.assert_not_called()

    def test_runtime_java_operand_reporting_failure_preserves_the_primary_refusal(self):
        for error_type, fail_secondary in itertools.product((OSError, ValueError), (False, True)):
            with self.subTest(error=error_type.__name__, fail_secondary=fail_secondary), \
                    self.runtime_fixture() as (root, budget, environment):
                qualification.os.environ["PENNILOGIC_API106_JAVA_VERSION"] = "21.0.12+101.0"
                errors, attempted, native_print = io.StringIO(), [], print

                def report(value, *args, **kwargs):
                    record = json.loads(value)
                    attempted.append(record["event"])
                    if record["event"] == "windows_observer_java_versions" or (
                            fail_secondary and record["event"] == "windows_observer_secondary_failure"):
                        raise error_type(MARKER)
                    return native_print(value, *args, **kwargs)

                with contextlib.redirect_stderr(errors), mock.patch("builtins.print", side_effect=report), \
                        self.assertRaises(qualification.Refused) as caught:
                    self.runtime_inputs(root, budget)
                self.assertEqual("observer-java-selection", str(caught.exception))
                self.assertEqual(["windows_observer_java_selection", "windows_observer_java_versions",
                                  "windows_observer_secondary_failure"], attempted)
                self.assertIn("java-selection-report-unavailable", "\n".join(caught.exception.__notes__))
                if fail_secondary:
                    self.assertIn("Observer secondary failure reporting also failed", caught.exception.__notes__)
                self.assertNotIn(MARKER, errors.getvalue() + "\n".join(caught.exception.__notes__))
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))
                self.assertFalse((root / qualification.OBSERVER_STATE).exists())
                budget.environment.assert_not_called()

    def test_runtime_java_refusal_keeps_main_nonzero_and_collection_closed(self):
        for fault in ("private-label", "wrong-build", "missing-runtime"):
            with self.subTest(fault=fault), self.runtime_fixture() as (root, budget, environment):
                left, right = "21.0.9", "unavailable"
                qualification.os.environ["PENNILOGIC_API106_JAVA_VERSION"] = MARKER
                if fault != "private-label":
                    left, right = "21.0.12.1", "21.0.12"
                    qualification.os.environ["PENNILOGIC_API106_JAVA_VERSION"] = "21.0.12+101.0"
                    runtime = 'JAVA_RUNTIME_VERSION="21.0.12.1+2-LTS"\n' if fault == "wrong-build" else ""
                    (Path(environment["PENNILOGIC_API106_JAVA"]) / "release").write_text(
                        'JAVA_VERSION="21.0.12.1"\n' + runtime + 'IMPLEMENTOR="Eclipse Adoptium"\n', encoding="ascii")
                output, errors = io.StringIO(), io.StringIO()
                with mock.patch.object(qualification, "ROOT", root), \
                        mock.patch.object(qualification.sys, "platform", "win32"), \
                        mock.patch.object(qualification, "observer_runtime_inputs", self.runtime_inputs), \
                        mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    self.assertEqual(1, qualification.main(["--require-prepared", "--api106-observer-pair"]))
                self.assertEqual([
                    {"event": "windows_observer_java_selection", "diagnostic_only": True,
                     "check": "selected-version-match", "matched": False},
                    {"event": "windows_observer_java_versions", "diagnostic_only": True,
                     "release_version": left, "selected_version": right},
                    {"event": "windows_qualification_refused", "code": "observer-java-selection"},
                ], [json.loads(line) for line in errors.getvalue().splitlines()])
                self.assertNotIn("windows_observer_owning_interval", output.getvalue())
                self.assertNotIn("windows_owning_suite_command", output.getvalue())
                self.assertFalse((root / qualification.OBSERVER_STATE).exists())
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))
                collected = io.StringIO()
                with contextlib.redirect_stdout(collected):
                    self.assertEqual(2, qualification.collect_observer_diagnostics(root))
                records = [json.loads(line) for line in collected.getvalue().splitlines()]
                self.assertEqual(1, len(records))
                self.assertEqual(("collection", "refused", "observer-state-unavailable"),
                                 (records[0]["carrier"], records[0]["status"], records[0]["code"]))
                for private in (MARKER, str(root), environment["PENNILOGIC_API106_JAVA"]):
                    self.assertNotIn(private, output.getvalue() + errors.getvalue() + collected.getvalue())
                budget.environment.assert_not_called()

    def test_runtime_java_unreadable_inputs_keep_existing_static_failure_without_selection_record(self):
        for fault in ("missing-home", "missing-java", "missing-javac", "missing-release", "utf8", "oversized-release"):
            with self.subTest(fault=fault), self.runtime_fixture() as (root, budget, environment):
                java = Path(environment["PENNILOGIC_API106_JAVA"])
                if fault == "missing-home":
                    qualification.os.environ.pop("JAVA_HOME")
                elif fault in ("missing-java", "missing-javac"):
                    (java / "bin" / (fault.removeprefix("missing-") + ".exe")).unlink()
                elif fault == "missing-release":
                    (java / "release").unlink()
                else:
                    (java / "release").write_bytes(b"\xff" if fault == "utf8" else b"x" * 16385)
                output, errors = io.StringIO(), io.StringIO()
                with mock.patch.object(qualification, "ROOT", root), \
                        mock.patch.object(qualification.sys, "platform", "win32"), \
                        mock.patch.object(qualification, "observer_runtime_inputs", self.runtime_inputs), \
                        mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    self.assertEqual(1, qualification.main(["--require-prepared", "--api106-observer-pair"]))
                records = [json.loads(line) for line in errors.getvalue().splitlines()]
                self.assertEqual(1, len(records))
                expected = ("observer-runtime-path" if fault == "missing-home" else
                            "observer-runtime-input-limit" if fault == "oversized-release" else "process-or-report-error")
                self.assertEqual({"event": "windows_qualification_refused", "code": expected}, records[0])
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))
                self.assertFalse((root / qualification.OBSERVER_STATE).exists())
                self.assertNotIn(str(root), output.getvalue() + errors.getvalue())
                budget.environment.assert_not_called()

    def test_runtime_selection_and_preparation_provenance_refuse_before_work(self):
        mutations = (
            ("GITHUB_ACTIONS", "false"), ("PENNILOGIC_API106_MONEY", "skipped"),
            ("PENNILOGIC_API106_PREPARED", ""), ("PENNILOGIC_API106_CHECKOUT", "b" * 40),
            ("PENNILOGIC_API106_TREE", "not-a-tree"), ("PENNILOGIC_API106_PYTHON", "python.exe"),
            ("PENNILOGIC_API106_PYTHON_VERSION", "3.13.0"), ("PENNILOGIC_API106_GIT_SHA256", "0" * 64),
            ("PENNILOGIC_API106_JAVA_VERSION", "17.0.1"), ("PENNILOGIC_API106_TEMP", "relative"),
            ("PENNILOGIC_API106_HEAD_SHA256", "0" * 64), ("PENNILOGIC_API106_INDEX_SHA256", "0" * 64),
            ("PENNILOGIC_API106_CONFIG_SHA256", "0" * 64),
        )
        for name, value in mutations:
            with self.subTest(input=name), self.runtime_fixture() as (root, budget, environment):
                with mock.patch.dict(qualification.os.environ, {name: value}), \
                        self.assertRaises((qualification.Refused, OSError)):
                    self.runtime_inputs(root, budget)
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))
        for relative in ("build/source-materialization", "build/contracts-money",
                         "build/money-client-interop/inputs", "build/database-admission"):
            with self.subTest(preparation=relative), self.runtime_fixture() as (root, budget, environment):
                (root / relative).rmdir()
                with self.assertRaises(FileNotFoundError):
                    self.runtime_inputs(root, budget)
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))

    def test_runtime_requires_outer_target_and_base_prefix_agreement(self):
        for subject, name in (("target", "executable"), ("target", "prefix"), ("target", "base_prefix"),
                              ("owner", "executable"), ("owner", "base_prefix")):
            with self.subTest(subject=subject, field=name), self.runtime_fixture() as (root, budget, environment):
                target = qualification.sys if subject == "target" else budget.sys
                with mock.patch.object(target, name, str(root)), \
                        self.assertRaisesRegex(qualification.Refused, "observer-python-selection"):
                    self.runtime_inputs(root, budget)
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))

    def test_runtime_changed_checkout_git_image_and_unowned_outputs_are_refused(self):
        for target in ("HEAD", "index", "config", "git"):
            with self.subTest(changed=target), self.runtime_fixture() as (root, budget, environment):
                path = Path(environment["PENNILOGIC_API106_GIT"]) if target == "git" else root / ".git" / target
                path.write_bytes(path.read_bytes() + b"changed")
                with self.assertRaisesRegex(qualification.Refused, "observer-git-(state-changed|selection)"):
                    self.runtime_inputs(root, budget)
        for relative in (".gradle", ".kotlin", "git.exe", "python.exe", "java.exe"):
            with self.subTest(output=relative), self.runtime_fixture() as (root, budget, environment):
                path = root / relative
                path.write_bytes(MARKER.encode())
                with self.assertRaisesRegex(qualification.Refused, "observer-unadmitted-runtime-state"):
                    self.runtime_inputs(root, budget)
                self.assertEqual(MARKER.encode(), path.read_bytes())
                self.assertEqual([], list(Path(environment["RUNNER_TEMP"]).iterdir()))

    def test_runtime_path_reparse_and_relative_selections_never_open_an_image(self):
        with self.runtime_fixture() as (root, budget, environment):
            target = Path(environment["PENNILOGIC_API106_GIT"]).parent
            lstat = Path.lstat

            def metadata(path):
                return mock.Mock(st_mode=qualification.stat.S_IFDIR, st_file_attributes=0x400) if path == target else lstat(path)

            with mock.patch.object(Path, "lstat", autospec=True, side_effect=metadata), \
                    mock.patch.object(qualification, "observer_runtime_bytes", wraps=qualification.observer_runtime_bytes) as read:
                with self.assertRaisesRegex(qualification.Refused, "observer-runtime-path"):
                    self.runtime_inputs(root, budget)
                self.assertFalse(any(call.args[0].name == "git.exe" for call in read.call_args_list))
        for value in (None, "", "relative", "bad\npath"):
            with self.subTest(path=value), self.assertRaises(qualification.Refused):
                qualification.observer_runtime_path(value, directory=False)

    def test_closed_interval_enforces_the_actual_strict_300_boundary(self):
        for returncode, elapsed in itertools.product(
            (0, 1), (-1, 0, 280_000_000_000, 299_999_999_999, 300_000_000_000, 301_000_000_000),
        ):
            with self.subTest(returncode=returncode, elapsed=elapsed), \
                    tempfile.TemporaryDirectory(prefix="observer-closed-time-") as temporary:
                root, output, budget = Path(temporary), io.StringIO(), self.budget()
                budget.run.return_value = subprocess.CompletedProcess([], returncode, b"", b"")
                with mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        mock.patch.object(qualification.time, "monotonic_ns", side_effect=(10**12, 10**12 + elapsed)), \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                    if 0 <= elapsed < 300_000_000_000:
                        self.assertEqual(returncode, qualification.observer_owning_command(root).returncode)
                    else:
                        with self.assertRaises(qualification.Refused) as caught:
                            qualification.observer_owning_command(root)
                        refusal = caught.exception
                        if returncode:
                            self.assertIs(budget.run.return_value, refusal.result)
                            self.assertEqual("owning-suite-command-failed", str(refusal))
                            refusal = refusal.__cause__
                        self.assertEqual("observer-closed-command-budget-exceeded", str(refusal))
                records = [json.loads(line) for line in output.getvalue().splitlines()]
                interval = records[-1]
                self.assertEqual({"event": "windows_observer_owning_interval", "diagnostic_only": True,
                                  "elapsed_ns": elapsed, "limit_seconds": 300,
                                  "within_limit": 0 <= elapsed < 300_000_000_000}, interval)
                self.assertNotIn("ok", interval)
                self.assertEqual(270, budget.run.call_args.args[2])
                self.assertEqual(1, budget.run.call_count)

    def test_closed_interval_includes_environment_owner_return_settlement_and_close(self):
        for close_seconds in (4, 5):
            with self.subTest(close_seconds=close_seconds), tempfile.TemporaryDirectory(prefix="observer-close-span-") as temporary:
                root, budget = Path(temporary), self.budget()
                admitted_environment = budget.environment.return_value
                clock, events = [0], []
                native_open, native_record = Path.open, qualification.observer_state_record

                def environment(**arguments):
                    events.append("environment")
                    clock[0] += 1_000_000_000
                    return admitted_environment

                def run(*arguments, **options):
                    events.append("owner-return-after-capture-and-cleanup")
                    clock[0] += 280_000_000_000
                    return subprocess.CompletedProcess([], 0, b"", b"")

                def record(stream, directory, fields):
                    native_record(stream, directory, fields)
                    if fields["phase"] == "settled":
                        events.append("settled")
                        clock[0] += 14_000_000_000

                def opening(path, *arguments, **options):
                    stream = native_open(path, *arguments, **options)
                    wrapped = mock.Mock(wraps=stream)

                    def close():
                        stream.close()
                        events.append("closed")
                        clock[0] += close_seconds * 1_000_000_000

                    wrapped.close.side_effect = close
                    return wrapped

                budget.environment.side_effect, budget.run.side_effect = environment, run
                output = io.StringIO()
                with mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        mock.patch.object(qualification.time, "monotonic_ns", side_effect=lambda: clock[0]), \
                        mock.patch.object(qualification, "observer_state_record", side_effect=record), \
                        mock.patch.object(Path, "open", autospec=True, side_effect=opening), \
                        contextlib.redirect_stdout(output):
                    if close_seconds == 4:
                        qualification.observer_owning_command(root)
                    else:
                        with self.assertRaisesRegex(qualification.Refused, "observer-closed-command-budget-exceeded"):
                            qualification.observer_owning_command(root)
                self.assertEqual(["environment", "owner-return-after-capture-and-cleanup", "settled", "closed"], events)
                interval = json.loads(output.getvalue().splitlines()[-1])
                self.assertEqual((295 + close_seconds) * 1_000_000_000, interval["elapsed_ns"])
                self.assertEqual(close_seconds == 4, interval["within_limit"])

    def test_closed_interval_cannot_replace_existing_budget_or_unconfirmed_cleanup_failure(self):
        for failure in ("budget", "cleanup"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix="observer-closed-failure-") as temporary:
                root, budget, output = Path(temporary), self.budget(), io.StringIO()
                primary = budget.BudgetExceeded() if failure == "budget" else OSError(MARKER)
                budget.run.side_effect = primary
                with mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        mock.patch.object(qualification.time, "monotonic_ns", side_effect=(0, 301_000_000_000)), \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(qualification.Refused if failure == "budget" else OSError) as caught:
                        qualification.observer_owning_command(root)
                self.assertTrue(caught.exception is primary or caught.exception.__cause__ is primary)
                self.assertNotIn(MARKER, output.getvalue())
                self.assertIs(json.loads(output.getvalue().splitlines()[-1])["within_limit"], False)
                self.assertEqual(2 if failure == "budget" else 1,
                                 len((root / qualification.OBSERVER_STATE).read_bytes().splitlines()))

    def test_closed_interval_is_enforced_inside_an_unrelated_caller_exception_handler(self):
        with tempfile.TemporaryDirectory(prefix="observer-caller-error-") as temporary:
            root = Path(temporary)
            budget = self.budget(subprocess.CompletedProcess([], 0, b"", b""))
            with mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                    mock.patch.object(qualification.time, "monotonic_ns", side_effect=(0, 300_000_000_000)), \
                    contextlib.redirect_stdout(io.StringIO()):
                try:
                    raise ValueError("unrelated synthetic caller error")
                except ValueError:
                    with self.assertRaisesRegex(qualification.Refused, "observer-closed-command-budget-exceeded"):
                        qualification.observer_owning_command(root)

    def test_closed_interval_reporting_failure_preserves_the_primary_owner_failure(self):
        with tempfile.TemporaryDirectory(prefix="observer-report-error-") as temporary:
            root, budget = Path(temporary), self.budget()
            primary = budget.BudgetExceeded()
            budget.run.side_effect = primary
            output = io.StringIO()

            def report(value, **options):
                if "windows_observer_owning_interval" in value:
                    raise OSError(MARKER)
                output.write(value + "\n")

            with mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                    mock.patch("builtins.print", side_effect=report):
                with self.assertRaises(qualification.Refused) as caught:
                    qualification.observer_owning_command(root)
            self.assertIs(primary, caught.exception.__cause__)
            self.assertIn("Closed observer interval reporting also failed", caught.exception.__notes__)
            self.assertNotIn(MARKER, output.getvalue())

    def test_inner_failure_report_io_keeps_owner_identity_and_custody_attempts(self):
        for kind, reporter_error, secondary_failure in itertools.product(
            ("budget", "output", "cleanup"), (OSError, ValueError), (False, True),
        ):
            with self.subTest(kind=kind, reporter=reporter_error, secondary=secondary_failure), \
                    tempfile.TemporaryDirectory(prefix="observer-primary-report-") as temporary:
                root, budget = Path(temporary), self.budget()
                primary = (budget.BudgetExceeded() if kind == "budget" else
                           budget.OutputExceeded() if kind == "output" else OSError(MARKER))
                budget.run.side_effect = primary
                failures = ("owning-failure", "secondary") if secondary_failure else ("owning-failure",)
                with self.precedence_io(root, failures, reporter_error) as observed, \
                        mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        mock.patch.object(qualification.time, "monotonic_ns", side_effect=(0, 1)):
                    with self.assertRaises(qualification.Refused if kind != "cleanup" else OSError) as caught:
                        qualification.observer_owning_command(root)
                self.assertIs(primary, caught.exception if kind == "cleanup" else caught.exception.__cause__)
                self.assertIn("Observer secondary failure: owning-failure-report-unavailable", caught.exception.__notes__)
                if secondary_failure:
                    self.assertIn("Observer secondary failure reporting also failed", caught.exception.__notes__)
                self.assertNotIn(MARKER, "\n".join(caught.exception.__notes__))
                self.assertEqual(int(kind != "cleanup"), observed["events"].count("settlement"))
                self.assertEqual(1, observed["events"].count("close"))
                state = [json.loads(line) for line in (root / qualification.OBSERVER_STATE).read_bytes().splitlines()]
                self.assertEqual(1 if kind == "cleanup" else 2, len(state))
                if kind != "cleanup":
                    reason = "work-budget-exceeded" if kind == "budget" else "output-budget-exceeded"
                    self.assertEqual("observer-owning-" + reason, str(caught.exception))
                    self.assertEqual(reason, state[-1]["status"])

    def test_settlement_and_close_report_io_preserve_active_owner_failure(self):
        cases = [(kind, failures) for kind in ("budget", "output") for failures in (
            ("settlement", "secondary"), ("close", "secondary"),
            ("owning-failure", "settlement", "close", "secondary", "interval"),
        )] + [("cleanup", ("owning-failure", "close", "secondary", "interval"))]
        for kind, failures in cases:
            with self.subTest(kind=kind, failures=failures), \
                    tempfile.TemporaryDirectory(prefix="observer-compound-finalization-") as temporary:
                root, budget = Path(temporary), self.budget()
                primary = (budget.BudgetExceeded() if kind == "budget" else
                           budget.OutputExceeded() if kind == "output" else OSError(MARKER))
                budget.run.side_effect = primary
                with self.precedence_io(root, failures) as observed, \
                        mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        mock.patch.object(qualification.time, "monotonic_ns", side_effect=(0, 300_000_000_000)):
                    with self.assertRaises(qualification.Refused if kind != "cleanup" else OSError) as caught:
                        qualification.observer_owning_command(root)
                self.assertIs(primary, caught.exception if kind == "cleanup" else caught.exception.__cause__)
                notes = caught.exception.__notes__
                for operation, code in (("settlement", "state-finalization"), ("close", "state-close-unconfirmed"),
                                        ("interval", "interval-report-unavailable"),
                                        ("owning-failure", "owning-failure-report-unavailable")):
                    if operation in failures:
                        self.assertIn("Observer secondary failure: " + code, notes)
                self.assertIn("Observer secondary failure: closed-command-budget-exceeded", notes)
                self.assertIn("Observer secondary failure reporting also failed", notes)
                self.assertNotIn(MARKER, "\n".join(notes))
                self.assertEqual(int(kind != "cleanup"), observed["events"].count("settlement"))
                self.assertEqual(1, observed["events"].count("close"))
                self.assertIn("report:interval", observed["events"])
                expected_records = 1 if kind == "cleanup" or "settlement" in failures else 2
                self.assertEqual(expected_records, len((root / qualification.OBSERVER_STATE).read_bytes().splitlines()))

    def test_prepared_state_refusal_survives_close_and_secondary_report_failure(self):
        with tempfile.TemporaryDirectory(prefix="observer-prepared-compound-") as temporary:
            root, budget = Path(temporary), self.budget()
            primary = qualification.Refused("observer-state-short-write")
            with self.precedence_io(root, ("close", "secondary")) as observed, \
                    mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                    mock.patch.object(qualification, "observer_state_record", side_effect=primary), \
                    mock.patch.object(qualification.time, "monotonic_ns", side_effect=(0, 1)):
                with self.assertRaises(qualification.Refused) as caught:
                    qualification.observer_owning_command(root)
            self.assertIs(primary, caught.exception)
            budget.run.assert_not_called()
            self.assertEqual(1, observed["events"].count("close"))
            self.assertNotIn("settlement", observed["events"])
            self.assertIn("Observer secondary failure: state-close-unconfirmed", primary.__notes__)
            self.assertIn("Observer secondary failure reporting also failed", primary.__notes__)

    def test_returned_results_finalize_custody_despite_command_report_failure(self):
        for returncode, reporter_error, failures in itertools.product(
            (0, 1), (OSError, ValueError),
            (("owning-result",), ("owning-result", "settlement", "close", "secondary")),
        ):
            with self.subTest(returncode=returncode, reporter=reporter_error, failures=failures), \
                    tempfile.TemporaryDirectory(prefix="observer-result-report-") as temporary:
                root = Path(temporary)
                result = subprocess.CompletedProcess([], returncode, MARKER.encode(), MARKER.encode())
                budget = self.budget(result)
                with self.precedence_io(root, failures, reporter_error) as observed, \
                        mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        mock.patch.object(qualification.time, "monotonic_ns", side_effect=(0, 1)):
                    with self.assertRaises(qualification.Refused if returncode else reporter_error) as caught:
                        qualification.observer_owning_command(root)
                failure = caught.exception
                if returncode:
                    self.assertIs(result, failure.result)
                    failure = failure.__cause__
                self.assertIs(observed["errors"]["owning-result"], failure)
                self.assertEqual(1, observed["events"].count("settlement"))
                self.assertEqual(1, observed["events"].count("close"))
                self.assertLess(observed["events"].index("report:owning-result"), observed["events"].index("settlement"))
                self.assertLess(observed["events"].index("settlement"), observed["events"].index("close"))
                rows = (root / qualification.OBSERVER_STATE).read_bytes().splitlines()
                self.assertEqual(1 if "settlement" in failures else 2, len(rows))
                self.assertIn("Observer secondary failure: owning-command-report-unavailable", caught.exception.__notes__)
                for operation, code in (("settlement", "state-finalization"), ("close", "state-close-unconfirmed")):
                    if operation in failures:
                        self.assertIn("Observer secondary failure: " + code, caught.exception.__notes__)

    def test_returned_nonzero_late_failure_keeps_complete_safe_outcomes(self):
        for elapsed, failures in ((300_000_000_000, ()), (301_000_000_000, ()),
                                  (1, ("interval",)), (300_000_000_000, ("interval",))):
            with self.subTest(elapsed=elapsed, failures=failures), \
                    tempfile.TemporaryDirectory(prefix="observer-late-outcomes-") as temporary:
                root = Path(temporary)
                report = WindowsOutcomeTests().python_report("FAIL").replace("OK (skipped=1)", "FAILED (failures=1, skipped=1)")
                result = subprocess.CompletedProcess([], 7, (MARKER + str(root)).encode(), report.encode())
                primary, observed, records = self.late_result(root, result, elapsed, failures)
                outcomes = [record for record in records if record["event"] == "test_outcome"]
                self.assertEqual(2, len(outcomes))
                self.assertEqual({"failed", "skipped"}, {record["outcome"] for record in outcomes})
                self.assertEqual(hashlib.sha256(qualification.PYTHON_TARGET.encode()).hexdigest(), outcomes[0]["id_sha256"])
                self.assertEqual(qualification.PYTHON_TARGET, outcomes[0]["required_test"])
                self.assertLess(observed["events"].index("report:interval"), observed["events"].index("report:projection"))
                if elapsed >= 300_000_000_000:
                    self.assertEqual("observer-closed-command-budget-exceeded", str(primary.__cause__))
                else:
                    self.assertIs(observed["errors"]["interval"], primary.__cause__)
                if "interval" in failures:
                    self.assertIn("Observer secondary failure: interval-report-unavailable", primary.__notes__)

    def test_returned_nonzero_late_failure_keeps_bounded_negative_prefix(self):
        for elapsed, failures in ((300_000_000_000, ()), (301_000_000_000, ()),
                                  (1, ("interval",)), (300_000_000_000, ("interval",))):
            with self.subTest(elapsed=elapsed, failures=failures), \
                    tempfile.TemporaryDirectory(prefix="observer-late-prefix-") as temporary:
                root, identity = Path(temporary), qualification.PYTHON_TARGET
                report = f"{identity.rsplit('.', 1)[-1]} ({identity}) ... ERROR\n{MARKER} {root}\n"
                result = subprocess.CompletedProcess([], 1, (MARKER + str(root)).encode(), report.encode())
                primary, observed, records = self.late_result(root, result, elapsed, failures)
                diagnostic, = [record for record in records if record["event"] == "windows_qualification_diagnostic"]
                self.assertEqual(1, diagnostic["exit_code"])
                self.assertIs(diagnostic["diagnostic_only"], True)
                self.assertIs(diagnostic["inventory_complete"], False)
                self.assertLess(len(json.dumps(diagnostic).encode()), 4096)
                for name in ("stdout", "stderr"):
                    data = getattr(result, name)
                    self.assertEqual({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}, diagnostic[name])
                self.assertEqual("ambiguous-python-outcome", diagnostic["parser"]["code"])
                self.assertEqual(1, diagnostic["parser"]["negative_prefix_count"])
                self.assertIs(diagnostic["parser"]["negative_prefix_truncated"], False)
                prefix, = diagnostic["parser"]["negative_prefix"]
                self.assertEqual(hashlib.sha256(identity.encode()).hexdigest(), prefix["id_sha256"])
                self.assertEqual("error", prefix["outcome"])
                self.assertFalse(any(record["event"] == "test_outcome" for record in records))
                self.assertIn("Observer secondary failure: captured-python-outcomes-incomplete", primary.__notes__)
                self.assertLess(observed["events"].index("report:interval"), observed["events"].index("report:projection"))

    def test_returned_nonzero_inner_finalization_errors_keep_safe_projection(self):
        for operation, secondary in itertools.product(("owning-result", "settlement", "close"), (False, True)):
            with self.subTest(operation=operation, secondary=secondary), \
                    tempfile.TemporaryDirectory(prefix="observer-inner-result-") as temporary:
                root, identity = Path(temporary), qualification.PYTHON_TARGET
                report = f"{identity.rsplit('.', 1)[-1]} ({identity}) ... FAIL\n{MARKER}\n"
                result = subprocess.CompletedProcess([], 1, MARKER.encode(), report.encode())
                failures = (operation, "secondary") if secondary else (operation,)
                primary, observed, records = self.late_result(root, result, 1, failures)
                self.assertIs(observed["errors"][operation], primary.__cause__)
                diagnostic, = [record for record in records if record["event"] == "windows_qualification_diagnostic"]
                self.assertEqual([{"id_sha256": hashlib.sha256(identity.encode()).hexdigest(), "outcome": "failed"}],
                                 diagnostic["parser"]["negative_prefix"])
                rows = (root / qualification.OBSERVER_STATE).read_bytes().splitlines()
                self.assertEqual(1 if operation == "settlement" else 2, len(rows))
                if secondary:
                    self.assertIn("Observer secondary failure reporting also failed", primary.__notes__)

    def test_failed_result_projection_io_cannot_replace_retained_nonzero(self):
        for complete, reporter_error, secondary in itertools.product((False, True), (OSError, ValueError), (False, True)):
            with self.subTest(complete=complete, reporter=reporter_error, secondary=secondary), \
                    tempfile.TemporaryDirectory(prefix="observer-projection-report-") as temporary:
                root, identity = Path(temporary), qualification.PYTHON_TARGET
                report = (WindowsOutcomeTests().python_report("FAIL") if complete else
                          f"{identity.rsplit('.', 1)[-1]} ({identity}) ... FAIL\n{MARKER}\n")
                report = report.replace("OK (skipped=1)", "FAILED (failures=1, skipped=1)")
                result = subprocess.CompletedProcess([], 1, MARKER.encode(), report.encode())
                failures = ("projection", "secondary") if secondary else ("projection",)
                primary, observed, records = self.late_result(root, result, 300_000_000_000, failures, reporter_error)
                self.assertEqual("observer-closed-command-budget-exceeded", str(primary.__cause__))
                self.assertIn("Observer secondary failure: captured-python-outcome-report-unavailable", primary.__notes__)
                self.assertFalse(any(record["event"] in ("test_outcome", "windows_qualification_diagnostic")
                                     for record in records))
                self.assertEqual(1, observed["events"].count("report:projection"))
                if secondary:
                    self.assertIn("Observer secondary failure reporting also failed", primary.__notes__)

    def test_successful_result_late_reporting_or_finalization_failure_still_refuses(self):
        for operation, reporter_error, secondary in itertools.product(
            ("interval", "settlement", "close"), (OSError, ValueError), (False, True),
        ):
            with self.subTest(operation=operation, reporter=reporter_error, secondary=secondary), \
                    tempfile.TemporaryDirectory(prefix="observer-zero-refusal-") as temporary:
                root = Path(temporary)
                result = subprocess.CompletedProcess([], 0, b"", b"")
                budget = self.budget(result)
                failures = (operation, "secondary") if secondary else (operation,)
                with self.precedence_io(root, failures, reporter_error) as observed, \
                        mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        mock.patch.object(qualification.time, "monotonic_ns", side_effect=(0, 1)):
                    with self.assertRaises(reporter_error if operation == "interval" else OSError) as caught:
                        qualification.observer_owning_command(root)
                self.assertIs(observed["errors"][operation], caught.exception)
                self.assertEqual(1, observed["events"].count("settlement"))
                self.assertEqual(1, observed["events"].count("close"))
        with tempfile.TemporaryDirectory(prefix="observer-zero-overrun-report-") as temporary:
            root, budget = Path(temporary), self.budget(subprocess.CompletedProcess([], 0, b"", b""))
            with self.precedence_io(root, ("interval", "secondary")), \
                    mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                    mock.patch.object(qualification.time, "monotonic_ns", side_effect=(0, 300_000_000_000)):
                with self.assertRaisesRegex(qualification.Refused, "observer-closed-command-budget-exceeded") as caught:
                    qualification.observer_owning_command(root)
            self.assertIn("Observer secondary failure: interval-report-unavailable", caught.exception.__notes__)
            self.assertIn("Observer secondary failure reporting also failed", caught.exception.__notes__)

    def test_normal_nonzero_result_bypasses_outer_write_seek_read_and_close(self):
        for complete, operation in itertools.product((False, True), ("write", "seek", "read", "close")):
            with self.subTest(complete=complete, operation=operation), \
                    tempfile.TemporaryDirectory(prefix="observer-no-restaging-") as temporary:
                root, identity = Path(temporary), qualification.PYTHON_TARGET
                report = (WindowsOutcomeTests().python_report("FAIL").replace(
                    "OK (skipped=1)", "FAILED (failures=1, skipped=1)") if complete else
                    f"{identity.rsplit('.', 1)[-1]} ({identity}) ... ERROR\n{MARKER} {root}\n")
                result = subprocess.CompletedProcess([], 7, (MARKER + str(root)).encode(), report.encode())
                budget = self.budget(result)
                with self.unused_outer_capture(operation), self.precedence_io(root) as observed, \
                        mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        mock.patch.object(qualification.time, "monotonic_ns", side_effect=(0, 1)), \
                        mock.patch.object(qualification.subprocess, "run") as direct, \
                        mock.patch.object(qualification, "junit_outcomes") as junit:
                    with self.assertRaises(qualification._ObserverResultRefused) as caught:
                        qualification.qualify(root, require_prepared=True, api106_observer_pair=True)
                primary = caught.exception
                self.assertIs(result, primary.result)
                self.assertIsNone(primary.__cause__)
                self.assertEqual("owning-suite-command-failed", str(primary))
                direct.assert_not_called()
                junit.assert_not_called()
                self.assertEqual(1, budget.run.call_count)
                self.assertEqual(270, budget.run.call_args.args[2])
                self.assertEqual(1, observed["events"].count("settlement"))
                self.assertEqual(1, observed["events"].count("close"))
                self.assertLess(observed["events"].index("close"), observed["events"].index("report:interval"))
                self.assertLess(observed["events"].index("report:interval"), observed["events"].index("report:projection"))
                records = [json.loads(line) for line in observed["stdout"].getvalue().splitlines()
                           if line.startswith("{")]
                if complete:
                    outcomes = [record for record in records if record["event"] == "test_outcome"]
                    self.assertEqual(["failed", "skipped"], [record["outcome"] for record in outcomes])
                    self.assertEqual([hashlib.sha256(name.encode()).hexdigest() for name in
                                      (identity, "test_fixture.OtherTest.test_other")],
                                     [record["id_sha256"] for record in outcomes])
                    self.assertEqual(identity, outcomes[0]["required_test"])
                    self.assertFalse(any(record["event"] == "windows_qualification_diagnostic" for record in records))
                else:
                    diagnostic, = [record for record in records if record["event"] == "windows_qualification_diagnostic"]
                    self.assertEqual(7, diagnostic["exit_code"])
                    self.assertIs(diagnostic["diagnostic_only"], True)
                    self.assertIs(diagnostic["inventory_complete"], False)
                    self.assertLess(len(json.dumps(diagnostic).encode()), 4096)
                    for name in ("stdout", "stderr"):
                        data = getattr(result, name)
                        self.assertEqual({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}, diagnostic[name])
                    self.assertEqual("ambiguous-python-outcome", diagnostic["parser"]["code"])
                    self.assertEqual(1, diagnostic["parser"]["negative_prefix_count"])
                    self.assertIs(diagnostic["parser"]["negative_prefix_truncated"], False)
                    self.assertEqual([{
                        "id_sha256": hashlib.sha256(identity.encode()).hexdigest(), "outcome": "error",
                        "error": {"exception": "unclassified", "source_frames": [],
                                  "incomplete": True, "truncated": False},
                    }],
                                     diagnostic["parser"]["negative_prefix"])
                    self.assertFalse(any(record["event"] == "test_outcome" for record in records))
                    self.assertIn("Observer secondary failure: captured-python-outcomes-incomplete", primary.__notes__)

    def test_normal_nonzero_projection_io_preserves_result_without_replaying_partial_output(self):
        for (complete, fail_at), reporter_error, secondary in itertools.product(
            ((False, 1), (True, 1), (True, 2)), (OSError, ValueError), (False, True),
        ):
            with self.subTest(complete=complete, fail_at=fail_at, reporter=reporter_error, secondary=secondary), \
                    tempfile.TemporaryDirectory(prefix="observer-normal-projection-") as temporary:
                root, identity = Path(temporary), qualification.PYTHON_TARGET
                text = (WindowsOutcomeTests().python_report("FAIL").replace(
                    "OK (skipped=1)", "FAILED (failures=1, skipped=1)") if complete else
                    f"{identity.rsplit('.', 1)[-1]} ({identity}) ... FAIL\n{MARKER} {root}\n")
                result = subprocess.CompletedProcess([], 9, (MARKER + str(root)).encode(), text.encode())
                output, errors, attempts, original_print = io.StringIO(), io.StringIO(), [], print

                def report(value, **options):
                    event = json.loads(value).get("event") if value.startswith("{") else None
                    if event in ("test_outcome", "windows_qualification_diagnostic"):
                        attempts.append(event)
                        if len(attempts) == fail_at:
                            raise reporter_error(MARKER + str(root))
                    if event == "windows_observer_secondary_failure" and secondary:
                        raise reporter_error(MARKER + str(root))
                    original_print(value, **options)

                with self.unused_outer_capture("close"), contextlib.redirect_stdout(output), \
                        contextlib.redirect_stderr(errors), mock.patch("builtins.print", side_effect=report), \
                        mock.patch.object(qualification, "observer_owning_command", return_value=result) as owned, \
                        mock.patch.object(qualification, "junit_outcomes") as junit:
                    with self.assertRaises(qualification._ObserverResultRefused) as caught:
                        qualification.qualify(root, require_prepared=True, api106_observer_pair=True)
                owned.assert_called_once_with(root)
                junit.assert_not_called()
                primary = caught.exception
                self.assertIs(result, primary.result)
                self.assertIsNone(primary.__cause__)
                self.assertEqual("owning-suite-command-failed", str(primary))
                self.assertEqual(fail_at, len(attempts))
                self.assertIn("Observer secondary failure: captured-python-outcome-report-unavailable", primary.__notes__)
                if secondary:
                    self.assertIn("Observer secondary failure reporting also failed", primary.__notes__)
                records = [json.loads(line) for line in output.getvalue().splitlines() if line.startswith("{")]
                outcomes = [record for record in records if record["event"] == "test_outcome"]
                self.assertEqual(fail_at - 1, len(outcomes))
                if outcomes:
                    self.assertEqual(identity, outcomes[0]["required_test"])
                public = output.getvalue() + errors.getvalue() + "\n".join(primary.__notes__)
                self.assertNotIn(MARKER, public)
                self.assertNotIn(str(root), public)
                self.assertNotIn('"ok": true', public)

    def test_active_owner_refusal_is_not_replaced_by_outer_capture_close(self):
        for kind in ("complete-result", "incomplete-result", "refused", "cleanup"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="observer-active-no-restaging-") as temporary:
                root, identity = Path(temporary), qualification.PYTHON_TARGET
                text = (WindowsOutcomeTests().python_report("FAIL").replace(
                    "OK (skipped=1)", "FAILED (failures=1, skipped=1)") if kind == "complete-result" else
                    f"{identity.rsplit('.', 1)[-1]} ({identity}) ... ERROR\n{MARKER}\n")
                result = subprocess.CompletedProcess([], 1, MARKER.encode(), text.encode())
                cause = OSError(MARKER)
                primary = (qualification._ObserverResultRefused(result, cause) if kind.endswith("-result") else
                           qualification.Refused("observer-state-short-write") if kind == "refused" else cause)
                with self.unused_outer_capture("close"), self.precedence_io(root) as observed, \
                        mock.patch.object(qualification, "observer_owning_command", side_effect=primary) as owned, \
                        mock.patch.object(qualification, "junit_outcomes") as junit:
                    with self.assertRaises(type(primary)) as caught:
                        qualification.qualify(root, require_prepared=True, api106_observer_pair=True)
                self.assertIs(primary, caught.exception)
                owned.assert_called_once_with(root)
                junit.assert_not_called()
                records = [json.loads(line) for line in observed["stdout"].getvalue().splitlines()
                           if line.startswith("{")]
                if kind.endswith("-result"):
                    self.assertIs(result, caught.exception.result)
                    self.assertIs(cause, caught.exception.__cause__)
                    self.assertEqual("owning-suite-command-failed", str(caught.exception))
                    self.assertEqual(2 if kind == "complete-result" else 1, len(records))
                else:
                    self.assertEqual([], records)

    def test_normal_nonzero_result_preserves_failed_junit_outcome(self):
        fixture = WindowsOutcomeTests()
        for task, status in itertools.product(("> Task :test", "> Task :test FAILED"), ("failure", "error")):
            with self.subTest(task=task, status=status), \
                    tempfile.TemporaryDirectory(prefix="observer-nonzero-junit-") as temporary:
                root = Path(temporary)
                result = subprocess.CompletedProcess(
                    [], 7, (task + "\n" + MARKER + str(root)).encode(), fixture.python_report().encode(),
                )
                budget = self.budget(result)

                def run(*unused, **options):
                    fixture.write_junit(root, status)
                    return result

                budget.run.side_effect = run
                with self.unused_outer_capture("close"), self.precedence_io(root) as observed, \
                        mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        mock.patch.object(qualification.time, "monotonic_ns", side_effect=(0, 1)), \
                        mock.patch.object(qualification.subprocess, "run") as direct, \
                        mock.patch.object(qualification, "junit_outcomes", wraps=qualification.junit_outcomes) as junit:
                    with self.assertRaises(qualification._ObserverResultRefused) as caught:
                        qualification.qualify(root, require_prepared=True, api106_observer_pair=True)
                primary = caught.exception
                self.assertIs(result, primary.result)
                self.assertIsNone(primary.__cause__)
                self.assertEqual("owning-suite-command-failed", str(primary))
                self.assertEqual([], getattr(primary, "__notes__", []))
                direct.assert_not_called()
                junit.assert_called_once_with(root)
                self.assertEqual(1, budget.run.call_count)
                self.assertEqual(270, budget.run.call_args.args[2])
                self.assertEqual(1, observed["events"].count("settlement"))
                self.assertEqual(1, observed["events"].count("close"))
                self.assertLess(observed["events"].index("close"), observed["events"].index("report:projection"))
                records = [json.loads(line) for line in observed["stdout"].getvalue().splitlines()
                           if line.startswith("{")]
                outcomes = [record for record in records if record["event"] == "test_outcome"]
                self.assertEqual(["passed", "skipped", "failed" if status == "failure" else "error"],
                                 [record["outcome"] for record in outcomes])
                self.assertEqual(3, len({record["id_sha256"] for record in outcomes}))
                self.assertEqual({
                    "event": "test_outcome", "suite": "junit:test",
                    "id_sha256": hashlib.sha256(
                        (qualification.KOTLIN_CLASS + "\0" + qualification.KOTLIN_METHOD).encode()).hexdigest(),
                    "outcome": "failed" if status == "failure" else "error",
                    "required_test": qualification.KOTLIN_CLASS + "." + qualification.KOTLIN_METHOD,
                }, outcomes[-1])
                self.assertFalse(any(record["event"] == "windows_qualification_diagnostic" for record in records))

    def test_normal_nonzero_junit_diagnostic_is_preserved_before_owning_refusal(self):
        fixture = WindowsOutcomeTests()
        with tempfile.TemporaryDirectory(prefix="observer-nonzero-junit-diagnostic-") as temporary:
            root, output, errors, reports = Path(temporary), io.StringIO(), io.StringIO(), []
            result = subprocess.CompletedProcess([], 7, b"> Task :test FAILED\n", fixture.python_report().encode())

            def run(directory):
                self.assertEqual(root, directory)
                reports.append(fixture.write_junit_cases(root, "TEST-duplicate.xml", [
                    (qualification.KOTLIN_CLASS, qualification.KOTLIN_METHOD),
                    (qualification.KOTLIN_CLASS, qualification.KOTLIN_METHOD),
                ])[1])
                return result

            with self.unused_outer_capture("close"), contextlib.redirect_stdout(output), \
                    contextlib.redirect_stderr(errors), \
                    mock.patch.object(qualification, "observer_owning_command", side_effect=run) as owned:
                with self.assertRaises(qualification._ObserverResultRefused) as caught:
                    qualification.qualify(root, require_prepared=True, api106_observer_pair=True)
            owned.assert_called_once_with(root)
            primary = caught.exception
            self.assertIs(result, primary.result)
            self.assertIsNone(primary.__cause__)
            self.assertEqual("owning-suite-command-failed", str(primary))
            self.assertIn("Observer secondary failure: captured-junit-outcomes-incomplete", primary.__notes__)
            records = [json.loads(line) for line in output.getvalue().splitlines() if line.startswith("{")]
            outcomes = [record for record in records if record["event"] == "test_outcome"]
            self.assertEqual(["passed", "skipped"], [record["outcome"] for record in outcomes])
            diagnostic, = [record for record in records if record["event"] == "windows_qualification_diagnostic"]
            metadata = {
                "bytes": len(reports[0]), "sha256": hashlib.sha256(reports[0]).hexdigest(), "testcase_count": 2,
                "suite_counts": {"tests": 2, "failures": 0, "errors": 0, "skipped": 0}, "metadata_complete": True,
            }
            self.assertEqual({
                "event": "windows_qualification_diagnostic", "diagnostic_only": True,
                "inventory_complete": False, "exit_code": 7, "junit": {
                    "code": "duplicate-junit-case",
                    "id_sha256": hashlib.sha256(
                        (qualification.KOTLIN_CLASS + "\0" + qualification.KOTLIN_METHOD).encode()).hexdigest(),
                    "classname_sha256": hashlib.sha256(qualification.KOTLIN_CLASS.encode()).hexdigest(),
                    "name_sha256": hashlib.sha256(qualification.KOTLIN_METHOD.encode()).hexdigest(),
                    "same_report": True,
                    "first": {"report_position": 1, "case_position": 1, "report": metadata},
                    "current": {"report_position": 1, "case_position": 2, "report": metadata},
                    "prefix": {"selected_reports": 1, "completed_reports": 0, "completed_cases": 1,
                               "encountered_cases": 2},
                },
            }, diagnostic)
            self.assertLess(len(json.dumps(diagnostic).encode()), 4096)
            public = output.getvalue() + errors.getvalue() + "\n".join(primary.__notes__)
            self.assertNotIn(MARKER, public)
            self.assertNotIn(str(root), public)
            self.assertNotIn('"ok": true', public)

    def test_normal_nonzero_junit_io_preserves_primary_without_replaying_outcomes(self):
        fixture = WindowsOutcomeTests()
        cases = [(stage, OSError) for stage in (
            "open", "read", "close", "read-and-close", "parse", "parse-and-close",
            "junit-first", "junit-last", "junit-diagnostic",
        )] + [(stage, ValueError) for stage in ("junit-first", "junit-last", "junit-diagnostic")]
        for (stage, reporter_error), secondary in itertools.product(cases, (False, True)):
            with self.subTest(stage=stage, reporter=reporter_error, secondary=secondary), \
                    tempfile.TemporaryDirectory(prefix="observer-nonzero-junit-io-") as temporary:
                root, output, errors = Path(temporary), io.StringIO(), io.StringIO()
                original_open, original_print = Path.open, print
                failure, streams, attempts, operations = reporter_error(MARKER + str(root)), [], [], []
                result = subprocess.CompletedProcess([], 7, b"> Task :test FAILED\n", fixture.python_report().encode())

                def run(directory):
                    self.assertEqual(root, directory)
                    if stage == "junit-diagnostic":
                        fixture.write_junit_cases(root, "TEST-duplicate.xml", [
                            (qualification.KOTLIN_CLASS, qualification.KOTLIN_METHOD),
                            (qualification.KOTLIN_CLASS, qualification.KOTLIN_METHOD),
                        ])
                    else:
                        fixture.write_junit(root, "failure")
                        fixture.write_junit_cases(root, "TEST-z.xml", [(MARKER, "test_" + MARKER)])
                        if stage.startswith("parse"):
                            (root / qualification.JUNIT / "TEST-fixture.xml").write_bytes(
                                b"<testsuite>" + MARKER.encode() + b"\0</testsuite>")
                    return result

                def opening(path, *arguments, **options):
                    if path.parent != root / qualification.JUNIT or arguments != ("rb",):
                        return original_open(path, *arguments, **options)
                    if stage == "open":
                        raise failure
                    stream = original_open(path, *arguments, **options)
                    streams.append(stream)
                    wrapped = mock.MagicMock(wraps=stream)
                    wrapped.__enter__.return_value = wrapped

                    def read(size):
                        operations.append("read")
                        if stage in ("read", "read-and-close"):
                            raise failure
                        return stream.read(size)

                    def close(*unused):
                        operations.append("close")
                        stream.close()
                        if stage in ("close", "read-and-close", "parse-and-close"):
                            raise failure
                        return False

                    wrapped.read.side_effect = read
                    wrapped.__exit__.side_effect = close
                    return wrapped

                def report(value, **options):
                    record = json.loads(value) if value.startswith("{") else {}
                    event = record.get("event")
                    if event == "test_outcome" and record["suite"] == "junit:test":
                        attempts.append("outcome")
                        if len(attempts) == {"junit-first": 1, "junit-last": 2}.get(stage):
                            raise failure
                    if event == "windows_qualification_diagnostic" and stage == "junit-diagnostic":
                        attempts.append("diagnostic")
                        raise failure
                    if event == "windows_observer_secondary_failure" and secondary:
                        raise failure
                    original_print(value, **options)

                with self.unused_outer_capture("close"), contextlib.redirect_stdout(output), \
                        contextlib.redirect_stderr(errors), mock.patch.object(Path, "open", autospec=True, side_effect=opening), \
                        mock.patch("builtins.print", side_effect=report), \
                        mock.patch.object(qualification, "observer_owning_command", side_effect=run) as owned:
                    with self.assertRaises(qualification._ObserverResultRefused) as caught:
                        qualification.qualify(root, require_prepared=True, api106_observer_pair=True)
                owned.assert_called_once_with(root)
                primary = caught.exception
                self.assertIs(result, primary.result)
                self.assertIsNone(primary.__cause__)
                self.assertEqual("owning-suite-command-failed", str(primary))
                self.assertIn("Observer secondary failure: captured-junit-outcome-report-unavailable", primary.__notes__)
                if secondary:
                    self.assertIn("Observer secondary failure reporting also failed", primary.__notes__)
                self.assertTrue(all(stream.closed for stream in streams))
                self.assertEqual(len(streams), operations.count("close"))
                self.assertEqual({"junit-first": 1, "junit-last": 2, "junit-diagnostic": 1}.get(stage, 0), len(attempts))
                records = [json.loads(line) for line in output.getvalue().splitlines() if line.startswith("{")]
                outcomes = [record for record in records if record["event"] == "test_outcome"]
                self.assertEqual(["passed", "skipped"] + (["failed"] if stage == "junit-last" else []),
                                 [record["outcome"] for record in outcomes])
                self.assertEqual(len(outcomes), len({record["id_sha256"] for record in outcomes}))
                self.assertFalse(any(record["event"] == "windows_qualification_diagnostic" for record in records))
                public = output.getvalue() + errors.getvalue() + "\n".join(primary.__notes__)
                self.assertNotIn(MARKER, public)
                self.assertNotIn(str(root), public)
                self.assertNotIn('"ok": true', public)

    def test_zero_result_reuses_owned_captures_without_outer_temporary_io(self):
        fixture = WindowsOutcomeTests()
        for operation in ("write", "seek", "read", "close"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(prefix="observer-zero-no-restaging-") as temporary:
                root, output = Path(temporary), io.StringIO()
                result = subprocess.CompletedProcess([], 0, b"> Task :test\n", fixture.python_report().encode())

                def run(directory):
                    self.assertEqual(root, directory)
                    fixture.write_junit(root)
                    return result

                with self.unused_outer_capture(operation), contextlib.redirect_stdout(output), \
                        mock.patch.object(qualification, "observer_owning_command", side_effect=run) as owned, \
                        mock.patch.object(qualification.subprocess, "run") as direct:
                    qualification.qualify(root, require_prepared=True, api106_observer_pair=True)
                owned.assert_called_once_with(root)
                direct.assert_not_called()
                records = [json.loads(line) for line in output.getvalue().splitlines() if line.startswith("{")]
                self.assertEqual(3, len([record for record in records if record["event"] == "test_outcome"]))
                self.assertEqual({"event": "windows_qualification", "ok": True, "python_tests": 2, "junit_tests": 1},
                                 records[-1])
                self.assertNotIn(MARKER, output.getvalue())
                self.assertNotIn(str(root), output.getvalue())

    def test_zero_result_later_projection_and_junit_reporting_errors_still_refuse(self):
        fixture = WindowsOutcomeTests()
        for stage, reporter_error in itertools.product(
            ("python-first", "python-last", "junit-outcome", "qualified", "negative-prefix", "junit-diagnostic"),
            (OSError, ValueError),
        ):
            with self.subTest(stage=stage, reporter=reporter_error), \
                    tempfile.TemporaryDirectory(prefix="observer-zero-required-report-") as temporary:
                root, output, errors, original_print = Path(temporary), io.StringIO(), io.StringIO(), print
                identity = qualification.PYTHON_TARGET
                text = (f"{identity.rsplit('.', 1)[-1]} ({identity}) ... ERROR\n{MARKER}\n"
                        if stage == "negative-prefix" else fixture.python_report())
                result = subprocess.CompletedProcess([], 0, b"> Task :test\n", text.encode())
                failure, outcomes = reporter_error(MARKER + str(root)), []

                def run(directory):
                    self.assertEqual(root, directory)
                    if stage == "junit-diagnostic":
                        identities = [(qualification.KOTLIN_CLASS, qualification.KOTLIN_METHOD)] * 2
                        fixture.write_junit_cases(root, "TEST-duplicate.xml", identities)
                    else:
                        fixture.write_junit(root)
                    return result

                def report(value, **options):
                    event = json.loads(value).get("event") if value.startswith("{") else None
                    if event == "test_outcome":
                        outcomes.append(event)
                    if ((event == "test_outcome" and len(outcomes) == {
                            "python-first": 1, "python-last": 2, "junit-outcome": 3,
                        }.get(stage))
                            or (event == "windows_qualification" and stage == "qualified")
                            or (event == "windows_qualification_diagnostic"
                                and stage in ("negative-prefix", "junit-diagnostic"))):
                        raise failure
                    original_print(value, **options)

                with self.unused_outer_capture("close"), contextlib.redirect_stdout(output), \
                        contextlib.redirect_stderr(errors), mock.patch("builtins.print", side_effect=report), \
                        mock.patch.object(qualification, "observer_owning_command", side_effect=run) as owned:
                    with self.assertRaises(reporter_error) as caught:
                        qualification.qualify(root, require_prepared=True, api106_observer_pair=True)
                self.assertIs(failure, caught.exception)
                self.assertNotIsInstance(caught.exception, qualification._ObserverResultRefused)
                owned.assert_called_once_with(root)
                public = output.getvalue() + errors.getvalue()
                self.assertNotIn(MARKER, public)
                self.assertNotIn(str(root), public)
                self.assertNotIn('"ok": true', public)

    def test_ordinary_path_retains_its_two_serial_temporary_captures(self):
        fixture, original_temporary_file = WindowsOutcomeTests(), qualification.tempfile.TemporaryFile
        for require_prepared in (False, True):
            with self.subTest(require_prepared=require_prepared), \
                    tempfile.TemporaryDirectory(prefix="ordinary-capture-preserved-") as temporary:
                with mock.patch.object(qualification.tempfile, "TemporaryFile", wraps=original_temporary_file) as capture, \
                        mock.patch.object(qualification, "observer_owning_command") as observer:
                    records = fixture.exercise(Path(temporary), require_prepared=require_prepared)
                self.assertEqual([mock.call(), mock.call()], capture.call_args_list)
                observer.assert_not_called()
                self.assertEqual({"event": "windows_qualification", "ok": True, "python_tests": 2, "junit_tests": 1},
                                 records[-1])

    def test_runtime_shadowed_tools_or_missing_system_shell_refuse_before_owner_creation(self):
        for name in ("python", "git", "java", "cmd", "powershell"):
            with self.subTest(tool=name), tempfile.TemporaryDirectory(prefix="observer-shadowed-") as temporary:
                root, budget = Path(temporary), self.budget()
                resolve = budget.resolve_command.side_effect
                if name in ("python", "git", "java"):
                    budget.resolve_command.side_effect = (
                        lambda command, environment: [str(root / "unadmitted.exe")] if command[0] == name
                        else resolve(command, environment)
                    )
                else:
                    system = Path(budget.environment.return_value["COMSPEC"]).parent
                    path = system / "cmd.exe" if name == "cmd" else system / "WindowsPowerShell/v1.0/powershell.exe"
                    path.unlink()
                with mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        contextlib.redirect_stdout(io.StringIO()), self.assertRaises((qualification.Refused, OSError)):
                    qualification.observer_owning_command(root)
                budget.run.assert_not_called()
                self.assertFalse((root / qualification.OBSERVER_STATE).exists())

    def test_every_valid_pair_prefix_is_nonaccepting_and_whole_records_are_preserved(self):
        records = self.pair()
        for count in range(7):
            with self.subTest(count=count):
                observed, complete = qualification.observer_pair_records(self.encode(records[:count]))
                self.assertEqual(records[:count], observed)
                self.assertEqual(count == 6, complete)
        records = self.pair()[:3]
        records[-1]["outcome"] = "process-or-cleanup-error"
        records.append({**self.pair()[4], "outcome": "not-executed",
                        "reason": "required-process-or-cleanup-error"})
        for key in ("elapsed_ms", "returncode", "stdout"):
            del records[-1][key]
        records.append({**self.pair()[-1], "required": "process-or-cleanup-error", "auxiliary": "not-executed"})
        self.assertEqual((records, True), qualification.observer_pair_records(self.encode(records)))
        for started in (False, True):
            prefix = self.pair()[:2 if started else 1]
            prefix.append({**records[-2], "role": "required", "reason": "insufficient-complete-arm-budget"})
            self.assertEqual((prefix, False), qualification.observer_pair_records(self.encode(prefix)))

    def test_pair_order_types_envelopes_caps_and_acceptance_drift_refuse_the_whole_input(self):
        changes = (
            lambda rows: rows[0].update(v=True),
            lambda rows: rows[0].update(event=MARKER),
            lambda rows: rows[0].update(enclosing_seconds=61),
            lambda rows: rows[0].update(arm_cleanup_seconds=True),
            lambda rows: rows[1].update(role="auxiliary-no-lookup-delegates"),
            lambda rows: rows[2].update(elapsed_ms=-1),
            lambda rows: rows[2].update(returncode=True),
            lambda rows: rows[2].update(stdout={"text_bytes": 0, "sha256": "a" * 64}),
            lambda rows: rows[2].update(outcome="process-or-cleanup-error"),
            lambda rows: rows[4].update(returncode=1),
            lambda rows: rows[5].update(acceptance=True),
            lambda rows: rows[5].update(auxiliary="work-budget-exceeded"),
            lambda rows: rows.insert(2, copy.deepcopy(rows[1])),
            lambda rows: rows.append(copy.deepcopy(rows[-1])),
        )
        for change in changes:
            records = self.pair()
            change(records)
            with self.subTest(change=change), self.assertRaises(qualification.Refused):
                qualification.observer_pair_records(self.encode(records))
        valid = self.encode(self.pair())
        for data in (valid[:-1], valid + b"\n", valid.replace(b"\n", b"\r\n"), b"\xff\n", b"\x1b\n",
                     b" " * 4097, b" " * 1024 + b"\n", valid.replace(b'"v":1', b'"v":1,"v":1', 1),
                     valid + self.encode(self.pair()[:1])):
            with self.subTest(size=len(data)), self.assertRaises(qualification.Refused):
                qualification.observer_pair_records(data)

    def test_enclosure_prefix_cleanup_and_inventory_do_not_attest_report_close_or_success(self):
        records = self.enclosure()
        for count in range(7):
            prefix = records[:count]
            self.assertEqual((prefix, count == 6), qualification.observer_enclosure_records(self.encode(prefix)))
        for count in range(5):
            prefix = records[:count] + [records[-1]]
            self.assertEqual((prefix, False), qualification.observer_enclosure_records(self.encode(prefix)))
        records[-1]["owned_tree_and_control_released"] = False
        self.assertEqual((records, True), qualification.observer_enclosure_records(self.encode(records)))
        mutations = (
            lambda rows: rows[0].update(work_seconds=60),
            lambda rows: rows[0].update(binding_sha256=MARKER),
            lambda rows: rows[1].update(suite_job_retained=False),
            lambda rows: rows[1].update(known_live_discovery_members=True),
            lambda rows: rows[3].update(elapsed_ms=0),
            lambda rows: rows[4].update(inventory_complete=False),
            lambda rows: rows[4].update(exit_code=True),
            lambda rows: rows[5].update(report_close_not_attested_by_this_record=False),
            lambda rows: rows.pop(1),
            lambda rows: rows.append(rows[-1]),
        )
        for mutate in mutations:
            records = self.enclosure()
            mutate(records)
            with self.subTest(mutate=mutate), self.assertRaises(qualification.Refused):
                qualification.observer_enclosure_records(self.encode(records))
        for data in (b"x" * 8193, b"x" * 1024 + b"\n", self.encode(self.enclosure()[:1] * 9)):
            with self.assertRaises(qualification.Refused):
                qualification.observer_enclosure_records(data)

    def test_boundary_retains_every_legacy_and_c_shape_without_writer_success_inference(self):
        valid = [b"", b"E", b"EU", b"EUX"]
        valid += [("ES" + "".join(flags) + tail).encode("ascii")
                  for flags in itertools.product("01", repeat=3) for tail in ("", "X", "C", "CX")]
        for data in valid:
            with self.subTest(data=data):
                observed = qualification.observer_boundary(data)
                self.assertEqual("observed" if b"C" in data else "not-observed",
                                 observed["pre_record_writer_return"])
                self.assertEqual("after-write-output" if data.endswith(b"X") else "none-observed" if not data
                                 else "command-entry" if data == b"E" else "before-write-output",
                                 observed["checkpoint"])
                self.assertNotIn("write_success", observed)
        for data in (b"C", b"EC", b"EUC", b"EUCX", b"ES1C11", b"ES111XC", b"ES111CC", b"ES111CX\n",
                     b"ES111CXX", b"ES111CX" + b"x" * 8192):
            with self.subTest(data=data[:8]), self.assertRaises(qualification.Refused):
                qualification.observer_boundary(data)

    def test_collector_reads_only_six_settled_carriers_and_keeps_failed_owning_result(self):
        with tempfile.TemporaryDirectory(prefix="observer-collection-") as temporary:
            root = Path(temporary)
            self.custody(root)
            self.carriers(root)
            self.write(root, qualification.LOOKUP.with_name("arbitrary-private.json"), MARKER.encode())
            read = qualification.diagnostic_bytes
            with mock.patch.object(qualification, "diagnostic_bytes", wraps=read) as calls:
                result, records = self.collect(root)
            self.assertEqual(0, result)
            self.assertEqual(list(qualification.OBSERVER_FILES), [row["carrier"] for row in records])
            self.assertEqual([qualification.OBSERVER_STATE, *(path for path, _ in qualification.OBSERVER_FILES.values())],
                             [call.args[1] for call in calls.call_args_list])
            self.assertTrue(all(row["owning_command"] == {"status": "exited", "returncode": 1} for row in records))
            self.assertEqual(self.pair(), records[2]["records"])
            self.assertEqual(self.enclosure(), records[3]["records"])
            self.assertIs(records[-1]["capsule_complete"], False)
            self.assertIs(records[-1]["carrier_complete"], True)

    def test_missing_stale_partial_or_unsettled_custody_never_reads_a_carrier(self):
        for kind in ("missing", "unsettled", "foreign-context", "extra-line", "false-absence", "boolean-version"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="observer-custody-") as temporary:
                root = Path(temporary)
                self.carriers(root)
                if kind != "missing":
                    state = self.custody(root, settle=kind != "unsettled")
                    data = state.read_bytes()
                    if kind == "foreign-context":
                        data = data.replace(qualification.observer_context(root).encode("ascii"), b"f" * 64)
                    if kind == "extra-line":
                        data += b"{}\n"
                    if kind == "false-absence":
                        data = data.replace(b'"all_six_absent":true', b'"all_six_absent":1')
                    if kind == "boolean-version":
                        data = data.replace(b'"v":1', b'"v":true')
                    state.write_bytes(data)
                with mock.patch.object(qualification, "diagnostic_bytes", wraps=qualification.diagnostic_bytes) as calls:
                    result, rows = self.collect(root)
                self.assertEqual(2, result)
                self.assertEqual(["collection"], [row["carrier"] for row in rows])
                self.assertEqual([qualification.OBSERVER_STATE], [call.args[1] for call in calls.call_args_list])

    def test_partial_malformed_oversized_or_changed_carriers_never_publish_valid_prefixes_as_complete(self):
        cases = (
            ("pair", self.encode(self.pair()[:3]), "partial"),
            ("pair", self.encode(self.pair()) + b"{}\n", "refused"),
            ("enclosure", self.encode(self.enclosure()[:-1]), "partial"),
            ("enclosure", b"x" * 8193, "refused"),
            ("required-boundary", b"ES111CXX", "refused"),
            ("required-lookup", WindowsShellLookupDiagnosticTests().encode(
                WindowsShellLookupDiagnosticTests().v2_records()[:3]), "partial"),
            ("auxiliary-lookup", WindowsShellLookupDiagnosticTests().encode(
                WindowsShellLookupDiagnosticTests().v2_records()), "refused"),
        )
        for carrier, data, status in cases:
            with self.subTest(carrier=carrier, status=status), tempfile.TemporaryDirectory(prefix="observer-refusal-") as temporary:
                root = Path(temporary)
                self.custody(root)
                self.carriers(root)
                self.write(root, qualification.OBSERVER_FILES[carrier][0], data)
                result, rows = self.collect(root)
                self.assertEqual(2, result)
                selected, = [row for row in rows if row["carrier"] == carrier]
                self.assertEqual(status, selected["status"])
                self.assertIs(selected["carrier_complete"], False)
                if status == "refused":
                    self.assertNotIn("records", selected)
                    self.assertNotIn("observation", selected)
        with tempfile.TemporaryDirectory(prefix="observer-link-") as temporary:
            root = Path(temporary)
            state = self.custody(root)
            os.link(state, state.with_suffix(".linked"))
            self.assertEqual("nonregular-path", self.collect(root)[1][0]["code"])

    def test_same_job_binding_rejects_context_drift_without_exporting_environment(self):
        environment = {
            "GITHUB_ACTIONS": "true", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": "PenniLogic/api", "GITHUB_REPOSITORY_ID": "1394134582",
            "GITHUB_REPOSITORY_OWNER_ID": "335295566", "GITHUB_JOB": "windows", "GITHUB_SHA": "a" * 40,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GH_TOKEN": MARKER,
        }
        with tempfile.TemporaryDirectory(prefix="observer-context-") as temporary:
            root = Path(temporary)
            with mock.patch.dict(qualification.os.environ, environment, clear=True):
                self.custody(root)
                self.carriers(root)
                self.assertEqual(0, self.collect(root)[0])
                for key, replacement in (("GITHUB_RUN_ID", "124"), ("GITHUB_RUN_ATTEMPT", "2"),
                                         ("GITHUB_JOB", "ci"), ("GITHUB_REPOSITORY_ID", "1394135059"),
                                         ("GITHUB_REPOSITORY_OWNER_ID", "1"), ("GITHUB_SHA", "b" * 40),
                                         ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_ACTIONS", "false"),
                                         ("GITHUB_ACTIONS", "True")):
                    with self.subTest(key=key), mock.patch.dict(qualification.os.environ, {key: replacement}):
                        self.assertEqual(2, self.collect(root)[0])

    def test_each_fixed_read_uses_one_overflow_byte_and_checks_reparse_and_file_identity(self):
        with tempfile.TemporaryDirectory(prefix="observer-read-bound-") as temporary:
            root = Path(temporary)
            native_open, native_lstat, native_fstat = qualification.os.fdopen, Path.lstat, qualification.os.fstat
            readers = []

            @contextlib.contextmanager
            def bounded_read(descriptor, mode, **options):
                with native_open(descriptor, mode, **options) as stream:
                    reader = mock.Mock(wraps=stream)
                    readers.append(reader)
                    yield reader

            for relative, limit in qualification.OBSERVER_FILES.values():
                path = self.write(root, relative, b"x" * (limit + 20))
                with mock.patch.object(qualification.os, "fdopen", side_effect=bounded_read):
                    self.assertEqual(limit + 1, len(qualification.diagnostic_bytes(root, relative, limit)))
                readers[-1].read.assert_called_once_with(limit + 1)

            relative, limit = qualification.OBSERVER_FILES["auxiliary-boundary"]
            path = root / relative
            for guarded in (root, root / "build", path.parent, path):
                def lstat(candidate):
                    return (mock.Mock(st_mode=qualification.stat.S_IFREG, st_file_attributes=0x400)
                            if candidate == guarded else native_lstat(candidate))

                with self.subTest(reparse=guarded.name), mock.patch.object(Path, "lstat", autospec=True, side_effect=lstat), \
                        mock.patch.object(qualification.os, "open") as reader:
                    with self.assertRaisesRegex(qualification.Refused, "reparse-path"):
                        qualification.diagnostic_bytes(root, relative, limit)
                    reader.assert_not_called()
            for field in ("st_ino", "st_size", "st_mtime_ns"):
                calls = []

                def fstat(descriptor):
                    metadata = native_fstat(descriptor)
                    calls.append(metadata)
                    if len(calls) == 2:
                        values = {key: getattr(metadata, key)
                                  for key in ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns")}
                        values[field] += 1
                        return mock.Mock(**values)
                    return metadata

                with self.subTest(changed=field), mock.patch.object(qualification.os, "fstat", side_effect=fstat):
                    with self.assertRaisesRegex(qualification.Refused, "file-changed"):
                        qualification.diagnostic_bytes(root, relative, limit)

    def test_worst_case_lookup_projection_remains_bounded_and_never_truncates_roots(self):
        lookup = WindowsShellLookupDiagnosticTests()
        records = lookup.v2_records()
        records[0]["roots"] = [
            {"i": index, "kind": "unknown", "sha256": hashlib.sha256(str(index).encode("ascii")).hexdigest(),
             "duplicate_of": None} for index in range(32)
        ]
        records[2]["ms"] = 100000
        records[3]["ms"] = 600000
        records[4].update(ms=600000, lookup_ms=500000, command_type=256)
        with tempfile.TemporaryDirectory(prefix="observer-public-bound-") as temporary:
            root = Path(temporary)
            self.custody(root)
            self.carriers(root)
            self.write(root, qualification.LOOKUP, lookup.encode(records))
            result, rows = self.collect(root)
            self.assertEqual(0, result)
            required, = [row for row in rows if row["carrier"] == "required-lookup"]
            self.assertEqual(32, len(required["records"][0]["roots"]))
            size = len(json.dumps(required, sort_keys=True, separators=(",", ":")).encode("ascii")) + len(os.linesep)
            self.assertLessEqual(size, 4096)
            with mock.patch.object(qualification, "DIAGNOSTIC_BYTE_LIMIT", size - 1):
                result, rows = self.collect(root)
            self.assertEqual(2, result)
            required, = [row for row in rows if row["carrier"] == "required-lookup"]
            self.assertEqual("projection-limit", required["code"])
            self.assertNotIn("records", required)

    def test_cli_is_explicit_default_off_and_collection_never_launches_owning_work(self):
        with mock.patch.object(qualification.sys, "platform", "win32"), \
                mock.patch.object(qualification, "qualify") as qualify, \
                mock.patch.object(qualification, "collect_observer_diagnostics", return_value=2) as collect:
            with mock.patch.dict(qualification.os.environ, {"PENNILOGIC_API106_OBSERVER_PAIR": "true"}):
                self.assertEqual(0, qualification.main(["--require-prepared"]))
            qualify.assert_called_once_with(qualification.ROOT, require_prepared=True)
            qualify.reset_mock()
            self.assertEqual(0, qualification.main(["--require-prepared", "--api106-observer-pair"]))
            qualify.assert_called_once_with(qualification.ROOT, require_prepared=True, api106_observer_pair=True)
            qualify.reset_mock()
            self.assertEqual(2, qualification.main(["--collect-api106-observer-pair"]))
            collect.assert_called_once_with(qualification.ROOT)
            qualify.assert_not_called()
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                qualification.main(["--api106-observer-pair", "--collect-api106-observer-pair"])

    def test_unapproved_whole_command_budget_and_unprepared_inputs_refuse_before_work(self):
        self.assertEqual((270, 300), (qualification.OBSERVER_COMMAND_SECONDS, qualification.OBSERVER_CLOSED_SECONDS))
        with tempfile.TemporaryDirectory(prefix="observer-not-admitted-") as temporary:
            root = Path(temporary)
            self.runtime_selection.side_effect = qualification.Refused("observer-same-job-preparation")
            with mock.patch.object(qualification, "observer_budget_module") as module, \
                    mock.patch.object(qualification.subprocess, "run") as direct:
                with self.assertRaisesRegex(qualification.Refused, "observer-same-job-preparation"):
                    qualification.qualify(root, require_prepared=True, api106_observer_pair=True)
                module.assert_called_once_with(root)
                module.reset_mock()
                with self.assertRaisesRegex(qualification.Refused, "observer-pair-requires-prepared"):
                    qualification.qualify(root, api106_observer_pair=True)
                module.assert_not_called()
                direct.assert_not_called()
            self.assertFalse((root / qualification.OBSERVER_STATE).exists())
            for invalid in (None, False, True, 0, -1, 269, 271, 300, "270", float("inf")):
                with self.subTest(allowance=invalid), mock.patch.object(qualification, "OBSERVER_COMMAND_SECONDS", invalid), \
                        mock.patch.object(qualification, "observer_budget_module") as module:
                    with self.assertRaisesRegex(qualification.Refused, "observer-whole-command-budget-unapproved"):
                        qualification.observer_owning_command(root)
                    module.assert_not_called()

    def test_mocked_whole_command_uses_existing_owner_capture_and_exact_full_suite_argv(self):
        with tempfile.TemporaryDirectory(prefix="observer-command-") as temporary:
            root = Path(temporary)
            budget = self.budget()
            with mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                    mock.patch.object(qualification.subprocess, "run") as direct:
                result = qualification.observer_owning_command(root)
                direct.assert_not_called()
            self.assertEqual(1, result.returncode)
            budget.run.assert_called_once_with(
                [sys.executable, str(root / "scripts/quality.py"), "test", "--require-prepared", "--api106-observer-pair"],
                root, 270, capture=True, separate=True, env=budget.environment.return_value,
            )
            self.runtime_selection.assert_called_once_with(root, budget)
            budget.environment.assert_called_once_with(supplied={"CI": "true", "JAVA_HOME": "synthetic-jdk"},
                                                       runtime_dirs=[Path("synthetic-git-directory")])
            state = [json.loads(line) for line in (root / qualification.OBSERVER_STATE).read_bytes().splitlines()]
            self.assertEqual({"v": 1, "phase": "settled", "status": "exited", "returncode": 1}, state[-1])
            before = (root / qualification.OBSERVER_STATE).read_bytes()
            with mock.patch.object(qualification, "observer_budget_module") as module:
                with self.assertRaisesRegex(qualification.Refused, "observer-preexisting-diagnostic"):
                    qualification.observer_owning_command(root)
                module.assert_not_called()
            self.assertEqual(before, (root / qualification.OBSERVER_STATE).read_bytes())

    def test_each_stale_carrier_and_wrong_budget_source_refuses_before_import_or_spawn(self):
        for relative, _ in qualification.OBSERVER_FILES.values():
            with self.subTest(relative=relative.name), tempfile.TemporaryDirectory(prefix="observer-stale-") as temporary:
                root = Path(temporary)
                path = self.write(root, relative, MARKER.encode())
                with mock.patch.object(qualification, "observer_budget_module") as module:
                    with self.assertRaisesRegex(qualification.Refused, "observer-preexisting-diagnostic"):
                        qualification.observer_owning_command(root)
                    module.assert_not_called()
                self.assertEqual(MARKER.encode(), path.read_bytes())
                self.assertFalse((root / qualification.OBSERVER_STATE).exists())
        with tempfile.TemporaryDirectory(prefix="observer-owner-pin-") as temporary:
            root = Path(temporary)
            self.write(root, Path("scripts/process_budget.py"), b"raise AssertionError('must not import')\n")
            with self.assertRaisesRegex(qualification.Refused, "observer-budget-source"):
                qualification.observer_budget_module(root)

    def test_state_finalization_and_close_failures_cannot_replace_the_primary_budget_failure(self):
        for failed_operation in ("record", "close"):
            with self.subTest(operation=failed_operation), tempfile.TemporaryDirectory(prefix="observer-state-error-") as temporary:
                root = Path(temporary)
                budget = self.budget()
                primary = budget.BudgetExceeded()
                budget.run.side_effect = primary
                original_record = qualification.observer_state_record
                original_open = Path.open
                streams = []

                def record(stream, directory, fields):
                    if failed_operation == "record" and fields["phase"] == "settled":
                        raise OSError(MARKER)
                    original_record(stream, directory, fields)

                def opening(path, *args, **kwargs):
                    stream = original_open(path, *args, **kwargs)
                    streams.append(stream)
                    if failed_operation == "close":
                        wrapped = mock.Mock(wraps=stream)

                        def close():
                            stream.close()
                            raise OSError(MARKER)

                        wrapped.close.side_effect = close
                        return wrapped
                    return stream

                output, errors = io.StringIO(), io.StringIO()
                with mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        mock.patch.object(qualification, "observer_state_record", side_effect=record), \
                        mock.patch.object(Path, "open", autospec=True, side_effect=opening), \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    with self.assertRaises((qualification.Refused, budget.BudgetExceeded)) as caught:
                        qualification.observer_owning_command(root)
                self.assertTrue(all(stream.closed for stream in streams))
                self.assertTrue(caught.exception is primary or caught.exception.__cause__ is primary)
                self.assertIn("state-finalization" if failed_operation == "record" else "state-close-unconfirmed",
                              errors.getvalue())
                self.assertNotIn(MARKER, output.getvalue() + errors.getvalue())

    def test_a_short_prepared_record_never_releases_the_mocked_owner(self):
        with tempfile.TemporaryDirectory(prefix="observer-short-state-") as temporary:
            root = Path(temporary)
            budget = self.budget()
            original_open = Path.open
            streams = []

            def opening(path, *args, **kwargs):
                stream = original_open(path, *args, **kwargs)
                streams.append(stream)
                wrapped = mock.Mock(wraps=stream)
                wrapped.write.side_effect = lambda data: stream.write(data[:1])
                return wrapped

            with mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                    mock.patch.object(Path, "open", autospec=True, side_effect=opening):
                with self.assertRaisesRegex(qualification.Refused, "observer-state-short-write"):
                    qualification.observer_owning_command(root)
            budget.run.assert_not_called()
            self.assertTrue(all(stream.closed for stream in streams))
            self.assertEqual("partial-line", self.collect(root)[1][0]["code"])

    def test_budget_and_cleanup_errors_keep_failure_precedence_and_unconfirmed_custody_closed(self):
        for failure in ("budget", "output", "cleanup"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix="observer-failure-") as temporary:
                root = Path(temporary)
                budget = self.budget()
                error = (budget.BudgetExceeded() if failure == "budget" else
                         budget.OutputExceeded() if failure == "output" else OSError(MARKER))
                budget.run.side_effect = error
                output = io.StringIO()
                with mock.patch.object(qualification, "observer_budget_module", return_value=budget), \
                        contextlib.redirect_stdout(output):
                    with self.assertRaises(qualification.Refused if failure != "cleanup" else OSError) as caught:
                        qualification.observer_owning_command(root)
                self.assertNotIn(MARKER, output.getvalue())
                state = (root / qualification.OBSERVER_STATE).read_bytes().splitlines()
                self.assertEqual(1 if failure == "cleanup" else 2, len(state))
                if failure == "cleanup":
                    self.assertIs(error, caught.exception)
                    self.assertEqual("observer-owner-not-settled", self.collect(root)[1][0]["code"])
                else:
                    self.assertIs(error, caught.exception.__cause__)
                    record, = [json.loads(line) for line in output.getvalue().splitlines()
                               if json.loads(line)["event"] == "windows_observer_owning_failure"]
                    self.assertEqual(failure + "-budget-exceeded" if failure == "output" else "work-budget-exceeded",
                                     record["code"])
                    self.assertLessEqual(len(output.getvalue().encode("ascii")), 4096)

    def test_paired_result_does_not_bypass_existing_complete_discovery_junit_or_exit_gates(self):
        fixture = WindowsOutcomeTests()
        for exit_code, task in ((0, "> Task :test"), (1, "> Task :test"), (0, "> Task :test FROM-CACHE")):
            with self.subTest(exit_code=exit_code, task=task), tempfile.TemporaryDirectory(prefix="observer-outcomes-") as temporary:
                root = Path(temporary)

                def run(unused_root):
                    fixture.write_junit(root)
                    return subprocess.CompletedProcess([], exit_code, (task + "\n").encode(),
                                                       fixture.python_report().encode())

                output = io.StringIO()
                with mock.patch.object(qualification, "observer_owning_command", side_effect=run) as owned, \
                        mock.patch.object(qualification.subprocess, "run") as direct, contextlib.redirect_stdout(output):
                    if exit_code or "FROM-CACHE" in task:
                        with self.assertRaises(qualification.Refused):
                            qualification.qualify(root, require_prepared=True, api106_observer_pair=True)
                        self.assertNotIn('"ok": true', output.getvalue())
                    else:
                        qualification.qualify(root, require_prepared=True, api106_observer_pair=True)
                        self.assertIn('"ok": true', output.getvalue())
                    owned.assert_called_once_with(root)
                    direct.assert_not_called()


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
