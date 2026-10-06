"""Android-only runtime/inventory plumbing; synthetic seams are not native or RC evidence."""

import contextlib
import copy
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import conformance_support as support
from conformance import steps


ACCEPTED_BASE = "1360c30a5caaff8039d76d57bfb9b060cf81a351"
RESTORE = "python -m pip install -r scripts/privacy_traffic/requirements.txt"
SELF_TEST = "python scripts/privacy_traffic_harness.py self-test"
INVENTORY = "python scripts/check_privacy_components.py"
TASK = ":app:privacyComponentInventory"
PREFIX = "PRIVACY_COMPONENT_INVENTORY "
CHANGED_ARTIFACTS = {
    "AGENTS.md", "README.md", "CONTRIBUTING.md", ".github/agent-policy.json",
    ".github/workflows/ci.yml", ".github/workflows/copilot-setup-steps.yml",
    "scripts/check_privacy_components.py",
}
API_PIN_AND_ADMISSION_ARTIFACTS = {
    "AGENTS.md", "README.md", "CONTRIBUTING.md", ".github/agent-policy.json",
    ".github/workflows/ci.yml", "scripts/materialize_money_sources.py",
    "scripts/prepare_database_admission.py", "src/main/resources/database-admission-installation.json",
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CanonicalPrivacyTests(unittest.TestCase):
    def test_only_android_artifacts_and_explicit_api_pin_and_admission_deltas_change_the_accepted_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in (
                "generate.py", "repository-profiles.json", "templates/check_repository.py",
                "templates/setup.py", "templates/pr_workflow_integrity.py",
                "templates/pr_workflow_integrity_checker.py", "api-money-sources.json",
                "templates/materialize_money_sources.py",
            ):
                content = subprocess.run(
                    ["git", "show", f"{ACCEPTED_BASE}:governance/{path}"],
                    cwd=support.GOVERNANCE.parent, env=support.defects.probe_environment(),
                    capture_output=True, check=True, timeout=30,
                ).stdout
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            accepted = load("accepted_android_privacy_baseline", root / "generate.py")
            current = support.generator
            for repo in current.PROFILES["repositories"]:
                with self.subTest(repo=repo):
                    previous = accepted.artifacts(repo)
                    candidate = current.artifacts(repo)
                    changed = {
                        path for path in previous.keys() | candidate.keys()
                        if previous.get(path) != candidate.get(path)
                    }
                    self.assertEqual(CHANGED_ARTIFACTS if repo == "android" else
                                     API_PIN_AND_ADMISSION_ARTIFACTS if repo == "api" else set(), changed)
                    if repo == "api":
                        expected = copy.deepcopy(accepted.PROFILES["repositories"][repo])
                        expected["commands"][2] = expected["commands"][2].replace(
                            "contracts-ea56c63d5c9b679537bd9205b04626049c20c572",
                            "contracts-aa8d90cb98cec9b6dd08c91b3a4d869e47362662",
                        )
                        self.assertEqual(expected, current.PROFILES["repositories"][repo])
                    elif repo != "android":
                        self.assertEqual(accepted.PROFILES["repositories"][repo],
                                         current.PROFILES["repositories"][repo])
            original = copy.deepcopy(accepted.PROFILES)
            original["repositories"]["android"]["install"] = [RESTORE]
            original["repositories"]["android"]["commands"] = current.profile_for("android")["commands"]
            original["repositories"]["api"]["commands"][2] = original["repositories"]["api"]["commands"][2].replace(
                "contracts-ea56c63d5c9b679537bd9205b04626049c20c572",
                "contracts-aa8d90cb98cec9b6dd08c91b3a4d869e47362662",
            )
            self.assertEqual(original, current.PROFILES)

    def test_accepted_money_inputs_flags_and_registry_survive_android_composition(self):
        current_registry = json.loads((support.GOVERNANCE / "conformance/check-names.json").read_bytes())
        api_source = next(entry["workflow_ref"] for entry in current_registry["entries"]
                          if entry["repo"] == "PenniLogic/api")
        for path in ("governance/api-money-sources.json", "governance/templates/materialize_money_sources.py"):
            with self.subTest(path=path):
                source = api_source if path.endswith("materialize_money_sources.py") else ACCEPTED_BASE
                accepted = subprocess.run(
                    ["git", "show", f"{source}:{path}"],
                    cwd=support.GOVERNANCE.parent, env=support.defects.probe_environment(),
                    capture_output=True, check=True, timeout=30,
                ).stdout
                current = (support.GOVERNANCE.parent / path).read_text(encoding="utf-8").encode("utf-8")
                if path.endswith("api-money-sources.json"):
                    old, updated = json.loads(accepted), json.loads(current)
                    updated["sources"][0]["commit"] = old["sources"][0]["commit"]
                    updated["sources"][0]["snapshot"] = old["sources"][0]["snapshot"]
                    changed_inputs = {
                        "runtime/kotlin/src/main/kotlin/com/pennilogic/contracts/money/Money.kt",
                        "generator/golden.json",
                    }
                    originals = {entry["path"]: entry for entry in old["sources"][0]["files"]}
                    updated["sources"][0]["files"] = [
                        originals[entry["path"]] if entry["path"] in changed_inputs else entry
                        for entry in updated["sources"][0]["files"]
                    ]
                    updated["provider_outputs"][0] = old["provider_outputs"][0]
                    updated["provider_outputs"][2] = old["provider_outputs"][2]
                    self.assertEqual(old, updated)
                else:
                    self.assertEqual(accepted, current)
        accepted = json.loads(subprocess.run(
            ["git", "show", f"{ACCEPTED_BASE}:governance/conformance/check-names.json"],
            cwd=support.GOVERNANCE.parent, env=support.defects.probe_environment(),
            capture_output=True, check=True, timeout=30,
        ).stdout)
        current = current_registry
        expected = copy.deepcopy(accepted)
        android = next(entry for entry in expected["entries"] if entry["repo"] == "PenniLogic/android")
        android["workflow_ref"] = "1a540182f48a492772e5230219306632528c3967"
        api = next(entry for entry in expected["entries"] if entry["repo"] == "PenniLogic/api")
        api["workflow_ref"] = next(entry["workflow_ref"] for entry in current["entries"]
                                   if entry["repo"] == "PenniLogic/api")
        self.assertEqual(expected, current)

    def test_commands_restore_declared_requirements_and_preserve_every_old_gate(self):
        commands = support.generator.profile_for("android")["commands"]
        self.assertEqual([
            "python scripts/check_repository.py", RESTORE,
            "python scripts/quality_gates.py ci", "python scripts/quality_gates.py self-test",
            SELF_TEST, INVENTORY, 'python -m unittest discover -s scripts/tests -p "test_*.py"',
        ], commands)
        self.assertNotIn("run-rc", "\n".join(commands))
        self.assertEqual([RESTORE], support.generator.profile_for("android")["install"])
        for setup in (False, True):
            document = json.loads(support.generator.workflow("android", setup=setup))
            job = document["jobs"]["copilot-setup-steps" if setup else "ci"]
            self.assertEqual("Copilot setup" if setup else "CI", job["name"])
            self.assertEqual("ubuntu-24.04", job["runs-on"])
            self.assertEqual(30, job["timeout-minutes"])
            self.assertEqual({"contents": "read"}, document["permissions"])
            self.assertNotIn("env", job)
            self.assertEqual({"python-version": "3.14"}, job["steps"][1]["with"])
            self.assertEqual({"distribution": "temurin", "java-version": "21"}, job["steps"][2]["with"])
            if setup:
                install = next(step for step in job["steps"] if step["name"] == "Install dependencies")
                self.assertEqual(RESTORE, install["run"])
            else:
                self.assertEqual(commands, steps.workflow_run_commands(
                    support.generator.workflow("android").encode("utf-8"),
                ))

    def test_privacy_commands_have_exact_categories_without_borrowing_native_gates(self):
        self.assertEqual(["test"], steps.classify(SELF_TEST))
        self.assertEqual(["checker"], steps.classify(INVENTORY))
        for command in (SELF_TEST, INVENTORY):
            for altered in (
                "echo " + command, command + " --skip", command + " || true",
                command + "; true", command + " ", command.replace("python ", "python3 ", 1),
                command.replace("/", "\\"), command + "\n",
            ):
                with self.subTest(command=altered):
                    self.assertEqual(["other"], steps.classify(altered))
                    self.assertEqual([], steps.detect_steps([altered])["consumer_self_tests"])
        commands = [
            command for command in support.generator.profile_for("android")["commands"]
            if command != "python scripts/quality_gates.py ci"
        ]
        self.assertEqual(["build", "lint"], steps.missing_categories(
            steps.detect_steps(commands), ("build", "test", "lint"),
        ))

    def test_cli_regeneration_refuses_each_removed_or_stubbed_privacy_command_and_recovers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invocation = [
                sys.executable, str(support.GOVERNANCE / "generate.py"),
                "--repository", "android", "--root", str(root),
            ]
            subprocess.run(invocation, capture_output=True, check=True, timeout=30)
            path = root / ".github" / "workflows" / "ci.yml"
            original = path.read_bytes()
            for command in (RESTORE, SELF_TEST, INVENTORY):
                for replacement in (None, "echo privacy skipped"):
                    with self.subTest(command=command, replacement=replacement):
                        document = json.loads(original)
                        run = next(step for step in document["jobs"]["ci"]["steps"]
                                   if step["name"] == "Run checks")
                        commands = run["run"].split("\n")
                        index = commands.index(command)
                        if replacement is None:
                            commands.pop(index)
                        else:
                            commands[index] = replacement
                        run["run"] = "\n".join(commands)
                        path.write_bytes(support.generator.encoded(document).encode("utf-8"))
                        refused = subprocess.run(
                            [*invocation, "--check"], capture_output=True, timeout=30, check=False,
                            text=True, encoding="utf-8",
                        )
                        self.assertEqual(1, refused.returncode)
                        self.assertEqual("Generated setup differs: .github/workflows/ci.yml\n", refused.stderr)
                        path.write_bytes(original)
                        subprocess.run([*invocation, "--check"], capture_output=True, check=True, timeout=30)

    def test_android_helper_is_generated_once_and_generation_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            support.generator.generate("android", root)
            original = support.tree_digest(root)
            helper = root / "scripts" / "check_privacy_components.py"
            self.assertEqual(
                (support.GOVERNANCE / "templates" / "check_privacy_components.py")
                .read_text(encoding="utf-8").encode("utf-8"),
                helper.read_bytes(),
            )
            support.generator.generate("android", root)
            self.assertEqual(original, support.tree_digest(root))
            support.generator.generate("android", root, check=True)
            helper.unlink()
            with self.assertRaisesRegex(ValueError, "scripts/check_privacy_components.py"):
                support.generator.generate("android", root, check=True)


class SourceRefusal(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def source_require(condition, code):
    if not condition:
        raise SourceRefusal(code)


class InventoryPlumbingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.native = mock.Mock()
        self.harness = mock.Mock(return_value=0)
        self.physical = mock.Mock(side_effect=lambda path: path)
        modules = {
            "privacy_traffic.safety": types.SimpleNamespace(
                MAX_DOCUMENT_BYTES=262_144, Refusal=SourceRefusal,
                physical=self.physical, require=source_require,
            ),
            "privacy_traffic_harness": types.SimpleNamespace(main=self.harness),
            "quality_gates": types.SimpleNamespace(
                EXECUTED="executed", ROOT=self.root, run_gradle=self.native,
                task_labels=lambda console: {TASK: ["executed"]},
            ),
        }
        with mock.patch.dict(sys.modules, modules):
            self.helper = load("synthetic_privacy_inventory_plumbing",
                               support.GOVERNANCE / "templates" / "check_privacy_components.py")
        self.raw = b'{"schema_version":1,"variants":{"debug":["synthetic:component:1"],"release":[]}}'
        self.native.return_value = types.SimpleNamespace(
            exit_code=0, console=f"> Task {TASK}\n{PREFIX}{self.raw.decode()}\nBUILD SUCCESSFUL\n",
        )

    def invoke(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.helper.main()
        return code, out.getvalue(), err.getvalue()

    def test_only_current_native_json_is_given_to_the_actual_harness_entry_point(self):
        seen = []

        def inspect(arguments):
            self.assertEqual("check-components", arguments[0])
            path = Path(arguments[1])
            self.assertTrue(path.is_relative_to(self.root / "build"))
            self.assertEqual(self.raw, path.read_bytes())
            seen.append(path)
            return 0

        self.harness.side_effect = inspect
        for _ in range(2):
            self.assertEqual((0, "", ""), self.invoke())
        self.assertNotEqual(seen[0], seen[1])
        self.assertTrue(all(not path.exists() and not path.parent.exists() for path in seen))
        self.assertEqual([], list((self.root / "build").iterdir()))
        self.native.assert_called_with(
            (TASK,), ("--init-script", str(self.root / "scripts" / "privacy_traffic" / "components.init.gradle"),
                      "--no-configuration-cache"),
        )
        self.assertEqual(2, self.harness.call_count)

    def test_failed_native_resolution_never_calls_the_assertion(self):
        self.native.return_value.exit_code = 7
        code, _, err = self.invoke()
        self.assertEqual(7, code)
        self.assertIn("native resolution failed", err)
        self.harness.assert_not_called()
        self.assertFalse((self.root / "build").exists())

    def test_missing_duplicate_malformed_prefix_or_empty_and_oversized_payload_are_refused(self):
        cases = [
            ("BUILD SUCCESSFUL\n", "component_inventory_prefix_refused"),
            (f"{PREFIX}{{}}\n{PREFIX}{{}}\n", "component_inventory_prefix_refused"),
            ("PRIVACY_COMPONENT_INVENTORY\t{}\n", "component_inventory_prefix_refused"),
            (PREFIX + "\n", "component_inventory_size_refused"),
            (PREFIX + "x" * 262_145 + "\n", "component_inventory_size_refused"),
        ]
        for console, expected in cases:
            with self.subTest(code=expected):
                self.native.return_value.console = console
                code, _, err = self.invoke()
                self.assertEqual(2, code)
                self.assertEqual({"code": expected, "release_qualified": False}, json.loads(err))
                self.harness.assert_not_called()
                self.assertFalse((self.root / "build").exists())

    def test_stale_missing_and_reused_task_outcomes_cannot_supply_evidence(self):
        for labels in (None, [], ["UP-TO-DATE"], ["FROM-CACHE"], ["SKIPPED"], ["NO-SOURCE"],
                       ["executed", "executed"], ["executed", "UP-TO-DATE"]):
            with self.subTest(labels=labels), mock.patch.object(
                self.helper, "task_labels", return_value={} if labels is None else {TASK: labels},
            ):
                code, _, err = self.invoke()
                self.assertEqual(2, code)
                self.assertEqual("component_inventory_not_fresh", json.loads(err)["code"])
                self.harness.assert_not_called()

    def test_existing_inventory_is_never_read_replaced_or_a_success_fallback(self):
        build = self.root / "build"
        build.mkdir()
        old = build / "privacy-component-inventory.json"
        old.write_bytes(b"synthetic stale sentinel")
        self.native.return_value.console = "BUILD SUCCESSFUL\n"
        self.assertEqual(2, self.invoke()[0])
        self.assertEqual(b"synthetic stale sentinel", old.read_bytes())
        self.harness.assert_not_called()

    def test_source_assertion_refusals_are_returned_unchanged_and_owned_file_is_cleaned(self):
        for code in (1, 2):
            with self.subTest(code=code):
                self.harness.return_value = code
                self.assertEqual(code, self.invoke()[0])
                self.assertEqual([], list((self.root / "build").iterdir()))

    def test_source_physical_path_refusal_is_explicit_and_native_never_starts(self):
        self.physical.side_effect = SourceRefusal("path_alias_refused")
        code, _, err = self.invoke()
        self.assertEqual(2, code)
        self.assertEqual({"code": "path_alias_refused", "release_qualified": False}, json.loads(err))
        self.native.assert_not_called()

    def test_io_failure_is_explicit_not_an_invalid_input_success(self):
        self.native.side_effect = OSError("synthetic unavailable wrapper")
        code, _, err = self.invoke()
        self.assertEqual(2, code)
        self.assertIn("owned input/output operation failed", err)
        self.harness.assert_not_called()

    def test_unconfirmed_native_shutdown_propagates_without_creating_or_cleaning_fixtures(self):
        self.native.side_effect = RuntimeError("synthetic unsafe native lifetime")
        with self.assertRaisesRegex(RuntimeError, "unsafe native lifetime"):
            self.invoke()
        self.harness.assert_not_called()
        self.assertFalse((self.root / "build").exists())


if __name__ == "__main__":
    unittest.main()
