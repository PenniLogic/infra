"""Step detection and check-name production (PenniLogic/infra#24 addendum items 1 and 2): every
profile has a real test step, unknown commands never count as tests, each rendered ci.yml produces
exactly the required native check, and a required context without a producing workflow is
reported as missing."""

import json
from pathlib import Path
import tempfile
import unittest

import conformance_support as support
from conformance import defects, github_api, run, steps
from test_api_node_runtime import BUILD_COMMAND


class ClassificationTests(unittest.TestCase):
    def test_every_profile_detects_at_least_one_test_and_a_lint_step(self):
        for name, profile in support.generator.PROFILES["repositories"].items():
            with self.subTest(profile=name):
                detected = steps.detect_steps(profile["commands"])
                self.assertTrue(detected["test"], "no test command detected")
                self.assertTrue(detected["lint"], "no lint command detected")
                self.assertEqual([], steps.missing_categories(detected))
                self.assertEqual(["python scripts/check_repository.py"], detected["checker"][:1])

    def test_gradle_build_counts_as_build_test_and_lint_and_unknown_commands_never_count(self):
        self.assertEqual(["build", "lint", "test"], steps.classify("python scripts/quality.py build"))
        self.assertEqual(["other"], steps.classify("echo tests skipped"))
        self.assertEqual(["other"], steps.classify("true"))
        detected = steps.detect_steps(["python scripts/check_repository.py", "echo ok"])
        self.assertEqual(["test"], steps.missing_categories(detected))

    def test_only_the_exact_android_ci_command_counts_as_build_test_and_lint(self):
        self.assertEqual(["build", "lint", "test"], steps.classify("python scripts/quality_gates.py ci"))
        unknown = [
            "echo python scripts/quality_gates.py ci", "echo 'python scripts/quality_gates.py ci'",
            "python scripts/quality_gates.py ci-stub", "python scripts/quality_gates.py ci_extra",
            "python scripts/quality_gates.py ci --debug", "python scripts/quality_gates.py ci && true",
            "python scripts/quality_gates.py ci; true", "python scripts/quality_gates.py ci # skipped",
            "python scripts/quality_gates.py CI", "python scripts/quality_gates.py all",
            "python scripts/quality_gates.py continuous-integration", "python scripts/quality_gates.py --ci",
            "python3 scripts/quality_gates.py ci", "python -u scripts/quality_gates.py ci",
            "python ./scripts/quality_gates.py ci", "python scripts\\quality_gates.py ci",
            "python quality_gates.py ci", "python scripts/other_quality_gates.py ci",
            " python scripts/quality_gates.py ci", "python  scripts/quality_gates.py ci",
            "python scripts/quality_gates.py ci ", "python scripts/quality_gates.py ci\n",
            "python scripts/quality_gates.py ci\r\n", "true",
        ]
        for command in unknown:
            with self.subTest(command=command):
                self.assertEqual(["other"], steps.classify(command))
                self.assertEqual([], steps.detect_steps([command])["consumer_self_tests"])

    def test_android_standalone_commands_keep_their_existing_classification(self):
        expected = {"build": ["build"], "test": ["test"], "lint": ["lint"],
                    "coverage": ["test"], "self-test": ["test"]}
        for gate, categories in expected.items():
            with self.subTest(gate=gate):
                self.assertEqual(categories, steps.classify(f"python scripts/quality_gates.py {gate}"))

    def test_removed_or_stubbed_android_ci_cannot_borrow_build_or_lint_from_the_self_test(self):
        commands = support.generator.PROFILES["repositories"]["android"]["commands"]
        ci = "python scripts/quality_gates.py ci"
        for replacement in (None, "echo tests skipped"):
            with self.subTest(replacement=replacement):
                changed = [command for command in commands if command != ci]
                if replacement is not None:
                    changed.insert(1, replacement)
                detected = steps.detect_steps(changed)
                self.assertEqual(["build", "lint"], steps.missing_categories(detected, ("build", "test", "lint")))
                self.assertEqual([
                    "python scripts/quality_gates.py self-test",
                    "python scripts/privacy_traffic_harness.py self-test --all-scripts",
                ], detected["consumer_self_tests"])

    def test_known_profiles_classify_as_reviewed(self):
        web = steps.detect_steps(support.generator.PROFILES["repositories"]["web"]["commands"])
        self.assertEqual(["npm test", "npm run check:bundle:planted"], web["test"])
        self.assertEqual(["npm run build"], web["build"])
        self.assertEqual(["npm run check:bundle:planted"], web["consumer_self_tests"])
        ai = steps.detect_steps(support.generator.PROFILES["repositories"]["ai-service"]["commands"])
        self.assertEqual(["uv run --locked pytest"], ai["test"])
        self.assertEqual(["uv run --locked ruff check .", "uv run --locked ruff format --check .", "uv run --locked mypy"], ai["lint"])
        android = steps.detect_steps(support.generator.PROFILES["repositories"]["android"]["commands"])
        self.assertEqual([
            "python scripts/quality_gates.py self-test",
            "python scripts/privacy_traffic_harness.py self-test --all-scripts",
        ], android["consumer_self_tests"])
        ci = "python scripts/quality_gates.py ci"
        self.assertEqual([ci], android["build"])
        self.assertEqual([ci], android["lint"])
        self.assertEqual(["python scripts/check_repository.py", "python scripts/check_privacy_components.py"],
                         android["checker"])
        self.assertEqual([ci, "python scripts/quality_gates.py self-test",
                          "python scripts/privacy_traffic_harness.py self-test --all-scripts"], android["test"])
        self.assertEqual(["python -m pip install -r scripts/privacy_traffic/requirements.txt"], android["install"])
        self.assertEqual([], android["other"])


class ProducedCheckTests(unittest.TestCase):
    def test_every_rendered_workflow_produces_exactly_the_required_native_check(self):
        for name in support.generator.PROFILES["repositories"]:
            with self.subTest(profile=name):
                artifacts = support.generator.artifacts(name)
                workflow = artifacts[".github/workflows/ci.yml"].encode("utf-8")
                policy = json.loads(artifacts[".github/agent-policy.json"])
                expected_checks = ({policy["required_native_check"], "Linux qualification", "Windows qualification"}
                                   if name in ("api", "infra") else {policy["required_native_check"]})
                self.assertEqual(expected_checks, steps.produced_check_names(workflow))
                manual = support.generator.PROFILES["repositories"][name]["commands"]
                expected = [
                    BUILD_COMMAND if name == "api" and command == "python scripts/quality.py build"
                    else support.generator.infra_ci_command(command) if name == "infra"
                    else command for command in manual
                ]
                actual = steps.workflow_run_commands(workflow)
                self.assertEqual(expected, actual)
                self.assertEqual(manual, policy["commands"])
                if name == "api":
                    self.assertEqual(9, len(actual))
                    self.assertEqual(1, manual.count("python scripts/quality.py build"))
                    for category in ("build", "test", "lint"):
                        self.assertIn(BUILD_COMMAND, steps.detect_steps(actual)[category])

    def test_api_report_drift_refuses_actual_removed_and_stubbed_rendered_tests(self):
        profile = support.generator.profile_for("api")
        with tempfile.TemporaryDirectory(prefix="api-sdk-conformance-drift-") as temporary:
            root = Path(temporary)
            support.generator.generate("api", root)
            context = defects.Context("api", profile, root, support.GOVERNANCE.parent)
            path = root / ".github/workflows/ci.yml"
            original = path.read_bytes()
            runner = lambda command, cwd: defects.subprocess_runner(command, cwd, 30)
            baseline = run.generated_baseline(support.generator, "api", root, support.GOVERNANCE.parent, runner)
            self.assertTrue(baseline["workflow_files_identical"])
            self.assertEqual(0, baseline["exit_code"])
            for transform in (defects._remove_test_lines, defects._stub_run_checks):
                with self.subTest(transform=transform.__name__):
                    document = json.loads(original)
                    transform(context, document)
                    mutated = support.generator.encoded(document).encode("utf-8")
                    actual = steps.workflow_run_commands(mutated)
                    self.assertNotIn(BUILD_COMMAND, actual)
                    self.assertEqual(profile["commands"][:7] if transform is defects._remove_test_lines
                                     else ["echo tests skipped"], actual)
                    path.write_bytes(mutated)
                    refused = run.generated_baseline(
                        support.generator, "api", root, support.GOVERNANCE.parent, runner,
                    )
                    self.assertEqual(1, refused["exit_code"])
                    self.assertFalse(refused["workflow_files_identical"])
                    self.assertEqual([".github/workflows/ci.yml"], refused["workflow_differences"])
                    self.assertEqual([], refused["stale_files"])
            path.write_bytes(original)
            recovered = run.generated_baseline(
                support.generator, "api", root, support.GOVERNANCE.parent, runner,
            )
            self.assertEqual(0, recovered["exit_code"])
            self.assertTrue(recovered["workflow_files_identical"])

    def test_job_without_a_name_produces_its_id_and_malformed_documents_produce_nothing(self):
        self.assertEqual({"build", "Named"}, steps.produced_check_names(
            json.dumps({"jobs": {"build": {"steps": []}, "x": {"name": "Named"}}}).encode()))
        self.assertEqual(set(), steps.produced_check_names(b"[]"))
        self.assertEqual(set(), steps.produced_check_names(b'{"jobs": []}'))
        self.assertEqual([], steps.workflow_run_commands(b'{"jobs": {"ci": {"steps": [{"name": "Other", "run": "x"}]}}}'))

    def test_required_context_without_a_producer_is_missing(self):
        produced = {"CI"}
        self.assertEqual([], github_api.missing_required_checks([{"context": "CI", "integration_id": 15368}], produced))
        self.assertEqual([], github_api.missing_required_checks([{"context": "CI", "integration_id": None}], produced))
        self.assertEqual([{"context": "policy", "integration_id": 15368}],
                         github_api.missing_required_checks([{"context": "policy", "integration_id": 15368}], produced))
        # A context bound to another app cannot be satisfied by the generated Actions job.
        self.assertEqual([{"context": "CI", "integration_id": 99}],
                         github_api.missing_required_checks([{"context": "CI", "integration_id": 99}], produced))
        self.assertEqual([{"context": "CI", "integration_id": 15368}],
                         github_api.missing_required_checks([{"context": "CI", "integration_id": 15368}], set()))

    def test_actual_adopted_target_gate_counts_but_scheduled_reports_do_not(self):
        for name in support.generator.PROFILES["repositories"]:
            files = {path: text.encode("utf-8") for path, text in support.generator.artifacts(name).items()
                     if path.startswith(".github/workflows/")}
            with self.subTest(profile=name):
                native = ({"CI", "Linux qualification", "Windows qualification"}
                          if name in ("api", "infra") else {"CI"})
                expected = native | {"PR workflow integrity"} if name == "infra" else native
                self.assertEqual(expected, steps.produced_pr_check_names(files))
                files.pop(".github/workflows/pr-workflow-integrity.yml", None)
                self.assertEqual(native, steps.produced_pr_check_names(files))
        self.assertEqual(set(), steps.produced_pr_check_names({
            ".github/workflows/pr-workflow-integrity.yml":
                b'{"on":{"workflow_dispatch":{}},"jobs":{"g":{"name":"PR workflow integrity"}}}',
            ".github/workflows/conformance.yml": support.generator.conformance_workflow().encode("utf-8"),
        }))


if __name__ == "__main__":
    unittest.main()
