"""Step detection and check-name production (PenniLogic/infra#24 addendum items 1 and 2): every
profile has a real test step, unknown commands never count as tests, each rendered ci.yml produces
exactly the required native check, and a required context without a producing workflow is
reported as missing."""

import json
import unittest

import conformance_support as support
from conformance import github_api, steps


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
                self.assertEqual(["python scripts/quality_gates.py self-test"], detected["consumer_self_tests"])

    def test_known_profiles_classify_as_reviewed(self):
        web = steps.detect_steps(support.generator.PROFILES["repositories"]["web"]["commands"])
        self.assertEqual(["npm test", "npm run check:bundle:planted"], web["test"])
        self.assertEqual(["npm run build"], web["build"])
        self.assertEqual(["npm run check:bundle:planted"], web["consumer_self_tests"])
        ai = steps.detect_steps(support.generator.PROFILES["repositories"]["ai-service"]["commands"])
        self.assertEqual(["uv run --locked pytest"], ai["test"])
        self.assertEqual(["uv run --locked ruff check .", "uv run --locked ruff format --check .", "uv run --locked mypy"], ai["lint"])
        android = steps.detect_steps(support.generator.PROFILES["repositories"]["android"]["commands"])
        self.assertEqual(["python scripts/quality_gates.py self-test"], android["consumer_self_tests"])
        ci = "python scripts/quality_gates.py ci"
        self.assertEqual([ci], android["build"])
        self.assertEqual([ci], android["lint"])
        self.assertEqual([ci, "python scripts/quality_gates.py self-test",
                          'python -m unittest discover -s scripts/tests -p "test_*.py"'], android["test"])
        self.assertEqual([], android["other"])


class ProducedCheckTests(unittest.TestCase):
    def test_every_rendered_workflow_produces_exactly_the_required_native_check(self):
        for name in support.generator.PROFILES["repositories"]:
            with self.subTest(profile=name):
                artifacts = support.generator.artifacts(name)
                workflow = artifacts[".github/workflows/ci.yml"].encode("utf-8")
                policy = json.loads(artifacts[".github/agent-policy.json"])
                self.assertEqual({policy["required_native_check"]}, steps.produced_check_names(workflow))
                self.assertEqual(support.generator.PROFILES["repositories"][name]["commands"],
                                 steps.workflow_run_commands(workflow))

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


if __name__ == "__main__":
    unittest.main()
