import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load("public_generator", HERE / "generate.py")
checker = load("repository_checker", HERE / "templates/check_repository.py")


class BaselineTests(unittest.TestCase):
    def test_all_repositories_have_public_hosted_readonly_ci(self):
        for repo in generator.PROFILES["repositories"]:
            with self.subTest(repo=repo):
                output = generator.artifacts(repo)
                for name in (".github/workflows/ci.yml", ".github/workflows/copilot-setup-steps.yml"):
                    checker.validate_workflow(name, output[name].encode())
                ci = json.loads(output[".github/workflows/ci.yml"])
                self.assertEqual("ubuntu-24.04", ci["jobs"]["ci"]["runs-on"])
                self.assertIn("pull_request", ci["on"])
                self.assertNotIn("pull_request_target", ci["on"])

    def test_single_user_policy_does_not_require_self_approval(self):
        for repo in generator.PROFILES["repositories"]:
            policy = json.loads(generator.artifacts(repo)[".github/agent-policy.json"])
            self.assertEqual(0, policy["github_approving_review_count"])
            self.assertTrue(policy["no_bypass"])
            self.assertEqual(["core"], policy["review_floor"])
            self.assertEqual(["qa"], policy["behavior_changes_add"])

    def test_api_build_is_real_and_foundations_do_not_invent_builds(self):
        api = json.loads(generator.workflow("api"))["jobs"]["ci"]["steps"]
        self.assertIn("python scripts/quality.py build", api[-2]["run"])
        self.assertIn("coverage --base", api[-1]["run"])
        web = json.loads(generator.workflow("web"))["jobs"]["ci"]["steps"]
        self.assertEqual("python scripts/check_repository.py", web[-1]["run"])

    def test_generator_drift_and_determinism(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generator.generate("web", root)
            first = (root / "AGENTS.md").read_bytes()
            generator.generate("web", root)
            self.assertEqual(first, (root / "AGENTS.md").read_bytes())
            generator.generate("web", root, check=True)
            (root / "AGENTS.md").write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Generated setup differs"):
                generator.generate("web", root, check=True)

    def test_secret_is_detected_without_echoing_value(self):
        value = ("gh" + "p_" + "a" * 36).encode()
        errors = checker.check({"example.txt": value})
        self.assertTrue(any("Possible credential" in item for item in errors))
        self.assertNotIn(value.decode(), "\n".join(errors))

    def test_duplicate_json_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            checker.json_document(b'{"key": 1, "key": 2}')

    def test_unpinned_action_is_rejected(self):
        workflow = json.loads(generator.workflow("web"))
        workflow["jobs"]["ci"]["steps"][0]["uses"] = "actions/checkout@main"
        with self.assertRaisesRegex(ValueError, "immutable"):
            checker.validate_workflow(".github/workflows/ci.yml", json.dumps(workflow).encode())

    def test_privileged_trigger_is_rejected(self):
        workflow = json.loads(generator.workflow("web"))
        workflow["on"]["pull_request_target"] = {}
        with self.assertRaisesRegex(ValueError, "trigger"):
            checker.validate_workflow(".github/workflows/ci.yml", json.dumps(workflow).encode())

    def test_writable_token_and_self_hosted_are_rejected(self):
        for mutation in ("token", "runner"):
            workflow = json.loads(generator.workflow("web"))
            if mutation == "token":
                workflow["permissions"] = {"contents": "write"}
            else:
                workflow["jobs"]["ci"]["runs-on"] = ["self-hosted"]
            with self.assertRaises(ValueError):
                checker.validate_workflow(".github/workflows/ci.yml", json.dumps(workflow).encode())

    def test_unimplemented_repositories_are_explicit(self):
        for repo in ("admin", "ai-service", "android", "contracts", "web"):
            self.assertIn("foundation only", generator.PROFILES["repositories"][repo]["state"])


if __name__ == "__main__":
    unittest.main()
