"""API CI prepares one pinned SDK and hands its executable to the optional CLI bridge."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import conformance_support as support


generator = support.generator
CI = ".github/workflows/ci.yml"
NODE_ARGUMENT = ' --money-client-interop-node "${MONEY_CLIENT_INTEROP_NODE:?API Node SDK was not prepared}"'


def api_steps():
    return json.loads(generator.workflow("api"))["jobs"]["ci"]["steps"]


def shell_path(path):
    text = path.as_posix()
    return "/" + text[0].lower() + text[2:] if os.name == "nt" else text


class ApiNodeRuntimeTests(unittest.TestCase):
    def test_sdk_pin_and_handoff_are_present_without_replacing_existing_gates(self):
        workflow = json.loads(generator.workflow("api"))
        steps = workflow["jobs"]["ci"]["steps"]
        self.assertEqual("24.14.0", generator.profile_for("api").get("node"))
        self.assertEqual("24.14.0\n", generator.artifacts("api")[".nvmrc"])
        self.assertEqual([
            "Checkout", "Python", "Node", "JDK", "Prepare API Node SDK",
            "Run checks", "Coverage against explicit base",
        ], [step["name"] for step in steps])
        self.assertEqual({
            "name": "Node",
            "uses": "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
            "with": {"node-version-file": ".nvmrc"},
        }, steps[2])
        self.assertIn('/node/24.14.0/x64"', steps[4]["run"])
        self.assertIn('"11.9.0"', steps[4]["run"])
        commands = list(generator.profile_for("api")["commands"])
        commands[commands.index("python scripts/quality.py build")] += NODE_ARGUMENT
        self.assertEqual("\n".join(commands), steps[5]["run"])
        self.assertEqual('python scripts/quality.py coverage --base "$BASE_SHA"' + NODE_ARGUMENT,
                         steps[6]["run"])
        self.assertEqual({"BASE_SHA": "${{ github.event.pull_request.base.sha || github.sha }}"},
                         steps[6]["env"])
        self.assertEqual({"contents": "read"}, workflow["permissions"])
        self.assertEqual(30, workflow["jobs"]["ci"]["timeout-minutes"])
        self.assertNotIn("env", workflow["jobs"]["ci"])
        for forbidden in ("ORG_GRADLE_PROJECT", "GRADLE_OPTS", "NODE_OPTIONS", "command -v",
                          "which node", "sudo", "ln -s", "GITHUB_PATH"):
            self.assertNotIn(forbidden, json.dumps(workflow))

    def test_api_requires_the_reviewed_sdk_and_does_not_accept_missing_or_floating_versions(self):
        for node in (None, "", "24", "24.x", "22.23.3", "24.21.0", "${{ github.token }}"):
            profile = copy.deepcopy(generator.profile_for("api"))
            if node is None:
                profile.pop("node", None)
            else:
                profile["node"] = node
            with self.subTest(node=node), self.assertRaises(ValueError):
                generator.validate_profile("api", profile)

    def test_only_build_coverage_and_self_test_receive_the_optional_flag(self):
        commands = (
            "python scripts/quality.py build",
            'python scripts/quality.py coverage --base "$BASE_SHA"',
            'python scripts/quality.py gate-self-test --artifact-dir "$RUNNER_TEMP"',
        )
        for command in commands:
            self.assertEqual(command + NODE_ARGUMENT, generator.api_node_command(command))
        profiles = copy.deepcopy(generator.PROFILES)
        profiles["repositories"]["api"]["commands"].append(commands[-1])
        with mock.patch.object(generator, "PROFILES", profiles):
            checks = next(step for step in api_steps() if step["name"] == "Run checks")
            self.assertEqual(commands[-1] + NODE_ARGUMENT, checks["run"].splitlines()[-1])
        for command in (
            "python scripts/quality.py prepare", "python scripts/quality.py verify",
            "python scripts/quality.py build-extra", "python scripts/quality.py test",
            *generator.profile_for("api")["commands"][:7],
        ):
            self.assertEqual(command, generator.api_node_command(command))
        setup = json.loads(generator.workflow("api", setup=True))
        self.assertNotIn("--money-client-interop-node", json.dumps(setup))
        self.assertNotIn("Prepare API Node SDK", json.dumps(setup))
        self.assertFalse(any("--money-client-interop-node" in command
                             for command in generator.profile_for("api")["commands"]))
        self.assertNotIn("gate-self-test", json.dumps(api_steps()))

    def test_generator_drift_check_refuses_missing_or_altered_sdk_and_either_handoff(self):
        with tempfile.TemporaryDirectory(prefix="api-node-drift-") as temporary:
            root = Path(temporary)
            generator.generate("api", root)
            generator.generate("api", root, check=True)
            original = (root / CI).read_bytes()
            for change in ("remove-node", "remove-preparation", "action-pin", "sdk-version",
                           "build-argument", "coverage-argument"):
                document = json.loads(original)
                steps = document["jobs"]["ci"]["steps"]
                if change == "remove-node":
                    steps[:] = [step for step in steps if step["name"] != "Node"]
                elif change == "remove-preparation":
                    steps[:] = [step for step in steps if step["name"] != "Prepare API Node SDK"]
                elif change == "action-pin":
                    next(step for step in steps if step["name"] == "Node")["uses"] = "actions/setup-node@" + "a" * 40
                else:
                    name = {"sdk-version": "Prepare API Node SDK", "build-argument": "Run checks",
                            "coverage-argument": "Coverage against explicit base"}[change]
                    step = next(step for step in steps if step["name"] == name)
                    step["run"] = (step["run"].replace("24.14.0", "24.21.0") if change == "sdk-version"
                                   else step["run"].replace(NODE_ARGUMENT, ""))
                (root / CI).write_bytes(generator.encoded(document).encode("utf-8"))
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, "Generated setup differs"):
                    generator.generate("api", root, check=True)
                (root / CI).write_bytes(original)
            (root / ".nvmrc").write_bytes(b"24\n")
            with self.assertRaisesRegex(ValueError, r"Generated setup differs: \.nvmrc"):
                generator.generate("api", root, check=True)


class ApiNodeStepTests(unittest.TestCase):
    def setUp(self):
        self.bash = shutil.which("bash")
        if self.bash is None:
            self.fail("Bash is required for the finite API SDK and argv fixtures")
        temporary = tempfile.TemporaryDirectory(prefix="api-node-step-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache = self.root / "runner cache with spaces $literal 'quote'"
        self.sdk = self.cache / "node/24.14.0/x64"
        self.node = self.sdk / "bin/node"
        self.npm = self.sdk / "lib/node_modules/npm/bin/npm-cli.js"
        self.node.parent.mkdir(parents=True)
        self.npm.parent.mkdir(parents=True)
        self.npm.write_bytes(b"// SDK layout fixture, not an npm installation.\n")
        self.node.write_text(
            '#!/bin/bash\nprintf "%s\\0" "$@" >> "$FIXTURE_PROBES"\nprintf "\\n" >> "$FIXTURE_PROBES"\n'
            'if [ "$#" = 1 ] && [ "$1" = --version ]; then\n'
            '  printf "%s\\n" "$FIXTURE_NODE_VERSION"\n  exit "$FIXTURE_NODE_EXIT"\n'
            'fi\n'
            'if [ "$#" = 2 ] && [ "$1" = "$FIXTURE_NPM" ] && [ "$2" = --version ]; then\n'
            '  printf "%s\\n" "$FIXTURE_NPM_VERSION"\n  exit "$FIXTURE_NPM_EXIT"\n'
            'fi\nexit 99\n',
            encoding="ascii", newline="\n",
        )
        self.node.chmod(0o755)
        self.environment_file = self.root / "step environment"
        self.environment_file.write_bytes(b"PRIOR_SETTING=kept\n")
        self.environment = support.defects.probe_environment()
        self.environment.update(
            RUNNER_TOOL_CACHE=shell_path(self.cache), GITHUB_ENV=shell_path(self.environment_file),
            FIXTURE_PROBES=shell_path(self.root / "probes"), FIXTURE_NPM=shell_path(self.npm),
            FIXTURE_NODE_VERSION="v24.14.0", FIXTURE_NPM_VERSION="11.9.0",
            FIXTURE_NODE_EXIT="0", FIXTURE_NPM_EXIT="0",
            FIXTURE_ARGV=shell_path(self.root / "argv"), BASE_SHA="b" * 40,
            RUNNER_TEMP=shell_path(self.root / "owned parent with spaces"),
        )
        self.steps = {step["name"]: step for step in api_steps()}

    def run_script(self, source):
        script = self.root / "emitted.sh"
        script.write_text(source + "\n", encoding="utf-8", newline="\n")
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-e", "-o", "pipefail", str(script)],
            cwd=self.root, env=self.environment, capture_output=True, check=False, timeout=15,
        )

    def prepare(self):
        self.assertIn("Prepare API Node SDK", self.steps)
        poison = 'node() { exit 97; }\nnpm() { exit 98; }\n'
        return self.run_script(poison + self.steps["Prepare API Node SDK"]["run"])

    def arguments(self, name):
        return [record.decode("utf-8").split("\0")[:-1]
                for record in (self.root / name).read_bytes().splitlines()]

    def test_preparation_uses_exact_sdk_not_ambient_node_and_forwards_one_quoted_argument(self):
        result = self.prepare()
        self.assertEqual(0, result.returncode, result.stderr)
        node, npm = shell_path(self.node), shell_path(self.npm)
        self.assertEqual([["--version"], [npm, "--version"]], self.arguments("probes"))
        self.assertEqual("PRIOR_SETTING=kept\nMONEY_CLIENT_INTEROP_NODE=" + node + "\n",
                         self.environment_file.read_text(encoding="utf-8"))
        key, value = self.environment_file.read_text(encoding="utf-8").splitlines()[1].split("=", 1)
        self.environment[key] = value
        recorder = 'python() { printf "%s\\0" "$@" >> "$FIXTURE_ARGV"; printf "\\n" >> "$FIXTURE_ARGV"; }\n'
        self_test = generator.api_node_command('python scripts/quality.py gate-self-test --artifact-dir "$RUNNER_TEMP"')
        result = self.run_script(recorder + self.steps["Run checks"]["run"] + "\n"
                                 + self.steps["Coverage against explicit base"]["run"] + "\n" + self_test)
        self.assertEqual(0, result.returncode, result.stderr)
        calls = self.arguments("argv")
        quality = [call for call in calls if call[:1] == ["scripts/quality.py"]]
        self.assertEqual([
            ["scripts/quality.py", "build", "--money-client-interop-node", node],
            ["scripts/quality.py", "coverage", "--base", "b" * 40, "--money-client-interop-node", node],
            ["scripts/quality.py", "gate-self-test", "--artifact-dir", self.environment["RUNNER_TEMP"],
             "--money-client-interop-node", node],
        ], quality)
        self.assertEqual(11, len(calls))
        self.assertFalse(any("--money-client-interop-node" in call for call in calls if call not in quality))

    def test_missing_or_invalid_runtime_never_publishes_a_path(self):
        for key, value in (
            ("RUNNER_TOOL_CACHE", ""), ("RUNNER_TOOL_CACHE", "relative"),
            ("RUNNER_TOOL_CACHE", "/cache\nINJECTED=value"), ("RUNNER_TOOL_CACHE", "/cache\rvalue"),
            ("FIXTURE_NODE_VERSION", "v22.23.3"), ("FIXTURE_NPM_VERSION", "10.9.9"),
            ("FIXTURE_NODE_EXIT", "1"), ("FIXTURE_NPM_EXIT", "1"),
        ):
            with self.subTest(key=key, value=value):
                original = self.environment[key]
                self.environment[key] = value
                result = self.prepare()
                self.environment[key] = original
                self.assertNotEqual(0, result.returncode)
                self.assertIn(b"::error::", result.stderr)
                self.assertEqual(b"PRIOR_SETTING=kept\n", self.environment_file.read_bytes())
        for missing in (self.node, self.npm):
            with self.subTest(missing=missing.name):
                saved = missing.with_name(missing.name + ".saved")
                missing.rename(saved)
                result = self.prepare()
                saved.rename(missing)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(b"::error::", result.stderr)
                self.assertEqual(b"PRIOR_SETTING=kept\n", self.environment_file.read_bytes())

    def test_missing_handoff_refuses_build_and_coverage_without_running_the_consumer(self):
        for value in (None, ""):
            self.environment.pop("MONEY_CLIENT_INTEROP_NODE", None)
            if value is not None:
                self.environment["MONEY_CLIENT_INTEROP_NODE"] = value
            for command in (
                generator.api_node_command("python scripts/quality.py build"),
                self.steps["Coverage against explicit base"]["run"],
                generator.api_node_command('python scripts/quality.py gate-self-test --artifact-dir "$RUNNER_TEMP"'),
            ):
                with self.subTest(value=value, command=command):
                    result = self.run_script('python() { echo "unexpected consumer"; }\n' + command)
                    self.assertNotEqual(0, result.returncode)
                    self.assertNotIn(b"unexpected consumer", result.stdout)
                    self.assertIn(b"API Node SDK was not prepared", result.stderr)


if __name__ == "__main__":
    unittest.main()
