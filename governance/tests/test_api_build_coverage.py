"""One API build owns coverage with the unchanged, quoted explicit-base handoff."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import conformance_support as support
from test_api_node_runtime import BASE_ARGUMENT, BUILD_COMMAND, NODE_ARGUMENT, shell_path


generator = support.generator
CI = ".github/workflows/ci.yml"
BASE_ENV = {"BASE_SHA": "${{ github.event.pull_request.base.sha || github.sha }}"}


class ApiBuildCoverageTests(unittest.TestCase):
    def test_one_build_receives_the_base_and_no_later_coverage_graph_runs(self):
        workflow = json.loads(generator.workflow("api"))
        steps = workflow["jobs"]["ci"]["steps"]
        commands = [line for step in steps for line in step.get("run", "").splitlines()
                    if line.startswith("python scripts/quality.py ")]
        self.assertEqual([BUILD_COMMAND], commands)
        self.assertEqual("Run checks", steps[-1]["name"])
        self.assertEqual([
            "Checkout", "Python", "Node", "JDK", "Prepare API Node SDK", "Run checks",
        ], [step["name"] for step in steps])
        expected = list(generator.profile_for("api")["commands"])
        expected[expected.index("python scripts/quality.py build")] = BUILD_COMMAND
        self.assertEqual(expected, steps[-1]["run"].splitlines())
        self.assertEqual({"contents": "read"}, workflow["permissions"])
        self.assertEqual(30, workflow["jobs"]["ci"]["timeout-minutes"])
        self.assertEqual({"persist-credentials": False, "fetch-depth": 0}, steps[0]["with"])

    def test_base_expression_and_all_event_triggers_are_preserved(self):
        workflow = json.loads(generator.workflow("api"))
        self.assertEqual({
            "workflow_dispatch": {}, "push": {"branches": ["main"]},
            "pull_request": {"branches": ["main"]},
        }, workflow["on"])
        steps = workflow["jobs"]["ci"]["steps"]
        self.assertEqual([BASE_ENV], [step["env"] for step in steps if "env" in step])
        self.assertEqual(BASE_ENV, steps[-1]["env"])
        self.assertNotIn("env", workflow["jobs"]["ci"])
        self.assertNotIn("${{", steps[-1]["run"])
        self.assertEqual({}, json.loads(generator.workflow("api", setup=True))["on"]["workflow_dispatch"])

    def test_generator_refuses_missing_or_altered_base_handoff_and_duplicate_coverage(self):
        with tempfile.TemporaryDirectory(prefix="api-combined-drift-") as directory:
            root = Path(directory)
            generator.generate("api", root)
            original = (root / CI).read_bytes()
            for change in ("base-environment", "base-argument", "base-expression", "duplicate-coverage"):
                document = json.loads(original)
                steps = document["jobs"]["ci"]["steps"]
                checks = next(step for step in steps if step["name"] == "Run checks")
                if change == "base-environment":
                    checks.pop("env", None)
                elif change == "base-argument":
                    checks["run"] = checks["run"].replace(BASE_ARGUMENT, "")
                elif change == "base-expression":
                    checks["env"] = {"BASE_SHA": "${{ github.sha }}"}
                else:
                    steps.append({
                        "name": "Coverage against explicit base",
                        "run": 'python scripts/quality.py coverage --base "$BASE_SHA"' + NODE_ARGUMENT,
                    })
                (root / CI).write_bytes(generator.encoded(document).encode("utf-8"))
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, "Generated setup differs"):
                    generator.generate("api", root, check=True)
            (root / CI).write_bytes(original)
            generator.generate("api", root, check=True)


class ApiCombinedArgvTests(unittest.TestCase):
    def setUp(self):
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash, "Bash is required to execute the emitted API argv fixture")
        temporary = tempfile.TemporaryDirectory(prefix="api-combined-argv-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        steps = json.loads(generator.workflow("api"))["jobs"]["ci"]["steps"]
        self.checks = next(step for step in steps if step["name"] == "Run checks")["run"]
        self.build = next(line for line in self.checks.splitlines()
                          if line.startswith("python scripts/quality.py build"))
        self.node = shell_path(self.root / "SDK with spaces $literal 'quote';literal" / "node")
        self.argv_file = self.root / "argv"
        self.environment = support.defects.probe_environment()
        self.environment.update(
            BASE_SHA="b" * 40, MONEY_CLIENT_INTEROP_NODE=self.node,
            FIXTURE_ARGV=shell_path(self.argv_file), FIXTURE_BUILD_EXIT="0",
        )

    def run_script(self, source):
        script = self.root / "emitted.sh"
        script.write_text(source + "\n", encoding="utf-8", newline="\n")
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-e", "-o", "pipefail", str(script)],
            cwd=self.root, env=self.environment, capture_output=True, check=False, timeout=15,
        )

    def test_checks_invoke_one_combined_build_and_keep_python_tests_last(self):
        recorder = (
            'python() { printf "%s\\0" "$@" >> "$FIXTURE_ARGV"; '
            'printf "\\n" >> "$FIXTURE_ARGV"; '
            'if [ "$1" = scripts/quality.py ]; then return "$FIXTURE_BUILD_EXIT"; fi; }\n'
        )
        for exit_code in (0, 37):
            with self.subTest(build_exit=exit_code):
                self.argv_file.unlink(missing_ok=True)
                self.environment["FIXTURE_BUILD_EXIT"] = str(exit_code)
                result = self.run_script(recorder + self.checks)
                self.assertEqual(exit_code, result.returncode, result.stderr)
                calls = [record.decode("utf-8").split("\0")[:-1]
                         for record in self.argv_file.read_bytes().splitlines()]
                quality = [call for call in calls if call[:1] == ["scripts/quality.py"]]
                self.assertEqual([[
                    "scripts/quality.py", "build", "--base", "b" * 40,
                    "--money-client-interop-node", self.node,
                ]], quality)
                self.assertEqual(9 if exit_code == 0 else 8, len(calls))
                self.assertEqual(["-m", "unittest", "discover", "-s", "scripts/tests"]
                                 if exit_code == 0 else quality[0], calls[-1])

    def test_base_is_one_literal_operand_even_when_empty_or_shell_like(self):
        recorder = 'python() { printf "%s\\0" "$@" > "$FIXTURE_ARGV"; }\n'
        for base in (None, "", "b" * 40, "0" * 40, "$(touch injected-base)",
                     '"; touch injected-base; #', "base\nINJECTED=value"):
            with self.subTest(base=base):
                if base is None:
                    self.environment.pop("BASE_SHA", None)
                else:
                    self.environment["BASE_SHA"] = base
                result = self.run_script(recorder + self.build)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual([
                    "scripts/quality.py", "build", "--base", "" if base is None else base,
                    "--money-client-interop-node", self.node,
                ], self.argv_file.read_text(encoding="utf-8").split("\0")[:-1])
                self.assertFalse((self.root / "injected-base").exists())


if __name__ == "__main__":
    unittest.main()
