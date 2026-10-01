"""Run the unchanged web/admin npm and ai-service uv commands on real, minimal fake consumers.

These integration tests install only the fake consumers' declared test-runner dependencies in
temporary trees. They prove the planted-defect mechanics, not hosted metadata or consumer main.
Native infra CI/setup and Conformance provision their toolchains; missing tools fail explicitly.
"""

import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest

import conformance_support as support
from conformance import defects


def workflow_exercise():
    value = json.loads(support.generator.conformance_workflow())
    step = next(step for step in value["jobs"]["conformance"]["steps"] if step["name"] == "Run conformance")
    return tuple(re.search(r"--exercise ([a-z,]+)", step["run"]).group(1).split(","))


def execute(command, root):
    result = defects.subprocess_runner(command, root, timeout=180)
    if result.exit_code != 0:
        raise AssertionError(f"fake consumer preparation failed: {command}\n{result.output}")
    return result


def require_tools(*names):
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise RuntimeError("Real conformance fixture coverage requires " + ", ".join(missing))


def print_versions(root, *commands):
    for command in commands:
        result = execute(command, root)
        print(f"fixture runtime {command}: {result.output.strip()}", flush=True)


def records_for(root, name):
    context = defects.Context(name, support.generator.profile_for(name), root, support.GOVERNANCE.parent)
    selected = [item for item in defects.applicable_fixtures(context) if item.toolchain in ("node", "uv")]
    def snapshot():
        return {path: (root / path).read_bytes() for path in support.git(root, "ls-files").splitlines()}

    before = snapshot()
    records = {item["id"]: item for item in defects.run_fixtures(context, fixtures=selected,
                                                               exercise=workflow_exercise())}
    if before != snapshot() or defects.git_status(root):
        raise AssertionError("the real runtime fixtures did not restore the fake consumer")
    return records


class RealNodeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require_tools("node", "npm")
        cls.temporary = tempfile.TemporaryDirectory(prefix="conformance-real-node-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.records = {}
        for name in ("web", "admin"):
            tests = "tests/unit" if name == "admin" else "tests"
            root = support.make_consumer(Path(cls.temporary.name) / name, name, {
                "package.json": json.dumps({
                    "name": "synthetic-conformance-consumer", "private": True, "type": "module",
                    "scripts": {"test": "vitest run"},
                    "devDependencies": {"vitest": "5.0.2"},
                }) + "\n",
                f"{tests}/baseline.test.ts": "import { expect, test } from 'vitest';\n"
                                           "test('baseline', () => expect(2).toBe(1 + 1));\n",
            })
            execute("npm install --package-lock-only --ignore-scripts --no-audit --no-fund", root)
            support.git(root, "add", "package-lock.json")
            support.git(root, "commit", "-q", "-m", "fake consumer dependency lock")
            execute(support.generator.profile_for(name)["install"][0], root)
            print_versions(root, "node --version", "npm --version", "npm exec -- vitest --version")
            execute("npm test", root)
            cls.records[name] = records_for(root, name)

    def test_web_and_admin_real_npm_tests_refuse_the_executed_failing_test(self):
        for name, records in self.records.items():
            record = records["typescript-test-failing"]
            with self.subTest(profile=name):
                self.assertEqual("proved", record["outcome"], record)
                self.assertEqual("npm test", record["probes"][-1]["command"])
                self.assertNotEqual(0, record["probes"][-1]["exit_code"])
                self.assertIn("planted defect", record["probes"][-1]["output_tail"])

    def test_web_and_admin_real_npm_tests_refuse_the_removed_suite(self):
        for name, records in self.records.items():
            record = records["typescript-tests-removed"]
            with self.subTest(profile=name):
                self.assertEqual("proved", record["outcome"], record)
                self.assertNotEqual(0, record["probes"][-1]["exit_code"])
                self.assertIn("No test files found", record["probes"][-1]["output_tail"])


class RealUvFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require_tools("uv")
        cls.temporary = tempfile.TemporaryDirectory(prefix="conformance-real-uv-")
        cls.addClassCleanup(cls.temporary.cleanup)
        root = support.make_consumer(Path(cls.temporary.name) / "ai-service", "ai-service", {
            "pyproject.toml": '[project]\nname = "synthetic-conformance-consumer"\nversion = "0.0.0"\n'
                              'requires-python = ">=3.14"\ndependencies = []\n'
                              '[dependency-groups]\ndev = ["pytest>=9,<10"]\n'
                              '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
            "tests/test_baseline.py": "def test_baseline():\n    assert 2 == 1 + 1\n",
        })
        execute("uv lock", root)
        support.git(root, "add", "uv.lock")
        support.git(root, "commit", "-q", "-m", "fake consumer dependency lock")
        execute("uv sync --locked", root)
        print_versions(root, "uv --version", "uv run --locked pytest --version")
        execute("uv run --locked pytest", root)
        cls.records = records_for(root, "ai-service")

    def test_ai_real_locked_pytest_refuses_the_executed_failing_test(self):
        record = self.records["python-pytest-failing"]
        self.assertEqual("proved", record["outcome"], record)
        self.assertEqual("uv run --locked pytest", record["probes"][-1]["command"])
        self.assertEqual(1, record["probes"][-1]["exit_code"])
        self.assertIn("test_planted_defect_must_fail", record["probes"][-1]["output_tail"])

    def test_ai_real_locked_pytest_refuses_the_removed_suite(self):
        record = self.records["python-pytest-removed"]
        self.assertEqual("proved", record["outcome"], record)
        self.assertEqual(5, record["probes"][-1]["exit_code"])
        self.assertIn("no tests ran", record["probes"][-1]["output_tail"])


if __name__ == "__main__":
    unittest.main()
