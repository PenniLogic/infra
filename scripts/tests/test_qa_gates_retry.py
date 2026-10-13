"""Retry-limit configuration check (PenniLogic/infra#28, E25-F01): docs flake_policy retry limits.

Each negative has a passing control and exactly one mutation, and asserts the exact static rule code.
"""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
import qa_gates_policy as policies
import qa_gates_retry as retry
import qa_gates_support as qs
import qa_gates_tags as tags


class CommandConstructTests(unittest.TestCase):
    def test_plain_words_are_never_matched(self):
        self.assertEqual(retry.command_constructs("echo retries entries attempt rerun"), [])

    def test_known_flags_are_counted(self):
        cases = {
            "pytest --reruns 2": 2, "pytest --reruns=1": 1, "vitest run --retry=3": 3, "npx playwright test --retries 2": 2,
            "tool --max-attempts 3": 2, "mvn -Dsurefire.rerunFailingTestsCount=2 test": 2,
            "./gradlew test -PmaxRetries=2": 2, "env PYTEST_RERUNS=4": None,
            "x --max-runs=1": 0,
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                found = retry.command_constructs(command)
                self.assertEqual(found, [("unknown", None)] if expected is None else [("count", expected)])

    def test_forced_task_rerun_is_not_a_retry(self):
        self.assertEqual(retry.command_constructs("./gradlew test --rerun-tasks --rerun"), [])

    def test_unreadable_count_fails_closed(self):
        self.assertEqual(retry.command_constructs("pytest --reruns 1"), [("count", 1)])
        self.assertEqual(retry.command_constructs("pytest --reruns ${{ inputs.n }}"), [("unknown", None)])

    def test_unknown_retry_flag_fails_closed(self):
        self.assertEqual(retry.command_constructs("pytest --reruns 1"), [("count", 1)])
        self.assertEqual(retry.command_constructs("pytest --retry-on-flake 1"), [("unknown", None)])


class DocumentConstructTests(unittest.TestCase):
    def test_keys_actions_and_commands_are_found(self):
        step = {"uses": "nick-fields/retry@0123456789012345678901234567890123456789",
                "with": {"max_attempts": 3, "command": "pytest --reruns 1"}}
        self.assertEqual(sorted(retry.constructs({"steps": [step]})), [("count", 1), ("count", 2)])
        self.assertEqual(retry.re_executions(retry.constructs({"steps": [step]})), 5)
        self.assertEqual(retry.constructs({"test": {"retry": False}}), [("count", 0)])

    def test_retry_action_without_count_fails_closed(self):
        control = {"uses": "nick-fields/retry@v3", "with": {"max_attempts": 1}}
        self.assertEqual(retry.constructs(control), [("count", 0)])
        self.assertEqual(retry.constructs({"uses": "nick-fields/retry@v3", "with": {}}), [("unknown", None)])

    def test_unreadable_key_value_fails_closed(self):
        self.assertEqual(retry.constructs({"retries": 1}), [("count", 1)])
        self.assertEqual(retry.constructs({"retries": {"count": 1}}), [("unknown", None)])

    def test_retry_shaped_dependency_is_reported_only(self):
        self.assertEqual(retry.constructs({"devDependencies": {"vitest": "1.0.0"}}), [])
        self.assertEqual(retry.constructs({"devDependencies": {"p-retry": "1.0.0"}}), [("report", None)])

    def test_script_names_are_labels(self):
        self.assertEqual(retry.constructs({"scripts": {"test:flaky": "vitest run"}}), [])
        self.assertEqual(retry.constructs({"scripts": {"test:flaky": "vitest run --retry 2"}}), [("count", 2)])

    def test_compounded_count_is_capped(self):
        self.assertEqual(retry.re_executions([("count", 1), ("count", 1)]), 3)
        huge = [("count", 10 ** 5000)] * 3
        self.assertEqual(retry.re_executions(huge), retry.EXECUTION_CAP)

    def test_depth_is_bounded(self):
        node = {}
        for _ in range(retry.MAX_DEPTH):
            node = {"a": node}
        self.assertEqual(retry.constructs(node), [])
        with self.assertRaises(retry.Refused) as caught:
            retry.constructs({"a": {"a": node}})
        self.assertEqual(caught.exception.code, "CONFIG-DEPTH")


CI = ".github/workflows/ci.yml"


def workflow(ci_step=None, money_step=None, **top):
    steps = {"ci": ci_step, "money": money_step}
    document = {"name": "synthetic", "on": {"pull_request": {}}, **top, "jobs": {}}
    for key, step in steps.items():
        document["jobs"][key] = {"runs-on": "ubuntu-24.04", "steps": [step or {"run": "python -m unittest"}]}
    return document


def judge(*documents, manifest_doc=None, runner_configs=()):
    manifest = tags.parse_manifest(qs.encode(manifest_doc or qs.manifest_document()))
    return retry.evaluate(policy=policies.load_policy(), manifest=manifest,
                          workflows=[(CI, document) for document in documents], runner_configs=runner_configs)


def rules(report):
    return [(finding["rule"], finding["job"], finding["count"]) for finding in report["findings"]]


class EvaluateTests(unittest.TestCase):
    def test_clean_workflow_passes(self):
        report = judge(workflow())
        self.assertEqual((report["decision"], report["findings"]), ("pass", []))
        self.assertEqual(report["counts"], {"inputs": 1, "jobs": 2, "failing": 0, "reported": 0})

    def test_retry_config_above_limit_fails(self):
        self.assertEqual(judge(workflow({"run": "pytest --reruns 1"}))["decision"], "pass")
        report = judge(workflow({"run": "pytest --reruns 2"}))
        self.assertEqual((report["decision"], rules(report)), ("fail", [("RETRY-LIMIT-EXCEEDED", "ci", 2)]))

    def test_money_path_zero_retries(self):
        self.assertEqual(judge(workflow(money_step={"run": "pytest --reruns 0"}))["decision"], "pass")
        report = judge(workflow(money_step={"run": "pytest --reruns 1"}))
        self.assertEqual((report["decision"], rules(report)), ("fail", [("RETRY-MONEY-PATH", "money", 1)]))

    def test_constructs_compound_within_a_job(self):
        self.assertEqual(judge(workflow({"run": "pytest --reruns 1"}))["decision"], "pass")
        step = {"uses": "nick-fields/retry@v3", "with": {"max_attempts": 2, "command": "pytest --reruns 1"}}
        self.assertEqual(rules(judge(workflow(step))), [("RETRY-LIMIT-EXCEEDED", "ci", 3)])

    def test_top_level_constructs_apply_to_every_job(self):
        self.assertEqual(judge(workflow(env={"CI": "true"}))["decision"], "pass")
        report = judge(workflow(env={"PYTEST_ADDOPTS": "--reruns 1"}))
        self.assertEqual(rules(report), [("RETRY-MONEY-PATH", "money", 1)])

    def test_unknown_construct_fails_closed(self):
        self.assertEqual(judge(workflow({"run": "pytest --reruns 1"}))["decision"], "pass")
        report = judge(workflow({"run": "pytest --rerun-flaky"}))
        self.assertEqual((report["decision"], rules(report)), ("fail", [("RETRY-UNKNOWN", "ci", 1)]))

    def test_runner_config_takes_the_strictest_limit(self):
        manifest_doc = qs.manifest_document()
        manifest_doc["jobs"] = manifest_doc["jobs"][:1]
        config = ("package.json", {"scripts": {"test": "vitest run --retry 1"}})
        self.assertEqual(judge(workflow(), manifest_doc=manifest_doc, runner_configs=[config])["decision"], "pass")
        report = judge(workflow(), runner_configs=[config])
        self.assertEqual(rules(report), [("RETRY-MONEY-PATH", None, 1)])

    def test_dependency_name_is_reported_without_failing(self):
        config = ("package.json", {"devDependencies": {"p-retry": "1.0.0"}})
        report = judge(workflow(), runner_configs=[config])
        self.assertEqual((report["decision"], rules(report)), ("pass", [("RETRY-DEPENDENCY", None, 1)]))

    def test_shape_refusals(self):
        self.assertEqual(judge(workflow())["decision"], "pass")
        cases = {
            "CONFIG-SHAPE": workflow() | {"jobs": {}},
            "CONFIG-JOB-KEY": workflow() | {"jobs": {"bad key": {"steps": []}}},
        }
        for code, document in cases.items():
            with self.subTest(code=code), self.assertRaises(retry.Refused) as caught:
                judge(document)
            self.assertEqual(caught.exception.code, code)
        with self.assertRaises(retry.Refused) as caught:
            judge(workflow(), runner_configs=[("../package.json", {})])
        self.assertEqual(caught.exception.code, "INPUT-PATH")


class MainTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / ".github" / "workflows").mkdir(parents=True)
        self.manifest = self.root / "manifest.json"
        self.manifest.write_bytes(qs.encode(qs.manifest_document()))

    def write(self, relative, data):
        (self.root / relative).write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode("utf-8"))

    def run_main(self, *arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = retry.main(["--root", str(self.root), "--manifest", str(self.manifest), *arguments])
        return code, json.loads(output.getvalue())

    def test_exit_codes(self):
        self.write(CI, workflow())
        self.assertEqual(self.run_main("--workflow", CI)[0], 0)
        self.write(CI, workflow({"run": "pytest --reruns 2"}))
        code, report = self.run_main("--workflow", CI)
        self.assertEqual((code, report["decision"], rules(report)), (1, "fail", [("RETRY-LIMIT-EXCEEDED", "ci", 2)]))

    def test_refusals_exit_two(self):
        self.write(CI, workflow())
        self.write("package.json", {"scripts": {}})
        self.assertEqual(self.run_main("--workflow", CI, "--runner-config", "package.json")[0], 0)
        cases = {
            "INPUT-NONE": (),
            "USAGE": ("--workflow", CI, "--unknown"),
            "INPUT-PATHS": ("--workflow", CI, "--workflow", CI),
            "INPUT-PATH": ("--workflow", "ci.yml"),
            "INPUT-UNREADABLE": ("--workflow", ".github/workflows/missing.yml"),
        }
        # Review round 1, ADVSEC-R1-11: a help token inside a check command is refused, not exit 0.
        for token in ("--help", "-h"):
            with self.subTest(token=token):
                self.assertEqual(self.run_main("--workflow", CI, token),
                                 (2, {"schema": retry.REPORT_SCHEMA, "decision": "refused", "reason": "USAGE"}))
        for code, arguments in cases.items():
            with self.subTest(code=code):
                self.assertEqual(self.run_main(*arguments), (2, {"schema": retry.REPORT_SCHEMA,
                                                                 "decision": "refused", "reason": code}))

    def test_unrepresentable_root_is_refused(self):
        self.write(CI, workflow())
        self.assertEqual(self.run_main("--workflow", CI)[0], 0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = retry.main(["--root", str(self.root) + "\0", "--manifest", str(self.manifest), "--workflow", CI])
        self.assertEqual((code, json.loads(output.getvalue())["reason"]), (2, "INPUT-UNREADABLE"))

    def test_non_json_config_is_refused(self):
        self.write(CI, workflow())
        self.assertEqual(self.run_main("--workflow", CI)[0], 0)
        self.write(CI, b"name: synthetic\njobs: {}\n")
        self.assertEqual(self.run_main("--workflow", CI), (2, {"schema": retry.REPORT_SCHEMA,
                                                               "decision": "refused", "reason": "CONFIG-JSON"}))

    def test_duplicate_key_is_refused(self):
        self.write(CI, workflow())
        self.assertEqual(self.run_main("--workflow", CI)[0], 0)
        self.write(CI, b'{"jobs": {"ci": {"steps": []}}, "jobs": {}}')
        self.assertEqual(self.run_main("--workflow", CI)[1]["reason"], "CONFIG-JSON")


if __name__ == "__main__":
    unittest.main()
