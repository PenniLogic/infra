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
        self.assertEqual(retry.constructs({"steps": [step]}), [("wrap", 2, (("count", 1),))])
        self.assertEqual(sorted(retry.leaves(retry.constructs({"steps": [step]}))), [("count", 1), ("count", 2)])
        self.assertEqual(retry.re_executions(retry.constructs({"steps": [step]})), 5)
        self.assertEqual(retry.constructs({"test": {"retry": False}}), [("count", 0)])

    def test_retry_action_without_count_fails_closed(self):
        control = {"uses": "nick-fields/retry@v3", "with": {"max_attempts": 1}}
        self.assertEqual(retry.constructs(control), [("wrap", 0, ())])
        self.assertEqual(retry.constructs({"uses": "nick-fields/retry@v3", "with": {}}), [("unknown", None)])

    def test_unreadable_key_value_fails_closed(self):
        self.assertEqual(retry.constructs({"retries": 1}), [("count", 1)])
        self.assertEqual(retry.constructs({"retries": {"count": 1}}), [("unknown", None)])

    def test_retry_shaped_dependency_is_reported_only(self):
        top = {"dependency_maps": True}
        self.assertEqual(retry.constructs({"devDependencies": {"vitest": "1.0.0"}}, **top), [])
        self.assertEqual(retry.constructs({"devDependencies": {"p-retry": "1.0.0"}}, **top), [("report", None)])

    def test_script_names_are_labels(self):
        self.assertEqual(retry.constructs({"scripts": {"test:flaky": "vitest run"}}), [])
        self.assertEqual(retry.constructs({"scripts": {"test:flaky": "vitest run --retry 2"}}), [("count", 2)])

    def test_compounded_count_is_capped(self):
        self.assertEqual(retry.re_executions([("wrap", 1, (("count", 1),))]), 3)
        huge = ("count", 10 ** 5000)
        self.assertEqual(retry.re_executions([huge] * 3), retry.EXECUTION_CAP)
        self.assertEqual(retry.re_executions([("wrap", 10 ** 5000, (huge,))]), retry.EXECUTION_CAP)

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
    """Findings other than RETRY-ATTEMPT-HIDDEN, which HiddenAttemptTests asserts on its own."""
    return [(finding["rule"], finding["job"], finding["count"]) for finding in report["findings"]
            if finding["rule"] != "RETRY-ATTEMPT-HIDDEN"]


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
        for token in ("--help", "-h", "-hh", "-hX"):  # -hh, -hX: review round 3, ADVSEC-R3-08
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


def one_job(*steps, key="ci", **job_keys):
    return {"name": "synthetic", "on": {"pull_request": {}},
            "jobs": {key: {"runs-on": "ubuntu-24.04", **job_keys, "steps": list(steps)}}}


def plain_manifest():
    """The synthetic manifest without its money-path job (no strictest limit)."""
    document = qs.manifest_document()
    document["jobs"] = document["jobs"][:1]
    return document


class IndependentStepsTests(unittest.TestCase):
    # Review round 1, PS-2: sequential steps, scripts and commands do not re-execute each other.
    def test_two_independent_once_retried_steps_pass(self):
        steps = [{"run": "python -m pytest --reruns 1 tests/unit"}, {"run": "python -m pytest --reruns 1 tests/it"}]
        report = judge(one_job(*steps), manifest_doc=plain_manifest())
        self.assertEqual((report["decision"], report["checked"][0]["re_executions"]), ("pass", 1))
        wrapped = {"uses": "nick-fields/retry@v3", "with": {"max_attempts": 2, "command": steps[0]["run"]}}
        report = judge(one_job(wrapped, steps[1]), manifest_doc=plain_manifest())
        self.assertEqual(rules(report), [("RETRY-LIMIT-EXCEEDED", "ci", 3)])

    def test_independent_commands_and_scripts_take_the_largest(self):
        self.assertEqual(retry.re_executions(retry.command_constructs("pytest --reruns 1; pytest --reruns 1")), 1)
        # Review round 2, PS-4: several retry flags of one command are alternatives too (the runner applies one).
        self.assertEqual(retry.re_executions(retry.command_constructs("pytest --reruns 1 --max-retries 1")), 1)
        scripts = {"scripts": {"test": "vitest run --retry 1", "e2e": "playwright test --retries 1"}}
        self.assertEqual(retry.re_executions(retry.constructs(scripts)), 1)
        scripts["scripts"]["e2e"] = "playwright test --retries 2"
        self.assertEqual(retry.re_executions(retry.constructs(scripts)), 2)


class HiddenAttemptTests(unittest.TestCase):
    # Review round 1, PS-5 / ADVSEC-R1-01: an in-runner or whole-step retry hides the failed attempt from the
    # quarantine gate; the brief's "fail above 1" stands, so it is reported for the QA/Reliability decision.
    def test_hidden_retry_is_reported(self):
        clean = judge(one_job({"run": "python -m pytest"}), manifest_doc=plain_manifest())
        self.assertEqual((clean["decision"], clean["findings"]), ("pass", []))
        for step in ({"run": "mvn -Dsurefire.rerunFailingTestsCount=1 test"},
                     {"uses": "nick-fields/retry@v3", "with": {"max_attempts": 2, "command": "python -m pytest"}}):
            with self.subTest(step=sorted(step)):
                report = judge(one_job(step), manifest_doc=plain_manifest())
                self.assertEqual((report["decision"], [(f["rule"], f["effect"]) for f in report["findings"]]),
                                 ("pass", [("RETRY-ATTEMPT-HIDDEN", "report")]))


class ValueFlagTests(unittest.TestCase):
    # Review round 1, ADVSEC-R1-02 / -08 / -09: flags inside NAME=value values, env maps and spliced quotes.
    def test_flags_inside_name_value_values_are_read(self):
        self.assertEqual(rules(judge(one_job({"run": "PYTEST_ADDOPTS=-v python -m pytest"}),
                                     manifest_doc=plain_manifest())), [])
        for command, count in (("PYTEST_ADDOPTS=--reruns=5 python -m pytest", 5),
                               ("export PYTEST_ADDOPTS=--reruns=5", 5),
                               ('echo "PYTEST_ADDOPTS=--reruns 5" >> "$GITHUB_ENV"', 5),
                               ("MAVEN_ARGS=-Dsurefire.rerunFailingTestsCount=3 mvn -B test", 3),
                               ("python -m pytest -o addopts=--reruns=5", 5),
                               ("python -m pytest --re''runs 5", 5)):
            with self.subTest(command=command):
                report = judge(one_job({"run": command}), manifest_doc=plain_manifest())
                self.assertEqual(rules(report), [("RETRY-LIMIT-EXCEEDED", "ci", count)])

    def test_dependency_map_names_in_workflow_env_are_read(self):
        control = judge(one_job({"run": "python -m pytest $OVERRIDES"}, env={"OVERRIDES": "-v"}),
                        manifest_doc=plain_manifest())
        self.assertEqual(control["decision"], "pass")
        report = judge(one_job({"run": "python -m pytest $OVERRIDES"}, env={"OVERRIDES": "--reruns 5"}),
                       manifest_doc=plain_manifest())
        self.assertEqual(rules(report), [("RETRY-LIMIT-EXCEEDED", "ci", 5)])

    def test_workflow_rerun_requests_fail_closed(self):
        self.assertEqual(judge(one_job({"run": "gh run list --limit 1"}), manifest_doc=plain_manifest())["decision"],
                         "pass")
        for command in ("gh run rerun 123 --failed",
                        "curl -X POST https://api.github.com/repos/o/r/actions/runs/1/rerun-failed-jobs"):
            with self.subTest(command=command):
                report = judge(one_job({"run": command}), manifest_doc=plain_manifest())
                self.assertEqual(rules(report), [("RETRY-UNKNOWN", "ci", 1)])

    def test_non_count_modifiers_of_named_mechanisms_pass(self):
        # Review round 1, PS-6.
        self.assertEqual(retry.command_constructs("pytest --reruns 1 --reruns-delay 2 --only-rerun x"),
                         [("count", 1)])
        step = {"uses": "nick-fields/retry@v3", "with": {"timeout_minutes": 10, "max_attempts": 2,
                                                         "retry_on": "error", "retry_wait_seconds": 5,
                                                         "retry_on_exit_code": 2, "on_retry_command": "echo again",
                                                         "warning_on_retry": True, "command": "npm test"}}
        self.assertEqual(judge(one_job(step), manifest_doc=plain_manifest())["decision"], "pass")
        self.assertEqual(retry.command_constructs("pytest --reruns x --reruns-delay 2"), [("unknown", None)])


class UnmappedJobTests(unittest.TestCase):
    # Review round 1, ADVSEC-R1-07: an unmapped job never silently gets a laxer limit than the manifest's strictest.
    def test_unmapped_job_takes_the_strictest_limit(self):
        step = {"run": "python -m pytest --reruns 1"}
        control = judge(one_job(step, key="money-tests"), manifest_doc=plain_manifest())
        self.assertEqual((control["decision"], control["checked"][0]["limit"]), ("pass", 1))
        self.assertEqual(rules(control), [("RETRY-MANIFEST-JOB-UNCHECKED", "ci", 1)])
        report = judge(one_job(step, key="money-tests"))
        self.assertEqual(rules(report), [("RETRY-JOB-UNMAPPED", "money-tests", 1),
                                         ("RETRY-MANIFEST-JOB-UNCHECKED", "ci", 1),
                                         ("RETRY-MANIFEST-JOB-UNCHECKED", "money", 1),
                                         ("RETRY-MONEY-PATH", "money-tests", 1)])


NICK_FIELDS_INPUTS = {
    # Every input of nick-fields/retry action.yml (read with `gh api repos/nick-fields/retry/contents/action.yml`).
    "timeout_minutes": 10, "timeout_seconds": 600, "max_attempts": 2, "command": "python -m pytest",
    "retry_wait_seconds": 5, "shell": "bash", "polling_interval_seconds": 1, "retry_on": "error",
    "warning_on_retry": True, "on_retry_command": "echo again", "continue_on_error": False,
    "new_command_on_retry": "python -m pytest --lf", "retry_on_exit_code": 2,
}


class RoundTwoRetryTests(unittest.TestCase):
    # Review round 2, PS-5: every documented nick-fields/retry input other than the attempt count is a modifier.
    def test_every_nick_fields_retry_input_is_read_as_documented(self):
        control = {"uses": "nick-fields/retry@v3", "with": {"timeout_minutes": 10, "max_attempts": 2,
                                                            "command": "python -m pytest"}}
        self.assertEqual(judge(one_job(control), manifest_doc=plain_manifest())["decision"], "pass")
        step = {"uses": "nick-fields/retry@v3", "with": dict(NICK_FIELDS_INPUTS)}
        report = judge(one_job(step), manifest_doc=plain_manifest())
        self.assertEqual((report["decision"], rules(report), report["checked"][0]["re_executions"]), ("pass", [], 1))
        # Its command is still read: the action (two attempts) wraps it, so 2 x (3 + 1) executions.
        step["with"]["new_command_on_retry"] = "python -m pytest --reruns 3"
        self.assertEqual(rules(judge(one_job(step), manifest_doc=plain_manifest())),
                         [("RETRY-LIMIT-EXCEEDED", "ci", 7)])

    # Review round 2, ADVSEC-R2-10: a deep NAME=value chain is a CONFIG-DEPTH refusal, not a traceback.
    def test_deep_name_value_chain_is_refused(self):
        shallow = "A=" * retry.MAX_DEPTH + "--reruns=1 python -m pytest"
        self.assertEqual(retry.command_constructs(shallow), [("count", 1)])
        with self.assertRaises(retry.Refused) as caught:
            retry.command_constructs("A=" * 3000 + "1 python -m pytest")
        self.assertEqual(caught.exception.code, "CONFIG-DEPTH")

    # Review round 2, ADVSEC-R2-03: spaced expressions, the job re-run endpoint and gh global flags.
    def test_rerun_requests_in_every_spelling_fail_closed(self):
        for control in ("gh api repos/o/r/actions/runs/${{ github.event.workflow_run.id }}/jobs",
                        "gh --repo o/r run list", "gh api repos/o/r/actions/jobs/$JOB_ID/logs"):
            with self.subTest(control=control):
                self.assertEqual(retry.command_constructs(control), [])
        for command in ("gh api -X POST repos/o/r/actions/runs/${{ github.event.workflow_run.id }}/rerun-failed-jobs",
                        "gh api -X POST repos/${{ github.repository }}/actions/runs/${{ github.run_id }}/rerun",
                        "gh api -X POST repos/o/r/actions/jobs/$JOB_ID/rerun",
                        "gh --repo o/r run rerun 123 --failed", "gh -R o/r run rerun 123"):
            with self.subTest(command=command):
                self.assertEqual(retry.command_constructs(command), [("unknown", None)])
        self.assertEqual(retry.command_constructs("pytest --reruns ${{ inputs.n }}"), [("unknown", None)])

    # Review round 2, PS-4: only a known wrapper multiplies; flags of one command and env against steps do not.
    def test_only_a_wrapper_multiplies(self):
        wrapped = {"uses": "nick-fields/retry@v3", "with": {"max_attempts": 2, "command": "python -m pytest --reruns 1"}}
        report = judge(one_job(wrapped), manifest_doc=plain_manifest())
        self.assertEqual(rules(report), [("RETRY-LIMIT-EXCEEDED", "ci", 3)])
        shapes = (
            one_job({"run": "mvn -Dsurefire.rerunFailingTestsCount=1 -Dfailsafe.rerunFailingTestsCount=1 verify"}),
            one_job({"run": "pytest"}, {"run": "npx vitest run --retry=1"}, env={"PYTEST_ADDOPTS": "--reruns 1"}),
            one_job({"run": "python -m pytest --reruns 1 --reruns 1"}),
        )
        for document in shapes:
            with self.subTest(document=document["jobs"]["ci"]):
                report = judge(document, manifest_doc=plain_manifest())
                self.assertEqual((report["decision"], rules(report), report["checked"][0]["re_executions"]),
                                 ("pass", [], 1))

    # Review round 2, ADVSEC-R2-08: a retry-shaped command word of a command line is a wrapper; it fails closed.
    def test_retry_wrapper_commands_fail_closed(self):
        control = judge(one_job({"name": "Retry flaky tests", "run": "CI=1 python -m pytest", "shell": "bash -e {0}"}),
                        manifest_doc=plain_manifest())
        self.assertEqual((control["decision"], control["findings"]), ("pass", []))
        for step in ({"run": "retry --times=3 -- python -m pytest"}, {"run": "CI=1 retry -t 3 python -m pytest"},
                     {"run": "./scripts/retry.sh python -m pytest"},
                     {"run": "python -m pytest", "shell": "retry --times 3 -- bash -e {0}"}):
            with self.subTest(step=step):
                report = judge(one_job(step), manifest_doc=plain_manifest())
                self.assertEqual(rules(report), [("RETRY-UNKNOWN", "ci", 1)])
        self.assertEqual(retry.constructs({"scripts": {"test:retry": "node --test"}}), [])
        self.assertEqual(retry.constructs({"scripts": {"test": "retry -n 3 node --test"}}), [("unknown", None)])


class WorkflowInputTests(unittest.TestCase):
    # Review round 2, ADVSEC-R2-04: leaving out a workflow file the manifest maps refuses the check.
    setUp, write, run_main = MainTests.setUp, MainTests.write, MainTests.run_main

    def test_unchecked_manifest_workflow_is_refused(self):
        other = ".github/workflows/other.yml"
        self.write(CI, workflow({"run": "python -m pytest --reruns 9"}))
        self.write(other, one_job({"run": "echo synthetic"}, key="other"))
        self.write("package.json", {"scripts": {"test": "node --test"}})
        code, report = self.run_main("--workflow", CI, "--workflow", other)
        self.assertEqual((code, ("RETRY-LIMIT-EXCEEDED", "ci", 9) in rules(report)), (1, True))
        refused = {"schema": retry.REPORT_SCHEMA, "decision": "refused", "reason": "INPUT-WORKFLOWS-MISSING"}
        for arguments in (("--runner-config", "package.json"), ("--workflow", other)):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.run_main(*arguments), (2, refused))


class RoundThreeTokenTests(unittest.TestCase):
    # Review round 3, ADVSEC-R3-01: GitHub evaluates an expression before the shell, so flags and wrapper words in
    # its string literals are read; an expression used as a flag's value still fails closed.
    def test_flags_inside_expression_literals_are_read(self):
        cases = {
            "pytest ${{ '--reruns=5' }}": [("count", 5)],
            "pytest ${{ runner.os == 'Linux' && '--reruns 3' || '' }}": [("count", 3)],
            "pytest ${{ runner.os == 'Linux' && '--quiet' || '' }}": [],
            "pytest ${{ format('--reruns={0}', 5) }}": [("unknown", None)],
            "${{ 'retry' }} --times 3 -- pytest": [("unknown", None)],
            "pytest --reruns ${{ inputs.n }}": [("unknown", None)],
            "pytest --reruns ${{ inputs.fast && '1' || inputs.n }}": [
                ("alternatives", ([("unknown", None)], [("count", 1)]))],
            "echo ${{ github.sha }} ${{ 'it''s' }}": [],
            "echo ${{ github.sha": [("unknown", None)],
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(retry.command_constructs(command, True), expected)
        control = judge(one_job({"run": "pytest", "env": {"PYTEST_ADDOPTS": "${{ '--quiet' }}"}}),
                        manifest_doc=plain_manifest())
        self.assertEqual((control["decision"], rules(control)), ("pass", []))
        report = judge(one_job({"run": "pytest", "env": {"PYTEST_ADDOPTS": "${{ '--reruns=5' }}"}}),
                       manifest_doc=plain_manifest())
        self.assertEqual((report["decision"], rules(report)), ("fail", [("RETRY-LIMIT-EXCEEDED", "ci", 5)]))

    # Review round 3, ADVSEC-R3-07: gh.exe, `$''`/`$""` inside a flag, and a wrapper inside a retry action command.
    def test_token_variants_fail_closed_or_are_joined(self):
        self.assertEqual(retry.command_constructs("gh.exe run list"), [])
        for command in ("gh.exe run rerun $ID --failed", "C:\\tools\\GH.EXE run rerun 1", "/opt/bin/gh run rerun 1"):
            with self.subTest(command=command):
                self.assertEqual(retry.command_constructs(command), [("unknown", None)])
        self.assertEqual(retry.command_constructs("pytest --re''runs 5"), [("count", 5)])
        for command in ("pytest --re$''runs 5", 'pytest --re$""runs 5'):
            with self.subTest(command=command):
                self.assertEqual(retry.command_constructs(command), [("count", 5)])
        inputs = {"max_attempts": 2, "timeout_minutes": 10}
        control = {"uses": "nick-fields/retry@v3", "with": {**inputs, "command": "./run.sh -- pytest"}}
        self.assertEqual(retry.constructs(control), [("wrap", 1, ())])
        for key in ("on_retry_command", "new_command_on_retry"):  # non-count modifiers outside a retry action too
            with self.subTest(modifier=key):
                self.assertEqual(retry.constructs({key: "pytest"}), [])
        for key in ("command", "on_retry_command", "new_command_on_retry"):
            with self.subTest(key=key):
                step = {"uses": "nick-fields/retry@v3", "with": {**inputs, key: "./retry.sh --times 5 -- pytest"}}
                self.assertEqual(retry.constructs(step), [("wrap", 1, (("unknown", None),))])

    # Review round 3, ADVSEC-R3-09: the expression and `gh` scans are linear; a value at CONFIG_LIMIT is quick.
    def test_scans_are_linear(self):
        import time
        started = time.monotonic()
        self.assertEqual(retry.command_constructs("${{" * (retry.CONFIG_LIMIT // 3)), [("unknown", None)])
        many = retry.command_constructs("gh run rerun " * (retry.CONFIG_LIMIT // 13))
        self.assertEqual(set(many), {("unknown", None)})
        self.assertLess(time.monotonic() - started, 10)


class InheritedEnvironmentTests(unittest.TestCase):
    # Review round 3, PS-1: a wrapped command inherits workflow env, job env and $GITHUB_ENV exports, so their
    # in-runner retries multiply with the wrapper as step env does; an unwrapped step keeps them as alternatives.
    WRAP = {"uses": "nick-fields/retry@v3", "with": {"max_attempts": 2, "timeout_minutes": 10, "command": "pytest"}}
    ENV = {"PYTEST_ADDOPTS": "--reruns 1"}
    EXPORT = {"run": 'echo "PYTEST_ADDOPTS=--reruns 1" >> "$GITHUB_ENV"'}

    def check(self, document, expected):
        report = judge(document, manifest_doc=plain_manifest())
        self.assertEqual(report["checked"][0]["re_executions"], expected)
        return report

    def test_wrapper_compounds_every_inherited_environment(self):
        shapes = {
            "step": one_job({**self.WRAP, "env": self.ENV}),
            "job": one_job(self.WRAP, env=self.ENV),
            "workflow": {**one_job(self.WRAP), "env": self.ENV},
            "github_env": one_job(self.EXPORT, self.WRAP),
        }
        for shape, document in shapes.items():
            with self.subTest(shape=shape):
                report = self.check(document, 3)
                self.assertEqual(rules(report), [("RETRY-LIMIT-EXCEEDED", "ci", 3)])
                hidden = [finding["count"] for finding in report["findings"] if finding["rule"] == "RETRY-ATTEMPT-HIDDEN"]
                self.assertEqual(hidden, [2])  # the wrapper and the env flag, each counted once
        self.assertEqual(rules(self.check(one_job(self.WRAP), 1)), [])

    def test_unwrapped_step_keeps_environment_as_an_alternative(self):
        for document in (one_job({"run": "pytest"}, env=self.ENV), {**one_job({"run": "pytest"}), "env": self.ENV},
                         one_job(self.EXPORT, {"run": "pytest"})):
            with self.subTest(document=document):
                self.assertEqual(rules(self.check(document, 1)), [])

    def test_wrapper_compounds_the_runner_configuration(self):
        wrapped = {**self.WRAP, "with": {**self.WRAP["with"], "command": "npm test"}}
        runner = [("package.json", {"scripts": {"test": "vitest run --retry 1"}})]
        control = judge(one_job({"run": "npm test"}), manifest_doc=plain_manifest(), runner_configs=runner)
        self.assertEqual((control["checked"][0]["re_executions"], rules(control)), (0, []))
        report = judge(one_job(wrapped), manifest_doc=plain_manifest(), runner_configs=runner)
        self.assertEqual((report["checked"][0]["re_executions"], rules(report)),
                         (3, [("RETRY-LIMIT-EXCEEDED", "ci", 3)]))
