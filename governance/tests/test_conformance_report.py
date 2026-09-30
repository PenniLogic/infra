"""Report builder and orchestrator (PenniLogic/infra#24 addendum items 1, 3 and 6): a repository fails
for every reason the job must catch (id mismatch, workflow drift, failed checker, no test step,
missing required check, planted defect not proved, red or over-budget main CI), the published
document carries no local path or credential-shaped string, the Markdown summary is rendered from
the redacted document, and the orchestrator runs end to end against a fake consumer and a fake
API with no network."""

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

import conformance_support as support
from conformance import defects, report, run


def passing_record(**overrides):
    record = {
        "repository": "PenniLogic/example", "profile": "example", "repository_id": 1, "language": "python",
        "profile_timeout_minutes": 10,
        "identity": {"id": 1, "expected_id": 1, "verified": True}, "api_error": None, "clone_error": None,
        "main_sha": "a" * 40,
        "generated_baseline": {"workflow_files_identical": True, "workflow_differences": [], "stale_files": []},
        "repository_check": {"exit_code": 0},
        "detected_steps": {"build": [], "test": ["python -m unittest discover -s scripts/tests"], "lint": ["x"], "consumer_self_tests": []},
        "required_checks": {"produced": ["CI"], "required": [{"context": "CI", "integration_id": 15368}], "missing": [],
                            "strict_up_to_date": True, "branch_rules": {}, "rulesets": [{"name": "Protect main", "enforcement": "active", "bypass_actors": []}]},
        "registry": {"entry": {"repo": "PenniLogic/example"}, "check_name_produced": True, "workflow_ref_renders_current_workflow": True},
        "last_main_run": {"conclusion": "success", "head_sha": "a" * 40, "wall_clock_seconds": 47, "within_budget": True},
        "planted_defects": [{"id": "python-test-failing", "language": "python", "toolchain": "python", "outcome": "proved", "probes": []}],
        "language_coverage": {"python": "proved"},
    }
    record.update(overrides)
    return record


class EvaluationTests(unittest.TestCase):
    def test_a_clean_record_passes_without_findings(self):
        record = report.evaluate_repository(passing_record())
        self.assertEqual("pass", record["result"])
        self.assertEqual([], record["failures"])
        self.assertEqual([], record["warnings"])

    def test_each_failure_reason_fails_the_repository(self):
        cases = {
            "repository id does not match": {"identity": {"id": 2, "expected_id": 1, "verified": False}},
            "read-only API unavailable": {"api_error": "GET /x failed with HTTP 403"},
            "scratch checkout unavailable": {"clone_error": "git clone failed"},
            "generated workflow files differ": {"generated_baseline": {"workflow_files_identical": False, "workflow_differences": [".github/workflows/ci.yml"], "stale_files": []}},
            "own scripts/check_repository.py failed": {"repository_check": {"exit_code": 1}},
            "no test step detected": {"detected_steps": {"build": [], "test": [], "lint": [], "consumer_self_tests": []}},
            "requires no status check": {"required_checks": {"produced": ["CI"], "required": [], "missing": [], "strict_up_to_date": True}},
            "no generated workflow produces: policy": {"required_checks": {"produced": ["CI"], "required": [{"context": "policy"}], "missing": [{"context": "policy", "integration_id": None}], "strict_up_to_date": True}},
            "no check-name registry entry": {"registry": {"entry": None}},
            "registry check name is not produced": {"registry": {"entry": {}, "check_name_produced": False}},
            "workflow_ref does not render": {"registry": {"entry": {}, "check_name_produced": True, "workflow_ref_renders_current_workflow": False}},
            "planted defect python-test-failing: not_proved": {"planted_defects": [{"id": "python-test-failing", "language": "python", "toolchain": "python", "outcome": "not_proved", "reason": "stub", "probes": []}]},
            "planted defect python-test-failing: error": {"planted_defects": [{"id": "python-test-failing", "language": "python", "toolchain": "python", "outcome": "error", "reason": "not restored", "probes": []}]},
            "last main CI run concluded failure": {"last_main_run": {"conclusion": "failure", "head_sha": "a" * 40, "wall_clock_seconds": 40, "within_budget": True}},
            "over the 10-minute budget": {"last_main_run": {"conclusion": "success", "head_sha": "a" * 40, "wall_clock_seconds": 700, "within_budget": False}},
        }
        for expected, overrides in cases.items():
            with self.subTest(expected=expected):
                record = report.evaluate_repository(passing_record(**overrides))
                self.assertEqual("fail", record["result"])
                self.assertTrue(any(expected in failure for failure in record["failures"]), record["failures"])

    def test_a_job_error_fails_the_repository_with_one_line(self):
        record = report.evaluate_repository({"repository": "PenniLogic/example", "profile": "example",
                                             "job_error": "RuntimeError: boom", "planted_defects": [], "language_coverage": {}})
        self.assertEqual("fail", record["result"])
        self.assertEqual(["the conformance job itself failed for this repository: RuntimeError: boom"], record["failures"])
        self.assertEqual([], record["warnings"])
        markdown = report.render_markdown(report.build_report([record], None, "anonymous", ()))
        self.assertIn("| PenniLogic/example |", markdown)

    def test_warnings_do_not_fail_the_repository(self):
        record = report.evaluate_repository(passing_record(
            profile_timeout_minutes=30,
            generated_baseline={"workflow_files_identical": True, "workflow_differences": [], "stale_files": ["scripts/check_repository.py"]},
            required_checks={"produced": ["CI"], "required": [{"context": "CI", "integration_id": 15368}], "missing": [], "strict_up_to_date": False},
            last_main_run={"conclusion": "success", "head_sha": "b" * 40, "wall_clock_seconds": 700, "within_budget": False},
            planted_defects=[{"id": "kotlin-test-failing", "language": "kotlin", "toolchain": "java", "outcome": "not_exercised", "probes": []}],
            language_coverage={"kotlin": "not_exercised"},
        ))
        self.assertEqual("pass", record["result"])
        joined = "\n".join(record["warnings"])
        self.assertIn("predate the current generator", joined)
        self.assertIn("up to date", joined)
        self.assertIn("over the 10-minute budget (profile timeout 30 min)", joined)
        self.assertIn("kotlin planted defects not exercised", joined)
        self.assertIn("main moved since the last completed CI run", joined)
        record = report.evaluate_repository(passing_record(last_main_run=None))
        self.assertEqual("pass", record["result"])
        self.assertIn("no completed main CI run found for the required workflow", record["warnings"])


class DocumentTests(unittest.TestCase):
    def test_report_aggregates_results_and_is_deterministic(self):
        records = [passing_record(), passing_record(repository="PenniLogic/other", repository_check={"exit_code": 1})]
        document = report.build_report(records, "c" * 40, "anonymous", ("python",), generated_at="2026-09-30T12:00:00+00:00",
                                       api_requests=10, rate_limit_remaining=50, not_run=["node planted defects not exercised for: web"])
        self.assertEqual("fail", document["result"])
        self.assertEqual(["PenniLogic/other: the repository's own scripts/check_repository.py failed"], document["failures"])
        self.assertEqual(report.SCHEMA, document["schema"])
        again = report.build_report([passing_record(), passing_record(repository="PenniLogic/other", repository_check={"exit_code": 1})],
                                    "c" * 40, "anonymous", ("python",), generated_at="2026-09-30T12:00:00+00:00",
                                    api_requests=10, rate_limit_remaining=50, not_run=["node planted defects not exercised for: web"])
        self.assertEqual(report.to_json(document), report.to_json(again))
        markdown = report.render_markdown(document)
        self.assertIn("| PenniLogic/example |", markdown)
        self.assertIn("**FAIL**", markdown)
        self.assertIn("- FAIL PenniLogic/other:", markdown)
        self.assertIn("## Branch rulesets on main (read-only)", markdown)
        self.assertIn("## Not run in this report", markdown)
        self.assertIn("node planted defects not exercised for: web", markdown)
        self.assertIn("0 min 47 s", markdown)

    def test_redaction_removes_local_paths_and_credential_shaped_strings(self):
        scratch = Path.home() / "conformance-scratch"
        infra = Path.home() / "repos" / "infra"
        replacements = report.path_replacements(scratch, infra)
        token = "ghp_" + "A" * 36
        key_header = "-----BEGIN RSA " + "PRIVATE KEY-----"  # assembled so the repository checker never sees the literal
        document = {
            "command": [str(infra / "governance" / "generate.py"), "--root", str(scratch / "docs")],
            "output": f"File {scratch.as_posix()}/docs/scripts/tests/x.py line 1\n{token}\n{key_header}",
            str(scratch / "as-key"): {"python": sys.executable},
            "home": str(Path.home()),
        }
        redacted = report.redact(document, replacements)
        flattened = report.to_json(redacted)
        self.assertNotIn(str(Path.home()), flattened)
        self.assertNotIn(Path.home().as_posix(), flattened)
        self.assertNotIn(sys.executable, flattened)
        self.assertNotIn(token, flattened)
        self.assertNotIn(key_header, flattened)
        self.assertEqual(["<infra>/governance/generate.py", "--root", "<scratch>/docs"],
                         [part.replace("\\", "/") for part in redacted["command"]])
        self.assertIn("<scratch>/docs/scripts/tests/x.py", redacted["output"])
        self.assertIn("[redacted]", redacted["output"])
        self.assertIn("<scratch>/as-key", {key.replace("\\", "/") for key in redacted})
        self.assertEqual("<home>", redacted["home"])


class OrchestratorTests(support.ConsumerCase):
    def test_parse_arguments_rejects_unknown_toolchains(self):
        args = run.parse_arguments(["--scratch", "s", "--output", "o", "--exercise", "python,node"])
        self.assertEqual(("python", "node"), args.exercise)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            run.parse_arguments(["--scratch", "s", "--output", "o", "--exercise", "python,cobol"])

    def test_prepare_checkout_reuses_a_clean_clone_of_the_expected_origin_only(self):
        root, sha, reused, error = run.prepare_checkout(self.scratch, support.ORGANIZATION, self.profile_name)
        self.assertEqual(self.root, root)
        self.assertEqual(support.git(self.root, "rev-parse", "HEAD").strip(), sha)
        self.assertTrue(reused)
        self.assertIsNone(error)
        (self.root / "README.md").write_text("dirty", encoding="utf-8")
        _, sha, _, error = run.prepare_checkout(self.scratch, support.ORGANIZATION, self.profile_name)
        self.assertIsNone(sha)
        self.assertEqual("scratch checkout is not clean", error)
        support.git(self.root, "checkout", "--", "README.md")
        support.git(self.root, "remote", "set-url", "origin", "https://github.com/Other/x.git")
        root, sha, reused, error = run.prepare_checkout(self.scratch, support.ORGANIZATION, self.profile_name)
        self.assertIsNone(root)
        self.assertEqual("existing scratch directory is not a clone of the expected repository", error)

    def test_generated_baseline_separates_workflow_drift_from_stale_files(self):
        runner = lambda command, cwd: defects.subprocess_runner(command, cwd, 120)  # noqa: E731
        baseline = run.generated_baseline(support.generator, self.profile_name, self.root, support.GOVERNANCE.parent, runner)
        self.assertTrue(baseline["workflow_files_identical"])
        self.assertEqual([], baseline["stale_files"])
        self.assertEqual(0, baseline["exit_code"])
        (self.root / "README.md").write_text("stale", encoding="utf-8")
        baseline = run.generated_baseline(support.generator, self.profile_name, self.root, support.GOVERNANCE.parent, runner)
        self.assertTrue(baseline["workflow_files_identical"])
        self.assertEqual(["README.md"], baseline["stale_files"])
        self.assertEqual(1, baseline["exit_code"])
        (self.root / ".github/workflows/ci.yml").write_text("{}", encoding="utf-8")
        baseline = run.generated_baseline(support.generator, self.profile_name, self.root, support.GOVERNANCE.parent, runner)
        self.assertFalse(baseline["workflow_files_identical"])
        self.assertEqual([".github/workflows/ci.yml"], baseline["workflow_differences"])

    def test_inspect_repository_end_to_end_with_a_fake_api_passes_and_records_every_section(self):
        head = support.git(self.root, "rev-parse", "HEAD").strip()
        client = support.fake_client_for(self.profile_name, self.profile["id"], head)
        registry_document = run.registry_module.load_registry()
        runner = lambda command, cwd: defects.subprocess_runner(command, cwd, 300)  # noqa: E731
        record = run.inspect_repository(self.profile_name, self.profile, support.generator, client, registry_document,
                                        self.scratch, support.GOVERNANCE.parent, runner, ("python",))
        report.evaluate_repository(record)
        self.assertEqual("pass", record["result"], record["failures"])
        self.assertTrue(record["identity"]["verified"])
        self.assertEqual(head, record["main_sha"])
        self.assertTrue(record["reused_existing_clone"])
        self.assertTrue(record["generated_baseline"]["workflow_files_identical"])
        self.assertEqual(0, record["repository_check"]["exit_code"])
        self.assertEqual(["CI"], record["produced_check_names"])
        self.assertEqual([], record["required_checks"]["missing"])
        self.assertEqual("Protect main", record["required_checks"]["rulesets"][0]["name"])
        self.assertTrue(record["registry"]["check_name_produced"])
        self.assertIn(record["registry"]["workflow_ref_renders_current_workflow"], (True, "unverifiable"))
        self.assertEqual(47, record["last_main_run"]["wall_clock_seconds"])
        self.assertEqual({"proved"}, {defect["outcome"] for defect in record["planted_defects"]})
        self.assertEqual([], defects.git_status(self.root))
        self.assertEqual(5, client.requests)  # identity, rulesets, ruleset detail, branch rules, runs

    def test_inspect_repository_fails_closed_on_id_mismatch_missing_producer_and_api_errors(self):
        head = support.git(self.root, "rev-parse", "HEAD").strip()
        runner = lambda command, cwd: defects.Result(0, "")  # noqa: E731
        registry_document = run.registry_module.load_registry()
        client = support.fake_client_for(self.profile_name, self.profile["id"], head,
                                         identity={"id": 42, "full_name": "x", "default_branch": "main"},
                                         branch_rules=support.branch_rules_payload(contexts=(("CI", 15368), ("policy", 15368))))
        record = run.inspect_repository(self.profile_name, self.profile, support.generator, client, registry_document,
                                        self.scratch, support.GOVERNANCE.parent, runner, ())
        report.evaluate_repository(record)
        self.assertEqual("fail", record["result"])
        self.assertFalse(record["identity"]["verified"])
        self.assertEqual([{"context": "policy", "integration_id": 15368}], record["required_checks"]["missing"])
        self.assertTrue(any("policy" in failure for failure in record["failures"]))
        self.assertEqual({"not_exercised"}, {defect["outcome"] for defect in record["planted_defects"]})
        failing = support.fake_client_for(self.profile_name, self.profile["id"], head,
                                          identity=run.github_api.ApiError("GET failed with HTTP 403"))
        record = run.inspect_repository(self.profile_name, self.profile, support.generator, failing, registry_document,
                                        self.scratch, support.GOVERNANCE.parent, runner, ())
        report.evaluate_repository(record)
        self.assertEqual("fail", record["result"])
        self.assertIsNone(record["required_checks"])
        self.assertTrue(any("read-only API unavailable" in failure for failure in record["failures"]))

    def test_redacting_runner_removes_a_path_before_the_harness_truncates_the_output(self):
        """Regression: the 400-character tail kept per probe could start in the middle of a local path,
        leaving its second half in the report; redaction therefore happens before truncation."""
        replacements = report.path_replacements(self.scratch, support.GOVERNANCE.parent)
        marker = str(self.scratch / "docs" / "scripts" / "tests" / "test_planted.py")
        script = f"import sys; sys.stdout.write('A' * 1000 + {marker!r} + ' line 1'); sys.exit(1)"
        runner = run.redacting_runner(60, replacements)
        result = runner([sys.executable, "-c", script], self.root)
        self.assertEqual(1, result.exit_code)
        self.assertNotIn(str(self.scratch), result.output)
        self.assertNotIn(self.scratch.name, result.output[-defects.RECORDED_TAIL:])
        self.assertIn("<scratch>", result.output[-defects.RECORDED_TAIL:])

    def test_main_writes_redacted_report_and_summary_and_exits_with_the_result(self):
        head = support.git(self.root, "rev-parse", "HEAD").strip()
        client = support.fake_client_for(self.profile_name, self.profile["id"], head)
        output = self.scratch / "out"
        out = io.StringIO()
        with mock.patch.object(run.github_api, "choose_client", lambda mode: client), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = run.main(["--scratch", str(self.scratch), "--output", str(output), "--repository", self.profile_name,
                             "--github-client", "anonymous", "--generated-at", "2026-09-30T12:00:00+00:00", "--command-timeout", "300"])
        self.assertEqual(0, code, out.getvalue())
        document = json.loads((output / "conformance-report.json").read_text(encoding="utf-8"))
        summary = (output / "conformance-summary.md").read_text(encoding="utf-8")
        self.assertEqual("pass", document["result"])
        self.assertEqual("2026-09-30T12:00:00+00:00", document["generated_at"])
        self.assertEqual(["python"], document["exercised_toolchains"])
        for text in ((output / "conformance-report.json").read_text(encoding="utf-8"), summary):
            self.assertNotIn(str(self.scratch), text)
            self.assertNotIn(self.scratch.as_posix(), text)
            self.assertNotIn(str(Path.home()), text)
            self.assertNotIn(sys.executable, text)
        self.assertIn("<scratch>", (output / "conformance-report.json").read_text(encoding="utf-8"))
        self.assertIn("Conformance PASS: 1 repositories, 0 failure(s)", out.getvalue())
        self.assertEqual([], document["not_run"])  # no non-python fixture applies to the .github profile
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(2, run.main(["--scratch", str(self.scratch), "--output", str(output), "--repository", "nope"]))

    def test_main_still_writes_the_report_when_one_repository_inspection_crashes(self):
        output = self.scratch / "crash"

        def crash(*args, **kwargs):
            raise RuntimeError("unexpected")

        with mock.patch.object(run.github_api, "choose_client", lambda mode: support.FakeClient({})), \
                mock.patch.object(run, "inspect_repository", crash), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = run.main(["--scratch", str(self.scratch), "--output", str(output), "--repository", self.profile_name,
                             "--github-client", "anonymous"])
        self.assertEqual(1, code)
        document = json.loads((output / "conformance-report.json").read_text(encoding="utf-8"))
        self.assertEqual("fail", document["result"])
        self.assertIn("RuntimeError: unexpected", document["failures"][0])
        self.assertTrue((output / "conformance-summary.md").is_file())


if __name__ == "__main__":
    unittest.main()
