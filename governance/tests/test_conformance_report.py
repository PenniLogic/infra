"""Report builder and orchestrator (PenniLogic/infra#24 addendum items 1, 3 and 6): a repository fails
for every reason the job must catch (id mismatch, workflow drift, failed checker, no test step,
missing required check, planted defect not proved, red or over-budget main CI), the published
document carries no local path or credential-shaped string, the Markdown summary is rendered from
the redacted document, and the orchestrator runs end to end against a fake consumer and a fake
API with no network."""

import contextlib
import copy
import io
import json
import subprocess
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

    def test_redaction_covers_repr_json_lower_case_and_short_spellings(self):
        """Q1 / S4: a failed command's repr doubles the backslashes, tools lower-case the drive and
        user, JSON encodes the same doubled form, Windows may print the 8.3 name; all are redacted."""
        scratch = Path.home() / "conformance-scratch"
        replacements = report.path_replacements(scratch, None)
        native = str(scratch / "api" / "gradlew.bat")
        spellings = {
            "plain": native,
            "repr": repr(native)[1:-1],
            "json": json.dumps(native)[1:-1],
            "lower": native.lower(),
            "upper": native.upper(),
            "posix": (scratch / "api" / "gradlew.bat").as_posix(),
            "nested json": json.dumps({"cmd": [native]}),
        }
        for label, text in spellings.items():
            with self.subTest(spelling=label):
                redacted = report.redact_text(f"command failed: {text}", replacements)
                self.assertNotIn(str(Path.home()).lower(), redacted.lower())
                self.assertIn("<scratch>", redacted)
                self.assertEqual([], report.redaction_survivors({"x": redacted}, replacements))
        short = report.short_path(Path.home())
        if short and short.lower() != str(Path.home()).lower():
            redacted = report.redact_text(f"at {short}\\x.txt", replacements)
            self.assertNotIn(short.lower(), redacted.lower())
            self.assertEqual("at <home>\\x.txt", redacted)

    def test_user_name_is_redacted_as_a_path_component_and_the_self_scan_names_survivors(self):
        replacements = report.path_replacements(None, None)
        user = report.current_user()
        self.assertTrue(user)
        other = f"D:\\elsewhere\\{user}\\file.txt"
        self.assertEqual(f"D:\\elsewhere\\{report.USER_PLACEHOLDER}\\file.txt", report.redact_text(other, replacements))
        self.assertEqual(f"/srv/{report.USER_PLACEHOLDER}/x", report.redact_text(f"/srv/{user.upper()}/x", replacements))
        # The bare user name outside a path is not a marker: on the runner it is the word "runner".
        self.assertEqual(f"{user} said hi", report.redact_text(f"{user} said hi", replacements))
        self.assertEqual([], report.redaction_survivors({"ok": ["https://github.com/x", "ratio 3:1", "11:47:05Z", "<scratch>/api"]}, replacements))
        self.assertEqual(["drive path"], report.redaction_survivors({"leak": "see D:\\other\\thing"}, replacements))
        self.assertEqual(["drive path"], report.redaction_survivors({"leak": "see d:/other/thing"}, replacements))
        self.assertEqual(["drive path"], report.redaction_survivors({"leak": json.dumps("Z:\\repr\\form")}, replacements))
        self.assertIn("path needle", report.redaction_survivors({"leak": str(Path.home()).upper()}, replacements))
        self.assertEqual(["user in path"], report.redaction_survivors({"leak": f"//server/{user}/share"}, replacements))
        self.assertIn("path needle", report.redaction_survivors({str(Path.home()): "as a key"}, replacements))


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

    def test_prepare_checkout_disables_the_push_url_of_the_scratch_clone(self):
        """S1: a command run inside the scratch clone cannot push anywhere, whatever credential it finds."""
        self.assertEqual("", support.git(self.root, "config", "--default", "", "--get", "remote.origin.pushurl").strip())
        root, sha, reused, error = run.prepare_checkout(self.scratch, support.ORGANIZATION, self.profile_name)
        self.assertIsNone(error)
        self.assertEqual(run.DISABLED_PUSH_URL, support.git(self.root, "config", "--get", "remote.origin.pushurl").strip())
        self.assertEqual(f"https://github.com/{support.ORGANIZATION}/{self.profile_name}.git",
                         support.git(self.root, "remote", "get-url", "origin").strip(), "the fetch URL is untouched")
        push = subprocess.run(["git", "-C", str(self.root), "push", "--dry-run", "origin", "HEAD"],
                              capture_output=True, check=False, env=defects.probe_environment(), timeout=60)
        self.assertNotEqual(0, push.returncode)
        self.assertIn(b"DISABLED", push.stderr)
        # Idempotent on reuse, and the clone still counts as clean afterwards.
        root, sha, reused, error = run.prepare_checkout(self.scratch, support.ORGANIZATION, self.profile_name)
        self.assertIsNone(error)
        self.assertEqual([], defects.git_status(self.root))

    def test_scratch_git_commands_run_in_the_isolated_environment(self):
        seen = []
        real_run = subprocess.run

        def spy(command, **kwargs):
            seen.append(kwargs.get("env"))
            return real_run(command, **kwargs)

        with mock.patch.object(run.subprocess, "run", spy):
            run.prepare_checkout(self.scratch, support.ORGANIZATION, self.profile_name)
        self.assertTrue(seen)
        for env in seen:
            self.assertIsNotNone(env)
            self.assertEqual("1", env["GIT_CONFIG_NOSYSTEM"])
            self.assertNotIn("GIT_CONFIG_PARAMETERS", env)
            self.assertNotIn("GH_TOKEN", env)

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
        calls = []

        def runner(command, cwd):
            calls.append(command)
            return defects.Result(0, "")

        registry_document = run.registry_module.load_registry()
        client = support.fake_client_for(self.profile_name, self.profile["id"], head,
                                         identity={"id": 42, "full_name": "x", "default_branch": "main"},
                                         branch_rules=support.branch_rules_payload(contexts=(("CI", 15368), ("policy", 15368))))
        record = run.inspect_repository(self.profile_name, self.profile, support.generator, client, registry_document,
                                        self.scratch, support.GOVERNANCE.parent, runner, ("python",))
        report.evaluate_repository(record)
        self.assertEqual("fail", record["result"])
        self.assertFalse(record["identity"]["verified"])
        # S2: the id assertion gates execution — no clone, no checker, no fixture ran in the unverified repository.
        self.assertEqual([], calls)
        self.assertIsNone(record["main_sha"])
        self.assertIsNone(record["generated_baseline"])
        self.assertIsNone(record["repository_check"])
        self.assertEqual([], record["planted_defects"])
        self.assertEqual("repository identity not verified; nothing from the repository was executed", record["clone_error"])
        self.assertTrue(any("repository id does not match" in failure for failure in record["failures"]))
        # The read-only API facts are still recorded so the row explains itself.
        self.assertEqual([{"context": "policy", "integration_id": 15368}], record["required_checks"]["missing"])
        self.assertTrue(any("policy" in failure for failure in record["failures"]))
        failing = support.fake_client_for(self.profile_name, self.profile["id"], head,
                                          identity=run.github_api.ApiError("GET failed with HTTP 403"))
        record = run.inspect_repository(self.profile_name, self.profile, support.generator, failing, registry_document,
                                        self.scratch, support.GOVERNANCE.parent, runner, ("python",))
        report.evaluate_repository(record)
        self.assertEqual("fail", record["result"])
        self.assertEqual([], calls)
        self.assertIsNone(record["identity"]["verified"])
        self.assertIsNone(record["required_checks"])
        self.assertTrue(any("read-only API unavailable" in failure for failure in record["failures"]))

    def test_budget_minutes_reaches_the_recorded_run_and_its_evaluation(self):
        """Q4: a 120 s run is over a one-minute budget; 600 s is within and 601 s over the default."""
        head = support.git(self.root, "rev-parse", "HEAD").strip()
        client = support.fake_client_for(self.profile_name, self.profile["id"], head, runs=support.runs_payload(head, seconds=120))
        registry_document = run.registry_module.load_registry()
        record = run.inspect_repository(self.profile_name, self.profile, support.generator, client, registry_document,
                                        self.scratch, support.GOVERNANCE.parent, lambda command, cwd: defects.Result(0, ""),
                                        (), budget_minutes=1)
        self.assertEqual(1, record["last_main_run"]["budget_minutes"])
        self.assertEqual(120, record["last_main_run"]["wall_clock_seconds"])
        self.assertFalse(record["last_main_run"]["within_budget"])
        report.evaluate_repository(record, budget_minutes=1)
        # The profile's reviewed timeout (10) exceeds a one-minute budget, so the overrun is the documented warning.
        self.assertTrue(any("over the 1-minute budget (profile timeout 10 min)" in warning for warning in record["warnings"]),
                        record["warnings"])
        record["profile_timeout_minutes"] = 1
        report.evaluate_repository(record, budget_minutes=1)
        self.assertTrue(any("over the 1-minute budget" in failure for failure in record["failures"]), record["failures"])
        for seconds, within in ((600, True), (601, False)):
            client = support.fake_client_for(self.profile_name, self.profile["id"], head, runs=support.runs_payload(head, seconds=seconds))
            summary = run.github_api.last_main_run(client, f"{support.ORGANIZATION}/{self.profile_name}")
            self.assertEqual(seconds, summary["wall_clock_seconds"])
            self.assertEqual(within, summary["within_budget"], seconds)

    def test_registry_status_verifies_the_recorded_generator_commit_against_the_workflow_on_main(self):
        """Q6 / C1: the recorded commit must render the workflow on main; an unknown commit or a missing
        checkout is recorded as unverifiable and evaluated as a warning, never silently."""
        infra = support.GOVERNANCE.parent
        registry_document = run.registry_module.load_registry()
        full_name = f"{support.ORGANIZATION}/{self.profile_name}"
        current = support.generator.artifacts(self.profile_name)[".github/workflows/ci.yml"].encode("utf-8")
        status = run.registry_status(registry_document, infra, self.profile_name, full_name, {"CI"}, current)
        if status["workflow_ref_renders_current_workflow"] == "unverifiable":
            self.skipTest("registry commit not present in this shallow history")
        self.assertTrue(status["workflow_ref_renders_current_workflow"])
        self.assertTrue(status["check_name_produced"])
        drifted = run.registry_status(registry_document, infra, self.profile_name, full_name, {"CI"}, b'{"jobs": {"ci": {}}}')
        self.assertFalse(drifted["workflow_ref_renders_current_workflow"])
        record = report.evaluate_repository(passing_record(registry=drifted))
        self.assertIn("the registry workflow_ref does not render the workflow on main", record["failures"])
        unknown = copy.deepcopy(registry_document)
        next(entry for entry in unknown["entries"] if entry["repo"] == full_name)["workflow_ref"] = "0" * 40
        status = run.registry_status(unknown, infra, self.profile_name, full_name, {"CI"}, current)
        self.assertEqual("unverifiable", status["workflow_ref_renders_current_workflow"])
        record = report.evaluate_repository(passing_record(registry=status))
        self.assertEqual("pass", record["result"])
        self.assertTrue(any(warning.startswith("registry workflow_ref not verifiable in this run: ") and "history" in warning
                            for warning in record["warnings"]), record["warnings"])
        status = run.registry_status(registry_document, infra, self.profile_name, full_name, {"CI"}, None)
        self.assertEqual("unverifiable", status["workflow_ref_renders_current_workflow"])
        self.assertIn("no scratch checkout", status["note"])
        markdown = report.render_markdown(report.build_report([report.evaluate_repository(passing_record(registry=status))],
                                                              None, "anonymous", ()))
        self.assertIn("- warning PenniLogic/example: registry workflow_ref not verifiable in this run: no scratch checkout", markdown)
        missing = run.registry_status({"entries": []}, infra, self.profile_name, full_name, {"CI"}, current)
        self.assertIsNone(missing["entry"])
        self.assertIn("no check-name registry entry", report.evaluate_repository(passing_record(registry=missing))["failures"])

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
        raw = (output / "conformance-report.json").read_text(encoding="utf-8")
        # Q3: assert on the parsed strings (the JSON text doubles backslashes, hiding a native Windows path)
        # and on the raw text in every spelling the redaction promises to cover.
        for marker in (str(self.scratch), str(Path.home()), sys.executable):
            for text in report.strings_of(document):
                self.assertNotIn(marker.lower(), text.lower())
            for spelling in report.spellings(marker):
                self.assertNotIn(spelling.lower(), raw.lower())
                self.assertNotIn(spelling.lower(), summary.lower())
        self.assertEqual([], report.redaction_survivors(document, report.path_replacements(self.scratch, support.GOVERNANCE.parent)))
        self.assertIn("<scratch>", raw)
        self.assertTrue(summary.endswith("\n"))
        self.assertFalse(summary.endswith("\n\n"), "C4: exactly one newline at the end of the summary")
        self.assertIn("Conformance PASS: 1 repositories, 0 failure(s)", out.getvalue())
        self.assertEqual([], document["not_run"])  # no non-python fixture applies to the .github profile
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(2, run.main(["--scratch", str(self.scratch), "--output", str(output), "--repository", "nope"]))

    def test_main_writes_nothing_when_the_redaction_self_scan_finds_a_survivor(self):
        """Q1: a marker that survives redaction fails the job before any file is written."""
        head = support.git(self.root, "rev-parse", "HEAD").strip()
        client = support.fake_client_for(self.profile_name, self.profile["id"], head)
        output = self.scratch / "unwritten"
        err = io.StringIO()
        with mock.patch.object(run.github_api, "choose_client", lambda mode: client), \
                mock.patch.object(run.report_module, "redaction_survivors", lambda document, replacements, credentials: ["drive path"]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = run.main(["--scratch", str(self.scratch), "--output", str(output), "--repository", self.profile_name,
                             "--github-client", "anonymous", "--exercise", "node"])
        self.assertEqual(2, code)
        self.assertEqual([], list(output.iterdir()))
        self.assertIn("Redaction incomplete (drive path); nothing written", err.getvalue())

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

    def test_unconfirmed_probe_exit_aborts_repository_inspection_before_any_later_execution(self):
        head = support.git(self.root, "rev-parse", "HEAD").strip()
        client = support.fake_client_for(self.profile_name, self.profile["id"], head)
        registry_document = run.registry_module.load_registry()
        calls = []

        def unsafe(command, cwd):
            calls.append(command)
            raise defects.UnsafeProcessTreeError("synthetic teardown not confirmed")

        with self.assertRaisesRegex(defects.UnsafeProcessTreeError, "teardown not confirmed"):
            run.inspect_repository(self.profile_name, self.profile, support.generator, client, registry_document,
                                   self.scratch, support.GOVERNANCE.parent, unsafe, ("python",))
        self.assertEqual(1, len(calls), "do not run another checker or plant a defect after unsafe teardown")


if __name__ == "__main__":
    unittest.main()
