"""Report builder and orchestrator (PenniLogic/infra#24 addendum items 1, 3 and 6): a repository fails
for every reason the job must catch (id mismatch, workflow drift, failed checker, no test step,
missing required check, planted defect not proved, red or over-budget main CI), the published
document carries no local path or credential-shaped string, the Markdown summary is rendered from
the redacted document, and the orchestrator runs end to end against a fake consumer and a fake
API with no network."""

import contextlib
import copy
import html
import io
import json
import subprocess
import sys
import tempfile
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
    def test_a_legacy_clean_record_passes_with_explicit_unavailable_history(self):
        record = report.evaluate_repository(passing_record())
        self.assertEqual("pass", record["result"])
        self.assertEqual([], record["failures"])
        self.assertEqual("unavailable", record["ci_duration_trend"]["status"])
        self.assertEqual(["CI duration trend unavailable: completed main CI history was not available"], record["warnings"])

    def test_each_failure_reason_fails_the_repository(self):
        cases = {
            "repository id does not match": {"identity": {"id": 2, "expected_id": 1, "verified": False}},
            "read-only API unavailable": {"api_error": "GET /x failed with HTTP 403"},
            "scratch checkout unavailable": {"clone_error": "git clone failed"},
            "generated workflow files differ": {"generated_baseline": {"workflow_files_identical": False, "workflow_differences": [".github/workflows/ci.yml"], "stale_files": []}},
            "generator drift command timed out or could not run": {"generated_baseline": {"timed_out": True}},
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
    def test_probe_labels_are_literal_table_text_including_the_lost_placeholders(self):
        labels = [
            "generator drift check: generate.py --repository <profile> --root <scratch> --check",
            "profile command: <tag> & &lt;literal&gt; | `code` *stars* _name_ [link](url) ~~strike~~ \\path",
        ]
        for label in labels:
            probe = defects._probe_record(defects.Probe(label, "unused"), defects.Result(1, "refused"))
            document = report.build_report([passing_record(planted_defects=[{
                "id": "literal-label", "language": "workflow", "toolchain": "python",
                "outcome": "proved", "probes": [probe],
            }])], None, "fake", ())
            row = next(line for line in report.render_markdown(document).splitlines()
                       if line.startswith("| `literal-label`"))
            cells = row.strip("| ").split(" | ")
            encoded = cells[-1].split(" -> exit", 1)[0]
            with self.subTest(label=label):
                self.assertEqual(5, len(cells))
                self.assertEqual(label, html.unescape(encoded))
                self.assertNotIn("<", encoded)
                self.assertNotIn("|", encoded)
                self.assertFalse(any(character in encoded for character in "\\`*_[]~"))
                self.assertEqual(label, document["repositories"][0]["planted_defects"][0]["probes"][0]["label"])
                self.assertIn("exit 1 (as_expected)", row)
                self.assertIn("elapsed: unavailable s", row)

    def test_missing_probe_reason_uses_the_same_literal_table_escaping(self):
        reason = "tool <unavailable> & [not a link](url) | `literal`"
        record = passing_record(planted_defects=[{
            "id": "missing-probe", "language": "python", "toolchain": "python",
            "outcome": "error", "reason": reason, "probes": [],
        }])
        row = next(line for line in report.render_markdown(report.build_report([record], None, "fake", ())).splitlines()
                   if line.startswith("| `missing-probe`"))
        self.assertEqual(reason, html.unescape(row.strip("| ").split(" | ")[-1]))
        self.assertIn("ERROR", row)

    def test_execution_and_probe_timings_are_additive_not_historical_ci_durations(self):
        probe = defects._probe_record(defects.Probe("measured", "unused"), defects.Result(1, "", elapsed_seconds=2.25))
        record = passing_record(timings={"elapsed_seconds": 8.5, "checkout_seconds": 1.125},
                                planted_defects=[{"id": "measured", "language": "python", "toolchain": "python",
                                                  "outcome": "proved", "probes": [probe]}])
        execution = {"repository_workers": 1, "elapsed_seconds": 9.75, "unsafe_process_lifetime": None}
        document = report.build_report([record], None, "fake", (), execution=execution)
        raw = json.loads(report.to_json(document))
        self.assertEqual(execution, raw["execution"])
        self.assertEqual(2.25, raw["repositories"][0]["planted_defects"][0]["probes"][0]["elapsed_seconds"])
        self.assertEqual(47, raw["repositories"][0]["last_main_run"]["wall_clock_seconds"])
        markdown = report.render_markdown(document)
        self.assertIn("Serial repository inspection loop: 9.750 s; 1 worker.", markdown)
        self.assertIn("| PenniLogic/example | 8.500 | 1.125 |", markdown)
        self.assertIn("elapsed: 2.250 s", markdown)
        self.assertIn("not additional totals", markdown)
        self.assertNotIn("## Current conformance execution",
                         report.render_markdown(report.build_report([passing_record()], None, "fake", ())))

    def test_targeted_failure_evidence_is_published_separately_from_the_output_tail(self):
        heading = ("FAIL: test_planted_defect_must_fail "
                   "(test_planted_conformance_defect_0.PlantedConformanceDefect.test_planted_defect_must_fail)")
        probe = defects._probe_record(
            defects.Probe("unchanged unittest command", "python -m unittest discover -s scripts/tests",
                          expect_text=heading, expect_exit_code=1),
            defects.Result(1, "FAILED (failures=2)\n", failure_evidence=heading),
        )
        document = report.build_report([passing_record(planted_defects=[{
            "id": "python-test-failing", "language": "python", "toolchain": "python",
            "outcome": "proved", "probes": [probe],
        }])], None, "fake", ("python",))
        persisted = json.loads(report.to_json(document))["repositories"][0]["planted_defects"][0]["probes"][0]
        self.assertEqual(heading, persisted["failure_evidence"])
        self.assertEqual(1, persisted["expect_exit_code"])
        self.assertEqual("FAILED (failures=2)\n", persisted["output_tail"])
        self.assertIn(f"failure evidence: `{heading}`", report.render_markdown(document))

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


class OwnershipTests(unittest.TestCase):
    def test_layout_refuses_resolved_output_overlap_with_executing_infra(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scratch, infra = root / "scratch", root / "source-area" / "infra"
            for output in (infra, infra / "reports", infra.parent, root / "reports" / ".." / "source-area" / "infra"):
                with self.subTest(output=output), self.assertRaisesRegex(
                        run.OwnershipError, "report output overlaps the executing infra checkout"):
                    run.validate_layout(["docs"], scratch, output, infra)
            self.assertEqual([], list(root.iterdir()))

    def test_main_refuses_source_output_overlap_before_ownership_or_repository_work(self):
        for layout in ("equal", "nested", "ancestor"):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                scratch, infra = root / "scratch", root / "source-area" / "infra"
                output = {"equal": infra, "nested": infra / "reports", "ancestor": infra.parent}[layout]
                client = support.FakeClient({})
                stderr = io.StringIO()
                with mock.patch.object(run.generator_module, "INFRA_ROOT", infra), \
                        mock.patch.object(run.generator_module, "load", return_value=support.generator), \
                        mock.patch.object(run.github_api, "choose_client", return_value=client), \
                        mock.patch.object(run, "own_directories", wraps=run.own_directories) as own, \
                        mock.patch.object(run, "run_owned", return_value=0) as execute, \
                        contextlib.redirect_stderr(stderr):
                    code = run.main(["--scratch", str(scratch), "--output", str(output), "--repository", "docs"])
                self.assertEqual(2, code)
                self.assertIn("report output overlaps the executing infra checkout", stderr.getvalue())
                self.assertNotIn(str(root), stderr.getvalue())
                own.assert_not_called()
                execute.assert_not_called()
                self.assertEqual(0, client.requests)
                self.assertEqual([], list(root.iterdir()))

    def test_disjoint_and_sibling_output_stay_at_the_requested_location(self):
        for layout in ("disjoint", "sibling", "prefix-sibling"):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                scratch, infra = root / "scratch", root / "source-area" / "infra"
                infra.mkdir(parents=True)
                output = {"disjoint": root / "reports", "sibling": infra.parent / "reports",
                          "prefix-sibling": infra.with_name("infra-reports")}[layout]
                with mock.patch.object(run.generator_module, "INFRA_ROOT", infra), \
                        mock.patch.object(run.generator_module, "load", return_value=support.generator), \
                        mock.patch.object(run.github_api, "choose_client", return_value=support.FakeClient({})), \
                        mock.patch.object(run, "git", return_value=subprocess.CompletedProcess([], 0, b"a" * 40, b"")), \
                        mock.patch.object(defects, "isolation_directory", return_value=str(root / "unused-isolation")), \
                        mock.patch.object(run, "inspect_repository", return_value=passing_record(
                            repository="PenniLogic/docs", profile="docs")) as inspect, \
                        mock.patch.dict(run.os.environ, {"GITHUB_ACTIONS": "false"}), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = run.main(["--scratch", str(scratch), "--output", str(output), "--repository", "docs"])
                self.assertEqual(0, code)
                inspect.assert_called_once()
                self.assertEqual({"conformance-report.json", "conformance-summary.md"},
                                 {path.name for path in output.iterdir()})
                self.assertEqual([], list(infra.iterdir()))
                self.assertFalse((scratch / run.OWNERSHIP_MARKER).exists())

    def test_client_and_token_errors_precede_source_output_overlap(self):
        choose_client = run.github_api.choose_client
        cases = (("gh", "non-empty step-scoped GH_TOKEN"), ("anonymous", "requires --github-client gh"))
        for mode, expected in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                scratch, infra = root / "scratch", root / "infra"
                stderr = io.StringIO()
                with mock.patch.object(run.generator_module, "INFRA_ROOT", infra), \
                        mock.patch.object(run.generator_module, "load", return_value=support.generator), \
                        mock.patch.object(run.github_api, "choose_client", side_effect=lambda value: choose_client(
                            value, which=lambda name: "gh", environ={"GITHUB_ACTIONS": "true"})), \
                        mock.patch.object(run, "validate_layout", wraps=run.validate_layout) as validate, \
                        mock.patch.object(run, "own_directories") as own, \
                        mock.patch.object(run, "run_owned") as execute, \
                        contextlib.redirect_stderr(stderr):
                    code = run.main(["--scratch", str(scratch), "--output", str(infra),
                                     "--repository", "docs", "--github-client", mode])
                self.assertEqual(2, code)
                self.assertIn(expected, stderr.getvalue())
                validate.assert_not_called()
                own.assert_not_called()
                execute.assert_not_called()
                self.assertEqual([], list(root.iterdir()))

    def test_layout_refuses_source_and_report_overlap_before_any_checkout_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scratch, infra = root / "scratch", root / "source"
            for output in (scratch, scratch / "docs", scratch / "docs" / "report"):
                with self.subTest(output=output), self.assertRaisesRegex(run.OwnershipError, "report output overlaps"):
                    run.validate_layout(["docs"], scratch, output, infra)
            for source in (scratch, scratch / "docs", scratch / "docs" / "source"):
                with self.subTest(source=source), self.assertRaisesRegex(run.OwnershipError, "executing infra checkout"):
                    run.validate_layout(["docs"], scratch, root / "out", source)
            self.assertEqual([], list(root.iterdir()))

    def test_existing_output_owner_is_not_removed_when_scratch_acquisition_unwinds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scratch, output = root / "scratch", root / "output"
            marker = output / run.OWNERSHIP_MARKER
            marker.mkdir(parents=True)
            identity = marker.stat().st_ino
            with self.assertRaisesRegex(run.OwnershipError, "already owned"):
                with run.own_directories(scratch, output, {"unsafe_process_lifetime": None}):
                    self.fail("must not acquire an already-owned output")
            self.assertEqual(identity, marker.stat().st_ino)
            self.assertFalse((scratch / run.OWNERSHIP_MARKER).exists())

    def test_replaced_ownership_marker_is_retained_not_deleted_as_our_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scratch, output = root / "scratch", root / "output"
            marker = scratch / run.OWNERSHIP_MARKER
            with self.assertRaisesRegex(run.OwnershipError, "marker changed"):
                with run.own_directories(scratch, output, {"unsafe_process_lifetime": None}):
                    marker.rename(scratch / "retained-original-marker")
                    marker.mkdir()
            self.assertTrue(marker.is_dir())
            self.assertTrue((scratch / "retained-original-marker").is_dir())
            self.assertFalse((output / run.OWNERSHIP_MARKER).exists())


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

    def test_prepare_checkout_refuses_a_shared_git_directory_before_running_git(self):
        marker = self.root / ".git" / "commondir"
        marker.write_text("../shared", encoding="utf-8")
        with mock.patch.object(run, "git") as git:
            root, sha, reused, error = run.prepare_checkout(self.scratch, support.ORGANIZATION, self.profile_name)
        self.assertIsNone(root)
        self.assertIsNone(sha)
        self.assertIn("own unlinked Git directory", error)
        git.assert_not_called()
        marker.unlink()

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
        self.assertGreater(record["timings"]["checkout_seconds"], 0)
        measured_parts = (record["timings"]["checkout_seconds"]
                          + record["generated_baseline"]["elapsed_seconds"]
                          + record["repository_check"]["elapsed_seconds"]
                          + sum(probe["elapsed_seconds"] for item in record["planted_defects"] for probe in item["probes"]))
        self.assertGreaterEqual(record["timings"]["elapsed_seconds"], measured_parts)

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

    def test_optional_native_gate_source_and_actual_producer_fail_closed(self):
        document = run.registry_module.load_registry()
        entry = next(item for item in document["entries"] if item["repo"] == "PenniLogic/infra")
        self.assertIn("pr_gate", entry, "final source binding B is required")
        ci = support.generator.workflow("infra").encode("utf-8")
        gate = support.generator.pr_integrity_workflow("infra").encode("utf-8")
        status = run.registry_status(document, support.GOVERNANCE.parent, "infra", "PenniLogic/infra",
                                     {"CI", "PR workflow integrity"}, ci, gate)
        self.assertTrue(status["check_name_produced"])
        self.assertTrue(status["workflow_ref_renders_current_workflow"])
        self.assertTrue(status["pr_gate"]["workflow_ref_renders_current_workflow"])
        for content, produced in ((None, {"CI"}), (b"changed", {"CI", "PR workflow integrity"})):
            status = run.registry_status(document, support.GOVERNANCE.parent, "infra", "PenniLogic/infra",
                                         produced, ci, content)
            self.assertFalse(status["workflow_ref_renders_current_workflow"])
            self.assertEqual("fail", report.evaluate_repository(passing_record(registry=status))["result"])
        unavailable = copy.deepcopy(document)
        next(item for item in unavailable["entries"] if item["repo"] == "PenniLogic/infra")["pr_gate"]["workflow_ref"] = "0" * 40
        status = run.registry_status(unavailable, support.GOVERNANCE.parent, "infra", "PenniLogic/infra",
                                     {"CI", "PR workflow integrity"}, ci, gate)
        self.assertFalse(status["workflow_ref_renders_current_workflow"])
        self.assertIn("unavailable", status["note"])

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

        with mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False):
            record = run.inspect_repository(self.profile_name, self.profile, support.generator, client, registry_document,
                                            self.scratch, support.GOVERNANCE.parent, unsafe, ("python",))
        self.assertIn("teardown not confirmed", record["job_error"])
        self.assertTrue(record["identity"]["verified"], "keep facts collected before the interruption")
        self.assertTrue(record["restoration_deferred"])
        self.assertEqual(1, len(calls), "do not run another checker or plant a defect after unsafe teardown")

    def test_checkout_timings_cover_success_failure_and_an_unverified_not_started_checkout(self):
        for verified, checkout_error in ((True, None), (True, "synthetic clone failure"), (False, None)):
            identity = {"id": self.profile["id"] if verified else 42, "full_name": "synthetic", "default_branch": "main"}
            client = support.fake_client_for(self.profile_name, self.profile["id"], "a" * 40, identity=identity)
            values = [10.0, 11.0, 13.5, 17.0] if verified else [10.0, 17.0]
            with self.subTest(verified=verified, error=checkout_error), \
                    mock.patch.object(run, "prepare_checkout", return_value=(None, None, False, checkout_error)) as prepare, \
                    mock.patch.object(run.time, "monotonic", side_effect=values):
                record = run.inspect_repository(
                    self.profile_name, self.profile, support.generator, client, run.registry_module.load_registry(),
                    self.scratch, support.GOVERNANCE.parent, mock.Mock(), ())
            self.assertEqual(7.0, record["timings"]["elapsed_seconds"])
            self.assertEqual(2.5 if verified else None, record["timings"]["checkout_seconds"])
            self.assertEqual(int(verified), prepare.call_count)
            if checkout_error:
                self.assertEqual(checkout_error, record["clone_error"])

    def test_unexpected_command_runner_failure_retains_ownership_and_partial_repository_facts(self):
        client = support.fake_client_for(self.profile_name, self.profile["id"], "a" * 40)
        with mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False), \
                mock.patch.object(defects, "_windows_runner", side_effect=RuntimeError("synthetic runner failed")), \
                mock.patch.object(defects, "_posix_runner", side_effect=RuntimeError("synthetic runner failed")):
            record = run.inspect_repository(
                self.profile_name, self.profile, support.generator, client, run.registry_module.load_registry(),
                self.scratch, support.GOVERNANCE.parent, defects.subprocess_runner, ())
        self.assertTrue(record["identity"]["verified"])
        self.assertTrue(record["restoration_deferred"])
        self.assertIn("RuntimeError: synthetic runner failed", record["job_error"])
        self.assertEqual(1, client.requests)
        self.assertGreater(record["timings"]["elapsed_seconds"], 0)

    def test_checkout_timeout_retains_capture_and_elapsed_time_without_claiming_cleanup(self):
        client = support.fake_client_for(self.profile_name, self.profile["id"], "a" * 40)
        output = (str(self.scratch) + "\\partial clone output").encode()
        stderr = (str(self.scratch) + "\\partial clone error").encode()
        expired = subprocess.TimeoutExpired(["git", "clone"], 600, output=output, stderr=stderr)
        with mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False), \
                mock.patch.object(run, "prepare_checkout", side_effect=expired), \
                mock.patch.object(run.time, "monotonic", side_effect=[1.0, 2.0, 5.0, 7.0]):
            record = run.inspect_repository(
                self.profile_name, self.profile, support.generator, client, run.registry_module.load_registry(),
                self.scratch, support.GOVERNANCE.parent, mock.Mock(), ())
        self.assertEqual({"elapsed_seconds": 6.0, "checkout_seconds": 3.0}, record["timings"])
        self.assertTrue(record["restoration_deferred"])
        self.assertTrue(record["interrupted_checkout"]["timed_out"])
        self.assertEqual(600, record["interrupted_checkout"]["timeout_seconds"])
        self.assertFalse(record["interrupted_checkout"]["restoration_safe"])
        self.assertIn("<scratch>", record["interrupted_checkout"]["output_tail"])
        self.assertNotIn(str(self.scratch), record["interrupted_checkout"]["output_tail"])
        self.assertEqual(["git", "clone"], record["interrupted_checkout"]["command"])
        self.assertIn("<scratch>", record["interrupted_checkout"]["stderr_tail"])
        self.assertIn("partial clone error", record["interrupted_checkout"]["stderr_tail"])
        self.assertNotIn(str(self.scratch), record["interrupted_checkout"]["stderr_tail"])
        self.assertIn("TimeoutExpired", record["job_error"])

    def test_duplicate_roots_are_refused_before_repository_reads_or_execution_not_deduplicated(self):
        client = support.FakeClient({})
        with mock.patch.object(run.github_api, "choose_client", return_value=client) as choose, \
                mock.patch.object(run, "inspect_repository") as inspect, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = run.main(["--scratch", str(self.scratch), "--output", str(self.scratch / "duplicate-out"),
                             "--repository", self.profile_name, "--repository", self.profile_name])
        self.assertEqual(2, code)
        self.assertIn("no work was deduplicated", err.getvalue())
        choose.assert_called_once()
        self.assertEqual(0, client.requests)
        inspect.assert_not_called()

    def test_serial_failure_retains_requested_order_and_does_not_lose_later_rows(self):
        names = [self.profile_name, "docs", "infra"]
        calls = []
        client = support.FakeClient({"/synthetic-metadata": {}})

        def inspect(name, *args):
            calls.append(name)
            self.assertIs(client, args[2])
            client.get("/synthetic-metadata")
            if name == "docs":
                raise ValueError("synthetic ordinary failure")
            return passing_record(repository=f"PenniLogic/{name}", profile=name)

        output = self.scratch / "serial-out"
        with mock.patch.object(run.github_api, "choose_client", return_value=client) as choose, \
                mock.patch.object(run, "inspect_repository", side_effect=inspect), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = run.main(["--scratch", str(self.scratch), "--output", str(output),
                             *[value for name in names for value in ("--repository", name)]])
        document = json.loads((output / "conformance-report.json").read_text())
        self.assertEqual(1, code)
        self.assertEqual(names, calls)
        self.assertEqual(names, [record["profile"] for record in document["repositories"]])
        self.assertEqual(["pass", "fail", "pass"], [record["result"] for record in document["repositories"]])
        self.assertEqual(1, document["execution"]["repository_workers"])
        self.assertEqual(3, document["api_requests"], "keep requests made before an inspection failed")
        choose.assert_called_once()
        self.assertFalse((self.scratch / run.OWNERSHIP_MARKER).exists())
        self.assertFalse((output / run.OWNERSHIP_MARKER).exists())

    def test_abrupt_invocation_failure_retains_scratch_ownership_without_claiming_safe_cleanup(self):
        output = self.scratch / "interrupted-out"
        with mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False), \
                mock.patch.object(run.github_api, "choose_client", return_value=support.FakeClient({})), \
                mock.patch.object(run, "run_owned", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                run.main(["--scratch", str(self.scratch), "--output", str(output), "--repository", self.profile_name])
            self.assertTrue(defects._UNCONFIRMED_PROCESS)
        self.assertTrue((self.scratch / run.OWNERSHIP_MARKER).is_dir())
        self.assertFalse((output / run.OWNERSHIP_MARKER).exists())

    def test_ownership_io_failure_does_not_echo_an_unredacted_path(self):
        err = io.StringIO()
        with mock.patch.object(run.github_api, "choose_client", return_value=support.FakeClient({})), \
                mock.patch.object(run, "validate_layout", side_effect=PermissionError("Z:\\private\\scratch")), \
                contextlib.redirect_stderr(err):
            code = run.main(["--scratch", str(self.scratch), "--output", str(self.scratch / "out"),
                             "--repository", self.profile_name])
        self.assertEqual(2, code)
        self.assertIn("ownership refused: PermissionError", err.getvalue())
        self.assertNotIn("Z:", err.getvalue())

    def test_unsafe_lifetime_retains_scratch_ownership_and_refuses_later_execution_and_reuse(self):
        output = self.scratch / "unsafe-out"
        result = defects.Result(None, "captured timeout", timed_out=True, error="synthetic unsafe teardown",
                                restoration_safe=False, elapsed_seconds=0.75)
        error = defects.UnsafeProcessTreeError(result.error, result, ["synthetic command"])
        args = ["--scratch", str(self.scratch), "--output", str(output),
                "--repository", self.profile_name, "--repository", "docs"]
        with mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False), \
                mock.patch.object(run.github_api, "choose_client", return_value=support.FakeClient({})), \
                mock.patch.object(run, "inspect_repository", side_effect=error) as inspect, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = run.main(args)
            self.assertEqual(1, inspect.call_count)
            self.assertEqual(2, run.main(args), "an unconfirmed scratch cannot be silently reused")
            self.assertEqual(1, inspect.call_count)
        document = json.loads((output / "conformance-report.json").read_text())
        self.assertEqual(1, code)
        self.assertEqual(["fail", "fail"], [record["result"] for record in document["repositories"]])
        probe = document["repositories"][0]["interrupted_probe"]
        self.assertTrue(probe["timed_out"])
        self.assertFalse(probe["restoration_safe"])
        self.assertEqual(0.75, probe["elapsed_seconds"])
        self.assertEqual("captured timeout", probe["output_tail"])
        self.assertIsNone(document["repositories"][1]["timings"]["elapsed_seconds"])
        self.assertTrue((self.scratch / run.OWNERSHIP_MARKER).is_dir())
        self.assertFalse((output / run.OWNERSHIP_MARKER).exists())


if __name__ == "__main__":
    unittest.main()
