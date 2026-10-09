"""Offline CI history, pre-budget warning and publication regressions for infra#22."""

import contextlib
import copy
import datetime
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import conformance_support as support
from conformance import github_api, report, run
from test_conformance_report import passing_record


def runs_payload(seconds):
    runs = []
    for index, duration in enumerate(seconds, 1):
        started = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(days=index)
        runs.append({
            "id": index, "run_number": index, "name": "CI", "workflow_id": 123,
            "path": ".github/workflows/ci.yml", "head_branch": "main", "event": "push",
            "status": "completed", "conclusion": "success", "head_sha": f"{index:040x}",
            "run_attempt": 1, "run_started_at": started.isoformat(),
            "updated_at": (started + datetime.timedelta(seconds=duration)).isoformat(),
            "html_url": f"https://github.com/PenniLogic/example/actions/runs/{index}",
        })
    return {"total_count": len(runs), "workflow_runs": list(reversed(runs))}


def history_record(seconds, mutate=None, budget_minutes=10):
    payload = runs_payload(seconds)
    if mutate is not None:
        mutate(payload["workflow_runs"])
    client = support.fake_client_for("example", 1, "a" * 40, runs=payload)
    history = github_api.main_run_history(client, "PenniLogic/example", budget_minutes=budget_minutes)
    samples = history["runs"]
    return passing_record(
        main_sha=samples[0]["head_sha"] if samples else None,
        last_main_run=samples[0] if samples else None,
        main_run_history=history,
    )


class CollectionTests(unittest.TestCase):
    def test_one_bounded_read_keeps_ten_newest_ci_runs_including_non_successes(self):
        payload = runs_payload(range(101, 113))
        payload["workflow_runs"][0]["conclusion"] = "failure"
        payload["workflow_runs"][3]["conclusion"] = "cancelled"
        payload["workflow_runs"].insert(0, {"name": "Conformance"})
        client = support.fake_client_for("example", 1, "a" * 40, runs=payload)
        history = github_api.main_run_history(client, "PenniLogic/example")
        self.assertEqual(
            ["/repos/PenniLogic/example/actions/runs?branch=main&event=push&status=completed&per_page=100"],
            client.paths,
        )
        self.assertEqual(1, client.requests)
        self.assertEqual(10, history["sample_limit"])
        self.assertEqual(100, history["scan_limit"])
        self.assertEqual(13, history["scanned_runs"])
        self.assertFalse(history["scan_limit_reached"])
        self.assertEqual(list(range(12, 2, -1)), [sample["id"] for sample in history["runs"]])
        self.assertEqual(["failure", "success", "success", "cancelled"],
                         [sample["conclusion"] for sample in history["runs"][:4]])
        second = support.fake_client_for("example", 1, "a" * 40, runs=payload)
        self.assertEqual(history["runs"][0], github_api.last_main_run(second, "PenniLogic/example"))

    def test_bounded_scan_is_explicit_and_does_not_fetch_another_page(self):
        payload = runs_payload([240, 240, 240, 300])
        payload["workflow_runs"] += [{"name": "Conformance"}] * 96
        payload["total_count"] = 500
        client = support.fake_client_for("example", 1, "a" * 40, runs=payload)
        history = github_api.main_run_history(client, "PenniLogic/example")
        self.assertTrue(history["scan_limit_reached"])
        self.assertEqual(100, history["scanned_runs"])
        record = history_record([240, 240, 240, 300])
        record["main_run_history"] = history
        report.evaluate_repository(record)
        self.assertEqual(1, client.requests)
        self.assertTrue(any("100-run scan limit" in warning for warning in record["warnings"]))

    def test_empty_or_interleaved_other_workflows_are_not_invented_ci_history(self):
        for runs in ([], [{"name": "Conformance"}] * 100):
            with self.subTest(count=len(runs)):
                client = support.fake_client_for("example", 1, "a" * 40, runs={"workflow_runs": runs})
                history = github_api.main_run_history(client, "PenniLogic/example")
                record = report.evaluate_repository(passing_record(last_main_run=None, main_run_history=history))
                self.assertEqual([], history["runs"])
                self.assertEqual("insufficient_history", record["ci_duration_trend"]["status"])
                self.assertIsNone(record["ci_duration_trend"]["direction"])

    def test_invalid_api_shapes_fail_explicitly_without_echoing_the_body(self):
        for payload in (None, [], {}, {"workflow_runs": None}, {"workflow_runs": {}},
                        {"workflow_runs": ["synthetic-secret"]}, {"workflow_runs": [{}]},
                        {"workflow_runs": [{"name": None}]},
                        {"workflow_runs": [{"name": "CI"}] * 101}):
            with self.subTest(payload=payload):
                client = support.fake_client_for("example", 1, "a" * 40, runs=payload)
                with self.assertRaisesRegex(github_api.ApiError, "invalid workflow run") as caught:
                    github_api.main_run_history(client, "PenniLogic/example")
                self.assertNotIn("synthetic-secret", str(caught.exception))
                self.assertEqual(1, client.requests)

    def inspect(self, payload):
        profile = support.generator.PROFILES["repositories"]["infra"]
        client = support.fake_client_for("infra", profile["id"], "a" * 40, runs=payload)
        runner = mock.Mock(side_effect=AssertionError("consumer execution is outside this test"))
        with mock.patch.object(run, "prepare_checkout", return_value=(None, None, False, "synthetic omitted checkout")):
            record = run.inspect_repository(
                "infra", profile, support.generator, client, {"entries": []},
                Path("unused"), support.GOVERNANCE.parent, runner, (),
            )
        runner.assert_not_called()
        return record, client

    def test_caller_uses_the_same_read_for_last_run_and_history_without_consumer_execution(self):
        record, client = self.inspect(runs_payload([240, 240, 240, 360]))
        self.assertEqual(5, client.requests)
        self.assertEqual(1, sum("/actions/runs?" in path for path in client.paths))
        self.assertEqual(record["last_main_run"], record["main_run_history"]["runs"][0])
        self.assertEqual([360, 240, 240, 240],
                         [sample["wall_clock_seconds"] for sample in record["main_run_history"]["runs"]])
        self.assertIsNone(record["api_error"])

    def test_caller_preserves_api_failure_without_retry_or_success_fallback(self):
        record, client = self.inspect(github_api.ApiError("GET runs failed with HTTP 403"))
        report.evaluate_repository(record)
        self.assertEqual(5, client.requests)
        self.assertEqual("fail", record["result"])
        self.assertEqual("GET runs failed with HTTP 403", record["api_error"])
        self.assertIsNone(record["last_main_run"])
        self.assertEqual("unavailable", record["ci_duration_trend"]["status"])
        self.assertTrue(any("read-only API unavailable" in item for item in record["failures"]))


class TrendTests(unittest.TestCase):
    def test_pre_budget_regression_is_alerted(self):
        record = report.evaluate_repository(history_record([240, 240, 240, 360]))
        self.assertTrue(record["last_main_run"]["within_budget"])
        self.assertEqual("pass", record["result"])
        self.assertTrue(any("CI duration regression" in warning for warning in record["warnings"]),
                        record["warnings"])
        trend = record["ci_duration_trend"]
        self.assertEqual("available", trend["status"])
        self.assertEqual("regressing", trend["direction"])
        self.assertEqual(240, trend["baseline_seconds"])
        self.assertEqual(120, trend["change_seconds"])
        self.assertEqual(50, trend["change_percent"])
        self.assertEqual(["regression"], trend["alerts"])
        self.assertIn("without dropping required checks", record["warnings"][0])

    def test_regression_requires_both_absolute_and_relative_thresholds(self):
        for baseline, latest, expected in ((250, 309, False), (300, 360, True),
                                           (301, 361, False), (305, 366, True),
                                           (480, 575, False), (480, 576, True)):
            with self.subTest(baseline=baseline, latest=latest):
                record = report.evaluate_repository(history_record([baseline] * 3 + [latest]))
                self.assertEqual(expected, "regression" in record["ci_duration_trend"]["alerts"])
                self.assertTrue(record["last_main_run"]["within_budget"])

    def test_eighty_percent_warning_persists_even_when_the_window_is_flat(self):
        for seconds, expected in ((479, False), (480, True), (599, True), (600, True)):
            with self.subTest(seconds=seconds):
                record = report.evaluate_repository(history_record([seconds] * 10))
                trend = record["ci_duration_trend"]
                self.assertEqual(480, trend["warning_at_seconds"])
                self.assertEqual(expected, "approaching_budget" in trend["alerts"])
                self.assertEqual("no_material_change", trend["direction"])
                self.assertNotIn("regression", trend["alerts"])
                self.assertTrue(record["last_main_run"]["within_budget"])

    def test_prior_median_excludes_latest_and_comparison_does_not_mutate_history(self):
        record = history_record([100, 200, 300, 401, 500])
        before = copy.deepcopy(record["main_run_history"])
        report.evaluate_repository(record)
        trend = record["ci_duration_trend"]
        self.assertEqual(250, trend["baseline_seconds"])
        self.assertEqual(250, trend["change_seconds"])
        self.assertEqual(100, trend["change_percent"])
        self.assertEqual(before, record["main_run_history"])

    def test_repositories_have_independent_windows_and_alerts(self):
        regressed = history_record([240, 240, 240, 360])
        unchanged = history_record([400, 400, 400, 420])
        unchanged["repository"] = "PenniLogic/other"
        document = report.build_report([regressed, unchanged], None, "fake", ())
        self.assertEqual(2, document["repository_count"])
        self.assertEqual(["regression"], regressed["ci_duration_trend"]["alerts"])
        self.assertEqual(240, regressed["ci_duration_trend"]["baseline_seconds"])
        self.assertEqual([], unchanged["ci_duration_trend"]["alerts"])
        self.assertEqual(400, unchanged["ci_duration_trend"]["baseline_seconds"])
        self.assertEqual([], unchanged["warnings"])

    def test_fractional_median_and_improvement_are_reported_without_rounding_the_threshold(self):
        record = report.evaluate_repository(history_record([299, 300, 301, 302, 240]))
        trend = record["ci_duration_trend"]
        self.assertEqual(300.5, trend["baseline_seconds"])
        self.assertEqual(-60.5, trend["change_seconds"])
        self.assertEqual("improving", trend["direction"])
        self.assertEqual([], trend["alerts"])
        self.assertEqual([], record["warnings"])

    def test_short_history_never_claims_stability_but_still_warns_before_the_budget(self):
        for durations in ([], [480], [240, 480], [240, 240, 480]):
            with self.subTest(durations=durations):
                record = report.evaluate_repository(history_record(durations))
                trend = record["ci_duration_trend"]
                self.assertEqual("insufficient_history", trend["status"])
                self.assertIsNone(trend["direction"])
                self.assertIsNone(trend["baseline_seconds"])
                self.assertTrue(any("need at least 4 comparable runs" in warning for warning in record["warnings"]))
                self.assertEqual(bool(durations), "approaching_budget" in trend["alerts"])

    def test_missing_or_invalid_history_container_is_explicit_in_json_and_markdown(self):
        for history in (None, [], "invalid", {"runs": None}, {"runs": {}}, {"runs": [None]}):
            with self.subTest(history=history):
                document = report.build_report([passing_record(main_run_history=history)], None, "fake", ())
                record = document["repositories"][0]
                self.assertNotEqual("available", record["ci_duration_trend"]["status"])
                self.assertIsNone(record["ci_duration_trend"]["direction"])
                self.assertIn("CI duration trend", " ".join(record["warnings"]))
                self.assertIn("## CI wall-clock trends", report.render_markdown(document))
                self.assertEqual(report.SCHEMA, json.loads(report.to_json(document))["schema"])

    def test_different_or_missing_workflow_metadata_is_not_a_comparable_window(self):
        cases = {
            "workflow_id": 456, "path": ".github/workflows/another.yml",
            "event": "pull_request", "head_branch": "feature", "status": "in_progress",
            "run_attempt": None, "run_number": True, "id": None, "conclusion": None,
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                record = history_record([240, 240, 240, 480],
                                        mutate=lambda samples: samples[1].update({field: value}))
                report.evaluate_repository(record)
                self.assertEqual("invalid_history", record["ci_duration_trend"]["status"])
                self.assertIsNone(record["ci_duration_trend"]["direction"])
                self.assertIn("approaching_budget", record["ci_duration_trend"]["alerts"])
                self.assertEqual(4, len(record["main_run_history"]["runs"]))

    def test_duplicate_runs_wrong_order_and_mismatched_latest_are_explicit(self):
        for kind in ("duplicate", "order", "latest", "too_many"):
            with self.subTest(kind=kind):
                record = history_record([240, 240, 240, 480])
                samples = record["main_run_history"]["runs"]
                if kind == "duplicate":
                    samples[1]["id"] = samples[0]["id"]
                elif kind == "order":
                    samples[1], samples[2] = samples[2], samples[1]
                elif kind == "latest":
                    record["last_main_run"] = {**samples[0], "id": 99}
                else:
                    samples.extend(copy.deepcopy(samples) * 2)
                report.evaluate_repository(record)
                self.assertEqual("invalid_history", record["ci_duration_trend"]["status"])
                self.assertIsNone(record["ci_duration_trend"]["direction"])

    def test_invalid_or_timezone_less_timestamps_do_not_crash_or_count_as_fast_runs(self):
        for start, finish in ((None, "2026-10-03T00:04:00Z"), ("invalid", "2026-10-03T00:04:00Z"),
                              ("2026-10-03T00:00:00", "2026-10-03T00:04:00Z"),
                              ("2026-10-03", "2026-10-03"),
                              ("2026-10-03T00:05:00Z", "2026-10-03T00:04:00Z")):
            with self.subTest(start=start, finish=finish):
                record = history_record([240, 240, 240, 480], mutate=lambda samples: samples[1].update(
                    run_started_at=start, updated_at=finish,
                ))
                report.evaluate_repository(record)
                self.assertIsNone(record["main_run_history"]["runs"][1]["wall_clock_seconds"])
                self.assertEqual("invalid_history", record["ci_duration_trend"]["status"])
                self.assertIn("approaching_budget", record["ci_duration_trend"]["alerts"])
        self.assertEqual(240, github_api.wall_clock_seconds({
            "run_started_at": "2026-10-03T05:30:00+05:30", "updated_at": "2026-10-03T00:04:00Z",
        }))

    def test_every_non_success_and_rerun_stays_visible_instead_of_becoming_a_fast_baseline(self):
        for conclusion in sorted(report.RUN_CONCLUSIONS - {"success"}):
            with self.subTest(conclusion=conclusion):
                record = history_record([10, 240, 240, 480],
                                        mutate=lambda samples: samples[-1].update(conclusion=conclusion))
                report.evaluate_repository(record)
                self.assertEqual(conclusion, record["main_run_history"]["runs"][-1]["conclusion"])
                self.assertEqual("incomparable_history", record["ci_duration_trend"]["status"])
                self.assertIsNone(record["ci_duration_trend"]["baseline_seconds"])
                self.assertIn(f"concluded {conclusion}; retained", " ".join(record["warnings"]))
        record = history_record([240, 240, 240, 480],
                                mutate=lambda samples: samples[1].update(run_attempt=2))
        report.evaluate_repository(record)
        self.assertEqual("incomparable_history", record["ci_duration_trend"]["status"])
        self.assertEqual(2, record["main_run_history"]["runs"][1]["run_attempt"])
        self.assertIn("individual earlier attempts are not available", " ".join(record["warnings"]))
        self.assertIn("approaching_budget", record["ci_duration_trend"]["alerts"])

    def test_previous_failure_and_overrun_are_published_after_a_successful_latest_run(self):
        record = history_record([700, 240, 240, 480],
                                mutate=lambda samples: samples[-1].update(conclusion="failure"))
        document = report.build_report([record], None, "fake", ())
        self.assertEqual("pass", record["result"], "past failures do not rewrite the existing latest-run gate")
        self.assertEqual("incomparable_history", record["ci_duration_trend"]["status"])
        self.assertIn("historical main CI run 1 took 700 s, over", " ".join(record["warnings"]))
        summary = report.render_markdown(document)
        self.assertIn("[700](https://github.com/PenniLogic/example/actions/runs/1) / failure OVER BUDGET", summary)
        self.assertLess(summary.index("[700]"), summary.index("[480]"))

    def test_latest_failure_and_reviewed_timeout_overrun_semantics_are_unchanged(self):
        for timeout in (10, 30):
            for conclusion in ("success", "failure"):
                with self.subTest(timeout=timeout, conclusion=conclusion):
                    record = history_record([240, 240, 240, 601],
                                            mutate=lambda samples: samples[0].update(conclusion=conclusion))
                    record["profile_timeout_minutes"] = timeout
                    report.evaluate_repository(record)
                    self.assertFalse(record["last_main_run"]["within_budget"])
                    self.assertEqual("fail" if timeout == 10 or conclusion == "failure" else "pass", record["result"])
                    findings = record["failures"] if timeout == 10 else record["warnings"]
                    self.assertTrue(any("over the 10-minute budget" in item for item in findings))
                    if conclusion == "failure":
                        self.assertIn("last main CI run concluded failure", record["failures"])

    def test_custom_budget_is_used_for_every_run_and_the_early_warning(self):
        record = history_record([30, 30, 30, 48], budget_minutes=1)
        report.evaluate_repository(record, budget_minutes=1)
        self.assertEqual(48, record["ci_duration_trend"]["warning_at_seconds"])
        self.assertIn("approaching_budget", record["ci_duration_trend"]["alerts"])
        self.assertTrue(all(sample["budget_minutes"] == 1 for sample in record["main_run_history"]["runs"]))
        self.assertIn("1-minute budget", " ".join(record["warnings"]))

    def test_zero_baseline_is_explicitly_incomparable_not_a_division_error_or_stable(self):
        record = report.evaluate_repository(history_record([0, 0, 0, 480]))
        trend = record["ci_duration_trend"]
        self.assertEqual("incomparable_history", trend["status"])
        self.assertEqual(0, trend["baseline_seconds"])
        self.assertIsNone(trend["change_percent"])
        self.assertIsNone(trend["direction"])
        self.assertIn("approaching_budget", trend["alerts"])


class PublicationTests(unittest.TestCase):
    def test_json_shape_is_additive_and_markdown_shows_chronology_comparison_and_alert(self):
        record = history_record([240, 250, 260, 480])
        latest = copy.deepcopy(record["last_main_run"])
        document = report.build_report([record], "a" * 40, "fake", (), generated_at="2026-10-09T00:00:00Z")
        raw = report.to_json(document)
        self.assertEqual("pennilogic.infra.conformance/1", json.loads(raw)["schema"])
        self.assertEqual(latest, document["repositories"][0]["last_main_run"])
        self.assertEqual(4, len(document["repositories"][0]["main_run_history"]["runs"]))
        summary = report.render_markdown(document)
        self.assertIn("## CI wall-clock trends", summary)
        self.assertIn("Prior median (s)", summary)
        self.assertIn("| 250 | +230 s (+92%) | regressing; ALERT: approaching_budget, regression |", summary)
        self.assertLess(summary.index("[240]"), summary.index("[480]"))
        self.assertIn("- warning PenniLogic/example: CI duration regression", summary)
        self.assertEqual(raw, report.to_json(report.build_report(
            [record], "a" * 40, "fake", (), generated_at="2026-10-09T00:00:00Z",
        )))

    def invoke(self, record, hosted=False, environ=None, expect_written=True):
        temporary = tempfile.TemporaryDirectory(prefix="conformance-trend-output-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        output = root / "output"
        stdout, stderr = io.StringIO(), io.StringIO()
        environment = {name: value for name, value in os.environ.items()
                       if not name.startswith(("GH_", "GITHUB_", "ACTIONS_"))}
        environment.update(environ or {})
        if hosted:
            environment["GITHUB_ACTIONS"] = "true"
        client = support.FakeClient({})
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(run.github_api, "choose_client", return_value=client), \
                mock.patch.object(run.registry_module, "load_registry", return_value={}), \
                mock.patch.object(run.registry_module, "validate_registry", return_value=[]), \
                mock.patch.object(run.registry_module, "cross_check", return_value=[]), \
                mock.patch.object(run, "git", return_value=subprocess.CompletedProcess([], 0, b"a" * 40, b"")), \
                mock.patch.object(run, "inspect_repository", return_value=record), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = run.main(["--scratch", str(root / "scratch"), "--output", str(output), "--repository", "infra",
                             "--github-client", "gh" if hosted else "anonymous",
                             "--generated-at", "2026-10-09T00:00:00Z"])
        self.assertEqual(0, client.requests, "publication fixtures must never acquire GitHub metadata")
        if not expect_written:
            self.assertEqual([], list(output.iterdir()))
            return code, stdout.getvalue(), stderr.getvalue(), None, None
        return (code, stdout.getvalue(), stderr.getvalue(),
                (output / "conformance-report.json").read_text(encoding="utf-8"),
                (output / "conformance-summary.md").read_text(encoding="utf-8"))

    def test_cli_and_existing_artifacts_publish_the_same_pre_budget_warning_without_failing(self):
        code, stdout, stderr, raw, markdown = self.invoke(history_record([240, 240, 240, 360]))
        self.assertEqual(0, code)
        document = json.loads(raw)
        warning = document["repositories"][0]["warnings"][0]
        self.assertIn(f"  warning PenniLogic/example: {warning}", stdout)
        self.assertIn(f"- warning PenniLogic/example: {warning}", markdown)
        self.assertIn("## CI wall-clock trends", markdown)
        self.assertNotIn("::warning::", stdout)
        self.assertNotIn("::error::", stderr)

    def test_actions_annotations_escape_commands_and_are_emitted_only_after_redaction(self):
        token = "synthetic-opaque-trend-token"
        record = history_record([240, 240, 240, 480])
        record["registry"]["workflow_ref_renders_current_workflow"] = "unverifiable"
        record["registry"]["note"] = "fixture 100%\r\n::error::" + token
        record["main_run_history"]["runs"][1]["path"] = str(Path.home() / "synthetic-workflow")
        code, stdout, stderr, raw, markdown = self.invoke(record, hosted=True, environ={"GH_TOKEN": token})
        self.assertEqual(0, code)
        for output in (stdout, stderr, raw, markdown):
            self.assertNotIn(token, output)
            self.assertNotIn(str(Path.home()), output)
        annotations = [line for line in stdout.splitlines() if line.startswith("::warning::")]
        self.assertEqual(len(json.loads(raw)["repositories"][0]["warnings"]), len(annotations))
        self.assertIn("100%25%0D%0A::error::[redacted]", annotations[0])
        self.assertTrue(any("CI duration approaching budget" in line for line in annotations))
        self.assertFalse(any(line.startswith("::error::") for line in stdout.splitlines()))

    def test_cli_failure_exit_is_not_replaced_by_a_trend_warning(self):
        record = history_record([240, 240, 240, 601])
        code, stdout, _, raw, _ = self.invoke(record, hosted=True)
        self.assertEqual(1, code)
        self.assertEqual("fail", json.loads(raw)["result"])
        self.assertIn("  FAIL PenniLogic/example: last main CI run took 601 s", stdout)
        self.assertIn("::warning::PenniLogic/example: CI duration regression", stdout)

    def test_failed_redaction_scan_emits_no_report_or_warning_annotation(self):
        with mock.patch.object(run.report_module, "redaction_survivors", return_value=["credential"]):
            code, stdout, stderr, raw, markdown = self.invoke(
                history_record([240, 240, 240, 480]), hosted=True, expect_written=False,
            )
        self.assertEqual(2, code)
        self.assertEqual("", stdout)
        self.assertIn("Redaction incomplete (credential); nothing written", stderr)
        self.assertIsNone(raw)
        self.assertIsNone(markdown)

    def test_non_positive_cli_budget_is_refused_before_inspection(self):
        for budget in ("0", "-1"):
            with self.subTest(budget=budget), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as caught:
                run.parse_arguments(["--scratch", "unused", "--output", "unused", "--budget-minutes", budget])
            self.assertEqual(2, caught.exception.code)


if __name__ == "__main__":
    unittest.main()
