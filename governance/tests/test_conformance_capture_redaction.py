"""Synthetic cut-boundary regressions for the first capture tail, not an exfiltration claim."""

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import conformance_support as support
from conformance import defects, report, run
from test_conformance_report import passing_record


OPAQUE = "synthetic-opaque-cut-boundary-credential-value"


class CaptureRedactionTests(unittest.TestCase):
    def setUp(self):
        retained = mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False)
        retained.start()
        self.addCleanup(retained.stop)
        self.temporary = tempfile.TemporaryDirectory(prefix="conformance-cut-boundary-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.replacements = report.path_replacements(self.root, support.GOVERNANCE.parent)

    def command(self, marker, timed_out=False):
        payload = marker + "|" + "x" * (defects.OUTPUT_TAIL - len(marker))
        self.assertEqual(defects.OUTPUT_TAIL + 1, len(payload))
        return [sys.executable, "-c",
                f"import sys,time; sys.stdout.write({payload!r}); sys.stdout.flush(); time.sleep({6 if timed_out else 0})"]

    def result_or_posix_timeout(self, runner, command):
        try:
            return runner(command, self.root)
        except defects.UnsafeProcessTreeError as error:
            self.assertNotEqual("nt", os.name, "Windows must still confirm owned-tree teardown")
            self.assertIsNotNone(error.result)
            self.assertTrue(error.result.timed_out)
            self.assertFalse(error.result.restoration_safe)
            return error.result

    def capture(self, marker=OPAQUE, timed_out=False, wrapped=False):
        environ = {key: value for key, value in os.environ.items()
                   if key.upper() not in {"GH_TOKEN", "GITHUB_TOKEN"}}
        environ["GH_TOKEN"] = OPAQUE
        runner = run.redacting_runner(2, self.replacements, (OPAQUE,)) if wrapped else (
            lambda command, cwd: defects.subprocess_runner(command, cwd, timeout=2)
        )
        with mock.patch.object(defects.os, "environ", environ):
            result = self.result_or_posix_timeout(runner, self.command(marker, timed_out))
        self.assertEqual(timed_out, result.timed_out)
        self.assertEqual(None if timed_out else 0, result.exit_code)
        self.assertEqual(os.name == "nt" or not timed_out, result.restoration_safe)
        if result.restoration_safe:
            self.assertIsNone(result.error)
        else:
            self.assertIn("POSIX timeout", result.error)
        self.assertLessEqual(len(result.output), defects.OUTPUT_TAIL)
        return result

    def assert_redacted(self, result, marker, placeholder="[redacted]"):
        self.assertNotIn(marker, result.output)
        self.assertNotIn(marker[1:], result.output, "a first-cut suffix must not survive in Result.output")
        self.assertIn(placeholder, result.output)
        self.assertEqual([], report.redaction_survivors({"output": result.output}, self.replacements, (OPAQUE,)))

    def test_direct_normal_capture_redacts_the_exact_value_before_the_first_tail(self):
        self.assert_redacted(self.capture(), OPAQUE)

    def test_scoped_normal_capture_redacts_the_exact_value_before_the_first_tail(self):
        self.assert_redacted(self.capture(wrapped=True), OPAQUE)

    def test_direct_timeout_capture_redacts_the_exact_value_before_the_first_tail(self):
        self.assert_redacted(self.capture(timed_out=True), OPAQUE)

    def test_scoped_timeout_capture_redacts_the_exact_value_before_the_first_tail(self):
        self.assert_redacted(self.capture(timed_out=True, wrapped=True), OPAQUE)

    def test_credential_shapes_are_redacted_before_normal_and_timeout_tails(self):
        for marker in ("ghp_" + "Q" * 36, "github_pat_" + "R" * 40):
            for timed_out in (False, True):
                with self.subTest(shape=marker.split("_")[0], timed_out=timed_out):
                    self.assert_redacted(self.capture(marker, timed_out, wrapped=True), marker)

    def test_known_path_spellings_are_redacted_before_normal_and_timeout_tails(self):
        for marker in (str(self.root / "known-path.txt"), json.dumps(str(self.root / "known-path.txt"))[1:-1]):
            for timed_out in (False, True):
                with self.subTest(escaped="\\\\" in marker, timed_out=timed_out):
                    self.assert_redacted(self.capture(marker, timed_out, wrapped=True), marker, "<scratch>")

    def test_report_shape_and_both_retained_caps_are_unchanged(self):
        result = self.capture(wrapped=True)
        probe = defects.Probe("synthetic bounded output", "synthetic command", expect="observe")
        record = defects._probe_record(probe, result)
        self.assertEqual({
            "label", "command", "expect", "expect_text", "detail_text", "note", "exit_code",
            "timed_out", "outcome", "detail_surfaced", "output_tail", "elapsed_seconds",
        }, set(record))
        self.assertEqual(3000, defects.OUTPUT_TAIL)
        self.assertEqual(400, defects.RECORDED_TAIL)
        self.assertLessEqual(len(record["output_tail"]), defects.RECORDED_TAIL)
        self.assertNotIn(OPAQUE, report.to_json({"probe": record}))
        self.assertNotIn(OPAQUE[1:], report.to_json({"probe": record}))

    def test_printed_heading_is_redacted_but_never_supplies_unittest_attribution(self):
        heading = ("FAIL: test_planted_defect_must_fail "
                   "(test_planted_conformance_defect_0.PlantedConformanceDefect.test_planted_defect_must_fail)")
        payload = (heading + "\n" + "x" * defects.OUTPUT_TAIL).encode("utf-8")
        captured = defects._captured_output(
            payload, lambda text: report.redact_text(text, self.replacements, ("PlantedConformanceDefect",)),
        )
        self.assertEqual("", captured["failure_evidence"], "printed output is not a TestResult witness")
        self.assertNotIn("PlantedConformanceDefect", json.dumps(captured))
        self.assertEqual(defects.OUTPUT_TAIL, len(captured["output"]))

    def test_real_timeout_cannot_promote_a_printed_heading_to_proof(self):
        heading = ("FAIL: test_planted_defect_must_fail "
                   "(test_planted_conformance_defect_0.PlantedConformanceDefect.test_planted_defect_must_fail)")
        command = [sys.executable, "-c",
                   f"import sys,time; print({heading!r}, flush=True); "
                   f"print('x' * {defects.OUTPUT_TAIL}, flush=True); time.sleep(6)"]
        result = self.result_or_posix_timeout(
            lambda command, cwd: defects.subprocess_runner(command, cwd, timeout=2), command)
        self.assertTrue(result.timed_out)
        self.assertEqual(os.name == "nt", result.restoration_safe)
        self.assertEqual("", result.failure_evidence)
        self.assertNotIn(heading, result.output)
        probe = defects.Probe("synthetic timed-out capture", command, expect_text=heading, expect_exit_code=1)
        self.assertEqual("error", defects.probe_outcome(probe, result))

    def controller_sink(self, token_kind, padding_kind, timed_out, split):
        marker = OPAQUE if token_kind == "opaque" else "ghp_" + "Z" * 36
        scratch = self.root / ("scratch-" + "s" * 96)
        prefix = "" if split else "x|"
        available = defects.OUTPUT_TAIL + 1 - len(prefix) - len(marker) - 1
        if padding_kind == "credential":
            padding = "github_pat_" + "P" * (available - len("github_pat_"))
        else:
            unit = str(scratch)
            count, remainder = divmod(available, len(unit) + 1)
            padding = (unit + "|") * count + "x" * remainder
        payload = prefix + marker + "|" + padding
        self.assertEqual(3001, len(payload))
        command = [sys.executable, "-c",
                   f"import sys,time; sys.stdout.write({payload!r}); sys.stdout.flush(); time.sleep({6 if timed_out else 0})"]
        captured = []

        def inspect(name, profile, generator, client, registry_document, scratch, infra_root, runner, exercise,
                    refresh=False, budget_minutes=10):
            result = self.result_or_posix_timeout(runner, command)
            captured.append(result)
            probe = defects._probe_record(defects.Probe("synthetic JSON sink", "synthetic command", expect="pass"), result)
            return passing_record(
                repository="PenniLogic/infra", profile="infra", repository_id=profile["id"],
                planted_defects=[{
                    "id": "synthetic-json-sink", "language": "python", "toolchain": "python",
                    "outcome": "error" if result.timed_out else "proved", "reason": "synthetic timeout" if timed_out else None,
                    "probes": [probe],
                }],
            )

        output = self.root / f"output-{token_kind}-{padding_kind}-{timed_out}-{split}"
        environ = {key: value for key, value in os.environ.items() if key.upper() not in {"GH_TOKEN", "GITHUB_TOKEN"}}
        environ["GH_TOKEN"] = marker
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(defects.os, "environ", environ), \
                mock.patch.object(run.github_api, "choose_client", return_value=support.FakeClient({})), \
                mock.patch.object(run, "inspect_repository", side_effect=inspect), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = run.main(["--scratch", str(scratch), "--output", str(output), "--repository", "infra",
                             "--github-client", "gh", "--command-timeout", "2"])
        self.assertEqual(1 if timed_out else 0, code)
        self.assertEqual(timed_out, captured[0].timed_out)
        self.assertLessEqual(len(captured[0].output), defects.OUTPUT_TAIL)
        raw = (output / "conformance-report.json").read_text()
        document = json.loads(raw)
        summary = (output / "conformance-summary.md").read_text()
        self.assertEqual(report.SCHEMA, document["schema"])
        self.assertEqual([], report.redaction_survivors(document, report.path_replacements(scratch, support.GOVERNANCE.parent),
                                                      (marker,)))
        published = [raw, summary, stdout.getvalue(), stderr.getvalue()]
        self.assertFalse(any(marker in text or marker[1:] in text for text in published),
                         "a recoverable synthetic capture fragment reached a serialized report or output")
        self.assertLessEqual(len(document["repositories"][0]["planted_defects"][0]["probes"][0]["output_tail"]),
                             defects.RECORDED_TAIL)

    def test_controller_json_sink_blocks_split_values_when_credential_padding_shrinks(self):
        for token_kind in ("opaque", "shaped"):
            for timed_out in (False, True):
                for split in (False, True):
                    with self.subTest(kind=token_kind, timed_out=timed_out, split=split):
                        self.controller_sink(token_kind, "credential", timed_out, split)

    def test_controller_json_sink_blocks_split_values_when_known_path_padding_shrinks(self):
        for token_kind in ("opaque", "shaped"):
            for timed_out in (False, True):
                for split in (False, True):
                    with self.subTest(kind=token_kind, timed_out=timed_out, split=split):
                        self.controller_sink(token_kind, "path", timed_out, split)

    @unittest.skipUnless(os.name == "nt", "Windows owned-lifetime failure path")
    def test_windows_unconfirmed_normal_capture_still_redacts_and_retains_the_unsafe_flag(self):
        finish = defects._finish_windows_tree

        def unconfirmed(helpers, job, process):
            detail = finish(helpers, job, process)
            self.assertIsNone(detail, "the finite synthetic process must actually be stopped")
            return "synthetic unconfirmed teardown"

        environ = {**os.environ, "GH_TOKEN": OPAQUE}
        with mock.patch.object(defects.os, "environ", environ), \
                mock.patch.object(defects, "_finish_windows_tree", unconfirmed):
            result = defects._windows_runner(self.command(OPAQUE), self.root, defects.probe_environment(), 2)
        self.assertFalse(result.restoration_safe)
        self.assertIsNone(result.exit_code)
        self.assertEqual("synthetic unconfirmed teardown", result.error)
        self.assert_redacted(result, OPAQUE)


if __name__ == "__main__":
    unittest.main()
