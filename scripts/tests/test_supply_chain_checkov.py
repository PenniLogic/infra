"""Tests for the checkov-shaped report ingestion of scripts/supply_chain_reports.py."""

import copy
import json
from pathlib import Path
import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
from supply_chain_common import Refused
import supply_chain_exceptions as exceptions
import supply_chain_reports as reports


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "supply_chain"
PLANTED = json.loads((FIXTURES / "checkov-planted-high.json").read_text(encoding="utf-8"))


def clean():
    document = copy.deepcopy(PLANTED)
    document[0]["results"]["failed_checks"] = []
    document[0]["summary"]["failed"] = 0
    return document


def run(document):
    return reports.checkov_findings(json.dumps(document).encode("utf-8"), "infra/dockerfile")


class CheckovTests(unittest.TestCase):
    def test_control_clean_report_passes(self):
        self.assertEqual(run(clean()), [])
        self.assertEqual(run(clean()[0]), [])

    def test_planted_high_iac_check_fails(self):
        found = reports.checkov_findings((FIXTURES / "checkov-planted-high.json").read_bytes(), "infra/dockerfile")
        self.assertEqual([(entry["rule_id"], entry["severity"], entry["scanner"]) for entry in found],
                         [("CKV_SYNTH_1", "high", "checkov")])
        report = exceptions.evaluate(found, "high")
        self.assertEqual(report["decision"], "fail")
        self.assertNotIn("Dockerfile", json.dumps(report))

    def test_null_severity_is_unrated_and_blocks(self):
        document = copy.deepcopy(PLANTED)
        document[0]["results"]["failed_checks"][0]["severity"] = None
        found = run(document)
        self.assertEqual([(entry["severity"], entry["severity_basis"]) for entry in found], [("high", "unrated")])

    def test_low_severity_reports_without_blocking(self):
        document = copy.deepcopy(PLANTED)
        document[0]["results"]["failed_checks"][0]["severity"] = "LOW"
        self.assertEqual(exceptions.evaluate(run(document), "high")["decision"], "pass")

    def test_inline_skip_is_not_honored(self):
        document = copy.deepcopy(PLANTED)
        document[0]["results"]["skipped_checks"] = document[0]["results"].pop("failed_checks")
        document[0]["results"]["failed_checks"] = []
        document[0]["summary"].update({"failed": 0, "skipped": 1})
        found = run(document)
        self.assertEqual([entry["rule_id"] for entry in found], ["CKV_SYNTH_1"])
        self.assertEqual(exceptions.evaluate(found, "high")["decision"], "fail")


class CheckovIncompleteTests(unittest.TestCase):
    def refused(self, document, code):
        with self.assertRaises(Refused) as caught:
            run(document)
        self.assertEqual(caught.exception.code, code)

    def mutated(self, change):
        document = clean()
        change(document[0])
        return document

    def test_parsing_errors_fail_closed(self):
        self.refused(self.mutated(lambda s: s["results"].__setitem__("parsing_errors", ["/Dockerfile"])),
                     "SC-CHECKOV-INCOMPLETE")
        self.refused(self.mutated(lambda s: s["summary"].__setitem__("parsing_errors", 1)), "SC-CHECKOV-INCOMPLETE")

    def test_zero_resources_and_bare_summary_fail_closed(self):
        self.refused(self.mutated(lambda s: s["summary"].__setitem__("resource_count", 0)), "SC-CHECKOV-INCOMPLETE")
        self.refused(clean()[0]["summary"], "SC-CHECKOV-INCOMPLETE")
        self.refused([], "SC-CHECKOV-INCOMPLETE")

    def test_counts_must_match_listed_checks(self):
        for key in ("passed", "failed", "skipped"):
            with self.subTest(key=key):
                self.refused(self.mutated(lambda s, key=key: s["summary"].__setitem__(key, 5)),
                             "SC-CHECKOV-INCOMPLETE")
        self.refused(self.mutated(lambda s: s["summary"].pop("resource_count")), "SC-CHECKOV-INCOMPLETE")

    def test_shape_refusals(self):
        for change in (
            lambda s: s.pop("check_type"),
            lambda s: s.__setitem__("results", []),
            lambda s: s["results"].__setitem__("failed_checks", "CKV_SYNTH_1"),
        ):
            with self.subTest():
                self.refused(self.mutated(change), "SC-CHECKOV-SHAPE")
        bad_id = copy.deepcopy(PLANTED)
        bad_id[0]["results"]["failed_checks"][0]["check_id"] = "CKV SYNTH"
        self.refused(bad_id, "SC-CHECKOV-SHAPE")
        bad_severity = copy.deepcopy(PLANTED)
        bad_severity[0]["results"]["failed_checks"][0]["severity"] = "SEVERE"
        self.refused(bad_severity, "SC-CHECKOV-SHAPE")

    def test_bad_json(self):
        with self.assertRaises(Refused) as caught:
            reports.checkov_findings(b'[{"a": 1, "a": 1}]', "infra/dockerfile")
        self.assertEqual(caught.exception.code, "SC-CHECKOV-JSON")


if __name__ == "__main__":
    unittest.main()
