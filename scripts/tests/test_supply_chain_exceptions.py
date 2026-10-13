"""Tests for scripts/supply_chain_exceptions.py: the unavailable infra#23 seam and the gate evaluation."""

import json
import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
from supply_chain_common import Refused, finding
import supply_chain_exceptions as exceptions


def item(rule="SC-COMPOSE-PRIVILEGED", severity="high", scanner="builtin-compose", where="svc-a"):
    return finding(scanner, rule, severity, "infra/compose", "compose.service", where)


class FakeAvailableExceptions:
    """Test-only stand-in for the future infra#23 binding: suppresses by rule id from an in-memory table."""

    available = True

    def __init__(self, table):
        self.table = dict(table)
        self.calls = []

    def suppression(self, entry):
        self.calls.append(entry["rule_id"])
        return self.table.get(entry["rule_id"])


class RaisingExceptions:
    available = True

    def suppression(self, _entry):
        raise RuntimeError("synthetic port failure")


class UnavailablePortTests(unittest.TestCase):
    def test_default_port_reports_unavailable_and_blocks_every_high_finding(self):
        report = exceptions.evaluate([item()], "high")
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["exceptions"],
                         {"status": "unavailable", "reason": "exceptions unavailable (infra#23 not integrated)"})
        self.assertEqual([entry["effect"] for entry in report["findings"]], ["fail"])
        self.assertIsNone(report["findings"][0]["exception_id"])

    def test_unavailable_port_never_consults_a_table(self):
        port = exceptions.UnavailableExceptions()
        self.assertIsNone(port.suppression(item()))
        self.assertEqual(port.status()["status"], "unavailable")

    def test_no_findings_passes_and_still_states_unavailable(self):
        report = exceptions.evaluate([], "high")
        self.assertEqual(report["decision"], "pass")
        self.assertEqual(report["exceptions"]["status"], "unavailable")
        self.assertEqual(report["counts"]["by_effect"], {"fail": 0, "report": 0, "excepted": 0})


class ThresholdTests(unittest.TestCase):
    def test_boundary_high_fails_and_medium_reports(self):
        control = exceptions.evaluate([item(severity="high")], "high")
        mutated = exceptions.evaluate([item(severity="medium")], "high")
        self.assertEqual(control["decision"], "fail")
        self.assertEqual(mutated["decision"], "pass")
        self.assertEqual(mutated["findings"][0]["effect"], "report")
        self.assertEqual(mutated["counts"]["by_scanner"], {"builtin-compose": {
            "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}})

    def test_signature_rule_fails_below_the_threshold(self):
        control = exceptions.evaluate([item(rule="SC-COMPOSE-PRIVILEGED", severity="low")], "high")
        mutated = exceptions.evaluate([item(rule="SC-SIG-INVALID", severity="low", scanner="verifier")], "high")
        self.assertEqual(control["decision"], "pass")
        self.assertEqual(mutated["decision"], "fail")

    def test_unknown_threshold_is_refused(self):
        exceptions.evaluate([item()], "medium")
        with self.assertRaises(Refused) as caught:
            exceptions.evaluate([item()], "none")
        self.assertEqual(caught.exception.code, "SC-POLICY-THRESHOLD")

    def test_duplicate_fingerprints_are_counted_once(self):
        report = exceptions.evaluate([item(), item(), item(where="svc-b")], "high")
        self.assertEqual(len(report["findings"]), 2)
        self.assertEqual(report["counts"]["by_effect"]["fail"], 2)

    def test_duplicate_keeps_the_most_severe_entry_whatever_the_order(self):
        low, high = item(severity="low"), item(severity="high")
        self.assertEqual(low["fingerprint"], high["fingerprint"])
        control = exceptions.evaluate([high, low], "high")
        self.assertEqual((control["decision"], [entry["severity"] for entry in control["findings"]]),
                         ("fail", ["high"]))
        mutated = exceptions.evaluate([low, high], "high")
        self.assertEqual(mutated, control)

    def test_duplicate_with_equal_severity_keeps_the_unrated_basis(self):
        scanner = finding("trivy", "SYNTHETIC-VULN-0001", "high", "web/image", "image.package", "t", basis="scanner")
        unrated = finding("trivy", "SYNTHETIC-VULN-0001", "high", "web/image", "image.package", "t", basis="unrated")
        for order in ([scanner, unrated], [unrated, scanner]):
            with self.subTest(first=order[0]["severity_basis"]):
                report = exceptions.evaluate(order, "high")
                self.assertEqual([entry["severity_basis"] for entry in report["findings"]], ["unrated"])


class AvailablePortTests(unittest.TestCase):
    def test_suppression_is_published_with_its_id(self):
        control = exceptions.evaluate([item()], "high", FakeAvailableExceptions({}))
        mutated = exceptions.evaluate([item()], "high", FakeAvailableExceptions({"SC-COMPOSE-PRIVILEGED": "exc-1"}))
        self.assertEqual(control["decision"], "fail")
        self.assertEqual(mutated["decision"], "pass")
        self.assertEqual(mutated["exceptions"], {"status": "available"})
        self.assertEqual([(entry["effect"], entry["exception_id"]) for entry in mutated["findings"]],
                         [("excepted", "exc-1")])

    def test_signature_and_subject_rules_are_never_offered_to_the_port(self):
        port = FakeAvailableExceptions({"SC-SIG-UNSIGNED": "exc-1", "SC-SUBJECT-MISMATCH": "exc-2"})
        report = exceptions.evaluate([item(rule="SC-SIG-UNSIGNED", scanner="verifier", severity="critical"),
                                      item(rule="SC-SUBJECT-MISMATCH", scanner="trivy", severity="critical")],
                                     "high", port)
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(port.calls, [])
        self.assertEqual({entry["effect"] for entry in report["findings"]}, {"fail"})

    def test_malformed_exception_id_is_refused(self):
        exceptions.evaluate([item()], "high", FakeAvailableExceptions({"SC-COMPOSE-PRIVILEGED": "exc-1"}))
        with self.assertRaises(Refused) as caught:
            exceptions.evaluate([item()], "high", FakeAvailableExceptions({"SC-COMPOSE-PRIVILEGED": "Exc 1"}))
        self.assertEqual(caught.exception.code, "SC-EXCEPTIONS-ID")

    def test_erroring_port_fails_closed(self):
        with self.assertRaises(Refused) as caught:
            exceptions.evaluate([item()], "high", RaisingExceptions())
        self.assertEqual(caught.exception.code, "SC-EXCEPTIONS-PORT-ERROR")

    def test_port_without_an_explicit_availability_is_refused(self):
        class Ambiguous:
            available = "yes"

        with self.assertRaises(Refused) as caught:
            exceptions.evaluate([item()], "high", Ambiguous())
        self.assertEqual(caught.exception.code, "SC-EXCEPTIONS-PORT")


class ReportScrubbingTests(unittest.TestCase):
    def test_report_carries_no_location_text(self):
        marker = "planted-location-marker"
        text = json.dumps(exceptions.evaluate([item(where=marker)], "high"), ensure_ascii=True)
        self.assertNotIn(marker, text)
        self.assertIn("sha256:", text)


if __name__ == "__main__":
    unittest.main()
