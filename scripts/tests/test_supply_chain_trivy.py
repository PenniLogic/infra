"""Tests for the trivy-shaped report ingestion of scripts/supply_chain_reports.py."""

import copy
import json
from pathlib import Path
import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
from supply_chain_common import Refused
import supply_chain_exceptions as exceptions
import supply_chain_reports as reports


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "supply_chain"
PLANTED = json.loads((FIXTURES / "trivy-image-planted-vulnerable.json").read_text(encoding="utf-8"))
DIGEST = "sha256:" + "c" * 64


def clean():
    document = copy.deepcopy(PLANTED)
    del document["Results"][0]["Vulnerabilities"]
    return document


def config_report(misconfigurations, summary):
    result = {"Target": "Dockerfile", "Class": "config", "Type": "dockerfile",
              "Misconfigurations": misconfigurations}
    if summary is not None:
        result["MisconfSummary"] = summary
    return {"SchemaVersion": 2, "ArtifactName": ".", "ArtifactType": "filesystem", "Results": [result]}


def misconfiguration(status="FAIL", severity="HIGH"):
    return {"ID": "SYNTHETIC-MISCONF-0001", "Status": status, "Severity": severity,
            "CauseMetadata": {"Resource": "synthetic", "StartLine": 3}}


def run(document, kind="image", digest=DIGEST):
    return reports.trivy_findings(json.dumps(document).encode("utf-8"), "web/image", kind, digest)


class TrivyImageTests(unittest.TestCase):
    def test_clean_image_passes(self):
        self.assertEqual(run(clean()), [])
        self.assertEqual(exceptions.evaluate(run(clean()), "high")["decision"], "pass")

    def test_vulnerable_package_in_image_blocks_publish(self):
        found = reports.trivy_findings((FIXTURES / "trivy-image-planted-vulnerable.json").read_bytes(),
                                       "web/image", "image", DIGEST)
        self.assertEqual([(entry["rule_id"], entry["severity"], entry["severity_basis"]) for entry in found],
                         [("SYNTHETIC-VULN-0001", "high", "scanner")])
        report = exceptions.evaluate(found, "high")
        self.assertEqual(report["decision"], "fail")
        self.assertNotIn("synthetic-libplanted", json.dumps(report))

    def test_medium_vulnerability_reports_without_blocking(self):
        document = copy.deepcopy(PLANTED)
        document["Results"][0]["Vulnerabilities"][0]["Severity"] = "MEDIUM"
        self.assertEqual(exceptions.evaluate(run(document), "high")["decision"], "pass")

    def test_unknown_severity_is_unrated_and_blocks(self):
        document = copy.deepcopy(PLANTED)
        document["Results"][0]["Vulnerabilities"][0]["Severity"] = "UNKNOWN"
        found = run(document)
        self.assertEqual([(entry["severity"], entry["severity_basis"]) for entry in found], [("high", "unrated")])
        self.assertEqual(exceptions.evaluate(found, "high")["decision"], "fail")

    def test_subject_binding_by_image_id_or_repo_digest(self):
        self.assertEqual(run(clean(), digest="sha256:" + "d" * 64), [])
        for digest in ("sha256:" + "e" * 64, None, "c" * 64):
            with self.subTest(digest=digest), self.assertRaises(Refused) as caught:
                run(clean(), digest=digest)
            self.assertEqual(caught.exception.code, "SC-TRIVY-SUBJECT")

    def test_missing_metadata_is_refused(self):
        document = clean()
        del document["Metadata"]
        with self.assertRaises(Refused) as caught:
            run(document)
        self.assertEqual(caught.exception.code, "SC-TRIVY-SUBJECT")


class TrivyRefusalTests(unittest.TestCase):
    def refused(self, document, code, kind="image", digest=DIGEST):
        with self.assertRaises(Refused) as caught:
            run(document, kind, digest)
        self.assertEqual(caught.exception.code, code)

    def mutated(self, change):
        document = clean()
        change(document)
        return document

    def test_incomplete_reports_fail_closed(self):
        self.refused(self.mutated(lambda d: d.pop("Results")), "SC-TRIVY-INCOMPLETE")
        self.refused(self.mutated(lambda d: d.__setitem__("Results", [])), "SC-TRIVY-INCOMPLETE")

    def test_schema_and_kind(self):
        self.refused(self.mutated(lambda d: d.__setitem__("SchemaVersion", 1)), "SC-TRIVY-SCHEMA")
        self.refused(self.mutated(lambda d: d.__setitem__("SchemaVersion", 2.0)), "SC-TRIVY-SCHEMA")
        self.refused(self.mutated(lambda d: d.__setitem__("ArtifactType", "filesystem")), "SC-TRIVY-KIND")
        self.refused(clean(), "SC-TRIVY-KIND", kind="sbom")

    def test_shape_refusals(self):
        for change in (
            lambda d: d["Results"][0].pop("Target"),
            lambda d: d["Results"][0].__setitem__("Vulnerabilities", {"x": 1}),
            lambda d: d["Results"][0].__setitem__("Vulnerabilities", [{"VulnerabilityID": "bad id",
                                                                       "PkgName": "p", "Severity": "HIGH"}]),
            lambda d: d["Results"][0].__setitem__("Vulnerabilities", [{"VulnerabilityID": "SYNTHETIC-VULN-0002",
                                                                       "PkgName": "p", "Severity": "SEVERE"}]),
        ):
            with self.subTest():
                self.refused(self.mutated(change), "SC-TRIVY-SHAPE")

    def test_bad_json_and_artifact(self):
        with self.assertRaises(Refused) as caught:
            reports.trivy_findings(b"{", "web/image", "image", DIGEST)
        self.assertEqual(caught.exception.code, "SC-TRIVY-JSON")
        with self.assertRaises(Refused) as caught:
            reports.trivy_findings(json.dumps(clean()).encode(), "Web", "image", DIGEST)
        self.assertEqual(caught.exception.code, "SC-TRIVY-ARTIFACT")


class TrivyConfigTests(unittest.TestCase):
    def test_planted_high_misconfiguration_fails(self):
        control = run(config_report([], {"Successes": 3, "Failures": 0, "Exceptions": 0}), "config", None)
        self.assertEqual(control, [])
        found = run(config_report([misconfiguration()], {"Successes": 2, "Failures": 1, "Exceptions": 0}),
                    "config", None)
        self.assertEqual([(entry["rule_id"], entry["location_class"]) for entry in found],
                         [("SYNTHETIC-MISCONF-0001", "iac.resource")])
        self.assertEqual(exceptions.evaluate(found, "high")["decision"], "fail")

    def test_native_exception_status_is_not_honored(self):
        found = run(config_report([misconfiguration("EXCEPTION")], {"Successes": 2, "Failures": 0, "Exceptions": 1}),
                    "config", None)
        self.assertEqual(exceptions.evaluate(found, "high")["decision"], "fail")

    def test_summary_mismatch_is_incomplete(self):
        for summary in ({"Successes": 2, "Failures": 0, "Exceptions": 0}, None,
                        {"Successes": 2, "Failures": "1", "Exceptions": 0}):
            with self.subTest(summary=summary), self.assertRaises(Refused) as caught:
                run(config_report([misconfiguration()], summary), "config", None)
            self.assertEqual(caught.exception.code, "SC-TRIVY-INCOMPLETE")

    def test_config_report_takes_no_digest(self):
        with self.assertRaises(Refused) as caught:
            run(config_report([], None), "config", DIGEST)
        self.assertEqual(caught.exception.code, "SC-TRIVY-SUBJECT")


if __name__ == "__main__":
    unittest.main()
