"""Tests for scripts/supply_chain_deploy.py: tampered and unsigned artifact rejection by the deployment gate
(passing control with the test-only HMAC fake verifier + one mutation per negative, exact rule ids)."""

import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
from supply_chain_common import Refused
import supply_chain_deploy as deploy
import supply_chain_exceptions as exceptions
import supply_chain_support as fakes


class ExceptEverything:
    """A test-only available exceptions port that would except every finding offered to it."""

    available = True

    def suppression(self, _finding):
        return "synthetic-exception"


class DeployGateTests(unittest.TestCase):
    def setUp(self):
        self.fake = fakes.HmacFakeVerifier()
        self.sha = fakes.sha256(fakes.ARTIFACT)
        self.sbom = fakes.encode(fakes.sbom_document(self.sha))
        self.provenance = fakes.encode(fakes.provenance_statement(self.sha))
        self.signatures = {"artifact": self.fake.sign(self.sha), "sbom": self.fake.sign(fakes.sha256(self.sbom)),
                           "provenance": self.fake.sign(fakes.sha256(self.provenance))}

    def run_gate(self, sha=None, sbom=None, provenance=None, signatures=None, verifier="fake"):
        return deploy.deploy_findings(
            "web/bundle", self.sha if sha is None else sha, self.sbom if sbom is None else sbom,
            self.provenance if provenance is None else provenance,
            self.signatures if signatures is None else signatures, self.fake if verifier == "fake" else verifier)

    def located(self, found):
        return sorted((item["rule_id"], item["location_class"]) for item in found)

    def test_control_signed_bound_artifact_passes(self):
        found = self.run_gate()
        self.assertEqual(found, [])
        self.assertEqual(self.fake.calls, 3)
        self.assertEqual(exceptions.evaluate(found, "high")["decision"], "pass")

    def test_tampered_artifact_is_rejected(self):
        tampered = fakes.sha256(fakes.ARTIFACT + b"!")
        self.assertEqual(self.located(self.run_gate(sha=tampered)), [
            ("SC-SIG-INVALID", "artifact.signature"), ("SC-SUBJECT-PROVENANCE-MISMATCH", "provenance.subject"),
            ("SC-SUBJECT-SBOM-MISMATCH", "sbom.subject")])

    def test_unsigned_artifact_is_rejected(self):
        signatures = dict(self.signatures)
        del signatures["artifact"]
        self.assertEqual(self.located(self.run_gate(signatures=signatures)),
                         [("SC-SIG-UNSIGNED", "artifact.signature")])

    def test_null_signature_is_unsigned(self):
        self.assertEqual(self.located(self.run_gate(signatures={**self.signatures, "sbom": None})),
                         [("SC-SIG-UNSIGNED", "sbom.signature")])

    def test_unsigned_provenance_is_rejected(self):
        signatures = dict(self.signatures)
        del signatures["provenance"]
        self.assertEqual(self.located(self.run_gate(signatures=signatures)),
                         [("SC-SIG-UNSIGNED", "provenance.signature")])

    def test_sbom_changed_after_signing_is_rejected(self):
        self.assertEqual(self.located(self.run_gate(sbom=self.sbom + b"\n")),
                         [("SC-SIG-INVALID", "sbom.signature")])

    def test_provenance_changed_after_signing_is_rejected(self):
        self.assertEqual(self.located(self.run_gate(provenance=self.provenance + b" ")),
                         [("SC-SIG-INVALID", "provenance.signature")])

    def test_signature_swapped_between_members_is_rejected(self):
        swapped = {**self.signatures, "sbom": self.signatures["provenance"]}
        self.assertEqual(self.located(self.run_gate(signatures=swapped)), [("SC-SIG-INVALID", "sbom.signature")])

    def test_production_binding_fails_closed_for_every_member(self):
        self.assertEqual(self.located(self.run_gate(verifier=None)), [
            ("SC-SIG-VERIFIER-UNAVAILABLE", "artifact.signature"),
            ("SC-SIG-VERIFIER-UNAVAILABLE", "provenance.signature"),
            ("SC-SIG-VERIFIER-UNAVAILABLE", "sbom.signature")])

    def test_signature_failures_cannot_be_downgraded_or_excepted(self):
        signatures = dict(self.signatures)
        del signatures["artifact"]
        report = exceptions.evaluate(self.run_gate(signatures=signatures), "info", ExceptEverything())
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["findings"][0]["exception_id"], None)
        self.assertEqual(report["counts"]["by_rule"], {"SC-SIG-UNSIGNED": 1})


class DeployRefusalTests(unittest.TestCase):
    def test_signatures_document_is_strict(self):
        self.assertEqual(deploy.signatures_document(b'{"artifact": null}'), {"artifact": None})
        for data, code in ((b'{"artifact": null, "image": null}', "SC-DEPLOY-SIGNATURES-SHAPE"),
                           (b"[]", "SC-DEPLOY-SIGNATURES-SHAPE"),
                           (b'{"sbom": {}, "sbom": {}}', "SC-DEPLOY-SIGNATURES-JSON"),
                           (b"", "SC-DEPLOY-SIGNATURES-SIZE")):
            with self.subTest(code=code):
                with self.assertRaises(Refused) as caught:
                    deploy.signatures_document(data)
                self.assertEqual(caught.exception.code, code)

    def test_invalid_arguments_are_refused(self):
        sha = fakes.sha256(fakes.ARTIFACT)
        for args, code in ((("web/bundle", "sha256:" + sha, b"{}", b"{}", {}), "SC-DEPLOY-DIGEST"),
                           (("Web", sha, b"{}", b"{}", {}), "SC-DEPLOY-ARTIFACT"),
                           (("web/bundle", sha, b"{}", b"{}", {"image": None}), "SC-DEPLOY-SIGNATURES-SHAPE"),
                           (("web/bundle", sha, "{}", b"{}", {}), "SC-DEPLOY-INPUT")):
            with self.subTest(code=code):
                with self.assertRaises(Refused) as caught:
                    deploy.deploy_findings(*args)
                self.assertEqual(caught.exception.code, code)


if __name__ == "__main__":
    unittest.main()
