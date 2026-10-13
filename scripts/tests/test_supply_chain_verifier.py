"""Tests for scripts/supply_chain_verifier.py: unsigned, tampered, invalid and unavailable-verifier negatives."""

import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
from supply_chain_common import Refused
import supply_chain_exceptions as exceptions
import supply_chain_support as fakes
import supply_chain_verifier as verifier


ARTIFACT = b"synthetic deployable artifact bytes v1"


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.fake = fakes.HmacFakeVerifier()
        self.subject = fakes.sha256(ARTIFACT)
        self.signature = self.fake.sign(self.subject)

    def rules(self, findings):
        return [entry["rule_id"] for entry in findings]

    def test_control_signed_artifact_passes(self):
        self.assertEqual(verifier.check_signature("web/bundle", self.subject, self.signature, self.fake), [])
        self.assertEqual(self.fake.calls, 1)

    def test_tampered_artifact_is_rejected(self):
        tampered = fakes.sha256(ARTIFACT + b"!")
        found = verifier.check_signature("web/bundle", tampered, self.signature, self.fake)
        self.assertEqual(self.rules(found), ["SC-SIG-INVALID"])
        self.assertEqual(found[0]["severity"], "critical")

    def test_wrong_key_signature_is_rejected(self):
        other = fakes.HmacFakeVerifier().sign(self.subject)
        found = verifier.check_signature("web/bundle", self.subject, other, self.fake)
        self.assertEqual(self.rules(found), ["SC-SIG-INVALID"])

    def test_unsigned_artifact_is_rejected_without_calling_the_verifier(self):
        found = verifier.check_signature("web/bundle", self.subject, None, self.fake)
        self.assertEqual(self.rules(found), ["SC-SIG-UNSIGNED"])
        self.assertEqual(self.fake.calls, 0)

    def test_malformed_signature_objects_are_rejected(self):
        for signature in ({}, [], "sig", {"": "x"}, {str(index): index for index in range(65)}):
            with self.subTest(signature=type(signature).__name__):
                found = verifier.check_signature("web/bundle", self.subject, signature, self.fake)
                self.assertEqual(self.rules(found), ["SC-SIG-SHAPE"])
        self.assertEqual(self.fake.calls, 0)

    def test_production_binding_fails_closed(self):
        found = verifier.check_signature("web/bundle", self.subject, self.signature)
        self.assertEqual(self.rules(found), ["SC-SIG-VERIFIER-UNAVAILABLE"])

    def test_unavailable_fake_fails_closed(self):
        found = verifier.check_signature("web/bundle", self.subject, self.signature, fakes.unavailable())
        self.assertEqual(self.rules(found), ["SC-SIG-VERIFIER-UNAVAILABLE"])

    def test_erroring_verifier_fails_closed(self):
        found = verifier.check_signature("web/bundle", self.subject, self.signature,
                                         fakes.TableFakeVerifier(error=RuntimeError("synthetic")))
        self.assertEqual(self.rules(found), ["SC-SIG-VERIFIER-ERROR"])

    def test_non_boolean_answer_fails_closed(self):
        self.assertEqual(verifier.check_signature("web/bundle", self.subject, self.signature,
                                                  fakes.TableFakeVerifier(answer=True)), [])
        for answer in (1, "true", None, [True]):
            with self.subTest(answer=answer):
                found = verifier.check_signature("web/bundle", self.subject, self.signature,
                                                 fakes.TableFakeVerifier(answer=answer))
                self.assertEqual(self.rules(found), ["SC-SIG-VERIFIER-RESULT"])

    def test_invalid_subject_and_artifact_are_refused(self):
        for subject in ("sha256:" + self.subject, self.subject.upper(), self.subject[:-1], None):
            with self.subTest(subject=subject), self.assertRaises(Refused) as caught:
                verifier.check_signature("web/bundle", subject, self.signature, self.fake)
            self.assertEqual(caught.exception.code, "SC-SIG-SUBJECT")
        with self.assertRaises(Refused) as caught:
            verifier.check_signature("Web Bundle", self.subject, self.signature, self.fake)
        self.assertEqual(caught.exception.code, "SC-SIG-ARTIFACT")

    def test_member_location_is_validated(self):
        found = verifier.check_signature("web/bundle", self.subject, None, self.fake, location="sbom.signature")
        self.assertEqual([(item["rule_id"], item["location_class"]) for item in found],
                         [("SC-SIG-UNSIGNED", "sbom.signature")])
        with self.assertRaises(Refused) as caught:
            verifier.check_signature("web/bundle", self.subject, None, self.fake, location="image.signature")
        self.assertEqual(caught.exception.code, "SC-SIG-LOCATION")


class NoDowngradeTests(unittest.TestCase):
    def test_signature_failure_blocks_at_every_threshold(self):
        subject = fakes.sha256(ARTIFACT)
        found = verifier.check_signature("web/bundle", subject, None)
        for threshold in ("critical", "high", "medium", "low", "info"):
            with self.subTest(threshold=threshold):
                self.assertEqual(exceptions.evaluate(found, threshold)["decision"], "fail")

    def test_accepted_signature_contributes_no_finding(self):
        fake = fakes.HmacFakeVerifier()
        subject = fakes.sha256(ARTIFACT)
        found = verifier.check_signature("web/bundle", subject, fake.sign(subject), fake)
        self.assertEqual(exceptions.evaluate(found, "high")["decision"], "pass")


if __name__ == "__main__":
    unittest.main()
