"""Tests for scripts/supply_chain_provenance.py: subject-digest binding and statement shape (passing control + one
mutation per negative, exact rule id)."""

import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
from supply_chain_common import Refused, never_exceptable
import supply_chain_exceptions as exceptions
import supply_chain_provenance as provenance
import supply_chain_support as fakes


SHA = fakes.sha256(fakes.ARTIFACT)


def run(document, artifact_sha256=SHA):
    return provenance.provenance_findings(fakes.encode(document), "web/bundle", artifact_sha256)


def rules(document, artifact_sha256=SHA):
    return [item["rule_id"] for item in run(document, artifact_sha256)]


def refused(data, artifact_sha256=SHA):
    try:
        provenance.provenance_findings(data, "web/bundle", artifact_sha256)
    except Refused as caught:
        return caught.code
    raise AssertionError("not refused")


class BindingTests(unittest.TestCase):
    def test_control_statement_naming_the_artifact_passes(self):
        self.assertEqual(rules(fakes.provenance_statement(SHA)), [])

    def test_artifact_among_several_subjects_passes(self):
        document = fakes.provenance_statement(SHA)
        document["subject"].insert(0, {"name": "other.bin", "digest": {"sha512": "6" * 128}})
        self.assertEqual(rules(document), [])

    def test_tampered_artifact_is_rejected(self):
        found = run(fakes.provenance_statement(SHA), fakes.sha256(fakes.ARTIFACT + b"!"))
        self.assertEqual([item["rule_id"] for item in found], ["SC-SUBJECT-PROVENANCE-MISMATCH"])
        self.assertEqual(found[0]["severity"], "critical")
        self.assertTrue(never_exceptable(found[0]["rule_id"]))
        self.assertEqual(exceptions.evaluate(found, "info")["decision"], "fail")

    def test_subject_without_sha256_is_rejected(self):
        document = fakes.provenance_statement(SHA)
        document["subject"][0]["digest"] = {"sha512": "6" * 128}
        self.assertEqual(rules(document), ["SC-SUBJECT-PROVENANCE-MISMATCH"])

    def test_missing_builder_id_fails(self):
        document = fakes.provenance_statement(SHA)
        del document["predicate"]["runDetails"]["builder"]
        self.assertEqual(rules(document), ["SC-PROV-BUILDER-MISSING"])

    def test_invisible_builder_id_fails(self):
        document = fakes.provenance_statement(SHA)
        document["predicate"]["runDetails"]["builder"]["id"] = "\u200b"
        self.assertEqual(rules(document), ["SC-PROV-BUILDER-MISSING"])

    def test_blank_build_type_fails(self):
        document = fakes.provenance_statement(SHA)
        document["predicate"]["buildDefinition"]["buildType"] = " "
        self.assertEqual(rules(document), ["SC-PROV-BUILD-TYPE-MISSING"])

    def test_raw_digests_are_never_published(self):
        other = fakes.sha256(fakes.ARTIFACT + b"!")
        report = exceptions.evaluate(run(fakes.provenance_statement(SHA), other), "high")
        self.assertNotIn(SHA, repr(report))
        self.assertNotIn(other, repr(report))


class RefusalTests(unittest.TestCase):
    def test_control_is_accepted(self):
        self.assertEqual(rules(fakes.provenance_statement(SHA)), [])

    def test_malformed_statements_are_refused(self):
        cases = (
            (lambda d: d.update(_type="https://in-toto.io/Statement/v0.1"), "SC-PROV-TYPE"),
            (lambda d: d.update(predicateType="https://slsa.dev/provenance/v0.2"), "SC-PROV-PREDICATE-TYPE"),
            (lambda d: d.update(predicate=[]), "SC-PROV-SHAPE"),
            (lambda d: d["predicate"].pop("runDetails"), "SC-PROV-SHAPE"),
            (lambda d: d["predicate"]["runDetails"].update(builder="b"), "SC-PROV-SHAPE"),
            (lambda d: d.update(subject=[]), "SC-PROV-SUBJECT"),
            (lambda d: d["subject"][0].pop("name"), "SC-PROV-SUBJECT"),
            (lambda d: d["subject"][0].update(digest={}), "SC-PROV-SUBJECT"),
            (lambda d: d["subject"][0]["digest"].update(sha256=SHA.upper()), "SC-PROV-SUBJECT"),
            (lambda d: d["subject"][0]["digest"].update(sha256=SHA + "\n"), "SC-PROV-SUBJECT"),
            (lambda d: d["subject"][0]["digest"].update(sha512=1), "SC-PROV-SUBJECT"),
            (lambda d: d["subject"][0]["digest"].update({"sha256\x00": "x"}), "SC-PROV-SUBJECT"),
            (lambda d: d["subject"][0]["digest"].update({"\uff53ha256": SHA}), "SC-PROV-SUBJECT"),
        )
        for change, code in cases:
            document = fakes.provenance_statement(SHA)
            change(document)
            with self.subTest(code=code):
                self.assertEqual(refused(fakes.encode(document)), code)

    def test_strict_json_is_required(self):
        for data, code in ((b"", "SC-PROV-SIZE"), (b'{"_type": 1, "_type": 2}', "SC-PROV-JSON"),
                           (b"[Infinity]", "SC-PROV-JSON"), (b"[]", "SC-PROV-TYPE")):
            with self.subTest(code=code):
                self.assertEqual(refused(data), code)

    def test_invalid_arguments_are_refused(self):
        data = fakes.encode(fakes.provenance_statement(SHA))
        self.assertEqual(refused(data, "sha256:" + SHA), "SC-PROV-DIGEST")
        with self.assertRaises(Refused) as caught:
            provenance.provenance_findings(data, "../bundle", SHA)
        self.assertEqual(caught.exception.code, "SC-PROV-ARTIFACT")


if __name__ == "__main__":
    unittest.main()
