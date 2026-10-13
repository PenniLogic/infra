"""Tests for scripts/supply_chain_sbom.py: CycloneDX completeness and artifact binding (passing control + one
mutation per negative, exact rule id)."""

import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
from supply_chain_common import Refused, never_exceptable
import supply_chain_exceptions as exceptions
import supply_chain_sbom as sbom
import supply_chain_support as fakes


SHA = fakes.sha256(fakes.ARTIFACT)


def rules(document, artifact_sha256=SHA):
    return [item["rule_id"] for item in sbom.sbom_findings(fakes.encode(document), "web/bundle", artifact_sha256)]


def refused(data, artifact_sha256=SHA):
    try:
        sbom.sbom_findings(data, "web/bundle", artifact_sha256)
    except Refused as caught:
        return caught.code
    raise AssertionError("not refused")


class ControlTests(unittest.TestCase):
    def test_complete_bound_sbom_passes_for_every_supported_spec_version(self):
        for spec in sbom.SPEC_VERSIONS:
            with self.subTest(spec=spec):
                self.assertEqual(rules(fakes.sbom_document(SHA, spec)), [])
        report = exceptions.evaluate([], "high")
        self.assertEqual(report["decision"], "pass")

    def test_upper_case_hex_and_extra_strong_hash_are_accepted(self):
        document = fakes.sbom_document(SHA)
        document["metadata"]["component"]["hashes"][0]["content"] = SHA.upper()
        document["components"][0]["hashes"].append({"alg": "SHA-512", "content": "2" * 128})
        self.assertEqual(rules(document), [])

    def test_nested_components_are_checked(self):
        document = fakes.sbom_document(SHA)
        document["components"][0]["components"] = [fakes.component(3)]
        self.assertEqual(rules(document), [])
        document["components"][0]["components"][0]["purl"] = "synthetic-lib-3"
        self.assertEqual(rules(document), ["SC-SBOM-COMPONENT-PURL"])


class CompletenessTests(unittest.TestCase):
    """Each negative mutates exactly one field of the passing control."""

    def mutate(self, change):
        document = fakes.sbom_document(SHA)
        change(document)
        return rules(document)

    def test_component_missing_hash_fails(self):
        self.assertEqual(self.mutate(lambda d: d["components"][1].pop("hashes")), ["SC-SBOM-COMPONENT-HASH"])

    def test_component_with_only_weak_hash_fails(self):
        weak = [{"alg": "SHA-1", "content": "3" * 40}]
        self.assertEqual(self.mutate(lambda d: d["components"][1].update(hashes=weak)),
                         ["SC-SBOM-COMPONENT-HASH"])

    def test_component_with_malformed_hash_content_fails(self):
        bad = [{"alg": "SHA-256", "content": "g" * 64}]
        self.assertEqual(self.mutate(lambda d: d["components"][1].update(hashes=bad)),
                         ["SC-SBOM-COMPONENT-HASH"])

    def test_component_missing_name_version_or_purl_fails(self):
        for field, rule in (("name", "SC-SBOM-COMPONENT-NAME"), ("version", "SC-SBOM-COMPONENT-VERSION"),
                            ("purl", "SC-SBOM-COMPONENT-PURL")):
            with self.subTest(field=field):
                self.assertEqual(self.mutate(lambda d: d["components"][0].pop(field)), [rule])

    def test_invisible_or_control_text_is_not_a_name_or_version(self):
        for value in ("\u200b", "a\x00b", "1.0\u202e", "\u00a0", "line\nbreak"):
            for field, rule in (("name", "SC-SBOM-COMPONENT-NAME"), ("version", "SC-SBOM-COMPONENT-VERSION")):
                with self.subTest(field=field, value=repr(value)):
                    self.assertEqual(self.mutate(lambda d: d["components"][0].update({field: value})), [rule])

    def test_blank_version_fails(self):
        self.assertEqual(self.mutate(lambda d: d["components"][0].update(version="  ")),
                         ["SC-SBOM-COMPONENT-VERSION"])

    def test_no_components_fails(self):
        self.assertEqual(self.mutate(lambda d: d.update(components=[], dependencies=[])),
                         ["SC-SBOM-COMPONENTS-EMPTY"])

    def test_missing_serial_number_fails(self):
        self.assertEqual(self.mutate(lambda d: d.pop("serialNumber")), ["SC-SBOM-SERIAL"])

    def test_duplicate_bom_ref_fails(self):
        self.assertEqual(self.mutate(lambda d: d["components"].append(fakes.component(1))),
                         ["SC-SBOM-BOM-REF-DUPLICATE"])

    def test_dangling_dependency_fails(self):
        self.assertEqual(self.mutate(lambda d: d["dependencies"][0]["dependsOn"].append("pkg:generic/absent@0")),
                         ["SC-SBOM-DEPENDENCY-DANGLING"])

    def test_completeness_findings_block_at_the_default_threshold(self):
        document = fakes.sbom_document(SHA)
        document["components"][1].pop("hashes")
        found = sbom.sbom_findings(fakes.encode(document), "web/bundle", SHA)
        report = exceptions.evaluate(found, "high")
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["findings"][0]["severity"], "high")
        self.assertEqual(report["findings"][0]["scanner"], "builtin-sbom")


class BindingTests(unittest.TestCase):
    def test_sbom_of_a_tampered_artifact_is_rejected(self):
        tampered = fakes.sha256(fakes.ARTIFACT + b"!")
        found = sbom.sbom_findings(fakes.encode(fakes.sbom_document(SHA)), "web/bundle", tampered)
        self.assertEqual([item["rule_id"] for item in found], ["SC-SUBJECT-SBOM-MISMATCH"])
        self.assertEqual(found[0]["severity"], "critical")
        self.assertTrue(never_exceptable(found[0]["rule_id"]))

    def test_missing_subject_component_is_rejected(self):
        document = fakes.sbom_document(SHA)
        del document["metadata"]
        # The control's dependency graph is rooted at the subject, so its reference dangles too.
        self.assertEqual(rules(document), ["SC-SUBJECT-SBOM-MISSING", "SC-SBOM-DEPENDENCY-DANGLING"])

    def test_subject_without_sha256_is_rejected(self):
        document = fakes.sbom_document(SHA)
        document["metadata"]["component"]["hashes"] = [{"alg": "SHA-512", "content": "4" * 128}]
        self.assertEqual(rules(document), ["SC-SUBJECT-SBOM-MISSING"])

    def test_subject_with_conflicting_sha256_entries_is_rejected(self):
        document = fakes.sbom_document(SHA)
        document["metadata"]["component"]["hashes"].append({"alg": "SHA-256", "content": "5" * 64})
        self.assertEqual(rules(document), ["SC-SUBJECT-SBOM-MISSING"])

    def test_raw_subject_digest_is_never_published(self):
        tampered = fakes.sha256(fakes.ARTIFACT + b"!")
        report = exceptions.evaluate(
            sbom.sbom_findings(fakes.encode(fakes.sbom_document(SHA)), "web/bundle", tampered), "high")
        self.assertNotIn(SHA, repr(report))
        self.assertNotIn(tampered, repr(report))


class RefusalTests(unittest.TestCase):
    def test_control_is_accepted(self):
        self.assertEqual(rules(fakes.sbom_document(SHA)), [])

    def test_non_cyclonedx_documents_are_refused(self):
        for change, code in ((lambda d: d.update(bomFormat="SPDX"), "SC-SBOM-FORMAT"),
                             (lambda d: d.update(specVersion="1.3"), "SC-SBOM-SPEC"),
                             (lambda d: d.update(specVersion=1.6), "SC-SBOM-SPEC"),
                             (lambda d: d.update(metadata=[]), "SC-SBOM-SHAPE"),
                             (lambda d: d.update(components={}), "SC-SBOM-SHAPE"),
                             (lambda d: d["components"].append("pkg:generic/x@1"), "SC-SBOM-SHAPE"),
                             (lambda d: d["dependencies"][0].update(dependsOn=[1]), "SC-SBOM-SHAPE"),
                             (lambda d: d["components"][0].update({"bom-ref": ""}), "SC-SBOM-SHAPE")):
            document = fakes.sbom_document(SHA)
            change(document)
            with self.subTest(code=code):
                self.assertEqual(refused(fakes.encode(document)), code)

    def test_strict_json_is_required(self):
        control = fakes.encode(fakes.sbom_document(SHA))
        self.assertEqual(rules(fakes.sbom_document(SHA)), [])
        for data, code in ((b"", "SC-SBOM-SIZE"), (b"\xef\xbb\xbf" + control, "SC-SBOM-JSON"),
                           (b'{"bomFormat": "CycloneDX", "bomFormat": "CycloneDX"}', "SC-SBOM-JSON"),
                           (b"[NaN]", "SC-SBOM-JSON"), (b"\xff", "SC-SBOM-JSON"), (b"[]", "SC-SBOM-FORMAT")):
            with self.subTest(code=code, size=len(data)):
                self.assertEqual(refused(data), code)

    def test_excessive_nesting_is_refused(self):
        document = fakes.sbom_document(SHA)
        node = document["components"][0]
        for index in range(sbom.DEPTH_LIMIT):
            child = fakes.component(100 + index)
            node["components"] = [child]
            node = child
        self.assertEqual(refused(fakes.encode(document)), "SC-SBOM-SHAPE")

    def test_invalid_arguments_are_refused(self):
        data = fakes.encode(fakes.sbom_document(SHA))
        self.assertEqual(refused(data, SHA.upper()), "SC-SBOM-SUBJECT")
        with self.assertRaises(Refused) as caught:
            sbom.sbom_findings(data, "Web Bundle", SHA)
        self.assertEqual(caught.exception.code, "SC-SBOM-ARTIFACT")


if __name__ == "__main__":
    unittest.main()
