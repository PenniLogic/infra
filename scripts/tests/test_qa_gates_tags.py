"""Protected-tag manifest: committed classification and fail-closed rules (PenniLogic/infra#28; TS-M17).

Each negative has a passing control and exactly one mutation, and asserts the exact static refusal code.
"""

import copy
import unittest

import qa_gates_support as qs
import qa_gates_tags as tags
from qa_gates_common import Refused


# The committed, separately reviewed classification (status "proposed"): weakening a tag must change this table.
COMMITTED = {
    "infra.governance": {
        "test_android_privacy_canonical": {"privacy"}, "test_api_build_coverage": set(),
        "test_api_native_source_fetch": {"security"}, "test_api_node_runtime": set(),
        "test_api_windows_qualification": {"security"}, "test_baseline": {"security"},
        "test_capability_paragraph": set(), "test_conformance_api": {"security"},
        "test_conformance_capture_redaction": {"privacy", "security"}, "test_conformance_defects": {"security"},
        "test_conformance_native_runtime": {"security"}, "test_conformance_processes": set(),
        "test_conformance_registry": set(), "test_conformance_report": set(),
        "test_conformance_runtime": {"security"}, "test_conformance_runtime_fixtures": set(),
        "test_conformance_steps": set(), "test_conformance_trends": set(),
        "test_database_admission_installation": {"security"}, "test_generated_conformance_workflow": {"security"},
        "test_generated_pr_workflow_integrity": {"security"}, "test_infra_qualification": {"security"},
        "test_instruction_provenance": {"security"}, "test_money_source_fetch_reliability": {"money", "security"},
        "test_money_source_materialization": {"money", "security"},
        "test_money_source_materialization_failures": {"money", "security"},
        "test_pr_workflow_integrity": {"security"}, "test_rule_table": set(), "test_workflow_shape": {"security"},
        "test_workflow_validation": {"security"},
    },
    "infra.tooling": {
        "test_bootstrap": {"security"}, "test_database_admission": {"privacy", "security"},
        "test_integration_stack": set(), "test_qa_gates_cli": {"security"}, "test_qa_gates_junit": {"security"},
        "test_qa_gates_ledger": {"security"}, "test_qa_gates_policy": {"security"},
        "test_qa_gates_quarantine": {"security"}, "test_qa_gates_retry": {"security"},
        "test_qa_gates_tags": {"security"}, "test_smoke_infra": {"security"},
    },
}


def parse(document):
    return tags.parse_manifest(qs.encode(document))


class CommittedManifestTests(unittest.TestCase):
    def test_committed_manifest_classifies_the_infra_suites(self):
        manifest = tags.load_manifest()
        self.assertEqual((manifest.repository, manifest.status, manifest.confirmation_ref),
                         ("PenniLogic/infra", "proposed", None))
        self.assertEqual({package.id: (package.money_path, package.owner) for package in manifest.packages.values()},
                         {"infra.governance": (False, "@basiltt"), "infra.tooling": (False, "@basiltt")})
        self.assertEqual({(job.id, job.workflow, job.job, job.packages, job.money_path) for job in manifest.jobs.values()}, {
            ("infra-ci-linux", ".github/workflows/ci.yml", "ci", ("infra.governance", "infra.tooling"), False),
            ("infra-ci-windows", ".github/workflows/ci.yml", "windows", ("infra.governance", "infra.tooling"), False),
        })
        covered = {rule.value for rule in manifest.rules}
        self.assertEqual(covered, {module for modules in COMMITTED.values() for module in modules})
        for package, modules in COMMITTED.items():
            for module, expected in modules.items():
                with self.subTest(module=module):
                    classification = manifest.classify(f"unittest::{module}.SyntheticCase::test_case")
                    self.assertEqual((classification.state, classification.package.id, set(classification.tags)),
                                     ("known", package, expected))
        self.assertEqual(manifest.classify("unittest::test_not_listed.Case::test_case").state, "unknown")


class ClassificationTests(unittest.TestCase):
    def test_unknown_classification_fails_closed(self):
        manifest = parse(qs.manifest_document())
        known = manifest.classify(qs.identity(qs.PLAIN))
        self.assertEqual((known.state, known.protected, known.money_path), ("known", False, False))
        document = qs.manifest_document()
        document["rules"] = [rule for rule in document["rules"] if rule["value"] != "synthetic.plain"]
        unknown = parse(document).classify(qs.identity(qs.PLAIN))
        self.assertEqual((unknown.state, unknown.protected, unknown.money_path, unknown.package),
                         ("unknown", True, True, None))

    def test_rules_disagreeing_on_the_package_are_ambiguous(self):
        document = qs.manifest_document()
        extra = {"id": "PT-006", "field": "suite", "kind": "package", "value": "synthetic",
                 "package": "infra.tooling", "tags": [], "reason": "Synthetic suite rule"}
        document["rules"].append(extra)
        agreeing = parse(document).classify(qs.identity(qs.PLAIN))
        self.assertEqual((agreeing.state, agreeing.rules), ("known", ("PT-001", "PT-006")))
        extra["package"] = "infra.synthetic_money"
        ambiguous = parse(document).classify(qs.identity(qs.PLAIN))
        self.assertEqual((ambiguous.state, ambiguous.protected, ambiguous.money_path), ("ambiguous", True, True))

    def test_tags_are_the_union_of_matching_rules(self):
        document = qs.manifest_document()
        extra = {"id": "PT-006", "field": "classname", "kind": "package", "value": "synthetic.plain.Cases",
                 "package": "infra.tooling", "tags": [], "reason": "Synthetic class rule"}
        document["rules"].append(extra)
        self.assertFalse(parse(document).classify(qs.identity(qs.PLAIN)).protected)
        extra["tags"] = ["privacy"]
        self.assertEqual(parse(document).classify(qs.identity(qs.PLAIN)).tags, {"privacy"})

    def test_money_path_package_implies_the_money_tag(self):
        manifest = parse(qs.manifest_document())
        plain = manifest.classify(qs.identity(qs.PLAIN))
        ledger = manifest.classify(qs.identity(qs.MONEY_PATH))
        self.assertEqual((plain.tags, plain.money_path), (frozenset(), False))
        self.assertEqual((ledger.tags, ledger.money_path, ledger.protected), ({"money"}, True, True))
        self.assertTrue(manifest.jobs[qs.MONEY_JOB].money_path)
        self.assertFalse(manifest.jobs[qs.JOB].money_path)

    def test_package_and_path_rules_respect_their_boundaries(self):
        document = qs.manifest_document()
        document["rules"].append({"id": "PT-006", "field": "classname", "kind": "path", "value": "src/money",
                                  "package": "infra.synthetic_money", "tags": [], "reason": "Synthetic path rule"})
        manifest = parse(document)
        for classname, expected in (
            ("synthetic.plain", "known"), ("synthetic.plain.Cases", "known"), ("synthetic.plainer.Cases", "unknown"),
            ("src/money", "known"), ("src/money/format.test.ts", "known"), ("src/moneyx/format.test.ts", "unknown"),
            ("src/money.test.ts", "unknown"),
        ):
            with self.subTest(classname=classname):
                self.assertEqual(manifest.classify(qs.identity(classname)).state, expected)


class StructureTests(unittest.TestCase):
    def assertRefused(self, code, document):
        with self.assertRaises(Refused) as caught:
            parse(document)
        self.assertEqual(caught.exception.code, code)

    def mutated(self, change):
        document = qs.manifest_document()
        parse(document)
        change(document)
        return document

    def test_structure_refusals(self):
        def set_value(path, value):
            def change(document):
                target = document
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
            return change

        cases = (
            ("MANIFEST-KEYS", set_value(("unexpected",), 1)),
            ("MANIFEST-KEYS", set_value(("rules", 0, "unexpected"), 1)),
            ("MANIFEST-SCHEMA", set_value(("schema",), "pennilogic.qa-gates.protected-tests/2")),
            ("MANIFEST-UNKNOWN-PACKAGE", set_value(("rules", 0, "package"), "infra.unknown")),
            ("MANIFEST-UNKNOWN-PACKAGE", set_value(("jobs", 0, "packages"), ["infra.unknown"])),
            ("MANIFEST-VALUE", set_value(("rules", 1, "tags"), ["secret"])),
            ("MANIFEST-VALUE", set_value(("rules", 1, "tags"), ["security", "security"])),
            ("MANIFEST-VALUE", set_value(("rules", 1, "tags"), [["security"]])),
            ("MANIFEST-VALUE", set_value(("rules", 0, "package"), ["infra.tooling"])),
            ("MANIFEST-VALUE", set_value(("jobs", 0, "packages"), [["infra.tooling"]])),
            ("MANIFEST-VALUE", set_value(("rules", 0, "kind"), "glob")),
            ("MANIFEST-VALUE", set_value(("rules", 0, "value"), "synthetic..plain")),
            ("MANIFEST-VALUE", set_value(("packages", 1, "id"), "docs.tooling")),
            ("MANIFEST-VALUE", set_value(("packages", 1, "money_path"), 0)),
            ("MANIFEST-VALUE", set_value(("packages", 1, "owner"), "synthetic-owner")),
            ("MANIFEST-VALUE", set_value(("jobs", 0, "workflow"), "ci.yml")),
            ("MANIFEST-VALUE", set_value(("rules",), [])),
            ("MANIFEST-STATUS", set_value(("status",), "confirmed")),
            ("MANIFEST-STATUS", set_value(("confirmation_ref",), qs.TICKET)),
            ("MANIFEST-DUPLICATE", set_value(("rules", 1, "id"), "PT-001")),
            ("MANIFEST-DUPLICATE", set_value(("rules", 1, "value"), "synthetic.plain")),
            ("MANIFEST-DUPLICATE", set_value(("jobs", 1, "job"), "ci")),
        )
        for index, (code, change) in enumerate(cases):
            with self.subTest(index=index, code=code):
                self.assertRefused(code, self.mutated(change))

    def test_confirmed_status_requires_a_confirmation_reference(self):
        document = qs.manifest_document()
        document["status"], document["confirmation_ref"] = "confirmed", qs.TICKET
        self.assertEqual(parse(document).status, "confirmed")
        document["confirmation_ref"] = None
        self.assertRefused("MANIFEST-STATUS", document)

    def test_null_owner_is_admitted_and_kept_visible(self):
        document = qs.manifest_document()
        document["packages"][1]["owner"] = None
        self.assertIsNone(parse(document).packages["infra.tooling"].owner)

    def test_strict_json_refusals(self):
        data = qs.encode(qs.manifest_document())
        tags.parse_manifest(data)
        with self.assertRaises(Refused) as caught:
            tags.parse_manifest(data.replace(b'"status": "proposed",', b'"status": "proposed", "status": "proposed",', 1))
        self.assertEqual(caught.exception.code, "MANIFEST-JSON")
        with self.assertRaises(Refused) as caught:
            tags.parse_manifest(b"")
        self.assertEqual(caught.exception.code, "MANIFEST-SIZE")

    def test_invalid_identity_cannot_be_classified(self):
        manifest = parse(qs.manifest_document())
        manifest.classify(qs.identity())
        with self.assertRaises(Refused) as caught:
            manifest.classify("synthetic.suite::synthetic.plain.Cases")
        self.assertEqual(caught.exception.code, "MANIFEST-TEST-ID")


if __name__ == "__main__":
    unittest.main()
