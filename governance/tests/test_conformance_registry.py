"""The check-name registry (PenniLogic/infra#24, addendum item 2): schema validation with the
stdlib validator, an entry missing any required field is rejected, and the registry matches the
profiles the generator renders (one entry per profile, the check name the rendered ci.yml produces,
the profile's language, and a workflow_ref whose generator renders the current workflow)."""

import contextlib
import copy
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import conformance_support as support
from conformance import registry, schema


class SchemaValidatorTests(unittest.TestCase):
    SCHEMA = {
        "type": "object", "additionalProperties": False, "required": ["name", "tags"],
        "properties": {
            "name": {"type": "string", "pattern": "[a-z]+", "minLength": 2},
            "tags": {"type": "array", "minItems": 1, "uniqueItems": True, "items": {"type": "string", "enum": ["a", "b"]}},
            "kind": {"const": "fixed"},
            "count": {"type": "integer", "minimum": 0},
        },
    }

    def test_valid_document_has_no_errors(self):
        self.assertEqual([], schema.validate({"name": "ok", "tags": ["a"], "kind": "fixed", "count": 0}, self.SCHEMA))

    def test_each_keyword_reports_its_violation(self):
        cases = {
            "missing required property tags": {"name": "ok"},
            "property is not allowed": {"name": "ok", "tags": ["a"], "extra": 1},
            "does not match the required pattern": {"name": "OK", "tags": ["a"]},
            "shorter than the minimum length": {"name": "o", "tags": ["a"]},
            "fewer items than the minimum": {"name": "ok", "tags": []},
            "duplicates an earlier item": {"name": "ok", "tags": ["a", "a"]},
            "must be one of the enumerated values": {"name": "ok", "tags": ["z"]},
            "must equal the constant value": {"name": "ok", "tags": ["a"], "kind": "other"},
            "below the minimum": {"name": "ok", "tags": ["a"], "count": -1},
            "expected type integer": {"name": "ok", "tags": ["a"], "count": True},
            "expected type object": [],
        }
        for expected, instance in cases.items():
            with self.subTest(expected=expected):
                errors = schema.validate(instance, self.SCHEMA)
                self.assertTrue(any(expected in error for error in errors), errors)

    def test_unsupported_keyword_is_refused_rather_than_ignored(self):
        with self.assertRaises(schema.SchemaError):
            schema.check_schema({"type": "object", "properties": {"x": {"$ref": "#/other"}}})
        with self.assertRaises(schema.SchemaError):
            schema.check_schema({"type": "array", "items": {"oneOf": []}})


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.schema = registry.load_schema()
        self.document = registry.load_registry()

    def test_committed_registry_is_valid_and_matches_the_rendered_profiles(self):
        self.assertEqual([], registry.validate_registry(self.document, self.schema))
        self.assertEqual([], registry.cross_check(self.document))
        self.assertEqual(set(support.generator.PROFILES["repositories"]),
                         {registry.profile_name(entry["repo"]) for entry in self.document["entries"]})

    def test_entry_missing_any_required_field_is_rejected(self):
        for field in registry.REQUIRED_FIELDS:
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                del document["entries"][0][field]
                errors = registry.validate_registry(document, self.schema)
                self.assertEqual([f"/entries/0: missing required property {field}"], errors)

    def test_malformed_entries_are_rejected(self):
        cases = {
            "unknown field": ({"note": "x"}, "property is not allowed"),
            "short workflow_ref": ({"workflow_ref": "4e6e749"}, "does not match the required pattern"),
            "unknown language": ({"language": "cobol"}, "must be one of the enumerated values"),
            "empty check name": ({"check_name": ""}, "shorter than the minimum length"),
            "foreign owner": ({"repo": "Other/infra"}, "does not match the required pattern"),
        }
        for label, (change, expected) in cases.items():
            with self.subTest(label=label):
                document = copy.deepcopy(self.document)
                document["entries"][0].update(change)
                errors = registry.validate_registry(document, self.schema)
                self.assertTrue(any(expected in error for error in errors), errors)
        document = copy.deepcopy(self.document)
        document["entries"].append(dict(document["entries"][0]))
        self.assertIn("/entries/9: duplicates an earlier item", registry.validate_registry(document, self.schema))
        document["entries"][-1]["language"] = "kotlin"
        self.assertIn("/entries/9/repo: repository listed twice", registry.validate_registry(document, self.schema))
        document = copy.deepcopy(self.document)
        document["schema"] = "pennilogic.infra.check-names/2"
        self.assertTrue(registry.validate_registry(document, self.schema))

    def test_cross_check_reports_a_check_name_no_workflow_produces_and_a_missing_profile(self):
        document = copy.deepcopy(self.document)
        document["entries"][0]["check_name"] = "policy"
        errors = registry.cross_check(document)
        self.assertTrue(any("not produced by the rendered ci.yml" in error for error in errors), errors)
        self.assertTrue(any("differs from the policy's required native check" in error for error in errors), errors)
        document = copy.deepcopy(self.document)
        removed = document["entries"].pop()
        errors = registry.cross_check(document)
        self.assertIn(f"profile {registry.profile_name(removed['repo'])}: expected exactly one registry entry, found 0", errors)
        document = copy.deepcopy(self.document)
        document["entries"][0]["repo"] = f"{support.ORGANIZATION}/unknown"
        self.assertTrue(any("no generator profile" in error for error in registry.cross_check(document)))
        document = copy.deepcopy(self.document)
        document["entries"][0]["language"] = "kotlin" if document["entries"][0]["language"] != "kotlin" else "python"
        self.assertTrue(any("/language: expected" in error for error in registry.cross_check(document)))

    def test_expected_language_follows_the_profile_toolchain(self):
        expected = {".github": "python", "docs": "documentation", "contracts": "openapi", "api": "kotlin",
                    "ai-service": "python", "android": "kotlin", "web": "typescript", "admin": "typescript",
                    "infra": "python"}
        for name, profile in support.generator.PROFILES["repositories"].items():
            self.assertEqual(expected[name], registry.expected_language(name, profile), name)

    def test_strict_json_document_refuses_duplicate_keys_and_a_bom(self):
        with self.assertRaises(registry.RegistryError):
            registry.json_document(b'{"schema": 1, "schema": 2}')
        with self.assertRaises(registry.RegistryError):
            registry.json_document("\ufeff{}".encode("utf-8"))

    def test_workflow_ref_of_every_entry_renders_the_current_workflow(self):
        """The recorded generator commits must be in this checkout's history and render byte-identical ci.yml."""
        for entry in self.document["entries"]:
            name = registry.profile_name(entry["repo"])
            with self.subTest(repo=entry["repo"]):
                rendered = registry.render_workflow_at(support.GOVERNANCE.parent, entry["workflow_ref"], name)
                if rendered is None:
                    self.skipTest("commit not present in this (shallow) history")
                self.assertEqual(support.generator.artifacts(name)[".github/workflows/ci.yml"].encode("utf-8"), rendered)

    def test_render_workflow_at_returns_none_for_an_unknown_commit(self):
        def run(command, **kwargs):
            return subprocess.CompletedProcess(command, 128, b"", b"fatal: invalid object name")
        self.assertIsNone(registry.render_workflow_at(support.GOVERNANCE.parent, "0" * 40, "infra", run=run))

    def test_cli_reports_validity_and_rejects_a_broken_registry(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(0, registry.main([]))
            with tempfile.TemporaryDirectory() as scratch:
                broken = Path(scratch) / "check-names.json"
                document = copy.deepcopy(self.document)
                del document["entries"][0]["language"]
                broken.write_text(json.dumps(document), encoding="utf-8")
                self.assertEqual(1, registry.main(["--registry", str(broken)]))
                broken.write_bytes(b"\xff not json")
                self.assertEqual(1, registry.main(["--registry", str(broken)]))
        self.assertIn("Check-name registry valid: 9 repositories", out.getvalue())
        self.assertIn("/entries/0: missing required property language", err.getvalue())
        self.assertIn("Check-name registry unreadable", err.getvalue())


if __name__ == "__main__":
    unittest.main()
