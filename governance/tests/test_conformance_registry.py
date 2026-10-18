"""The check-name registry (PenniLogic/infra#24, addendum item 2): schema validation with the
stdlib validator, an entry missing any required field is rejected, and the registry matches the
profiles the generator renders (one entry per profile, the check name the rendered ci.yml produces,
the profile's language, and a workflow_ref whose generator renders the current workflow)."""

import contextlib
import copy
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import conformance_support as support
from conformance import generator as generator_module
from conformance import registry, schema, steps
from test_api_native_source_fetch import remove_observer_pair, remove_shell_focus


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
                self.assertIsNotNone(rendered, "every recorded workflow source must exist in real Git history")
                self.assertEqual(support.generator.artifacts(name)[".github/workflows/ci.yml"].encode("utf-8"), rendered)

    def api_source_ref(self, entry):
        self.assertIn("workflow_ref", entry)
        self.assertEqual("78e6d573f5956cfc933354d2a3fdf22bdea1d4b3", entry["workflow_ref"])
        return entry["workflow_ref"]

    def assert_api_helper_source_qualifier(self, qualifier):
        self.assertEqual(
            (117552, "6f6b47f9be3557a910b605b64a1f422be7bfa59000997a57997f4ef99b0443b7"),
            (len(qualifier), hashlib.sha256(qualifier).hexdigest()),
            "helper source alignment requires the reviewed 78e6 qualifier",
        )

    def assert_api_module_environment_qualifier(self, qualifier):
        self.assertEqual(
            (117468, "b5850ffb3286086602a617f0a99152f8c312453b160cd0b96e9e6bfbfcfccf10"),
            (len(qualifier), hashlib.sha256(qualifier).hexdigest()),
            "module environment control requires the reviewed 8b87 qualifier",
        )

    def assert_api_fixed_controls_qualifier(self, qualifier):
        self.assertEqual(
            (105474, "69db94e8923e299c399bfd8d80c1b2e9b54a1195e943bb85e387264664223f02"),
            (len(qualifier), hashlib.sha256(qualifier).hexdigest()),
            "fixed shell controls require the reviewed e504 qualifier",
        )

    def api_workflow_validator(self, source, root):
        namespace = {"__name__": "api_registry_digest_control", "__file__": str(root / "check_repository.py")}
        exec(compile(source, "API historical checker control", "exec"), namespace)
        return namespace["validate_workflow"]

    def test_infra_workflow_ref_exists_and_replays_its_committed_native_workflow(self):
        entry = next(entry for entry in self.document["entries"] if entry["repo"] == "PenniLogic/infra")
        self.assertEqual("e8a7558e90614e1f766596b6df331450db55deb9", entry["workflow_ref"])
        self.assertEqual("e8a7558e90614e1f766596b6df331450db55deb9", entry["pr_gate"]["workflow_ref"])
        self.assertEqual(entry["workflow_ref"], entry["pr_gate"]["workflow_ref"])
        rendered = registry.render_workflow_at(support.GOVERNANCE.parent, entry["workflow_ref"], "infra")
        self.assertIsNotNone(rendered, "the Infra source binding must exist in real Git history")
        self.assertEqual(support.generator.workflow("infra").encode("utf-8"), rendered)
        committed = subprocess.run(
            ["git", "--no-pager", "show", entry["workflow_ref"] + ":" + registry.CI_WORKFLOW],
            cwd=support.GOVERNANCE.parent, env=support.defects.probe_environment(),
            capture_output=True, check=False, timeout=30,
        )
        self.assertEqual(0, committed.returncode, "the Infra source must contain its rendered native workflow")
        self.assertEqual(rendered, committed.stdout)
        with tempfile.TemporaryDirectory(prefix="infra-registry-source-") as temporary:
            root = Path(temporary)
            for relative in ("generate.py", "repository-profiles.json", "templates/check_repository.py",
                             "templates/infra_ci_checker.py", "templates/pr_workflow_integrity.py",
                             "templates/pr_workflow_integrity_checker.py"):
                committed = subprocess.run(
                    ["git", "--no-pager", "show", entry["workflow_ref"] + ":governance/" + relative],
                    cwd=support.GOVERNANCE.parent, env=support.defects.probe_environment(),
                    capture_output=True, check=False, timeout=30,
                )
                self.assertEqual(0, committed.returncode, "the Infra binding must contain every checker source")
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(committed.stdout)
            historical = generator_module.load(root / "generate.py", name="infra_registry_source")
            rendered_checker = historical.checker("infra").encode("utf-8")
            self.assertEqual(support.generator.checker("infra").encode("utf-8"), rendered_checker)
            committed = subprocess.run(
                ["git", "--no-pager", "show", entry["workflow_ref"] + ":scripts/check_repository.py"],
                cwd=support.GOVERNANCE.parent, env=support.defects.probe_environment(),
                capture_output=True, check=False, timeout=30,
            )
            self.assertEqual(0, committed.returncode, "the Infra source must contain its rendered checker")
            self.assertEqual(rendered_checker, committed.stdout)

    def test_previous_infra_ref_cannot_bind_the_security_preparation_workflows(self):
        current = support.generator.artifacts("infra")
        for workflow_file in (registry.CI_WORKFLOW, registry.PR_GATE_WORKFLOW):
            with self.subTest(workflow_file=workflow_file):
                rendered = registry.render_workflow_at(
                    support.GOVERNANCE.parent, "889c5c35a1677ef33899a2e63bc528d3bac802f9", "infra",
                    workflow_file=workflow_file,
                )
                self.assertIsNotNone(rendered, "the prior Infra source must exist for this regression")
                self.assertNotEqual(current[workflow_file].encode("utf-8"), rendered)

    def test_pre_split_infra_ref_cannot_bind_the_independent_windows_suites(self):
        current = support.generator.artifacts("infra")
        for workflow_file in (registry.CI_WORKFLOW, registry.PR_GATE_WORKFLOW):
            with self.subTest(workflow_file=workflow_file):
                rendered = registry.render_workflow_at(
                    support.GOVERNANCE.parent, "1e16ccc161d1bd964e3c0c438d9e3bac2c95f8e1", "infra",
                    workflow_file=workflow_file,
                )
                self.assertIsNotNone(rendered, "the committed pre-split Infra source must exist")
                self.assertNotEqual(current[workflow_file].encode("utf-8"), rendered)

    @contextlib.contextmanager
    def api_generator_at(self, ref):
        with tempfile.TemporaryDirectory(prefix="api-registry-source-") as temporary:
            root = Path(temporary)
            for relative in ("generate.py", "repository-profiles.json", "templates/check_repository.py",
                             "templates/api_ci_checker.py", "templates/qualify_windows.py"):
                committed = subprocess.run(
                    ["git", "--no-pager", "show", ref + ":governance/" + relative],
                    cwd=support.GOVERNANCE.parent, env=support.defects.probe_environment(),
                    capture_output=True, check=False, timeout=30,
                )
                self.assertEqual(0, committed.returncode, "the API binding must contain every checker and qualifier source")
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(committed.stdout)
            yield root, generator_module.load(root / "generate.py", name="api_registry_source_" + ref)

    def test_api_workflow_ref_exists_and_replays_the_current_reader_and_checker(self):
        entry = next(entry for entry in self.document["entries"] if entry["repo"] == "PenniLogic/api")
        ref = self.api_source_ref(entry)
        kind = subprocess.run(
            ["git", "--no-pager", "cat-file", "-t", ref], cwd=support.GOVERNANCE.parent,
            env=support.defects.probe_environment(), capture_output=True, check=False, timeout=30,
        )
        self.assertEqual(0, kind.returncode)
        self.assertEqual(b"commit\n", kind.stdout)
        rendered = registry.render_workflow_at(support.GOVERNANCE.parent, ref, "api")
        self.assertIsNotNone(rendered, "the API source binding must exist in real Git history")
        self.assertEqual(support.generator.workflow("api").encode("utf-8"), rendered)
        with self.api_generator_at(ref) as (root, historical):
            qualifier = (root / "templates/qualify_windows.py").read_bytes()
            self.assert_api_helper_source_qualifier(qualifier)
            self.assertEqual((support.GOVERNANCE / "templates/qualify_windows.py").read_bytes(), qualifier)
            self.assertEqual(support.generator.workflow("api"), historical.workflow("api"))
            self.assertEqual(support.generator.checker("api"), historical.checker("api"))
            self.assertIsNone(self.api_workflow_validator(historical.checker("api"), root)(
                ".github/workflows/ci.yml", rendered))

    def test_api_source_binding_rejects_data_tree_stale_and_placeholder_refs(self):
        entry = next(entry for entry in self.document["entries"] if entry["repo"] == "PenniLogic/api")
        for case, ref in (
            ("reviewed-data-tree-not-commit", "3a6c9d6006c28139204200058634862b0505dc2c"),
            ("fixed-controls-data-tree-not-commit", "a09f30073ae6af946b87227681de9b2bd6e8a72c"),
            ("module-environment-data-tree-not-commit", "6a1ebb15cfe7d50b1823fba299e35d53be698201"),
            ("helper-alignment-data-tree-not-commit", "3a239dfa95b6917c6cc705a92a47050f996ae29d"),
            ("API-source-not-Infra-source", "5948543f7ce6c3d8382c63bda0510e81f4941c17"),
            ("previous-fixed-controls-source", "e504364cbce8525053540d48d661b23e1d930db9"),
            ("previous-fixed-controls-binding", "cfc7c741e22e0ef060edc2f736b1ba073810991a"),
            ("previous-focus-source", "a5c572a23e9c90dfc6732c70d06eeedcd94f52fa"),
            ("previous-focus-binding", "e2bd839f8e79c7146c2bf006f811e0638647669b"),
            ("previous-semver-source", "1ddc3434d8826605fc9dce7adb843d185dc92aaa"),
            ("previous-binding-commit", "47f8ac77155603f7b156c9ab214c36e95c26d6fb"),
            ("missing-source", "0" * 40),
            ("empty-source", ""),
            ("null-source", None),
            ("moving-head-placeholder", "HEAD"),
        ):
            with self.subTest(case=case), self.assertRaises(AssertionError):
                self.api_source_ref({**entry, "workflow_ref": ref})
        with self.subTest(case="missing-workflow-ref"), self.assertRaises(AssertionError):
            self.api_source_ref({key: value for key, value in entry.items() if key != "workflow_ref"})

    def api_before_helper_source_alignment(self):
        current = (support.GOVERNANCE / "templates/qualify_windows.py").read_bytes()
        self.assert_api_helper_source_qualifier(current)
        for added, previous in (
            (b'OBSERVER_BUDGET_BYTES = 33441\n', b'OBSERVER_BUDGET_BYTES = 30820\n'),
            (b'OBSERVER_BUDGET_SHA256 = "eca36677c55d7addb00660532fd1aafa4343db752bb014641c667530ada83525"\n',
             b'OBSERVER_BUDGET_SHA256 = "a551e6959a2a56c91e657a7c2a5b64b04607f56fe2f55f68e9e5cc4c9270f364"\n'),
            (b'    "scripts/tests/test_money_mutation.py": (248547, "987aeb75eb219d2cd5a927f89eb84a0e2f9c67f834ab419f45a8d02d383f390e"),\n',
             b'    "scripts/tests/test_money_mutation.py": (235983, "c237505d6d986aa6fe98472ac874f92a4be62363fa7774723ea8cb9016d2fb72"),\n'),
            (b'    "scripts/process_budget.py": (33441, "eca36677c55d7addb00660532fd1aafa4343db752bb014641c667530ada83525"),\n',
             b'    "scripts/process_budget.py": (30820, "a551e6959a2a56c91e657a7c2a5b64b04607f56fe2f55f68e9e5cc4c9270f364"),\n'),
            (b"        # The helper discards ambient input and builds OS-inbox plus KnownFolder-shared output.\n"
             b"        # This bridge deliberately replaces that output with the child's singleton inbox path.\n",
             b"        # The unchanged helper strips PSModulePath; only this already-owned bridge sets the child's input.\n"),
        ):
            self.assertEqual(1, current.count(added))
            current = current.replace(added, previous, 1)
        self.assert_api_module_environment_qualifier(current)
        return current

    def test_previous_module_environment_refs_replay_workflow_and_checker_but_cannot_bind_helper_source(self):
        previous_qualifier = self.api_before_helper_source_alignment()
        workflow, checker = support.generator.workflow("api"), support.generator.checker("api")
        self.assertEqual("b4377f326ed95313328172fff4c78eb7c40f9ef203098074ff7d2a0702dc724e",
                         hashlib.sha256(workflow.encode("utf-8")).hexdigest())
        self.assertEqual("33eaa615a6d2fc79b21dd6054b5c026e38c1ecdb14a0e00ee53fc96495266e2d",
                         hashlib.sha256(checker.encode("utf-8")).hexdigest())
        entry = next(entry for entry in self.document["entries"] if entry["repo"] == "PenniLogic/api")
        for ref in ("8b87ef8188c68e68c8c0e9cb33878c3151a7e18e", "1dec8cbd5a752e474a7340373d26c6cf8392aa6e"):
            with self.subTest(ref=ref), self.api_generator_at(ref) as (root, historical):
                self.assertEqual(workflow, historical.workflow("api"))
                self.assertEqual(checker, historical.checker("api"))
                for case, source in (("current-checker", checker), ("historical-checker", historical.checker("api"))):
                    with self.subTest(case=case):
                        self.assertIsNone(self.api_workflow_validator(source, root)(
                            ".github/workflows/ci.yml", workflow.encode("utf-8")))
                qualifier = (root / "templates/qualify_windows.py").read_bytes()
                self.assertEqual(previous_qualifier, qualifier)
                self.assert_api_module_environment_qualifier(qualifier)
                with self.assertRaisesRegex(AssertionError, "helper source alignment requires the reviewed 78e6 qualifier"):
                    self.assert_api_helper_source_qualifier(qualifier)
                with self.assertRaises(AssertionError):
                    self.api_source_ref({**entry, "workflow_ref": ref})

    def api_before_module_environment_control(self):
        current = self.api_before_helper_source_alignment()
        self.assert_api_module_environment_qualifier(current)
        blocks = []
        for start, end, include_end, expected in (
            (b"def shell_focus_module_root_normalized(value):\n",
             b"def shell_focus_control(root, budget, environment, runtime, record):\n", False,
             (9409, "08496be172f0a57c8dc9080b6ef1fd525c0a72010ef0c21d29a37c230676f5ff")),
            (b'    if label == "os-module-root-environment":\n',
             b'    elif label == "explicit-built-in-utility":\n', True,
             (1265, "a4b264697b7d581a1fd43de9089396958b429d944de4c0a8bb70b5560e3362d9")),
        ):
            self.assertEqual(1, current.count(start))
            self.assertEqual(1, current.count(end))
            block = current[current.index(start):current.index(end) + (len(end) if include_end else 0)]
            self.assertEqual(expected, (len(block), hashlib.sha256(block).hexdigest()))
            blocks.append(block)
        for added, previous in (
            (b'SHELL_FOCUS_CONTROLS = ("plain-bare-command", "os-module-root-environment", "explicit-built-in-utility")\n',
             b'SHELL_FOCUS_CONTROLS = ("plain-bare-command", "explicit-built-in-utility")\n'),
            (b'SHELL_FOCUS_ENVIRONMENT_CARRIER = SHELL_FOCUS_CONTROL_DIRECTORY / "module-environment.jsonl"\n', b""),
            (b'    "focus-control-environment", "focus-control-carrier",\n', b""),
            (blocks[0], b""),
            (blocks[1], b'    if label == "explicit-built-in-utility":\n'),
            (b'        shell = str(Path(environment["COMSPEC"]).parent / "WindowsPowerShell" / "v1.0" / "powershell.exe")\n'
             b'        observer_require(budget.resolve_command(["powershell.exe"], environment) == [shell],\n',
             b'        observer_require(budget.resolve_command(["powershell.exe"], environment) == [command[0]],\n'),
            (b'        if record["label"] == "os-module-root-environment":\n'
             b'            carrier = root / SHELL_FOCUS_ENVIRONMENT_CARRIER\n'
             b'            observer_require(not carrier.exists() and not carrier.is_symlink(), "focus-control-carrier")\n', b""),
            (b'    if record["label"] == "os-module-root-environment" and record["owner_release"] == "helper-settled":\n'
             b'        record["environment"] = shell_focus_environment_evidence(root, environment)\n'
             b'        if record["outcome"] == "passed" and record["environment"]["status"] != "observed":\n'
             b'            record["outcome"] = ("admission-or-result-refused" if record["environment"]["status"] == "refused"\n'
             b'                                 else "inconclusive")\n', b""),
            (b'        "stage_scope": "parent-stages-plus-environment-child-carrier", "comparison": "ordered-counterfactual-not-causal-proof",\n',
             b'        "stage_scope": "parent-only-no-child-checkpoints", "comparison": "ordered-counterfactual-not-causal-proof",\n'),
            (b'            "process_boundary": ("shipped-bootstrap-to-isolated-python-bridge-to-shell"\n'
             b'                                 if label == "os-module-root-environment" else "shipped-bootstrap-to-shell"),\n'
             b'            "environment": ({"status": "unavailable", "code": "owner-not-confirmed-settled", "pre": None, "post": None}\n'
             b'                            if label == "os-module-root-environment" else None),\n', b""),
        ):
            self.assertEqual(1, current.count(added))
            current = current.replace(added, previous, 1)
        self.assert_api_fixed_controls_qualifier(current)
        return current

    def test_previous_fixed_control_refs_replay_workflow_and_checker_but_cannot_bind_module_environment(self):
        previous_qualifier = self.api_before_module_environment_control()
        workflow, checker = support.generator.workflow("api"), support.generator.checker("api")
        self.assertEqual("b4377f326ed95313328172fff4c78eb7c40f9ef203098074ff7d2a0702dc724e",
                         hashlib.sha256(workflow.encode("utf-8")).hexdigest())
        self.assertEqual("33eaa615a6d2fc79b21dd6054b5c026e38c1ecdb14a0e00ee53fc96495266e2d",
                         hashlib.sha256(checker.encode("utf-8")).hexdigest())
        for ref in ("e504364cbce8525053540d48d661b23e1d930db9", "cfc7c741e22e0ef060edc2f736b1ba073810991a"):
            with self.subTest(ref=ref), self.api_generator_at(ref) as (root, historical):
                self.assertEqual(workflow, historical.workflow("api"))
                self.assertEqual(checker, historical.checker("api"))
                for case, source in (("current-checker", checker), ("historical-checker", historical.checker("api"))):
                    with self.subTest(case=case):
                        self.assertIsNone(self.api_workflow_validator(source, root)(
                            ".github/workflows/ci.yml", workflow.encode("utf-8")))
                qualifier = (root / "templates/qualify_windows.py").read_bytes()
                self.assertEqual(previous_qualifier, qualifier)
                self.assert_api_fixed_controls_qualifier(qualifier)
                with self.assertRaisesRegex(AssertionError, "module environment control requires the reviewed 8b87 qualifier"):
                    self.assert_api_module_environment_qualifier(qualifier)

    def api_before_fixed_shell_controls(self):
        current = self.api_before_module_environment_control()
        self.assert_api_fixed_controls_qualifier(current)
        start = b"def shell_focus_control_command("
        end = b"def shell_focus(root, require_prepared=False):"
        self.assertEqual(1, current.count(start))
        self.assertEqual(1, current.count(end))
        controls = current[current.index(start):current.index(end)]
        self.assertEqual((7188, "d5bec28cadef4dd5e860f7c2dbfef9b1a567884447dc4c1fe1d65da2ad3a70b7"),
                         (len(controls), hashlib.sha256(controls).hexdigest()))
        for added, previous in (
            (b'SHELL_FOCUS_CONTROLS = ("plain-bare-command", "explicit-built-in-utility")\n'
             b'SHELL_FOCUS_CONTROL_DIRECTORY = LOOKUP.parent / "api106-fixed-shell-controls"\n', b""),
            (b'    "focus-control-shell", "focus-control-module", "focus-control-result", "focus-control-output",\n'
             b'    "focus-control-context", "focus-control-namespace", "focus-control-report-limit",\n', b""),
            (controls, b""),
            (b'    budget, started, before, environment = None, None, "absent", None\n',
             b'    budget, started, before = None, None, "absent"\n'),
            (b'    controls_passed = shell_focus_controls(root, budget, environment, report)\n'
             b'    return 0 if report["status"] == "passed" and controls_passed else 1\n',
             b'    return 0 if report["status"] == "passed" else 1\n'),
        ):
            self.assertEqual(1, current.count(added))
            current = current.replace(added, previous, 1)
        self.assertEqual((97831, "5ea60d30e6ea09c640243a461746c393627b2390b98bffd4e473deb7a8723799"),
                         (len(current), hashlib.sha256(current).hexdigest()))
        return current

    def test_previous_focus_refs_replay_workflow_and_checker_but_cannot_bind_fixed_controls(self):
        previous_qualifier = self.api_before_fixed_shell_controls()
        workflow, checker = support.generator.workflow("api"), support.generator.checker("api")
        self.assertEqual("b4377f326ed95313328172fff4c78eb7c40f9ef203098074ff7d2a0702dc724e",
                         hashlib.sha256(workflow.encode("utf-8")).hexdigest())
        for ref in ("a5c572a23e9c90dfc6732c70d06eeedcd94f52fa", "e2bd839f8e79c7146c2bf006f811e0638647669b"):
            with self.subTest(ref=ref), self.api_generator_at(ref) as (root, historical):
                self.assertEqual(workflow, historical.workflow("api"))
                self.assertEqual(checker, historical.checker("api"))
                for case, source in (("current-checker", checker), ("historical-checker", historical.checker("api"))):
                    with self.subTest(case=case):
                        self.assertIsNone(self.api_workflow_validator(source, root)(
                            ".github/workflows/ci.yml", workflow.encode("utf-8")))
                qualifier = (root / "templates/qualify_windows.py").read_bytes()
                self.assertEqual(previous_qualifier, qualifier)
                with self.assertRaisesRegex(AssertionError, "fixed shell controls require the reviewed e504 qualifier"):
                    self.assert_api_fixed_controls_qualifier(qualifier)

    def api_before_shell_focus(self):
        current = support.generator.workflow("api")
        previous = support.generator.encoded(remove_shell_focus(self, json.loads(current)))
        current_digest = hashlib.sha256(current.encode("utf-8")).hexdigest()
        self.assertEqual("b4377f326ed95313328172fff4c78eb7c40f9ef203098074ff7d2a0702dc724e", current_digest)
        previous_digest = hashlib.sha256(previous.encode("utf-8")).hexdigest()
        checker = support.generator.checker("api")
        self.assertEqual(1, checker.count(current_digest))
        current_binding = 'API_CI_SHA256 = "' + current_digest + '"'
        self.assertEqual(1, checker.count(current_binding))
        previous_binding = 'API_CI_SHA256 = "' + previous_digest + '"'
        return previous, checker.replace(current_binding, previous_binding, 1)

    def test_previous_api_refs_cannot_bind_the_focused_diagnostic(self):
        workflow, checker = self.api_before_shell_focus()
        current = self.api_before_fixed_shell_controls()
        self.assertEqual((97831, "5ea60d30e6ea09c640243a461746c393627b2390b98bffd4e473deb7a8723799"),
                         (len(current), hashlib.sha256(current).hexdigest()))
        for ref in ("1ddc3434d8826605fc9dce7adb843d185dc92aaa", "47f8ac77155603f7b156c9ab214c36e95c26d6fb"):
            with self.subTest(ref=ref), self.api_generator_at(ref) as (root, historical):
                self.assertNotEqual(support.generator.workflow("api"), historical.workflow("api"))
                self.assertNotEqual(support.generator.checker("api"), historical.checker("api"))
                self.assertEqual(workflow, historical.workflow("api"))
                self.assertEqual(checker, historical.checker("api"))
                for case, source, valid_workflow in (
                    ("current-checker-current-workflow", support.generator.checker("api"), support.generator.workflow("api")),
                    ("historical-checker-historical-workflow", historical.checker("api"), workflow),
                ):
                    with self.subTest(case=case):
                        self.assertIsNone(self.api_workflow_validator(source, root)(
                            ".github/workflows/ci.yml", valid_workflow.encode("utf-8")))
                for case, source, wrong_workflow in (
                    ("current-checker-historical-workflow", support.generator.checker("api"), workflow),
                    ("historical-checker-current-workflow", historical.checker("api"), support.generator.workflow("api")),
                ):
                    with self.subTest(case=case), self.assertRaisesRegex(ValueError, "API CI must match"):
                        self.api_workflow_validator(source, root)(
                            ".github/workflows/ci.yml", wrong_workflow.encode("utf-8"))
                qualifier = (root / "templates/qualify_windows.py").read_bytes()
                self.assertNotEqual(current, qualifier)
                self.assertEqual((78865, "31ab38c33e2c45c8bf324ebf55ff239a4a018ee68edd58bcafae52c5b00e5926"),
                                 (len(qualifier), hashlib.sha256(qualifier).hexdigest()))

    def test_previous_api_refs_cannot_bind_the_writer_return_reader(self):
        current = remove_observer_pair(self, json.loads(support.generator.workflow("api")))
        for ref in ("d31994d63001f97a0fc78c411cca9380ca2a7dcd", "c33625aae38673e49c0ad2d57277116b8b79ba98"):
            with self.subTest(ref=ref):
                rendered = registry.render_workflow_at(support.GOVERNANCE.parent, ref, "api")
                self.assertIsNotNone(rendered, "the prior API workflow source must exist for this regression")
                previous = json.loads(rendered)
                self.assertNotEqual(current, previous)
                old_reader = previous["jobs"]["windows"]["steps"][-1]
                new_reader = current["jobs"]["windows"]["steps"][-1]
                self.assertEqual("Read approved-shell command boundary", old_reader["name"])
                self.assertEqual({key: value for key, value in old_reader.items() if key != "run"},
                                 {key: value for key, value in new_reader.items() if key != "run"})
                self.assertNotIn("pre_record_writer_return", old_reader["run"])
                previous["jobs"]["windows"]["steps"][-1] = new_reader
                self.assertEqual(current, previous)

    def test_previous_api_ref_cannot_bind_the_observer_pair_opt_in(self):
        current = json.loads(support.generator.workflow("api"))
        for ref in ("0f5f7b7ce4baa8206add295ce0adee03292a5b20", "822c5a501879b5224a4e0020c5e84157749e9071"):
            with self.subTest(ref=ref):
                previous = registry.render_workflow_at(support.GOVERNANCE.parent, ref, "api")
                self.assertIsNotNone(previous, "the accepted pre-observer source must exist in real history")
                self.assertNotEqual(current, json.loads(previous))
                self.assertEqual(json.loads(previous), remove_observer_pair(self, copy.deepcopy(current)))

    def assert_only_scalar_git_selection_changed(self, historical):
        old_selection = "$git = (Get-Command git -CommandType Application -ErrorAction Stop).Source"
        new_selection = (
            "$git = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source"
        )
        previous = historical.workflow("api")
        current, current_checker = self.api_before_shell_focus()
        self.assertEqual(1, previous.count(old_selection))
        self.assertEqual(1, current.count(new_selection))
        self.assertNotEqual(current, previous)
        self.assertEqual(current, previous.replace(old_selection, new_selection, 1))
        previous_digest = hashlib.sha256(previous.encode("utf-8")).hexdigest()
        current_digest = hashlib.sha256(current.encode("utf-8")).hexdigest()
        previous_checker = historical.checker("api")
        self.assertEqual(1, previous_checker.count(previous_digest))
        self.assertEqual(1, current_checker.count(current_digest))
        self.assertNotEqual(current_checker, previous_checker)
        self.assertEqual(current_checker, previous_checker.replace(previous_digest, current_digest, 1))

    def test_previous_api_refs_cannot_bind_the_current_qualifier(self):
        for ref in ("cf96bdb7b19610ebe2fb0c7fc3de6748b53de9e4", "eaf93a885cd5e7b18bb2b2e3da8504f0b40dc2e5"):
            with self.subTest(ref=ref), tempfile.TemporaryDirectory(prefix="api-registry-stale-") as temporary:
                root = Path(temporary)
                for relative in ("generate.py", "repository-profiles.json", "templates/check_repository.py",
                                 "templates/api_ci_checker.py", "templates/qualify_windows.py"):
                    committed = subprocess.run(
                        ["git", "--no-pager", "show", ref + ":governance/" + relative],
                        cwd=support.GOVERNANCE.parent, env=support.defects.probe_environment(),
                        capture_output=True, check=False, timeout=30,
                    )
                    self.assertEqual(0, committed.returncode,
                                     "the prior API binding must contain every checker and qualifier source")
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(committed.stdout)
                historical = generator_module.load(root / "generate.py", name="api_registry_stale_source_" + ref)
                self.assert_only_scalar_git_selection_changed(historical)
                self.assertNotEqual((support.GOVERNANCE / "templates/qualify_windows.py").read_bytes(),
                                    (root / "templates/qualify_windows.py").read_bytes())

    def api_qualifier_at(self, ref):
        committed = subprocess.run(
            ["git", "--no-pager", "show", ref + ":governance/templates/qualify_windows.py"],
            cwd=support.GOVERNANCE.parent, env=support.defects.probe_environment(),
            capture_output=True, check=False, timeout=30,
        )
        self.assertEqual(0, committed.returncode, "the API qualifier control must exist in real Git history")
        return committed.stdout

    def test_previous_api_refs_cannot_bind_scalar_git_selection(self):
        scalar_qualifier = self.api_qualifier_at("f714f1dfb491944b447e699d8e4e9f7c84d6ed72")
        self.assertNotEqual((support.GOVERNANCE / "templates/qualify_windows.py").read_bytes(), scalar_qualifier)
        for ref in ("e94792d8605c42c8b9d8dd5ee398b757b27486eb", "f719c9d0242a0c80ea401cc18cc2e96da61cabce"):
            with self.subTest(ref=ref), tempfile.TemporaryDirectory(prefix="api-registry-scalar-") as temporary:
                root = Path(temporary)
                for relative in ("generate.py", "repository-profiles.json", "templates/check_repository.py",
                                 "templates/api_ci_checker.py", "templates/qualify_windows.py"):
                    committed = subprocess.run(
                        ["git", "--no-pager", "show", ref + ":governance/" + relative],
                        cwd=support.GOVERNANCE.parent, env=support.defects.probe_environment(),
                        capture_output=True, check=False, timeout=30,
                    )
                    self.assertEqual(0, committed.returncode,
                                     "the prior scalar binding must contain every checker and qualifier source")
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(committed.stdout)
                historical = generator_module.load(root / "generate.py", name="api_registry_scalar_source_" + ref)
                self.assert_only_scalar_git_selection_changed(historical)
                self.assertEqual(scalar_qualifier, (root / "templates/qualify_windows.py").read_bytes())

    def test_previous_api_refs_cannot_bind_java_selection_diagnostics(self):
        categorical_qualifier = self.api_qualifier_at("865ae9089cc8873f7762bb4febd2aca2ed500a9c")
        self.assertNotEqual((support.GOVERNANCE / "templates/qualify_windows.py").read_bytes(), categorical_qualifier)
        qualifiers = []
        for ref in ("f714f1dfb491944b447e699d8e4e9f7c84d6ed72", "f3dc0a9bfcd8fae8e59c10f67919b176c3dd719a"):
            with self.subTest(ref=ref):
                previous = registry.render_workflow_at(support.GOVERNANCE.parent, ref, "api")
                self.assertIsNotNone(previous, "the scalar-Git source must exist in real history")
                self.assertEqual(self.api_before_shell_focus()[0].encode("utf-8"), previous)
                qualifier = self.api_qualifier_at(ref)
                self.assertNotEqual(categorical_qualifier, qualifier)
                qualifiers.append(qualifier)
        self.assertEqual(qualifiers[0], qualifiers[1])

    def test_previous_api_refs_cannot_bind_java_version_operands(self):
        current = self.api_qualifier_at("14af2187b8c493910228e4a7da606d2b49bf9ebc")
        self.assertNotEqual((support.GOVERNANCE / "templates/qualify_windows.py").read_bytes(), current)
        categorical = current
        for added, previous in (
            (b'def observer_java_version_operand(value):\n'
             b'    if type(value) is str and len(value) <= 20 \\\n'
             b'            and re.fullmatch(r"21(?:\\.(?:0|[1-9][0-9]{0,4})){1,3}", value) is not None:\n'
             b'        return value\n'
             b'    return "unavailable"\n\n\n', b""),
            (b"def observer_java_require(condition, check, *, versions=None):",
             b"def observer_java_require(condition, check):"),
            (b'        if versions is not None:\n'
             b'            print(json.dumps({"event": "windows_observer_java_versions", "diagnostic_only": True,\n'
             b'                              "release_version": observer_java_version_operand(versions[0]),\n'
             b'                              "selected_version": observer_java_version_operand(versions[1])},\n'
             b'                             sort_keys=True), file=sys.stderr, flush=True)\n', b""),
            (b'observer_java_require(versions[0] == selected, "selected-version-match", versions=(versions[0], selected))',
             b'observer_java_require(versions[0] == selected, "selected-version-match")'),
        ):
            self.assertEqual(1, categorical.count(added))
            categorical = categorical.replace(added, previous, 1)
        for ref in ("865ae9089cc8873f7762bb4febd2aca2ed500a9c", "cc779064bb696beb33ecf9c424dea30d500d704a"):
            with self.subTest(ref=ref):
                workflow = registry.render_workflow_at(support.GOVERNANCE.parent, ref, "api")
                self.assertIsNotNone(workflow, "the categorical-Java source must exist in real Git history")
                self.assertEqual(self.api_before_shell_focus()[0].encode("utf-8"), workflow)
                qualifier = self.api_qualifier_at(ref)
                self.assertNotEqual(current, qualifier)
                self.assertEqual(categorical, qualifier)

    def test_previous_api_refs_cannot_bind_java_semver_contract(self):
        current = self.api_qualifier_at("1ddc3434d8826605fc9dce7adb843d185dc92aaa")
        self.assertNotEqual((support.GOVERNANCE / "templates/qualify_windows.py").read_bytes(), current)
        operands = current
        for added, previous in (
            (br'''def observer_java_version_matches(version, version_build, selected, release):
    if observer_java_version_operand(version) == "unavailable" or type(selected) is not str or len(selected) > 32:
        return False
    parts = version.split(".")
    if len(parts) not in (3, 4) or (len(parts) == 4 and parts[3] == "0"):
        return False
    setup = re.fullmatch(r"(21(?:\.(?:0|[1-9][0-9]{0,4})){2})\+([1-9][0-9]{0,6})(?:\.0)?", selected)
    if setup is None or setup[1] != ".".join(parts[:3]):
        return False
    runtimes = re.findall(r"^[ \t]*JAVA_RUNTIME_VERSION\b[^\n]*$", release, re.MULTILINE)
    if len(runtimes) != 1 or len(runtimes[0]) > 64:
        return False
    runtime = re.fullmatch(
        r'JAVA_RUNTIME_VERSION="(21(?:\.(?:0|[1-9][0-9]{0,4})){2,3})\+([1-9][0-9]?)(?:-LTS)?"', runtimes[0])
    if runtime is None or runtime[1] != version:
        return False
    if version_build is not None and version_build not in (runtime[2], runtime[2] + "-LTS"):
        return False
    # Adoptium adds patch * 100 to the build; builds 1..99 keep this mapping unambiguous.
    patch = int(parts[3]) if len(parts) == 4 else 0
    return int(setup[2]) == patch * 100 + int(runtime[2])


''', b""),
            (br'''    release = observer_runtime_bytes(java / "release", 16384).decode("utf-8").replace("\r\n", "\n")
    version_lines = re.findall(r"^[ \t]*JAVA_VERSION\b[^\n]*$", release, re.MULTILINE)
    versions = [match for line in version_lines if (
        match := re.fullmatch(r'JAVA_VERSION="(21(?:\.[0-9]+){1,3})(?:\+([0-9A-Za-z.-]+))?"', line))]
    selected_label = os.environ.get("PENNILOGIC_API106_JAVA_VERSION", "")
    selected = selected_label.split("+", 1)[0]
    observer_java_require(len(version_lines) == 1 and len(versions) == 1, "release-version-single-match")
    observer_java_require(observer_java_version_matches(versions[0][1], versions[0][2], selected_label, release),
                          "selected-version-match", versions=(versions[0][1], selected))
''', br'''    release = "\n".join(observer_runtime_bytes(java / "release", 16384).decode("utf-8").splitlines())
    versions = re.findall(r'^JAVA_VERSION="(21(?:\.[0-9]+){1,3})(?:\+[0-9A-Za-z.-]+)?"$', release, re.MULTILINE)
    selected = os.environ.get("PENNILOGIC_API106_JAVA_VERSION", "").split("+", 1)[0]
    observer_java_require(len(versions) == 1, "release-version-single-match")
    observer_java_require(versions[0] == selected, "selected-version-match", versions=(versions[0], selected))
'''),
        ):
            self.assertEqual(1, operands.count(added))
            operands = operands.replace(added, previous, 1)
        for ref in ("14af2187b8c493910228e4a7da606d2b49bf9ebc", "02fdb18b8fc022601fc49647b13ea9802403bfb3"):
            with self.subTest(ref=ref):
                workflow = registry.render_workflow_at(support.GOVERNANCE.parent, ref, "api")
                self.assertIsNotNone(workflow, "the operand-only source must exist in real Git history")
                self.assertEqual(self.api_before_shell_focus()[0].encode("utf-8"), workflow)
                qualifier = self.api_qualifier_at(ref)
                self.assertNotEqual(current, qualifier)
                self.assertEqual(operands, qualifier)

    def test_android_workflow_ref_exists_and_renders_the_exact_combined_caller(self):
        entry = next(entry for entry in self.document["entries"] if entry["repo"] == "PenniLogic/android")
        rendered = registry.render_workflow_at(support.GOVERNANCE.parent, entry["workflow_ref"], "android")
        self.assertIsNotNone(rendered, "the Android source binding must exist in real Git history")
        self.assertEqual(support.generator.workflow("android").encode("utf-8"), rendered)
        self.assertEqual([
            "python scripts/check_repository.py",
            "python -m pip install -r scripts/privacy_traffic/requirements.txt",
            "python scripts/quality_gates.py ci",
            "python scripts/quality_gates.py self-test",
            "python scripts/privacy_traffic_harness.py self-test --all-scripts",
            "python scripts/check_privacy_components.py",
        ], steps.workflow_run_commands(rendered))

    def test_previous_android_privacy_ref_cannot_bind_the_combined_workflow(self):
        previous = registry.render_workflow_at(
            support.GOVERNANCE.parent, "1a540182f48a492772e5230219306632528c3967", "android",
        )
        self.assertIsNotNone(previous, "the accepted privacy workflow must be present for this regression")
        self.assertEqual([
            "python scripts/privacy_traffic_harness.py self-test",
            "python scripts/check_privacy_components.py",
            'python -m unittest discover -s scripts/tests -p "test_*.py"',
        ], steps.workflow_run_commands(previous)[-3:])
        self.assertNotEqual(support.generator.workflow("android").encode("utf-8"), previous)

    def test_previous_android_standalone_ref_cannot_bind_the_grouped_workflow(self):
        previous = registry.render_workflow_at(
            support.GOVERNANCE.parent, "4e6e749fd849ae58f2b13c21215022c1bc410b9f", "android",
        )
        self.assertIsNotNone(previous, "the accepted standalone workflow must be present for this regression")
        self.assertNotEqual(support.generator.workflow("android").encode("utf-8"), previous)
        commands = steps.workflow_run_commands(previous)
        self.assertNotIn("python scripts/quality_gates.py ci", commands)
        for gate in ("build", "test", "lint", "coverage"):
            self.assertIn(f"python scripts/quality_gates.py {gate}", commands)
        self.assertEqual([
            "python scripts/quality_gates.py self-test",
            'python -m unittest discover -s scripts/tests -p "test_*.py"',
        ], commands[-2:])

    def test_android_ref_commits_the_current_inventory_extractor_not_only_its_command(self):
        entry = next(entry for entry in self.document["entries"] if entry["repo"] == "PenniLogic/android")
        committed = subprocess.run(
            ["git", "show", entry["workflow_ref"] + ":governance/templates/check_privacy_components.py"],
            cwd=support.GOVERNANCE.parent, env=support.defects.probe_environment(),
            capture_output=True, check=False, timeout=30,
        )
        self.assertEqual(0, committed.returncode, "the Android binding must name a real extractor source commit")
        self.assertEqual(
            support.generator.artifacts("android")["scripts/check_privacy_components.py"].encode("utf-8"),
            committed.stdout,
        )
        previous = registry.render_workflow_at(
            support.GOVERNANCE.parent, "2832988d641137b65d32e4f51491157e9e09be4f", "android",
        )
        self.assertIsNotNone(previous)
        self.assertNotEqual(support.generator.workflow("android").encode("utf-8"), previous)

    def test_render_workflow_at_returns_none_for_an_unknown_commit(self):
        def run(command, **kwargs):
            return subprocess.CompletedProcess(command, 128, b"", b"fatal: invalid object name")
        self.assertIsNone(registry.render_workflow_at(support.GOVERNANCE.parent, "0" * 40, "infra", run=run))

    def test_opt_in_gate_binding_is_schema_checked_and_never_added_to_unopted_profiles(self):
        document = copy.deepcopy(self.document)
        infra = next(entry for entry in document["entries"] if entry["repo"] == "PenniLogic/infra")
        infra["pr_gate"] = {"check_name": "PR workflow integrity", "workflow_ref": "a" * 40}
        self.assertEqual([], registry.validate_registry(document, self.schema))
        self.assertEqual([], registry.cross_check(document))
        for key in ("check_name", "workflow_ref"):
            broken = copy.deepcopy(document)
            entry = next(entry for entry in broken["entries"] if entry["repo"] == "PenniLogic/infra")
            del entry["pr_gate"][key]
            self.assertTrue(registry.validate_registry(broken, self.schema))
        for value in ({"check_name": "CI", "workflow_ref": "a" * 40},
                      {"check_name": "PR workflow integrity", "workflow_ref": "short"},
                      {"check_name": "PR workflow integrity", "workflow_ref": "a" * 40, "token": "denied"}):
            infra["pr_gate"] = value
            self.assertTrue(registry.validate_registry(document, self.schema))
        infra["pr_gate"] = {"check_name": "PR workflow integrity", "workflow_ref": "a" * 40}
        document["entries"][0]["pr_gate"] = dict(infra["pr_gate"])
        self.assertTrue(any("has not opted in" in message for message in registry.cross_check(document)))
        del document["entries"][0]["pr_gate"]
        del infra["pr_gate"]
        self.assertTrue(any("needs its source binding" in message for message in registry.cross_check(document)))

    def test_gate_ref_is_a_real_source_commit_containing_its_native_rendering(self):
        entry = next(entry for entry in self.document["entries"] if entry["repo"] == "PenniLogic/infra")
        self.assertIn("pr_gate", entry, "source A must be followed by a real registry-only binding B")
        self.assertEqual("e8a7558e90614e1f766596b6df331450db55deb9", entry["pr_gate"]["workflow_ref"])
        rendered = registry.render_workflow_at(
            support.GOVERNANCE.parent, entry["pr_gate"]["workflow_ref"], "infra",
            workflow_file=registry.PR_GATE_WORKFLOW,
        )
        self.assertIsNotNone(rendered, "missing source history is a failure, not skipped gate proof")
        self.assertEqual(support.generator.pr_integrity_workflow("infra").encode("utf-8"), rendered)
        committed = subprocess.run(
            ["git", "show", entry["pr_gate"]["workflow_ref"] + ":" + registry.PR_GATE_WORKFLOW],
            cwd=support.GOVERNANCE.parent, capture_output=True, check=False, timeout=30,
            env=support.defects.probe_environment(),
        )
        self.assertEqual(0, committed.returncode)
        self.assertEqual(rendered, committed.stdout)
        self.assertIsNone(registry.render_workflow_at(
            support.GOVERNANCE.parent, "0" * 40, "infra", workflow_file=registry.PR_GATE_WORKFLOW,
        ))

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
