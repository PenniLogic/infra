"""Real plan/pre-apply CLI tests in owned, explicitly synthetic installations.

The production installation has no accepted policy/inventory. Tests replacing
their own temporary trust file are not provider-acceptance or deployment proof.
"""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import support
import database_admission as gate
import database_baseline as baseline
from database_sql import SqlRefused, inspect_sql


FIXTURES = Path(__file__).parent / "fixtures" / "database_admission"
ACCEPTED_FIXTURES = FIXTURES / "accepted-docs-62a"
ACCEPTED_POLICY_COMMIT = "62a627f67ced1494679be6321ae9deb7f6af7692"
PROPOSAL_POLICY_COMMIT = "69919765f4ce4798bc85f8dcb685890d18bb5b38"
POLICY_COMMIT = "f" * 40  # Synthetic installation identity, not provider acceptance.
API_COMMIT = "a" * 40
RESULT_KEYS = {
    "schema", "gate", "command", "decision", "reason", "scope", "plan_sha256",
    "scripts", "policy_commit", "inventory_commit", "provider_activation", "sql_executed",
}


def encode(content):
    return base64.b64encode(content).decode("ascii")


def fingerprint(content):
    return hashlib.sha256(content).hexdigest()


def sql_hash(sql):
    return fingerprint(sql.replace("\r\n", "\n").encode("utf-8"))


def policy_contents(*, accepted=True):
    result = {}
    for name in ("ADR-025.md", "embedding-policy.json", "embedding-policy.schema.json", "accepted-records.json"):
        folder = ACCEPTED_FIXTURES if accepted and name in {"ADR-025.md", "accepted-records.json"} else FIXTURES / "adr"
        result["adr/" + name] = (folder / name).read_bytes()
    return result


def source_pair(repository_id, commit, contents):
    pin = {"repository_id": repository_id, "commit": commit, "files": [
        {"path": name, "sha256": fingerprint(content), "bytes": len(content)}
        for name, content in sorted(contents.items())
    ]}
    supplied = {"repository_id": repository_id, "commit": commit, "files": [
        {"path": name, "content_base64": encode(content)} for name, content in sorted(contents.items())
    ]}
    return pin, supplied


class BoundaryCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pennilogic-db-admission-")
        self.addCleanup(self.temporary.cleanup)
        self.installation = Path(self.temporary.name)
        (self.installation / "scripts").mkdir()
        (self.installation / "database").mkdir()
        for name in ("database_admission.py", "database_sql.py", "database_baseline.py"):
            shutil.copyfile(support.SCRIPTS / name, self.installation / "scripts" / name)
        self.trust = json.loads(gate.TRUST_FILE.read_bytes())
        self.policy_files = policy_contents()
        self.trust["accepted_policy"], policy = source_pair(1394134442, POLICY_COMMIT, self.policy_files)
        self.evidence = {"src/record-contract.json": b'{"fixture":"synthetic reviewed integer-minor-unit source"}\n'}
        self.source_pin, source = source_pair(1394134582, API_COMMIT, self.evidence)
        self.request = {
            "schema": "pennilogic.database-admission.request/1", "runtime": gate.RUNTIME,
            "policy": policy, "inventory": {"content_base64": "", "source": source}, "packages": [],
            "migrations": [], "selection": [{"id": "V001__sample", "direction": "up"}],
        }
        self.data = {"schema": "pennilogic.database-admission.inventory/1", "nodes": [
            {"id": "money", "kind": "SOURCE", "source_kind": "INTEGER_MINOR_UNITS", "evidence": list(self.evidence)},
            {"id": "currency", "kind": "SOURCE", "source_kind": "CURRENCY_CODE", "evidence": list(self.evidence)},
        ], "scripts": []}
        self.define(
            "CREATE TABLE pennilogic.sample (amount_minor BIGINT NOT NULL CHECK (amount_minor <> 0), "
            "currency CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'));",
            [
                {"name": "pennilogic.sample.amount_minor", "sql_type": "bigint", "provenance": "money"},
                {"name": "pennilogic.sample.currency", "sql_type": "char(3)", "provenance": "currency"},
            ],
        )

    def define(self, sql, columns, reverse="DROP TABLE pennilogic.sample RESTRICT;", direction="down", reverse_columns=None):
        self.request["migrations"] = [{"id": "V001__sample", "up": sql, "reverse": {"direction": direction, "sql": reverse}}]
        self.data["scripts"] = [
            {"migration": "V001__sample", "direction": "up", "sha256": sql_hash(sql),
             "grammar": "postgresql17-ddl-v1", "columns": columns},
            {"migration": "V001__sample", "direction": direction, "sha256": sql_hash(reverse),
             "grammar": "postgresql17-ddl-v1", "columns": [] if reverse_columns is None else reverse_columns},
        ]
        self.seal_inventory()

    def seal_inventory(self):
        content = gate.canonical(self.data)
        self.request["inventory"]["content_base64"] = encode(content)
        self.trust["accepted_inventories"] = [
            {"sha256": fingerprint(content), "bytes": len(content), "source": self.source_pin},
        ]

    def replace_policy_file(self, name, content, repin=False):
        for record in self.request["policy"]["files"]:
            if record["path"] == name:
                record["content_base64"] = encode(content)
        if repin:
            for record in self.trust["accepted_policy"]["files"]:
                if record["path"] == name:
                    record.update(sha256=fingerprint(content), bytes=len(content))

    def snapshot(self):
        return {
            str(item.relative_to(self.installation)): (fingerprint(item.read_bytes()), item.stat().st_mode)
            for item in self.installation.rglob("*") if item.is_file()
        }

    def invoke(self, command="plan", request=None, raw=None, production=False, extra_args=()):
        (self.installation / "database" / "admission-trust.json").write_bytes(gate.canonical(self.trust))
        before = self.snapshot()
        request = self.request if request is None else request
        if command == "admit-apply" and "plan_sha256" not in request:
            request = {**request, "plan_sha256": "0" * 64}
        environment = {
            key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
            if key in os.environ
        }
        environment.update(PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
        executable = support.SCRIPTS / "database_admission.py" if production else self.installation / "scripts" / "database_admission.py"
        result = subprocess.run(
            [sys.executable, "-B", str(executable), command, *extra_args],
            input=gate.canonical(request) if raw is None else raw,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
            cwd=self.installation, timeout=15, check=False,
        )
        self.assertEqual(before, self.snapshot(), "admission changed source, trust, or filesystem state")
        return result

    def response(self, result):
        self.assertEqual(b"", result.stderr, result.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(1, len(result.stdout.splitlines()), result.stdout)
        document = json.loads(result.stdout)
        self.assertEqual(RESULT_KEYS, set(document))
        self.assertEqual("pennilogic.database-admission.result/1", document["schema"])
        self.assertEqual(gate.GATE, document["gate"])
        self.assertFalse(document["provider_activation"])
        self.assertFalse(document["sql_executed"])
        return document

    def deny(self, reason=None, **kwargs):
        result = self.invoke(**kwargs)
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        document = self.response(result)
        self.assertEqual("DENY", document["decision"])
        self.assertEqual([], document["scripts"])
        self.assertIsNone(document["plan_sha256"])
        if reason is not None:
            self.assertEqual(reason, document["reason"])
        return document

    def admit(self):
        plan_result = self.invoke()
        self.assertEqual(0, plan_result.returncode, plan_result.stdout + plan_result.stderr)
        plan = self.response(plan_result)
        self.assertEqual("ADMIT", plan["decision"])
        apply_result = self.invoke("admit-apply", request={**self.request, "plan_sha256": plan["plan_sha256"]})
        self.assertEqual(0, apply_result.returncode, apply_result.stdout + apply_result.stderr)
        apply = self.response(apply_result)
        self.assertEqual("ADMIT", apply["decision"])
        self.assertEqual(plan["scripts"], apply["scripts"])
        return plan


class AdmissionBoundaryTests(BoundaryCase):
    def test_installed_production_path_denies_accepted_source_even_from_fake_accepted_cwd(self):
        for command in ("plan", "admit-apply"):
            with self.subTest(command=command):
                self.deny("POLICY_UNACCEPTED", command=command, production=True)

    def test_normal_integer_minor_units_currency_constraints_and_exact_buffers_survive_both_boundaries(self):
        result = self.admit()
        self.assertEqual([{"migration_index": 0, "direction": "up",
                           "sha256": sql_hash(self.request["migrations"][0]["up"])}], result["scripts"])
        self.assertEqual(POLICY_COMMIT, result["policy_commit"])
        self.assertEqual(API_COMMIT, result["inventory_commit"])

    def test_missing_policy_refuses_without_write(self):
        self.request["policy"] = None
        for command in ("plan", "admit-apply"):
            self.deny("POLICY_MISSING", command=command)

    def test_oversized_type_arguments_have_static_refusals_at_both_boundaries(self):
        for sql_type in ("NUMERIC(" + "9" * 5000 + ")", "NUMERIC(20," + "9" * 5000 + ")",
                         "VARCHAR(" + "0" * 5000 + "1)"):
            self.define("CREATE TABLE pennilogic.sample (value " + sql_type + ");", [])
            for command in ("plan", "admit-apply"):
                with self.subTest(type_prefix=sql_type[:20], command=command):
                    self.deny("SQL_UNSUPPORTED_TYPE", command=command)

    def test_postgres_line_comment_endings_cannot_hide_extension_or_column_changes(self):
        for newline in ("\r", "\n", "\r\n", "\n\r"):
            for direction in ("up", "down", "compensating"):
                hidden = " -- ordinary comment" + newline + "CREATE EXTENSION vector;"
                reverse_direction = "compensating" if direction == "compensating" else "down"
                self.define("CREATE SCHEMA pennilogic;" + (hidden if direction == "up" else ""), [],
                            reverse="DROP SCHEMA pennilogic RESTRICT;" + (hidden if direction != "up" else ""),
                            direction=reverse_direction)
                for command in ("plan", "admit-apply"):
                    with self.subTest(newline=repr(newline), direction=direction, command=command):
                        self.deny("DATABASE_EXTENSION_DENIED", command=command)
        self.define("CREATE SCHEMA pennilogic; -- ordinary comment\r"
                    "CREATE TABLE pennilogic.sample (ordinary REAL[]);", [])
        self.deny("COLUMN_INVENTORY_MISMATCH")

    def test_standalone_carriage_return_ends_an_ordinary_comment(self):
        self.define("-- vector is only a comment\rCREATE SCHEMA pennilogic;", [])
        self.admit()

    def test_api_and_package_entrypoints_cannot_select_another_runtime_or_enable_anything(self):
        self.request["runtime"] = "MANAGED_CLOUD"
        self.deny("REQUEST_VERSION")
        self.request["runtime"] = gate.RUNTIME
        self.request["provider_activation"] = True
        self.deny("OBJECT_FIELDS")

    def test_allow_flags_or_caller_hashes_cannot_supply_trust(self):
        for name, value in (("accepted", True), ("embedding", False), ("trust_path", "admission-trust.json"),
                            ("policy_sha256", gate.POLICY_FILES["adr/embedding-policy.json"][0])):
            with self.subTest(field=name):
                request = {**self.request, name: value}
                self.deny("OBJECT_FIELDS", request=request)
        result = self.invoke(extra_args=("--trust", "admission-trust.json"))
        self.assertEqual(2, result.returncode)

    def test_missing_empty_unregistered_tampered_inventory_is_not_self_attestation(self):
        original = copy.deepcopy(self.request["inventory"])
        for content in (b"", b"{}", gate.canonical({**self.data, "embedding": False})):
            self.request["inventory"] = {**original, "content_base64": encode(content)}
            self.deny("INVENTORY_UNACCEPTED")
        self.request["inventory"] = original
        self.trust["accepted_inventories"] = []
        self.deny("INVENTORY_UNACCEPTED")

    def test_every_script_is_checked_before_any_apply_not_just_selection(self):
        reverse = self.request["migrations"][0]["reverse"]
        reverse["sql"] = "CREATE EXTENSION vector;"
        self.data["scripts"][1]["sha256"] = sql_hash(reverse["sql"])
        self.seal_inventory()
        for command in ("plan", "admit-apply"):
            self.deny("DATABASE_EXTENSION_DENIED", command=command)

    def test_compensation_is_not_a_hidden_second_schema_apply_path(self):
        self.define("CREATE SCHEMA pennilogic;", [], reverse="CREATE EXTENSION vector;", direction="compensating")
        for direction in ("up", "compensating"):
            self.request["selection"][0]["direction"] = direction
            self.deny("DATABASE_EXTENSION_DENIED")
            self.deny("DATABASE_EXTENSION_DENIED", command="admit-apply")

    def test_positive_reverse_and_compensation_are_content_bound(self):
        for direction in ("down", "compensating"):
            self.define("CREATE SCHEMA pennilogic;", [], reverse="DROP SCHEMA pennilogic RESTRICT;", direction=direction)
            self.request["selection"][0]["direction"] = direction
            self.assertEqual(direction, self.admit()["scripts"][0]["direction"])

    def test_plan_replay_for_changed_selection_or_trust_is_denied(self):
        plan = self.admit()
        request = copy.deepcopy(self.request)
        request["selection"][0]["direction"] = "down"
        request["plan_sha256"] = plan["plan_sha256"]
        self.deny("PLAN_CHANGED", command="admit-apply", request=request)
        self.trust["non_vector_extensions"] = ["pgcrypto"]
        self.deny("PLAN_CHANGED", command="admit-apply", request={**self.request, "plan_sha256": plan["plan_sha256"]})

    def test_changed_buffer_is_refused_even_with_a_prior_positive_plan(self):
        plan = self.admit()
        request = copy.deepcopy(self.request)
        request["migrations"][0]["up"] += " CREATE EXTENSION vector;"
        self.deny("SQL_CHECKSUM", command="admit-apply", request={**request, "plan_sha256": plan["plan_sha256"]})

    def test_duplicate_extra_missing_scripts_and_mixed_selection_do_not_skip_checks(self):
        original = copy.deepcopy(self.data["scripts"])
        self.data["scripts"].append(copy.deepcopy(original[0]))
        self.seal_inventory()
        self.deny("INVENTORY_SCRIPT_SET")
        self.data["scripts"] = original[:1]
        self.seal_inventory()
        self.deny("INVENTORY_SCRIPT_SET")
        self.data["scripts"] = original
        self.seal_inventory()
        for selection in ([{"id": "unknown", "direction": "up"}],
                          self.request["selection"] * 2,
                          [{"id": "V001__sample", "direction": "up"}, {"id": "V001__sample", "direction": "down"}]):
            self.deny("SELECTION", request={**self.request, "selection": selection})

    def test_noop_housekeeping_and_complete_set_validation_can_select_no_sql_without_skipping_the_gate(self):
        self.request["selection"] = []
        self.assertEqual([], self.admit()["scripts"])
        self.request["migrations"][0]["reverse"]["sql"] = "CREATE EXTENSION vector;"
        self.data["scripts"][1]["sha256"] = sql_hash("CREATE EXTENSION vector;")
        self.seal_inventory()
        self.deny("DATABASE_EXTENSION_DENIED")
        self.deny("DATABASE_EXTENSION_DENIED", command="admit-apply")

    def test_crlf_checksum_matches_original_api_but_full_request_plan_is_not_reused(self):
        self.request["migrations"][0]["up"] += "\r\n"
        self.data["scripts"][0]["sha256"] = sql_hash(self.request["migrations"][0]["up"])
        self.seal_inventory()
        self.admit()

    def test_schema_inventory_must_exactly_cover_every_new_column_and_type(self):
        for mutation in ("missing", "extra", "type", "duplicate", "provenance"):
            original = copy.deepcopy(self.data)
            columns = self.data["scripts"][0]["columns"]
            if mutation == "missing":
                columns.pop()
            elif mutation == "extra":
                columns.append({"name": "pennilogic.sample.extra", "sql_type": "bigint", "provenance": "money"})
            elif mutation == "type":
                columns[0]["sql_type"] = "integer"
            elif mutation == "duplicate":
                columns.append(copy.deepcopy(columns[0]))
            else:
                columns[0]["provenance"] = "missing"
            self.seal_inventory()
            self.deny()
            self.data = original
        self.seal_inventory()

    def test_no_unreviewed_non_vector_extension_or_package_is_granted_by_the_gate(self):
        for package in ("pgvector", "vector", "PGVECTOR", "vectors", "postgresql-17-pgvector", "unknown"):
            self.request["packages"] = [package]
            self.deny("DATABASE_PACKAGE_DENIED")
        self.request["packages"] = ["postgresql-17"]
        self.deny("DATABASE_PACKAGE_DENIED")
        self.trust["database_packages"] = ["postgresql-17"]
        self.admit()

    def test_vector_and_unknown_sql_extensions_fail_with_comments_case_and_static_intent(self):
        for name in ("vector", "pgvector", "vectors", "vchord", "pgvecto_rs", "unexpected"):
            for sql in (f"CREATE EXTENSION {name};", f'CrEaTe /* outer /* inner */ ok */ ExTeNsIoN "{name}";'):
                with self.subTest(extension=name, sql_form=sql.startswith("CrEaTe")):
                    self.define(sql, [])
                    self.deny("DATABASE_EXTENSION_DENIED")
        self.define("CREATE EXTENSION pgcrypto;", [])
        self.deny("DATABASE_EXTENSION_DENIED")
        self.trust["non_vector_extensions"] = ["pgcrypto"]
        self.admit()
        self.define('CREATE EXTENSION "uuid-ossp";', [])
        self.trust["non_vector_extensions"] = ["uuid-ossp"]
        self.admit()

    def test_installation_cannot_declare_a_vector_extension_as_non_vector(self):
        for name in ("vector", "pgvector", "vectors", "vchord"):
            self.trust["non_vector_extensions"] = [name]
            self.deny("TRUST_EXTENSION_POLICY")

    def test_missing_or_tampered_source_is_never_evidence(self):
        original = copy.deepcopy(self.request["inventory"]["source"])
        for mutation in ("commit", "repository_id", "content", "missing", "duplicate", "path"):
            source = copy.deepcopy(original)
            if mutation == "commit":
                source["commit"] = "b" * 40
            elif mutation == "repository_id":
                source["repository_id"] = 1
            elif mutation == "content":
                source["files"][0]["content_base64"] = encode(b"synthetic changed writer")
            elif mutation == "missing":
                source["files"] = []
            elif mutation == "duplicate":
                source["files"] *= 2
            else:
                source["files"][0]["path"] = "../outside"
            self.request["inventory"]["source"] = source
            self.deny()
        self.request["inventory"]["source"] = original

    def test_denied_diagnostics_never_echo_content_names_paths_or_sql(self):
        sentinel = "synthetic-sensitive-sentinel-do-not-echo"
        self.request["migrations"][0]["up"] += f"\n-- {sentinel}\n"
        result = self.invoke()
        self.assertEqual(1, result.returncode)
        self.assertNotIn(sentinel.encode(), result.stdout + result.stderr)
        self.assertNotIn(b"CREATE TABLE", result.stdout + result.stderr)
        self.assertNotIn(str(self.installation).encode(), result.stdout + result.stderr)


class SemanticProvenanceTests(BoundaryCase):
    def vector(self, source_kind, sql_type, transforms=()):
        self.data["nodes"] = [
            {"id": "source", "kind": "SOURCE", "source_kind": source_kind, "evidence": list(self.evidence)},
            {"id": "vector", "kind": "EMBED", "inputs": ["source"]},
        ]
        node = "vector"
        for index, transform in enumerate(transforms):
            key = f"step{index}"
            self.data["nodes"].append({"id": key, "kind": transform, "inputs": [node]})
            node = key
        self.define(f"CREATE TABLE pennilogic.sample (ordinary_value {sql_type});", [
            {"name": "pennilogic.sample.ordinary_value", "sql_type": sql_type.lower(), "provenance": node},
        ])

    def test_user_vectors_are_denied_for_every_original_source_and_nonvector_wrapper_on_both_boundaries(self):
        for origin in ("TRANSACTION", "MERCHANT", "MEMO", "ASSISTANT_CONVERSATION"):
            for sql_type in ("real[]", "double precision[]", "numeric(18,6)[]", "json", "jsonb", "bytea", "text", "bigint[]"):
                with self.subTest(origin=origin, sql_type=sql_type):
                    self.vector(origin, sql_type)
                    self.deny("EMBEDDING_COLUMN_DENIED")
                    self.deny("EMBEDDING_COLUMN_DENIED", command="admit-apply")

    def test_ciphertext_encoding_alias_hash_aggregation_and_quantization_never_clear_lineage(self):
        for transform in ("ENCRYPT", "ENCODE", "HASH", "QUANTIZE", "ALIAS", "AGGREGATE"):
            self.vector("MEMO", "bytea", (transform, "ENCODE", "ALIAS"))
            self.deny("EMBEDDING_COLUMN_DENIED")
            self.deny("EMBEDDING_COLUMN_DENIED", command="admit-apply")

    def test_static_vector_label_does_not_grant_a_database_destination(self):
        self.vector("NON_USER_REFERENCE", "real[]")
        self.deny("EMBEDDING_COLUMN_DENIED")

    def test_ordinary_json_binary_numeric_arrays_are_not_regex_blocked(self):
        self.data["nodes"] = [{"id": "ordinary", "kind": "SOURCE", "source_kind": "NON_USER_REFERENCE",
                               "evidence": list(self.evidence)}]
        for sql_type in ("real[]", "jsonb", "bytea", "numeric(12,3)", "double precision", "text", "bigint[]"):
            self.define(f"CREATE TABLE pennilogic.sample (vector_label {sql_type});", [
                {"name": "pennilogic.sample.vector_label", "sql_type": sql_type, "provenance": "ordinary"},
            ])
            self.admit()

    def test_unknown_static_assertions_boolean_claims_or_unregistered_relabelling_fail(self):
        self.vector("TRANSACTION", "jsonb")
        self.data["nodes"][-1] = {"id": "vector", "kind": "SOURCE", "source_kind": "NON_USER_REFERENCE",
                                  "evidence": list(self.evidence)}
        self.request["inventory"]["content_base64"] = encode(gate.canonical(self.data))
        self.deny("INVENTORY_UNACCEPTED")
        self.data["nodes"][-1]["embedding"] = False
        self.seal_inventory()
        self.deny("OBJECT_FIELDS")

    def test_unknown_missing_or_cyclic_provenance_is_not_a_nonembedding_default(self):
        self.vector("MEMO", "jsonb")
        original = copy.deepcopy(self.data)
        for kind in ("unknown", None, [], {}, False, 1):
            self.data = copy.deepcopy(original)
            self.data["nodes"][-1]["kind"] = kind
            self.seal_inventory()
            self.deny()
        for inputs in ([], ["absent"], ["vector"], ["source", "source"]):
            self.data = copy.deepcopy(original)
            self.data["nodes"][-1]["inputs"] = inputs
            self.seal_inventory()
            self.deny()
        self.data = copy.deepcopy(original)
        self.data["nodes"][0]["source_kind"] = "STATIC_TRUST_ME"
        self.seal_inventory()
        self.deny("PROVENANCE_SOURCE")
        self.data = copy.deepcopy(original)
        self.data["nodes"][0]["evidence"] = []
        self.seal_inventory()
        self.deny("PROVENANCE_SOURCE")

    def test_money_cannot_be_laundered_into_float_or_json(self):
        for sql_type in ("real", "double precision", "jsonb", "numeric(10,2)"):
            self.define(f"CREATE TABLE pennilogic.sample (amount_minor {sql_type});", [
                {"name": "pennilogic.sample.amount_minor", "sql_type": sql_type, "provenance": "money"},
            ])
            self.deny("MONEY_REPRESENTATION")

    def test_reversal_or_compensation_embedding_column_is_denied_even_when_forward_is_safe(self):
        for direction in ("down", "compensating"):
            self.vector("MERCHANT", "bytea", ("ENCRYPT",))
            vector_column = self.data["scripts"][0]["columns"]
            self.define("CREATE SCHEMA pennilogic;", [], direction=direction,
                        reverse="CREATE TABLE pennilogic.sample (ordinary_value BYTEA);",
                        reverse_columns=vector_column)
            self.deny("EMBEDDING_COLUMN_DENIED")
            self.request["selection"][0]["direction"] = direction
            self.deny("EMBEDDING_COLUMN_DENIED", command="admit-apply")
            self.request["selection"][0]["direction"] = "up"


class ProviderBindingTests(BoundaryCase):
    def test_every_exact_accepted_snapshot_is_supported_without_registering_it(self):
        for name, (checksum, size) in gate.POLICY_FILES.items():
            content = self.policy_files[name]
            self.assertEqual((checksum, size), (fingerprint(content), len(content)))
        self.assertEqual(
            ("148fe74a232a7bdc1b149f7807adbad24b1679aed0024c8ffe98b94d1cb6fd38", 33609),
            gate.POLICY_FILES["adr/ADR-025.md"],
        )
        registry = self.policy_files["adr/accepted-records.json"]
        self.assertEqual(
            ("ea8c941812c52710ffca99a9f7ea0128ce8b63d4d25d32400a51086d28efca71", 1953),
            (fingerprint(registry), len(registry)),
        )
        original = policy_contents(accepted=False)
        for name in ("adr/embedding-policy.json", "adr/embedding-policy.schema.json"):
            self.assertEqual(original[name], self.policy_files[name])
        self.assertEqual("9a7b97abeb9e8bc5a8e722561230b625f793966d34651d7f7ba68d17c7bca048",
                         fingerprint(original["adr/ADR-025.md"]))
        self.assertEqual("83b16677412db095c9242a03bf4fb1c4ef461e8eda4617c09652fee4a69bfee1",
                         fingerprint(original["adr/accepted-records.json"]))
        self.assertIsNone(json.loads(gate.TRUST_FILE.read_bytes())["accepted_policy"])
        self.assertEqual([], json.loads(gate.TRUST_FILE.read_bytes())["accepted_inventories"])

    def test_exact_accepted_source_survives_both_synthetic_boundaries_but_does_not_activate_production(self):
        self.trust["accepted_policy"], self.request["policy"] = source_pair(
            1394134442, ACCEPTED_POLICY_COMMIT, self.policy_files,
        )
        self.assertEqual(ACCEPTED_POLICY_COMMIT, self.admit()["policy_commit"])
        for command in ("plan", "admit-apply"):
            self.deny("POLICY_UNACCEPTED", command=command, production=True)

    def test_unaccepted_valid_proposal_and_local_registry_headers_never_enable_the_installed_gate(self):
        _pin, self.request["policy"] = source_pair(
            1394134442, PROPOSAL_POLICY_COMMIT, policy_contents(accepted=False),
        )
        self.deny("POLICY_UNACCEPTED", production=True)
        self.deny("POLICY_UNACCEPTED", command="admit-apply", production=True)

    def test_obsolete_proposal_bytes_are_not_an_alternate_supported_version(self):
        for commit in (PROPOSAL_POLICY_COMMIT, ACCEPTED_POLICY_COMMIT):
            self.trust["accepted_policy"], self.request["policy"] = source_pair(
                1394134442, commit, policy_contents(accepted=False),
            )
            for command in ("plan", "admit-apply"):
                with self.subTest(commit=commit, command=command):
                    self.deny("POLICY_UNSUPPORTED_VERSION", command=command)

    def test_obsolete_proposal_bytes_cannot_replace_current_pinned_source(self):
        _pin, self.request["policy"] = source_pair(
            1394134442, POLICY_COMMIT, policy_contents(accepted=False),
        )
        for command in ("plan", "admit-apply"):
            self.deny("SOURCE_BYTES", command=command)

    def test_obsolete_registry_cannot_bind_the_current_accepted_adr(self):
        self.replace_policy_file(
            "adr/accepted-records.json", policy_contents(accepted=False)["adr/accepted-records.json"], repin=True,
        )
        for command in ("plan", "admit-apply"):
            self.deny("POLICY_REGISTRY", command=command)

    def test_stale_wrong_repository_missing_duplicate_and_extra_provider_files_are_denied(self):
        original = copy.deepcopy(self.request["policy"])
        for mutation in ("commit", "repository", "missing", "duplicate", "extra"):
            self.request["policy"] = copy.deepcopy(original)
            if mutation == "commit":
                self.request["policy"]["commit"] = "c" * 40
            elif mutation == "repository":
                self.request["policy"]["repository_id"] = 1394135059
            elif mutation == "missing":
                self.request["policy"]["files"].pop()
            elif mutation == "duplicate":
                self.request["policy"]["files"].append(copy.deepcopy(original["files"][0]))
            else:
                self.request["policy"]["files"].append({"path": "adr/override.json", "content_base64": encode(b"{}")})
            self.deny()

    def test_policy_schema_adr_and_registry_raw_byte_tampering_is_rejected(self):
        for name, content in self.policy_files.items():
            original = copy.deepcopy(self.request["policy"])
            self.replace_policy_file(name, content + b"\n")
            for command in ("plan", "admit-apply"):
                with self.subTest(path=name, command=command):
                    self.deny("SOURCE_BYTES", command=command)
            self.request["policy"] = original

    def test_repinning_modified_supported_documents_is_not_an_escape(self):
        original_request = copy.deepcopy(self.request)
        original_trust = copy.deepcopy(self.trust)
        for name in gate.POLICY_FILES:
            self.request = copy.deepcopy(original_request)
            self.trust = copy.deepcopy(original_trust)
            self.replace_policy_file(name, self.policy_files[name] + b"\n", repin=True)
            for command in ("plan", "admit-apply"):
                with self.subTest(path=name, command=command):
                    self.deny("POLICY_UNSUPPORTED_VERSION", command=command)

    def test_local_trust_cannot_turn_this_supported_prohibited_version_into_allowed_or_unknown_version(self):
        name = "adr/embedding-policy.json"
        content = json.loads(self.policy_files[name])
        for key, value in (("policy_version", "2.0.0"), ("decision", "ALLOWED")):
            altered = {**content, key: value}
            self.replace_policy_file(name, gate.canonical(altered), repin=True)
            for command in ("plan", "admit-apply"):
                self.deny("POLICY_UNSUPPORTED_VERSION", command=command)

    def test_registered_but_stale_missing_duplicate_contradictory_adr_registry_is_rejected(self):
        name = "adr/accepted-records.json"
        for mutation in ("date", "sha256", "bytes", "missing", "duplicate"):
            registry = json.loads(self.policy_files[name])
            item = next(item for item in registry["items"] if item["number"] == "ADR-025")
            if mutation == "date":
                item["date"] = "2026-10-03"
            elif mutation == "sha256":
                item["sha256"] = "0" * 64
            elif mutation == "bytes":
                item["bytes"] -= 1
            elif mutation == "missing":
                registry["items"].remove(item)
            else:
                registry["items"].append(copy.deepcopy(item))
            self.replace_policy_file(name, gate.canonical(registry), repin=True)
            for command in ("plan", "admit-apply"):
                self.deny("POLICY_REGISTRY", command=command)

    def test_accepting_the_prohibited_choice_in_a_synthetic_installation_never_permits_vector_extension(self):
        self.define("CREATE EXTENSION vector;", [])
        self.deny("DATABASE_EXTENSION_DENIED")
        self.deny("DATABASE_EXTENSION_DENIED", command="admit-apply")


class SqlBoundaryTests(BoundaryCase):
    def test_supported_grammar_preserves_scalar_ledger_checks_without_inspecting_literal_names(self):
        sql = (
            "/* A nested /* comment */ cannot merge tokens. */ CREATE SCHEMA pennilogic;\n"
            "CREATE TABLE pennilogic.sample (id UUID PRIMARY KEY, amount_minor BIGINT NOT NULL "
            "CHECK (amount_minor BETWEEN -9223372036854775807 AND 9223372036854775807), "
            "currency CHAR(3) NOT NULL, created_at TIMESTAMPTZ(3) CHECK (isfinite(created_at)), "
            "label TEXT DEFAULT 'vector is only a literal', "
            "CONSTRAINT money_guard CHECK (amount_minor <> 0 AND char_length(currency) = 3), "
            "UNIQUE (id, currency));"
        )
        self.data["nodes"] = [{"id": "ordinary", "kind": "SOURCE", "source_kind": "NON_USER_REFERENCE",
                              "evidence": list(self.evidence)}]
        self.define(sql, [
            {"name": f"pennilogic.sample.{name}", "sql_type": kind, "provenance": "ordinary"}
            for name, kind in (("id", "uuid"), ("amount_minor", "bigint"), ("currency", "char(3)"),
                               ("created_at", "timestamptz(3)"), ("label", "text"))
        ])
        self.admit()

    def test_schema_qualified_add_column_has_the_same_semantic_gate(self):
        self.define('ALTER TABLE "pennilogic"."sample" ADD COLUMN "amount_minor" pg_catalog.int8;', [
            {"name": "pennilogic.sample.amount_minor", "sql_type": "bigint", "provenance": "money"},
        ])
        self.admit()

    def test_supported_catalog_type_aliases_normalize_without_exempting_embedding_lineage(self):
        self.data["nodes"] = [
            {"id": "source", "kind": "SOURCE", "source_kind": "NON_USER_REFERENCE", "evidence": list(self.evidence)},
            {"id": "vector", "kind": "EMBED", "inputs": ["source"]},
        ]
        for spelling, normal in (("int8[]", "bigint[]"), ("pg_catalog.float4[]", "real[]"),
                                 ("pg_catalog.float8[]", "double precision[]"), ("DECIMAL(8,2)", "numeric(8,2)")):
            self.define(f"CREATE TABLE pennilogic.sample (value {spelling});", [
                {"name": "pennilogic.sample.value", "sql_type": normal, "provenance": "source"},
            ])
            self.admit()
            self.data["scripts"][0]["columns"][0]["provenance"] = "vector"
            self.seal_inventory()
            self.deny("EMBEDDING_COLUMN_DENIED")

    def test_unknown_grammar_is_refused_even_if_its_inventory_checksum_was_registered(self):
        statements = [
            "CREATE DOMAIN pennilogic.harmless AS real[];",
            "CREATE TYPE pennilogic.harmless AS (value real[]);",
            "CREATE TABLE pennilogic.sample AS SELECT ARRAY[1,2] AS value;",
            "SELECT ARRAY[1,2] INTO pennilogic.sample;",
            "CREATE VIEW pennilogic.sample AS SELECT 1;",
            "CREATE FUNCTION pennilogic.f() RETURNS void LANGUAGE plpgsql AS $$BEGIN EXECUTE 'CREATE EXTENSION vector'; END$$;",
            "DO $x$ BEGIN EXECUTE 'CREATE EXTENSION vector'; END $x$;",
            "COPY pennilogic.sample FROM PROGRAM 'synthetic';",
            "INSERT INTO pennilogic.sample VALUES ('[1,2]');",
            "UPDATE pennilogic.sample SET value = '[1,2]';",
            "ALTER TABLE pennilogic.sample RENAME COLUMN amount_minor TO ordinary_value;",
            "ALTER TABLE pennilogic.sample ALTER COLUMN value TYPE bytea;",
            "CREATE TABLE pennilogic.sample (value public.harmless);",
            "CREATE TABLE pennilogic.sample (value vector(3));",
            "CREATE TABLE pennilogic.sample (value REAL[] GENERATED ALWAYS AS (ARRAY[1,2]) STORED);",
            "CREATE TABLE pennilogic.sample (value TEXT DEFAULT current_setting('secret'));",
            "CREATE TABLE pennilogic.sample (value TEXT CHECK (custom_function(value)));",
            "CREATE TABLE IF NOT EXISTS pennilogic.sample (value TEXT);",
            "CREATE EXTENSION pgcrypto CASCADE;",
            "CREATE EXTENSION pgcrypto VERSION '1.3';",
            "\\i hidden.sql",
            "BEGIN; CREATE EXTENSION vector; COMMIT;",
            "CREATE\u00a0EXTENSION vector;",
            "CREATE TABLE pennilogic.sample (value TEXT DEFAULT E'escaped\\'');",
            "CREATE TABLE pennilogic.sample (value TEXT DEFAULT $x$abc$x$);",
            "DROP TABLE pennilogic.sample CASCADE;",
            "CREATE TABLE pg_catalog.sample (value BIGINT);",
            "CREATE TABLE pennilogic.sample (value NUMERIC(4,5));",
        ]
        for sql in statements:
            with self.subTest(sql=sql.split(" ", 1)[0]):
                self.define(sql, [])
                self.deny()
                self.deny(command="admit-apply")

    def test_invalid_or_unterminated_tokens_do_not_hide_trailing_statements(self):
        for sql in ("", "-- comment only", "CREATE SCHEMA pennilogic; /*",
                    "CREATE SCHEMA pennilogic; '", "CREATE SCHEMA pennilogic; \"",
                    "CREATE SCHEMA pennilogic", "CREATE SCHEMA pennilogic; $bad$",
                    "CREATE SCHEMA pennilogic; \x00CREATE EXTENSION vector;"):
            self.define(sql, [])
            self.deny()

    def test_nested_comments_quotes_and_case_are_tokenized_not_filename_scanned(self):
        for sql in ("CrEaTe/* ignored */ScHeMa pennilogic;",
                    'CREATE SCHEMA "pennilogic"; -- CREATE EXTENSION vector;',
                    "/* vector */ CREATE SCHEMA pennilogic;"):
            self.define(sql, [])
            self.admit()


class FrozenLedgerTests(BoundaryCase):
    def frozen(self):
        contents = {f"src/main/resources/db/migrations/{file.name}": file.read_bytes()
                    for file in sorted((FIXTURES / "api").glob("*.sql"))}
        self.evidence = contents
        self.source_pin, source = source_pair(1394134582, baseline.API_COMMIT, contents)
        self.request["inventory"]["source"] = source
        self.data["nodes"] = [{"id": "legacy", "kind": "SOURCE", "source_kind": "TRANSACTION",
                               "evidence": list(contents)}]
        self.request["migrations"] = []
        self.data["scripts"] = []
        for index, name in enumerate(("V001__create_pennilogic_schema", "V002__create_ledger")):
            up = (FIXTURES / "api" / (name + ".up.sql")).read_text(encoding="utf-8")
            down = (FIXTURES / "api" / (name + ".down.sql")).read_text(encoding="utf-8")
            self.request["migrations"].append({"id": name, "up": up, "reverse": {"direction": "down", "sql": down}})
            for direction, sql in (("up", up), ("down", down)):
                columns = baseline.LEDGER_COLUMNS if index == 1 and direction == "up" else ()
                self.data["scripts"].append({
                    "migration": name, "direction": direction, "sha256": sql_hash(sql),
                    "grammar": "api-ledger-v2-exact",
                    "columns": [{"name": col, "sql_type": kind, "provenance": "legacy"} for col, kind in columns],
                })
        self.request["selection"] = [{"id": record["id"], "direction": "up"} for record in self.request["migrations"]]
        self.seal_inventory()

    def test_all_four_exact_original_scripts_preserve_ledger_checks_and_guarded_reversal(self):
        self.frozen()
        self.admit()
        self.request["selection"] = [{"id": record["id"], "direction": "down"}
                                     for record in reversed(self.request["migrations"])]
        self.admit()
        for (name, direction), (sha, _shape) in baseline.SCRIPTS.items():
            self.assertEqual(sha, fingerprint((FIXTURES / "api" / f"{name}.{direction}.sql").read_bytes()))

    def test_complete_frozen_stored_shape_matches_independent_column_declarations(self):
        sql = (FIXTURES / "api" / "V002__create_ledger.up.sql").read_text(encoding="utf-8")
        expected = []
        for table, body in re.findall(r"CREATE TABLE pennilogic\.([a-z_]+) \((.*?)\n\);", sql, re.S):
            for name, kind in re.findall(
                r"^    ([a-z_][a-z_0-9]*) (UUID|CHAR\(3\)|SMALLINT|BIGINT|TEXT|BOOLEAN|BYTEA|DATE|TIMESTAMPTZ\(3\))(?=[,\s])",
                body, re.M,
            ):
                expected.append((f"pennilogic.{table}.{name}", kind.lower()))
        self.assertEqual(70, len(expected))
        self.assertEqual(tuple(sorted(expected)), baseline.LEDGER_COLUMNS)

    def test_changed_routine_constraint_or_direction_cannot_reuse_accepted_baseline_language(self):
        self.frozen()
        sql = self.request["migrations"][1]["up"].replace("amount_minor BIGINT", "amount_minor REAL")
        self.request["migrations"][1]["up"] = sql
        self.data["scripts"][2]["sha256"] = sql_hash(sql)
        self.seal_inventory()
        self.deny("SQL_BASELINE_BINDING")
        self.data["scripts"][2]["grammar"] = "postgresql17-ddl-v1"
        self.seal_inventory()
        self.deny()

    def test_frozen_baseline_does_not_exempt_missing_columns_or_embedding_lineage(self):
        self.frozen()
        self.data["scripts"][2]["columns"].pop()
        self.seal_inventory()
        self.deny("COLUMN_INVENTORY_MISMATCH")
        self.frozen()
        self.data["nodes"].append({"id": "embedding", "kind": "EMBED", "inputs": ["legacy"]})
        self.data["scripts"][2]["columns"][0]["provenance"] = "embedding"
        self.seal_inventory()
        self.deny("EMBEDDING_COLUMN_DENIED")


class TransportTests(BoundaryCase):
    def test_duplicate_fields_bom_utf16_nonfinite_invalid_json_and_oversize_fail_closed(self):
        for raw in (
            b'{"schema":1,"schema":2}', b'{"schema":NaN}', b'{"schema":Infinity}',
            b"\xef\xbb\xbf{}", "{}".encode("utf-16"), b"{", b"\xff",
            b"[" * 5000 + b"]" * 5000, b" " * (gate.LIMIT + 1),
            b'{"n":' + b"9" * 5000 + b"}",
        ):
            with self.subTest(prefix=raw[:8]):
                self.deny(raw=raw)

    def test_untyped_json_fields_return_one_content_free_refusal_not_a_traceback(self):
        for field in gate.REQUEST_FIELDS:
            if field == "policy":
                values = (False, [], "invalid")
            elif field in {"packages", "selection"}:
                values = (None, False, 1, {})
            else:
                values = (None, False, 1, [], {})
            for value in values:
                with self.subTest(field=field, kind=type(value).__name__):
                    request = copy.deepcopy(self.request)
                    request[field] = value
                    self.deny(request=request)

    def test_json_surrogate_or_null_sql_is_refused_without_echo(self):
        for sql in ("\ud800", "\x00"):
            request = copy.deepcopy(self.request)
            request["migrations"][0]["up"] = sql
            self.deny(request=request)

    def test_trust_and_inventory_unknown_fields_or_boolean_numbers_do_not_coerce(self):
        original = copy.deepcopy(self.trust)
        for field in ("accepted_policy", "accepted_inventories", "non_vector_extensions", "database_packages"):
            self.trust = copy.deepcopy(original)
            self.trust[field] = True
            self.deny()
        self.trust = copy.deepcopy(original)
        self.trust["accepted_policy"]["files"][0]["bytes"] = True
        self.deny("INTEGER_SHAPE")
        self.trust = copy.deepcopy(original)
        self.trust["accepted_inventories"][0]["source"]["repository_id"] = True
        self.deny("INTEGER_SHAPE")

    def test_sql_complexity_is_bounded_and_unknown_content_never_becomes_a_skip(self):
        for sql in ("/*" * 34 + "x" + "*/" * 34,
                    "CREATE TABLE pennilogic.sample (x BIGINT CHECK (" + "(" * 40 + "x=1" + ")" * 40 + "));",
                    "CREATE SCHEMA pennilogic;" * 1025):
            self.define(sql, [])
            self.deny()


if __name__ == "__main__":
    unittest.main()
