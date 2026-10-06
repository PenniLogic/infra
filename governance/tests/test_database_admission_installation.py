"""Canonical installation mechanics with synthetic trust, not accepted-provider or deployment proof."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import test_money_source_materialization as money_tests


HERE = Path(__file__).resolve().parents[1]
SCRIPTS = HERE.parent / "scripts"
sys.path.insert(0, str(SCRIPTS / "tests"))
gate_tests = money_tests.load("database_installation_fixture_tests", SCRIPTS / "tests/test_database_admission.py")
generator = money_tests.generator
helper = money_tests.materializer
preparation = money_tests.load("database_preparation_template", HERE / "templates/prepare_database_admission.py")
CATALOG_PATH = HERE / "api-database-admission-installation.json"
CANONICAL = json.loads(CATALOG_PATH.read_bytes())
PENDING = {**copy.deepcopy(CANONICAL), "binding": None}


class Transport:
    def __init__(self):
        self.sources, self.contents, self.data, self.calls = {}, {}, {}, []

    def add(self, role, commit, contents):
        repository, repository_id, _paths = preparation.SOURCES[role]
        prefix = "/repos/" + repository
        source = {"repository": repository, "repository_id": repository_id, "commit": commit, "files": [
            {"path": name, "mode": "100644", **money_tests.binding(content)}
            for name, content in sorted(contents.items())
        ]}
        self.sources[role], self.contents[role] = source, contents
        self.data[prefix] = {"id": repository_id, "full_name": repository, "private": False,
                             "owner": {"id": 335295566, "login": "PenniLogic"}}
        directories = {""}
        for entry in source["files"]:
            parts = entry["path"].split("/")
            directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
            self.data[prefix + "/git/blobs/" + entry["git_blob"]] = {
                "sha": entry["git_blob"], "encoding": "base64", "size": entry["bytes"],
                "content": base64.b64encode(contents[entry["path"]]).decode("ascii"),
            }
        trees = {path: [] for path in directories}
        for entry in source["files"]:
            parent, _, name = entry["path"].rpartition("/")
            trees[parent].append({"path": name, "type": "blob", "mode": entry["mode"],
                                  "sha": entry["git_blob"], "size": entry["bytes"]})
        identities = {}
        for path in sorted(directories, key=lambda name: (name.count("/"), len(name)), reverse=True):
            identities[path] = money_tests.tree_identity(trees[path])
            if path:
                parent, _, name = path.rpartition("/")
                trees[parent].append({"path": name, "type": "tree", "mode": "040000", "sha": identities[path]})
        source["tree"] = identities[""]
        self.data[prefix + "/git/commits/" + commit] = {"sha": commit, "tree": {"sha": source["tree"]}}
        recursive = []
        for path, entries in trees.items():
            recursive.extend({**entry, "path": path + "/" + entry["path"] if path else entry["path"]}
                             for entry in entries)
        self.data[prefix + "/git/trees/" + source["tree"] + "?recursive=1"] = {
            "sha": source["tree"], "truncated": False, "tree": recursive,
        }
        return source

    def open(self, request, timeout):
        if request.get_method() != "GET" or not 0 < timeout <= helper.REQUEST_SECONDS:
            raise AssertionError("Only bounded read-only requests are allowed")
        self.calls.append(request)
        value = self.data[request.full_url.removeprefix("https://api.github.com")]
        return money_tests.Response(json.dumps(value).encode(), request.full_url)

    def client(self):
        return helper.ReadOnlyClient({"sources": list(self.sources.values())}, opener=self)


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.case = gate_tests.BoundaryCase()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root = self.case.installation

    def fixture(self):
        transport = Transport()
        transport.add("infra", "b" * 40, {
            name: (HERE.parent / name).read_bytes() for name in preparation.INFRA_FILES
        })
        transport.add("policy", gate_tests.POLICY_COMMIT, self.case.policy_files)
        evidence = transport.add("evidence", gate_tests.API_COMMIT, self.case.evidence)
        manifest = {
            "schema": "pennilogic.api-database-admission-source/1", "repository_id": 1394134582,
            "commit": evidence["commit"], "tree": evidence["tree"], "inventory": "database/admission-inventory.json",
            "files": [{key: entry[key] for key in ("path", "bytes", "sha256", "git_blob")} for entry in evidence["files"]],
        }
        transport.add("inventory", "c" * 40, {
            "database/admission-inventory.json": base64.b64decode(self.case.request["inventory"]["content_base64"]),
            "database/admission-inventory-source.json": preparation.document_bytes(manifest),
        })
        data = copy.deepcopy(PENDING)
        data["binding"] = {"sources": transport.sources, "payloads": []}
        contents = preparation.assemble(data, transport.contents, helper)
        data["binding"]["payloads"] = [
            {"path": name, "mode": "100644", "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            for name, content in sorted(contents.items())
        ]
        preparation.validate_authority(data, helper)
        return data, transport, contents

    def render(self, data):
        original = Path.read_bytes

        def read(path):
            return preparation.document_bytes(data) if path == CATALOG_PATH else original(path)

        with mock.patch.object(Path, "read_bytes", read):
            outputs = generator.database_admission_artifacts()
        outputs["scripts/materialize_money_sources.py"] = generator.money_materializer()
        for name, content in outputs.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content.encode("utf-8"))
            path.chmod(0o644)

    def install(self):
        data, transport, expected = self.fixture()
        self.render(data)
        result = preparation.prepare(self.root, data, helper, fetch=True, client=transport.client())
        self.assertEqual("prepared", result["status"])
        self.assertLessEqual(result["requests"], helper.MAX_REQUESTS)
        self.assertEqual(expected, preparation.verify(self.root, data, helper))
        return data, transport, expected

    def invoke(self, *args, request=None, raw=None):
        before = self.case.snapshot()
        environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(self.root / "scripts/prepare_database_admission.py"), *args],
            input=raw if raw is not None else preparation.document_bytes(self.case.request if request is None else request),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.root, env=environment, timeout=10, check=False,
        )
        self.assertEqual(before, self.case.snapshot(), "verification/admission mutated the installation")
        return result

    def refused(self, *args, code=None, **kwargs):
        result = self.invoke(*args, **kwargs)
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertEqual(b"", result.stdout)
        document = json.loads(result.stderr)
        self.assertEqual({"event", "status", "code"}, set(document))
        self.assertEqual("refused", document["status"])
        if code is not None:
            self.assertEqual(code, document["code"])

    def test_api_only_two_additive_artifacts_and_unchanged_money_workflow(self):
        for repo in generator.PROFILES["repositories"]:
            current = generator.artifacts(repo)
            with mock.patch.object(generator, "database_admission_artifacts", return_value={}):
                previous = generator.artifacts(repo)
            changed = {name for name in current.keys() | previous.keys() if current.get(name) != previous.get(name)}
            self.assertEqual({"scripts/prepare_database_admission.py",
                              "src/main/resources/database-admission-installation.json"} if repo == "api" else set(), changed)
        self.assertEqual(PENDING, preparation.validate_authority(PENDING, helper))
        self.assertIsNone(PENDING["binding"])
        self.assertEqual((32, 4 * 1024 * 1024, 10, 180),
                         (helper.MAX_REQUESTS, helper.MAX_TOTAL_BYTES, helper.REQUEST_SECONDS, helper.DEADLINE_SECONDS))

    def test_pending_source_authority_denies_every_real_entrypoint_without_writes(self):
        self.render(PENDING)
        for args in (("prepare",), ("prepare", "--fetch"), ("verify",), ("run", "plan"), ("run", "admit-apply")):
            with self.subTest(command=args):
                self.refused(*args, code="accepted-sources-unbound")
        self.assertFalse((self.root / preparation.OUTPUT).exists())

    def test_canonical_accepted_sources_still_require_explicit_preparation(self):
        self.assertEqual(CANONICAL, preparation.validate_authority(CANONICAL, helper))
        sources = CANONICAL["binding"]["sources"]
        expected = {
            "infra": ("8939daae876c6a2cd2aa1a8d57c03c22164af856", "300a86ef80d73a36af4fdc620d2cdb9ab60691c1", 3),
            "policy": ("62a627f67ced1494679be6321ae9deb7f6af7692", "b3240b191bf89e540ae03d951ccf46c640459e4d", 4),
            "inventory": ("b938b31e8dbdc1fc28188cadeca7a03483450724", "4cfe31807e62bb4becda7e34735a7ac1ca89c737", 2),
            "evidence": ("d39f4692c13413040439c5e87fed81728e0577f1", "8da895cc998e5ec43105cfb6fa41a82ea2194f8c", 7),
        }
        self.assertEqual(expected, {
            role: (source["commit"], source["tree"], len(source["files"])) for role, source in sources.items()
        })
        self.assertEqual(28, sum(len(source["files"]) + 3 for source in sources.values()))
        self.assertEqual(5, len(CANONICAL["binding"]["payloads"]))
        self.render(CANONICAL)
        self.refused("prepare", code="explicit-fetch-required")
        for command in (("verify",), ("run", "plan"), ("run", "admit-apply")):
            self.refused(*command, code="snapshot-missing")
        self.assertFalse((self.root / preparation.OUTPUT).exists())
        standalone = json.loads((SCRIPTS.parent / "database/admission-trust.json").read_bytes())
        self.assertIsNone(standalone["accepted_policy"])
        self.assertEqual([], standalone["accepted_inventories"])

    def test_existing_generated_attributes_preserve_bound_bytes_in_autocrlf_checkout(self):
        self.render(CANONICAL)
        attributes = generator.artifacts("api")[".gitattributes"].encode("utf-8")
        (self.root / ".gitattributes").write_bytes(attributes)
        files = (preparation.LAUNCHER, preparation.RESOURCE)
        expected = {path: (self.root / path).read_bytes() for path in files}
        environment = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
                       if key in os.environ}
        checkout = self.root / "clean-checkout"
        checkout.mkdir()
        for args in (
            ("init", "--quiet"),
            ("add", "--", ".gitattributes", *(str(path) for path in files)),
            ("checkout-index", "--all", "--prefix=" + str(checkout) + os.sep),
        ):
            result = subprocess.run(
                ["git", "-c", "core.autocrlf=true", *args], cwd=self.root, env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        for path, content in expected.items():
            with self.subTest(path=path):
                self.assertNotIn(b"\r", content)
                self.assertEqual(content, (checkout / path).read_bytes())
        self.assertEqual(attributes, (checkout / ".gitattributes").read_bytes())

    def test_generated_resource_binds_launcher_bytes_without_a_self_hash_cycle(self):
        self.render(PENDING)
        first = (self.root / preparation.RESOURCE).read_bytes()
        data = preparation.validate_installation(json.loads(first), helper)
        launcher = (self.root / preparation.LAUNCHER).read_bytes()
        self.assertEqual({"path": preparation.LAUNCHER.as_posix(), "mode": "100644", "bytes": len(launcher),
                          "sha256": hashlib.sha256(launcher).hexdigest()}, data["launcher"])
        authority = {key: item for key, item in data.items() if key != "launcher"}
        self.assertIn(("AUTHORITY_SHA256 = " + repr(hashlib.sha256(preparation.document_bytes(authority)).hexdigest())).encode(),
                      launcher)
        self.render(PENDING)
        self.assertEqual(first, (self.root / preparation.RESOURCE).read_bytes())

    def test_missing_bundle_never_implicitly_downloads(self):
        data, transport, _contents = self.fixture()
        self.render(data)
        self.refused("prepare", code="explicit-fetch-required")
        self.refused("verify", code="snapshot-missing")
        self.refused("run", "plan", code="snapshot-missing")
        self.assertEqual([], transport.calls)
        self.assertFalse((self.root / preparation.OUTPUT).exists())

    def test_explicit_prepare_and_offline_verify_are_deterministic_and_keep_five_payloads(self):
        data, transport, contents = self.install()
        before = self.case.snapshot()
        requests = len(transport.calls)
        for fetch in (False, True):
            result = preparation.prepare(self.root, data, helper, fetch=fetch, client=transport.client())
            self.assertEqual({"event": "database_admission_installation", "status": "verified_existing", "requests": 0}, result)
        self.assertEqual(requests, len(transport.calls))
        self.assertEqual(before, self.case.snapshot())
        self.assertEqual(preparation.PAYLOAD_FILES, set(contents))
        self.assertTrue(all("Authorization" not in request.headers for request in transport.calls))
        self.assertEqual(0, self.invoke("verify").returncode)
        inputs = json.loads(contents["inputs.json"])
        self.assertEqual({"policy", "inventory"}, set(inputs))
        self.assertEqual(gate_tests.API_COMMIT, inputs["inventory"]["source"]["commit"])
        self.assertNotEqual(data["binding"]["sources"]["inventory"]["commit"], inputs["inventory"]["source"]["commit"])

    def test_real_managed_plan_and_preapply_execute_snapshots_and_preserve_ledger_shapes(self):
        self.install()
        plan_process = self.invoke("run", "plan")
        self.assertEqual(0, plan_process.returncode, plan_process.stdout + plan_process.stderr)
        plan = self.case.response(plan_process)
        applied = self.invoke("run", "admit-apply", request={**self.case.request, "plan_sha256": plan["plan_sha256"]})
        self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
        self.assertEqual(plan["scripts"], self.case.response(applied)["scripts"])
        self.assertFalse(any(path.name == "__pycache__" for path in self.root.rglob("*")))

    def test_empty_selection_is_validated_without_fabricated_sql(self):
        self.case.request["selection"] = []
        self.install()
        process = self.invoke("run", "plan")
        self.assertEqual(0, process.returncode, process.stdout + process.stderr)
        self.assertEqual([], self.case.response(process)["scripts"])

    def test_compensation_vector_is_denied_through_both_managed_boundaries(self):
        self.case.define("CREATE SCHEMA pennilogic;", [], reverse="CREATE EXTENSION vector;", direction="compensating")
        self.install()
        for command in ("plan", "admit-apply"):
            request = {**self.case.request, **({"plan_sha256": "0" * 64} if command == "admit-apply" else {})}
            process = self.invoke("run", command, request=request)
            self.assertEqual(1, process.returncode)
            self.assertEqual("DATABASE_EXTENSION_DENIED", self.case.response(process)["reason"])

    def test_quoted_keyword_composite_type_is_denied_through_both_managed_boundaries(self):
        self.case.data["nodes"].append({
            "id": "ordinary", "kind": "SOURCE", "source_kind": "NON_USER_REFERENCE", "evidence": list(self.case.evidence),
        })
        self.case.define('CREATE TABLE pennilogic."bigint" (v TEXT); CREATE TABLE pennilogic.sample (amount "bigint");', [
            {"name": "pennilogic.bigint.v", "sql_type": "text", "provenance": "ordinary"},
            {"name": "pennilogic.sample.amount", "sql_type": "bigint", "provenance": "money"},
        ], reverse='DROP TABLE pennilogic.sample RESTRICT; DROP TABLE pennilogic."bigint" RESTRICT;')
        self.install()
        for selection in ([], self.case.request["selection"]):
            for command in ("plan", "admit-apply"):
                with self.subTest(selection=selection, command=command):
                    request = {**self.case.request, "selection": selection,
                               **({"plan_sha256": "0" * 64} if command == "admit-apply" else {})}
                    process = self.invoke("run", command, request=request)
                    self.assertEqual(1, process.returncode, process.stdout + process.stderr)
                    response = self.case.response(process)
                    self.assertEqual("SQL_UNSUPPORTED_TYPE", response["reason"])
                    self.assertEqual([], response["scripts"])
                    self.assertIsNone(response["plan_sha256"])

    def test_encrypted_embedding_alias_is_not_exempt_in_managed_bundle(self):
        self.case.data["nodes"].extend([
            {"id": "embedding", "kind": "EMBED", "inputs": ["money"]},
            {"id": "ciphertext", "kind": "ENCRYPT", "inputs": ["embedding"]},
            {"id": "ordinary", "kind": "ALIAS", "inputs": ["ciphertext"]},
        ])
        self.case.define("CREATE TABLE pennilogic.sample (ordinary BYTEA);", [
            {"name": "pennilogic.sample.ordinary", "sql_type": "bytea", "provenance": "ordinary"},
        ])
        self.install()
        process = self.invoke("run", "plan")
        self.assertEqual(1, process.returncode)
        self.assertEqual("EMBEDDING_COLUMN_DENIED", self.case.response(process)["reason"])

    def test_unknown_sql_remains_a_static_denial_after_installation(self):
        self.case.define("CREATE TABLE pennilogic.sample AS SELECT 1 AS ordinary;", [])
        self.install()
        process = self.invoke("run", "plan")
        self.assertEqual(1, process.returncode)
        self.assertEqual("SQL_UNSUPPORTED_GRAMMAR", self.case.response(process)["reason"])

    def test_old_plan_cannot_admit_changed_selection(self):
        self.install()
        plan = self.case.response(self.invoke("run", "plan"))
        request = {**self.case.request, "selection": [{"id": "V001__sample", "direction": "down"}],
                   "plan_sha256": plan["plan_sha256"]}
        process = self.invoke("run", "admit-apply", request=request)
        self.assertEqual(1, process.returncode)
        self.assertEqual("PLAN_CHANGED", self.case.response(process)["reason"])

    def test_changed_policy_or_inventory_envelope_is_not_a_caller_override(self):
        self.install()
        for key in ("policy", "inventory"):
            with self.subTest(key=key):
                self.refused("run", "plan", request={**self.case.request, key: {}}, code="installation-envelope")

    def test_old_or_tampered_policy_inputs_cannot_override_installed_accepted_bytes(self):
        self.install()
        _pin, obsolete = gate_tests.source_pair(
            1394134442, gate_tests.POLICY_COMMIT, gate_tests.policy_contents(accepted=False),
        )
        tampered = copy.deepcopy(self.case.request["policy"])
        for record in tampered["files"]:
            if record["path"] == "adr/ADR-025.md":
                record["content_base64"] = gate_tests.encode(self.case.policy_files[record["path"]] + b"\n")
        for name, policy in (("obsolete", obsolete), ("tampered", tampered)):
            for command in ("plan", "admit-apply"):
                request = {**self.case.request, "policy": policy,
                           **({"plan_sha256": "0" * 64} if command == "admit-apply" else {})}
                with self.subTest(source=name, command=command):
                    self.refused("run", command, request=request, code="installation-envelope")

    def test_prepared_obsolete_proposal_is_denied_at_both_managed_boundaries(self):
        self.case.policy_files = gate_tests.policy_contents(accepted=False)
        self.case.trust["accepted_policy"], self.case.request["policy"] = gate_tests.source_pair(
            1394134442, gate_tests.POLICY_COMMIT, self.case.policy_files,
        )
        self.install()
        for command in ("plan", "admit-apply"):
            request = {**self.case.request, **({"plan_sha256": "0" * 64} if command == "admit-apply" else {})}
            process = self.invoke("run", command, request=request)
            self.assertEqual(1, process.returncode)
            self.assertEqual("POLICY_UNSUPPORTED_VERSION", self.case.response(process)["reason"])

    def test_prepared_obsolete_registry_cannot_bind_the_accepted_adr(self):
        self.case.policy_files["adr/accepted-records.json"] = gate_tests.policy_contents(accepted=False)["adr/accepted-records.json"]
        self.case.trust["accepted_policy"], self.case.request["policy"] = gate_tests.source_pair(
            1394134442, gate_tests.POLICY_COMMIT, self.case.policy_files,
        )
        self.install()
        for command in ("plan", "admit-apply"):
            request = {**self.case.request, **({"plan_sha256": "0" * 64} if command == "admit-apply" else {})}
            process = self.invoke("run", command, request=request)
            self.assertEqual(1, process.returncode)
            self.assertEqual("POLICY_REGISTRY", self.case.response(process)["reason"])

    def test_input_cannot_replace_the_internal_module_snapshot(self):
        self.install()
        request = {**self.case.request, "modules": {"database_admission": "raise RuntimeError('UNTRUSTED')"}}
        process = self.invoke("run", "plan", request=request)
        self.assertEqual(1, process.returncode)
        self.assertEqual("OBJECT_FIELDS", self.case.response(process)["reason"])
        self.assertNotIn(b"UNTRUSTED", process.stdout + process.stderr)

    def test_credentials_and_python_environment_do_not_reach_the_provider_process(self):
        _data, _transport, payloads = self.install()
        with mock.patch.dict(os.environ, {"GH_TOKEN": "synthetic-secret", "GITHUB_TOKEN": "synthetic-secret",
                                          "PYTHONPATH": str(self.root), "PYTHONSTARTUP": "untrusted.py"}):
            with mock.patch.object(preparation.subprocess, "run", wraps=subprocess.run) as execution:
                _output, code = preparation.run("plan", preparation.document_bytes(self.case.request), self.root, payloads, helper)
        self.assertEqual(0, code)
        self.assertEqual([sys.executable, "-I", "-S", "-B", "-c", preparation.EXECUTOR, "plan"],
                         execution.call_args.args[0])
        self.assertLess(preparation.PROCESS_SECONDS, 10)
        self.assertTrue(set(execution.call_args.kwargs["env"]) <= {"SYSTEMROOT", "WINDIR"})

    def test_provider_timeout_or_stderr_is_static_not_a_success_shaped_fallback(self):
        _data, _transport, payloads = self.install()
        request = preparation.document_bytes(self.case.request)
        with mock.patch.object(preparation.subprocess, "run", side_effect=subprocess.TimeoutExpired("provider", 7)):
            with self.assertRaisesRegex(preparation.InstallationError, "^admission-process-timeout$"):
                preparation.run("plan", request, self.root, payloads, helper)
        failure = subprocess.CompletedProcess([], 1, b"", b"private diagnostic")
        with mock.patch.object(preparation.subprocess, "run", return_value=failure):
            with self.assertRaisesRegex(preparation.InstallationError, "^admission-process-result$"):
                preparation.run("plan", request, self.root, payloads, helper)

    def test_changed_resource_or_managed_helper_cannot_redefine_authority(self):
        self.install()
        for relative, code in ((preparation.RESOURCE, "installation-resource-bytes"),
                               (Path("scripts/materialize_money_sources.py"), "managed-helper-bytes")):
            path = self.root / relative
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            self.refused("run", "plan", code=code)
            path.write_bytes(original)

    def test_changed_launcher_is_not_admitted_by_its_own_honest_verifier(self):
        self.install()
        path = self.root / preparation.LAUNCHER
        path.write_bytes(path.read_bytes() + b"\n")
        self.refused("run", "plan")

    def test_writable_launcher_record_cannot_redefine_fixed_launcher_path(self):
        self.install()
        path = self.root / preparation.RESOURCE
        data = json.loads(path.read_bytes())
        data["launcher"]["path"] = "scripts/counterfeit.py"
        path.write_bytes(preparation.document_bytes(data))
        self.refused("run", "plan", code="installation-launcher")

    def test_tampered_payloads_are_refused_without_repair_or_execution(self):
        self.install()
        for name in sorted(preparation.PAYLOAD_FILES):
            path = self.root / preparation.OUTPUT / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            for command in (("prepare",), ("verify",), ("run", "plan")):
                self.refused(*command)
            path.write_bytes(original)

    def test_extra_shadow_bytecode_receipt_and_directory_are_not_authority(self):
        self.install()
        output = self.root / preparation.OUTPUT
        for name in ("scripts/json.py", "scripts/database_admission.pyc", "bundle-manifest.json"):
            path = output / name
            path.write_text("untrusted", encoding="ascii")
            self.refused("run", "plan", code="snapshot-inventory")
            path.unlink()
        extra = output / "scripts/__pycache__"
        extra.mkdir()
        self.refused("verify", code="snapshot-inventory")
        extra.rmdir()

    def test_hardlinks_are_refused_even_with_correct_bytes(self):
        self.install()
        path = self.root / preparation.OUTPUT / "inputs.json"
        alias = self.root / "hardlink.json"
        os.link(path, alias)
        self.refused("verify", code="snapshot-inventory")
        alias.unlink()

    def test_symlinked_payload_is_refused_before_execution(self):
        self.install()
        target = self.root / "external-inputs.json"
        path = self.root / preparation.OUTPUT / "inputs.json"
        path.rename(target)
        try:
            path.symlink_to(target)
        except OSError as error:
            self.skipTest("Owned symlink fixture unavailable: " + str(error.winerror if hasattr(error, "winerror") else error.errno))
        self.refused("run", "plan")

    def test_junction_components_are_refused(self):
        self.install()
        with mock.patch.object(Path, "is_junction", return_value=True):
            with self.assertRaises(helper.MaterializationError):
                preparation.verify(self.root, self.fixture()[0], helper)

    def test_wrong_payload_mode_is_refused(self):
        self.install()
        path = self.root / preparation.OUTPUT / "inputs.json"
        path.chmod(0o444 if os.name == "nt" else 0o755)
        try:
            self.refused("verify", code="installation-mode")
        finally:
            path.chmod(0o644)

    def test_request_limits_and_malformed_json_refuse_without_provider_diagnostics(self):
        self.install()
        for raw in (b"", b"{" + b" " * preparation.REQUEST_LIMIT, b"{}", b'{"policy":1,"policy":2}',
                    b"\xef\xbb\xbf{}", b"\xff"):
            with self.subTest(length=len(raw)):
                self.refused("run", "plan", raw=raw)

    def test_binding_rejects_unknown_paths_modes_ids_and_future_unbound_claims(self):
        good, _transport, _contents = self.fixture()
        mutations = (
            lambda data: data.update(accepted=True),
            lambda data: data.update(binding={}),
            lambda data: data["binding"]["sources"]["infra"].update(commit="main"),
            lambda data: data["binding"]["sources"]["infra"].update(tree="unknown"),
            lambda data: data["binding"]["sources"]["infra"].update(repository_id=True),
            lambda data: data["binding"]["sources"]["inventory"].update(repository="PenniLogic/infra"),
            lambda data: data["binding"]["sources"]["policy"]["files"][0].update(mode="120000"),
            lambda data: data["binding"]["sources"]["policy"]["files"][0].update(path="../policy.json"),
            lambda data: data["binding"]["sources"]["policy"]["files"].pop(),
            lambda data: data["binding"]["payloads"][0].update(path="scripts/shadow.py"),
            lambda data: data["binding"]["payloads"][0].update(mode="100755"),
            lambda data: data["binding"]["payloads"][0].update(bytes=True),
            lambda data: data["binding"]["payloads"].append(copy.deepcopy(data["binding"]["payloads"][0])),
        )
        before = self.case.snapshot()
        for index, mutate in enumerate(mutations):
            data = copy.deepcopy(good)
            mutate(data)
            with self.subTest(index=index), self.assertRaises((preparation.InstallationError, helper.MaterializationError)):
                preparation.validate_authority(data, helper)
        self.assertEqual(before, self.case.snapshot())

    def test_inventory_manifest_must_match_actual_evidence_not_a_new_source_claim(self):
        data, transport, _contents = self.fixture()
        original = transport.contents["inventory"]["database/admission-inventory-source.json"]
        for field, value in (("tree", "0" * 40), ("commit", "c" * 40), ("repository_id", True),
                             ("inventory", {"accepted": True}), ("files", [])):
            manifest = json.loads(original)
            manifest[field] = value
            contents = copy.deepcopy(transport.contents)
            contents["inventory"]["database/admission-inventory-source.json"] = preparation.document_bytes(manifest)
            changed = copy.deepcopy(data)
            for entry in changed["binding"]["sources"]["inventory"]["files"]:
                if entry["path"].endswith("-source.json"):
                    entry.update(money_tests.binding(contents["inventory"][entry["path"]]))
            with self.subTest(field=field), self.assertRaises(preparation.InstallationError):
                preparation.assemble(changed, contents, helper)

    def test_wrong_tree_or_blob_fails_before_any_output_is_created(self):
        data, transport, _contents = self.fixture()
        data["binding"]["sources"]["infra"]["tree"] = "0" * 40
        before = self.case.snapshot()
        with self.assertRaisesRegex(preparation.InstallationError, "^installation-source-tree$"):
            preparation.prepare(self.root, data, helper, fetch=True, client=transport.client())
        self.assertEqual(before, self.case.snapshot())
        self.assertFalse((self.root / preparation.OUTPUT).exists())
        data, transport, _contents = self.fixture()
        source = data["binding"]["sources"]["infra"]
        entry = source["files"][0]
        transport.data["/repos/" + source["repository"] + "/git/blobs/" + entry["git_blob"]]["content"] = "dGFtcGVyZWQ="
        with self.assertRaises(helper.MaterializationError):
            preparation.prepare(self.root, data, helper, fetch=True, client=transport.client())
        self.assertEqual(before, self.case.snapshot())

    def test_failed_publication_rolls_back_only_its_own_created_paths(self):
        data, transport, _contents = self.fixture()
        before = self.case.snapshot()
        original = Path.chmod

        def chmod(path, *args, **kwargs):
            if path.name == "inputs.json":
                raise OSError("synthetic fixture failure")
            return original(path, *args, **kwargs)

        with mock.patch.object(Path, "chmod", chmod), self.assertRaises(OSError):
            preparation.prepare(self.root, data, helper, fetch=True, client=transport.client())
        self.assertEqual(before, self.case.snapshot())
        self.assertFalse((self.root / "build").exists())


if __name__ == "__main__":
    unittest.main()
