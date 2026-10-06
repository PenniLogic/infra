"""API-only pinned preparation mechanics, not native GitHub CI qualification."""

import base64
import contextlib
import copy
from email.message import Message
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.request


HERE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load("money_source_generator", HERE / "generate.py")
materializer = load("money_source_template", HERE / "templates/materialize_money_sources.py")
CATALOG = json.loads((HERE / "api-money-sources.json").read_bytes())


def binding(content):
    return {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()}


def tree_identity(entries):
    ordered = sorted(entries, key=lambda entry: (
        entry["path"] + ("/" if entry["type"] == "tree" else "")
    ).encode("utf-8"))
    content = b"".join(entry["mode"].lstrip("0").encode("ascii") + b" "
                       + entry["path"].encode("utf-8") + b"\0" + bytes.fromhex(entry["sha"])
                       for entry in ordered)
    return hashlib.sha1(b"tree " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()


class Response(io.BytesIO):
    status = 200

    def __init__(self, body, url):
        super().__init__(body)
        self.url = url
        self.headers = Message()
        self.headers["Content-Length"] = str(len(body))
        self.chunked = False

    def geturl(self):
        return self.url


class Transport:
    def __init__(self):
        self.catalog = copy.deepcopy(CATALOG)
        self.data, self.contents, self.calls = {}, {}, []
        self.data["/user"] = {"login": "basiltt", "id": 54134686}
        for source in self.catalog["sources"]:
            repository = source["repository"]
            prefix = "/repos/" + repository
            self.data[prefix] = {"id": source["repository_id"], "full_name": repository, "private": False,
                                 "owner": {"id": 335295566, "login": "PenniLogic"}}
            directories = {""}
            for entry in source["files"]:
                content = ("synthetic source: " + entry["path"] + "\n").encode()
                entry.update(binding(content))
                self.contents[source["snapshot"] + "/" + entry["path"]] = content
                self.data[prefix + "/git/blobs/" + entry["git_blob"]] = {
                    "sha": entry["git_blob"], "encoding": "base64", "size": len(content),
                    "content": base64.b64encode(content).decode(),
                }
                parts = entry["path"].split("/")
                directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
            trees = {path: [] for path in directories}
            for entry in source["files"]:
                parent, _, name = entry["path"].rpartition("/")
                trees[parent].append({"path": name, "type": "blob", "mode": entry["mode"],
                                      "sha": entry["git_blob"], "size": entry["bytes"]})
            identities = {}
            for path in sorted(directories, key=lambda name: (name.count("/"), len(name)), reverse=True):
                identities[path] = tree_identity(trees[path])
                if path:
                    parent, _, name = path.rpartition("/")
                    trees[parent].append({"path": name, "type": "tree", "mode": "040000", "sha": identities[path]})
            self.data[prefix + "/git/commits/" + source["commit"]] = {
                "sha": source["commit"], "tree": {"sha": identities[""]},
            }
            recursive = []
            for path, entries in trees.items():
                self.data[prefix + "/git/trees/" + identities[path]] = {
                    "sha": identities[path], "truncated": False, "tree": entries,
                }
                recursive.extend({**entry, "path": path + "/" + entry["path"] if path else entry["path"]}
                                 for entry in entries)
            self.data[prefix + "/git/trees/" + identities[""] + "?recursive=1"] = {
                "sha": identities[""], "truncated": False, "tree": recursive,
            }
        self.provider = {}
        for source in self.catalog["sources"]:
            prefix = "source/" if source["repository"] == "PenniLogic/contracts" else "strategy/"
            for entry in source["files"]:
                self.provider[prefix + entry["path"]] = self.contents[source["snapshot"] + "/" + entry["path"]]
        for entry in self.catalog["provider_outputs"]:
            content = ("synthetic output: " + entry["path"] + "\n").encode()
            entry.update({key: value for key, value in binding(content).items() if key != "git_blob"})
            self.provider[entry["path"]] = content

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if request.get_method() != "GET":
            raise AssertionError("Only read-only GET is allowed")
        if not 0 < timeout <= materializer.REQUEST_SECONDS:
            raise AssertionError("Request must have a bounded timeout")
        path = request.full_url.removeprefix("https://api.github.com")
        value = self.data[path]
        if isinstance(value, Exception):
            raise value
        body = value if isinstance(value, bytes) else json.dumps(value).encode()
        return Response(body, request.full_url)

    def client(self, **kwargs):
        kwargs.setdefault("opener", self)
        return materializer.ReadOnlyClient(self.catalog, **kwargs)

    def write_provider(self, root):
        for name, content in self.provider.items():
            path = root / materializer.PROVIDER / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)


class CatalogAndRendererTests(unittest.TestCase):
    def test_accepted_aa8_money_golden_and_native_provenance_are_exact(self):
        source = CATALOG["sources"][0]
        self.assertEqual("aa8d90cb98cec9b6dd08c91b3a4d869e47362662", source["commit"])
        self.assertEqual("contracts-" + source["commit"], source["snapshot"])
        files = {entry["path"]: entry for entry in source["files"]}
        money = files["runtime/kotlin/src/main/kotlin/com/pennilogic/contracts/money/Money.kt"]
        self.assertEqual((8489, "eddf78d0c9f694d660a7b13fd8e9e1154bc9b6c801ba0782b72973055d86c79d",
                          "0eb20eee5c75c5f68af56c58c64565f065fd5fa5"),
                         (money["bytes"], money["sha256"], money["git_blob"]))
        golden = files["generator/golden.json"]
        self.assertEqual((7609, "62ea59630dfb1e1d028b82c411f7efce575c2403ba277ff807333cdc0423a328",
                          "0455f5548c0d102653ddbed1923a77fc80892aba"),
                         (golden["bytes"], golden["sha256"], golden["git_blob"]))
        outputs = {entry["path"]: entry for entry in CATALOG["provider_outputs"]}
        self.assertEqual((money["bytes"], money["sha256"]), (
            outputs["kotlin/src/main/kotlin/com/pennilogic/contracts/money/Money.kt"]["bytes"],
            outputs["kotlin/src/main/kotlin/com/pennilogic/contracts/money/Money.kt"]["sha256"],
        ))
        self.assertEqual((2404, "e982e5b7fcd26314cdf7a3fd79e3de5fd782ceac0bc35b6ea5c8e779c55b86a0"), (
            outputs["provider.json"]["bytes"], outputs["provider.json"]["sha256"],
        ))
        self.assertEqual("10d491ae90bc8f077afe5d45be671af52a5b7891c88eacfccd437a10f4956b21",
                         outputs["kotlin/src/main/kotlin/com/pennilogic/contracts/money/CurrencyRegistry.kt"]["sha256"])

    def test_real_catalog_has_all_exact_source_bindings(self):
        self.assertEqual(CATALOG, materializer.validate_catalog(CATALOG))
        self.assertEqual(["aa8d90cb98cec9b6dd08c91b3a4d869e47362662",
                          "a700e639585c61a4610e7b99dbd02b2dab28bdcc"],
                         [source["commit"] for source in CATALOG["sources"]])
        self.assertEqual([10, 1], [len(source["files"]) for source in CATALOG["sources"]])
        strategy = CATALOG["sources"][1]["files"][0]
        self.assertEqual(("governance/test-strategy.json", 80953,
                          "a0322e0337c7c0e496711f21a1aea01136c6047b787318fd805a0788c2239bb2",
                          "db7acd323db9b7807b749cda8c8378ebd274d4cb"),
                         (strategy["path"], strategy["bytes"], strategy["sha256"], strategy["git_blob"]))
        self.assertEqual(14, len(materializer.provider_bindings(CATALOG)))

    def test_only_api_changes_five_command_artifacts_and_adds_one_script(self):
        current = {repo: generator.artifacts(repo) for repo in generator.PROFILES["repositories"]}
        old = copy.deepcopy(generator.PROFILES)
        del old["repositories"]["api"]["money_source_materialization"]
        old["repositories"]["api"]["commands"] = [
            "python scripts/check_repository.py", "python scripts/quality.py build",
            "python -m unittest discover -s scripts/tests",
        ]
        with mock.patch.object(generator, "PROFILES", old):
            previous = {repo: generator.artifacts(repo) for repo in old["repositories"]}
        for repo in old["repositories"]:
            changed = {name for name in current[repo].keys() | previous[repo].keys()
                       if current[repo].get(name) != previous[repo].get(name)}
            self.assertEqual({
                "AGENTS.md", "README.md", "CONTRIBUTING.md", ".github/agent-policy.json",
                ".github/workflows/ci.yml", "scripts/materialize_money_sources.py",
            } if repo == "api" else set(), changed, repo)
        namespace = {"__file__": str(HERE / "templates/materialize_money_sources.py"), "__name__": "rendered_fixture"}
        exec(compile(current["api"]["scripts/materialize_money_sources.py"], "rendered_fixture", "exec"), namespace)
        self.assertEqual(CATALOG, namespace["CATALOG"])

    def test_preparation_precedes_the_unchanged_build_and_no_gate_is_removed(self):
        commands = generator.profile_for("api")["commands"]
        self.assertEqual("python scripts/check_repository.py", commands[0])
        self.assertEqual([
            "python scripts/materialize_money_sources.py",
            "python scripts/money_provider.py --source-root "
            '"build/source-materialization/contracts-aa8d90cb98cec9b6dd08c91b3a4d869e47362662" --strategy-file '
            '"build/source-materialization/docs-a700e639585c61a4610e7b99dbd02b2dab28bdcc/governance/test-strategy.json"',
            "python scripts/money_provider.py --verify", "python scripts/materialize_money_sources.py --verify",
        ], commands[1:5])
        self.assertEqual(["python scripts/quality.py build", "python -m unittest discover -s scripts/tests"], commands[5:])
        workflow = json.loads(generator.workflow("api"))
        self.assertEqual({"contents": "read"}, workflow["permissions"])
        self.assertEqual(30, workflow["jobs"]["ci"]["timeout-minutes"])
        self.assertEqual("CI", workflow["jobs"]["ci"]["name"])
        self.assertEqual('python scripts/quality.py coverage --base "$BASE_SHA"',
                         workflow["jobs"]["ci"]["steps"][-1]["run"])
        self.assertNotIn("GH_TOKEN", json.dumps(workflow))
        self.assertNotIn("authenticated-local", json.dumps(workflow))

    def test_profile_opt_in_cannot_widen_to_other_repositories(self):
        for repo, value in (("api", False), ("api", "true"), ("infra", True), ("contracts", True)):
            profile = copy.deepcopy(generator.PROFILES["repositories"][repo])
            profile["money_source_materialization"] = value
            with self.subTest(repo=repo, value=value), self.assertRaises(ValueError):
                generator.validate_profile(repo, profile)

    def test_unsafe_catalog_data_is_refused(self):
        changes = [
            lambda data: data["sources"][0].update(commit="main"),
            lambda data: data["sources"][0].update(repository_id=True),
            lambda data: data["sources"][0].update(repository="Other/contracts"),
            lambda data: data["sources"][0].update(snapshot="../other"),
            lambda data: data["sources"][0]["files"].pop(),
            lambda data: data["sources"][0]["files"][0].update(mode="120000"),
            lambda data: data["sources"][0]["files"][0].update(bytes=2**30),
            lambda data: data["sources"][0]["files"][0].update(bytes=True),
            lambda data: data["sources"][0]["files"][0].update(sha256="missing"),
            lambda data: data["sources"][0]["files"][0].update(git_blob="missing"),
            lambda data: data["sources"][0]["files"][1].update(path=data["sources"][0]["files"][0]["path"].upper()),
            lambda data: data["sources"][0]["files"][0].update(path="scripts"),
            lambda data: data["consumer"].update(repository="PenniLogic/contracts"),
            lambda data: data["provider_outputs"][0].update(path="kotlin/other.kt"),
            lambda data: data.update(extra="unexpected"),
        ]
        for change in changes:
            data = copy.deepcopy(CATALOG)
            change(data)
            with self.subTest(change=change), self.assertRaises(materializer.MaterializationError):
                materializer.validate_catalog(data)
        for path in ("../outside", "/absolute", "C:/outside", "scripts\\outside", "scripts//x",
                     "scripts/./x", "scripts/x.", "scripts/CON.py", "scripts/a%2fb", "scripts/\u00e9.py"):
            data = copy.deepcopy(CATALOG)
            data["sources"][0]["files"][0]["path"] = path
            with self.subTest(path=path), self.assertRaisesRegex(materializer.MaterializationError, "catalog-path"):
                materializer.validate_catalog(data)


class MaterializationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.transport = Transport()
        self.patch = mock.patch.object(materializer, "CATALOG", self.transport.catalog)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def prepare(self):
        return materializer.materialize(self.root, self.transport.client())

    def test_real_client_fetches_exact_git_objects_and_creates_only_owned_inputs(self):
        result = self.prepare()
        self.assertEqual("materialized", result["status"])
        self.assertEqual((11, 17), (result["inputs"], result["requests"]))
        self.assertFalse((self.root / materializer.PROVIDER).exists())
        for name, expected in self.transport.contents.items():
            self.assertEqual(expected, (self.root / materializer.INPUTS / name).read_bytes())
        materializer.verify_inputs(self.root)
        self.assertTrue(all("Authorization" not in request.headers for request, _ in self.transport.calls))
        self.assertFalse(any("main" in request.full_url for request, _ in self.transport.calls))

    def test_idempotency_performs_no_fetch_or_rewrite(self):
        self.prepare()
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns)
                  for path in (self.root / materializer.INPUTS).rglob("*") if path.is_file()}
        self.transport.calls.clear()
        result = self.prepare()
        self.assertEqual("verified_existing", result["status"])
        self.assertEqual([], self.transport.calls)
        self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before})

    def test_offline_verification_requires_every_provider_output_including_receipt(self):
        self.prepare()
        with self.assertRaisesRegex(materializer.MaterializationError, "snapshot-missing"):
            materializer.verify_provider(self.root)
        self.transport.write_provider(self.root)
        materializer.verify_provider(self.root)
        for name in ("provider.json", "kotlin/src/main/kotlin/com/pennilogic/contracts/money/Money.kt",
                     "strategy/governance/test-strategy.json", "source/scripts/generate_clients.py"):
            path = self.root / materializer.PROVIDER / name
            original = path.read_bytes()
            path.write_bytes(b"tampered")
            with self.subTest(name=name), self.assertRaises(materializer.MaterializationError):
                self.prepare()
            self.assertEqual(b"tampered", path.read_bytes())
            path.write_bytes(original)
            path.unlink()
            with self.subTest(missing=name), self.assertRaises(materializer.MaterializationError):
                materializer.verify_provider(self.root)
            path.write_bytes(original)
        self.assertEqual(17, len(self.transport.calls))

    def test_missing_tampered_extra_and_partial_snapshots_refuse_without_repair(self):
        self.prepare()
        base = self.root / materializer.INPUTS
        name, original = next(iter(self.transport.contents.items()))
        path = base / name
        self.transport.calls.clear()
        for mutate in (lambda: path.write_bytes(b"tampered"), path.unlink):
            mutate()
            with self.assertRaises(materializer.MaterializationError):
                self.prepare()
            self.assertEqual([], self.transport.calls)
            if path.exists():
                self.assertEqual(b"tampered", path.read_bytes())
            path.write_bytes(original)
        receipt = base / "materialization.json"
        original_receipt = receipt.read_bytes()
        receipt.write_bytes(b"{}")
        with self.assertRaisesRegex(materializer.MaterializationError, "snapshot-receipt"):
            self.prepare()
        receipt.write_bytes(original_receipt)
        extra = base / self.transport.catalog["sources"][0]["snapshot"] / "scripts" / "extra.py"
        extra.write_bytes(b"unapproved executable")
        with self.assertRaisesRegex(materializer.MaterializationError, "snapshot-inventory"):
            self.prepare()
        extra.unlink()
        (base / "unexpected-empty-directory").mkdir()
        with self.assertRaisesRegex(materializer.MaterializationError, "snapshot-inventory"):
            self.prepare()

    def test_bad_repository_commit_tree_mode_or_blob_never_creates_output(self):
        source = self.transport.catalog["sources"][0]
        prefix = "/repos/" + source["repository"]
        commit_path = prefix + "/git/commits/" + source["commit"]
        root = self.transport.data[commit_path]["tree"]["sha"]
        root_path = prefix + "/git/trees/" + root + "?recursive=1"
        entry = source["files"][0]
        blob_path = prefix + "/git/blobs/" + entry["git_blob"]
        changes = [
            (prefix, lambda value: value.update(id=1)),
            (prefix, lambda value: value["owner"].update(id=1)),
            (prefix, lambda value: value["owner"].update(login="Other")),
            (prefix, lambda value: value.update(private=True)),
            (prefix, lambda value: value.update(full_name="Other/contracts")),
            (commit_path, lambda value: value.update(sha="a" * 40)),
            (root_path, lambda value: value.update(truncated=True)),
            (root_path, lambda value: value.update(sha="a" * 40)),
            (root_path, lambda value: value["tree"][0].update(mode="120000")),
            (root_path, lambda value: value["tree"].clear()),
            (blob_path, lambda value: value.update(size=value["size"] + 1)),
            (blob_path, lambda value: value.update(content=base64.b64encode(b"tampered").decode())),
            (blob_path, lambda value: value.update(content="!not base64")),
            (blob_path, lambda value: value.update(sha="a" * 40)),
            (blob_path, lambda value: value.update(encoding="utf-8")),
        ]
        for path, mutate in changes:
            original = copy.deepcopy(self.transport.data[path])
            mutate(self.transport.data[path])
            with self.subTest(path=path, mutate=mutate), self.assertRaises(materializer.MaterializationError):
                self.prepare()
            self.assertFalse((self.root / materializer.INPUTS).exists())
            self.transport.data[path] = original

    def test_exact_git_blob_identity_is_required_beside_sha256(self):
        entry = copy.deepcopy(self.transport.catalog["sources"][0]["files"][0])
        entry["git_blob"] = "a" * 40
        content = next(iter(self.transport.contents.values()))
        with self.assertRaisesRegex(materializer.MaterializationError, "source-git-blob"):
            materializer.check_bytes(content, entry)

    def test_local_authentication_is_explicit_personal_and_forbidden_on_actions(self):
        env = {"GH_TOKEN": "synthetic-process-local-token"}
        with mock.patch.dict(os.environ, env, clear=True):
            client = self.transport.client(authenticated_local=True, environ=env)
            self.assertEqual(18, materializer.materialize(self.root, client)["requests"])
        self.assertTrue(all(request.headers["Authorization"] == "Bearer synthetic-process-local-token"
                            for request, _ in self.transport.calls))
        for denied in ({}, {"GITHUB_TOKEN": env["GH_TOKEN"]}, {**env, "GITHUB_ACTIONS": "true"}):
            with self.subTest(env=denied), self.assertRaisesRegex(materializer.MaterializationError, "local-authentication"):
                self.transport.client(authenticated_local=True, environ=denied)
        anonymous = self.transport.client(environ=env)
        self.assertNotIn("Authorization", anonymous.headers)

    def test_wrong_local_identity_refuses_before_any_repository_read(self):
        self.transport.data["/user"] = {"login": "corporate-fixture", "id": 7}
        env = {"GH_TOKEN": "synthetic-process-local-token"}
        with mock.patch.dict(os.environ, env, clear=True):
            client = self.transport.client(authenticated_local=True, environ=env)
            with self.assertRaisesRegex(materializer.MaterializationError, "local-personal-identity"):
                materializer.materialize(self.root, client)
        self.assertEqual(1, len(self.transport.calls))
        self.assertFalse((self.root / materializer.INPUTS).exists())

    def test_authenticated_local_mode_cannot_bypass_actions_refusal_using_an_existing_snapshot(self):
        self.prepare()
        before = len(self.transport.calls)
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GH_TOKEN": "synthetic-process-local-token"}, clear=True):
            with self.assertRaisesRegex(materializer.MaterializationError, "local-authentication"):
                materializer.materialize(self.root, authenticated_local=True)
        self.assertEqual(before, len(self.transport.calls))

    def test_linked_root_or_ancestor_is_refused_without_fetch(self):
        outside = self.root / "outside"
        outside.mkdir()
        link = self.root / "linked"
        if os.name == "nt":
            command = f"New-Item -ItemType Junction -Path '{link}' -Target '{outside}' | Out-Null"
            subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
                           check=True, capture_output=True, timeout=15)
        else:
            link.symlink_to(outside, target_is_directory=True)
        try:
            with self.assertRaisesRegex(materializer.MaterializationError, "output-path-linked"):
                materializer.materialize(link, self.transport.client())
            self.assertEqual([], self.transport.calls)
            self.assertEqual([], list(outside.iterdir()))
        finally:
            if link.is_junction():
                link.rmdir()
            else:
                link.unlink()

    def test_hardlinked_input_is_refused(self):
        self.prepare()
        name = next(iter(self.transport.contents))
        path = self.root / materializer.INPUTS / name
        alias = self.root / "alias"
        os.link(path, alias)
        with self.assertRaisesRegex(materializer.MaterializationError, "snapshot-inventory"):
            self.prepare()

    def test_symbolic_file_input_is_refused_when_native_symlinks_are_available(self):
        self.prepare()
        name, content = next(iter(self.transport.contents.items()))
        path = self.root / materializer.INPUTS / name
        path.unlink()
        target = self.root / "target"
        target.write_bytes(content)
        try:
            path.symlink_to(target)
        except OSError as error:
            if os.name != "nt":
                raise
            self.skipTest(f"Native file symlink unavailable: {type(error).__name__}; junction tested separately")
        else:
            with self.assertRaisesRegex(materializer.MaterializationError, "output-path-linked"):
                self.prepare()

    def test_output_path_cannot_escape_the_owned_root(self):
        for relative in (Path("..") / "outside", self.root / "absolute"):
            with self.subTest(relative=relative), self.assertRaisesRegex(materializer.MaterializationError, "output-path"):
                materializer.owned_path(self.root, relative)
        self.assertEqual([], self.transport.calls)

    def test_cli_refusals_are_static_and_missing_provider_is_not_success(self):
        self.prepare()
        with mock.patch.object(materializer, "ROOT", self.root):
            # Defaults are definition-bound; use wrappers to exercise the real CLI without a fixture option.
            with mock.patch.object(materializer, "verify_inputs", wraps=lambda: materializer.verify_directory(
                self.root, materializer.INPUTS, materializer.input_bindings(self.transport.catalog),
                materializer.catalog_bytes(self.transport.catalog),
            )), mock.patch.object(materializer, "verify_provider", wraps=lambda: materializer.verify_directory(
                self.root, materializer.PROVIDER, materializer.provider_bindings(self.transport.catalog),
            )), mock.patch.object(materializer.sys, "argv", ["materializer", "--verify"]):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(1, materializer.main())
                self.assertEqual("", out.getvalue())
                self.assertEqual({"event": "money_sources", "status": "refused", "code": "snapshot-missing"},
                                 json.loads(err.getvalue()))
                self.transport.write_provider(self.root)
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(0, materializer.main())


class TransportBoundsTests(unittest.TestCase):
    def setUp(self):
        self.transport = Transport()
        self.client = self.transport.client()
        self.path = "/repos/PenniLogic/contracts"

    def test_unlisted_hosts_repositories_refs_paths_and_blobs_are_not_fetched(self):
        for path in ("https://other.example/source", "/user", "/repos/PenniLogic/api",
                     "/repos/PenniLogic/contracts/git/commits/main",
                     "/repos/PenniLogic/contracts/git/blobs/" + "a" * 40,
                     self.path + "/../docs", self.path + "?redirect=1"):
            with self.subTest(path=path), self.assertRaisesRegex(materializer.MaterializationError, "source-api-path"):
                self.client.get(path)
        self.assertEqual([], self.transport.calls)

    def test_no_redirect_or_proxy_handler_is_permitted(self):
        client = materializer.ReadOnlyClient(self.transport.catalog)
        proxy = [handler for handler in client.opener.handlers if isinstance(handler, urllib.request.ProxyHandler)]
        self.assertTrue(not proxy or all(handler.proxies == {} for handler in proxy))
        self.assertTrue(any(isinstance(handler, materializer.NoRedirect) for handler in client.opener.handlers))
        stream = io.BytesIO(b"untrusted redirect body")
        with self.assertRaisesRegex(materializer.MaterializationError, "source-redirect"):
            materializer.NoRedirect().redirect_request(None, stream, 302, "redirect", {}, "https://other.example")
        self.assertTrue(stream.closed)

    def test_timeouts_http_errors_and_invalid_json_are_explicit_without_body_disclosure(self):
        for value, code in [
            (TimeoutError("untrusted exception content"), "source-unavailable"),
            (urllib.error.URLError("untrusted exception content"), "source-unavailable"),
            (urllib.error.HTTPError(self.path, 403, "untrusted exception content", {}, io.BytesIO(b"body")),
             "source-forbidden"),
            (b'{"id":1,"id":2}', "duplicate-json-key"),
            (b"\xef\xbb\xbf{}", "json-bom"), (b"\xff", "metadata-json"), (b'{"id":NaN}', "json-number"),
        ]:
            self.transport.data[self.path] = value
            with self.subTest(code=code), self.assertRaisesRegex(materializer.MaterializationError, "^" + code + "$"):
                self.client.get(self.path)

    def test_response_total_request_and_deadline_limits_are_not_success(self):
        self.transport.data[self.path] = b"x" * (materializer.MAX_RESPONSE_BYTES + 1)
        with self.assertRaisesRegex(materializer.MaterializationError, "source-size"):
            self.client.get(self.path)
        client = self.transport.client()
        client.budget.bytes = materializer.MAX_TOTAL_BYTES
        self.transport.data[self.path] = b"{}"
        with self.assertRaisesRegex(materializer.MaterializationError, "source-size"):
            client.get(self.path)
        client.budget.requests = materializer.MAX_REQUESTS
        with self.assertRaisesRegex(materializer.MaterializationError, "source-request-limit"):
            client.get(self.path)
        now = [0]
        budget = materializer.Budget(clock=lambda: now[0])
        now[0] = materializer.DEADLINE_SECONDS
        with self.assertRaisesRegex(materializer.MaterializationError, "source-deadline"):
            self.transport.client(budget=budget).get(self.path)

    def test_returned_url_and_status_must_match_the_fixed_https_get(self):
        class WrongResponse(Response):
            status = 201

        opener = mock.Mock()
        opener.open.return_value = WrongResponse(b"{}", "https://api.github.com" + self.path)
        with self.assertRaisesRegex(materializer.MaterializationError, "source-http"):
            self.transport.client(opener=opener).get(self.path)
        opener.open.return_value = Response(b"{}", "https://other.example")
        with self.assertRaisesRegex(materializer.MaterializationError, "source-redirect"):
            self.transport.client(opener=opener).get(self.path)


if __name__ == "__main__":
    unittest.main()
