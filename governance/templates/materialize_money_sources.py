"""Materialize exact accepted API Money inputs; never write the provider's outputs."""

import argparse
import base64
import binascii
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import urllib.error
import urllib.request


CATALOG = None
ROOT = Path(__file__).absolute().parents[1]
INPUTS = Path("build") / "source-materialization"
PROVIDER = Path("build") / "contracts-money"
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
            *(f"lpt{i}" for i in range(1, 10))}
SOURCE_IDS = {"PenniLogic/contracts": (1394134505, 10), "PenniLogic/docs": (1394134442, 1)}
MAX_FILE_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_REQUESTS = 32
REQUEST_SECONDS = 10
DEADLINE_SECONDS = 180


class MaterializationError(ValueError):
    """A static refusal code, never source content, credentials or an API error body."""


def require(condition, code):
    if not condition:
        raise MaterializationError(code)


def mapping(value):
    require(isinstance(value, dict), "metadata-shape")
    return value


def sha(value):
    require(isinstance(value, str) and SHA.fullmatch(value) is not None, "immutable-sha")
    return value


def json_document(content):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate-json-key")
            result[key] = value
        return result

    def number(value):
        result = float(value)
        require(math.isfinite(result), "json-number")
        return result

    def constant(_value):
        raise MaterializationError("json-number")

    try:
        text = content.decode("utf-8")
        require(not text.startswith("\ufeff"), "json-bom")
        result = json.loads(text, object_pairs_hook=unique, parse_float=number, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, MaterializationError):
            raise
        raise MaterializationError("metadata-json") from None
    pending = [(result, 0)]
    while pending:
        value, depth = pending.pop()
        require(depth <= 64, "metadata-depth")
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
    return result


def relative_path(value):
    require(isinstance(value, str) and 1 <= len(value) <= 512, "catalog-path")
    parts = value.split("/")
    require(len(parts) <= 16 and all(PART.fullmatch(part) is not None
            and not part.endswith(".") and part.split(".")[0].lower() not in RESERVED
            for part in parts), "catalog-path")
    return value


def file_binding(value, source=False):
    data = mapping(value)
    keys = {"path", "bytes", "sha256"} | ({"mode", "git_blob"} if source else set())
    require(set(data) == keys, "catalog-file")
    relative_path(data["path"])
    require(type(data["bytes"]) is int and 0 < data["bytes"] <= MAX_FILE_BYTES, "catalog-size")
    require(isinstance(data["sha256"], str) and DIGEST.fullmatch(data["sha256"]) is not None, "catalog-digest")
    if source:
        require(data["mode"] == "100644", "catalog-mode")
        sha(data["git_blob"])


def validate_catalog(value):
    catalog = mapping(value)
    require(set(catalog) == {"schema", "consumer", "sources", "provider_outputs"}
            and catalog["schema"] == "pennilogic.api-money-sources/1", "catalog-schema")
    consumer = mapping(catalog["consumer"])
    require(consumer == {"repository": "PenniLogic/api", "repository_id": 1394134582,
                         "organization_id": 335295566}
            and type(consumer["repository_id"]) is int and type(consumer["organization_id"]) is int,
            "consumer-identity")
    sources = catalog["sources"]
    require(isinstance(sources, list) and len(sources) == 2, "catalog-sources")
    seen = set()
    for raw in sources:
        source = mapping(raw)
        require(set(source) == {"repository", "repository_id", "commit", "snapshot", "files"}, "catalog-source")
        repository = source["repository"]
        require(isinstance(repository, str) and repository in SOURCE_IDS and repository not in seen,
                "source-identity")
        seen.add(repository)
        identity, count = SOURCE_IDS[repository]
        require(type(source["repository_id"]) is int and source["repository_id"] == identity, "source-identity")
        commit = sha(source["commit"])
        require(source["snapshot"] == repository.split("/")[1] + "-" + commit, "snapshot-path")
        files = source["files"]
        require(isinstance(files, list) and len(files) == count, "catalog-input-count")
        paths = set()
        for entry in files:
            file_binding(entry, source=True)
            path = entry["path"].lower()
            require(path not in paths, "catalog-path-collision")
            paths.add(path)
        require(not any(parent in paths for path in paths for parent in (
            "/".join(path.split("/")[:index]) for index in range(1, len(path.split("/")))
        )), "catalog-path-collision")
    outputs = catalog["provider_outputs"]
    require(isinstance(outputs, list) and len(outputs) == 3, "catalog-outputs")
    for entry in outputs:
        file_binding(entry)
    require({entry["path"] for entry in outputs} == {
        "kotlin/src/main/kotlin/com/pennilogic/contracts/money/Money.kt",
        "kotlin/src/main/kotlin/com/pennilogic/contracts/money/CurrencyRegistry.kt", "provider.json",
    }, "catalog-outputs")
    return catalog


def catalog_bytes(catalog):
    return (json.dumps(catalog, indent=2, sort_keys=True) + "\n").encode("utf-8")


class Budget:
    def __init__(self, clock=time.monotonic):
        self.clock, self.started = clock, clock()
        self.requests, self.bytes = 0, 0

    def remaining(self):
        remaining = DEADLINE_SECONDS - (self.clock() - self.started)
        require(remaining > 0, "source-deadline")
        return remaining

    def request(self):
        timeout = min(REQUEST_SECONDS, self.remaining())
        require(self.requests < MAX_REQUESTS, "source-request-limit")
        self.requests += 1
        return timeout


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise MaterializationError("source-redirect")


class ReadOnlyClient:
    """Use the accepted PR-validator's bounded Git-object GET pattern, without its gate policy."""

    def __init__(self, catalog, authenticated_local=False, budget=None, opener=None, environ=None):
        env = os.environ if environ is None else environ
        self.budget = budget or Budget()
        self.authenticated_local = authenticated_local
        self.headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                        "User-Agent": "PenniLogic-API-Money-source-materialization"}
        if authenticated_local:
            token = env.get("GH_TOKEN")
            require(env.get("GITHUB_ACTIONS") != "true" and isinstance(token, str)
                    and 20 <= len(token) <= 4096 and all(33 <= ord(char) <= 126 for char in token),
                    "local-authentication")
            self.headers["Authorization"] = "Bearer " + token
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        allowed = []
        for source in catalog["sources"]:
            prefix = re.escape("/repos/" + source["repository"])
            blobs = "|".join(entry["git_blob"] for entry in source["files"])
            allowed.append(prefix + r"(?:|/git/commits/" + source["commit"]
                           + r"|/git/trees/[0-9a-f]{40}|/git/blobs/(?:" + blobs + r"))")
        if authenticated_local:
            allowed.append("/user")
        self.paths = re.compile("|".join(allowed))

    def get(self, path):
        require(isinstance(path, str) and self.paths.fullmatch(path) is not None, "source-api-path")
        request = urllib.request.Request("https://api.github.com" + path, method="GET", headers=self.headers)
        timeout = self.budget.request()
        try:
            with self.opener.open(request, timeout=timeout) as response:
                require(response.status == 200, "source-http")
                require(response.geturl() == request.full_url, "source-redirect")
                parts, size = [], 0
                while True:
                    self.budget.remaining()
                    part = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - size))
                    if not part:
                        break
                    size += len(part)
                    self.budget.bytes += len(part)
                    require(size <= MAX_RESPONSE_BYTES and self.budget.bytes <= MAX_TOTAL_BYTES, "source-size")
                    parts.append(part)
                self.budget.remaining()
                return json_document(b"".join(parts))
        except urllib.error.HTTPError as error:
            error.close()
            raise MaterializationError("source-denied" if error.code in (401, 403, 404) else "source-http") from None
        except http.client.HTTPException:
            raise MaterializationError("source-protocol") from None
        except (urllib.error.URLError, OSError, TimeoutError):
            raise MaterializationError("source-unavailable") from None


class GitSnapshot:
    def __init__(self, client, source, organization_id):
        self.client, self.source = client, source
        repository = source["repository"]
        data = mapping(client.get("/repos/" + repository))
        owner = mapping(data.get("owner"))
        require(type(data.get("id")) is int and data["id"] == source["repository_id"]
                and type(owner.get("id")) is int and owner["id"] == organization_id
                and owner.get("login") == "PenniLogic" and data.get("full_name") == repository
                and data.get("private") is False, "source-repository-identity")
        self.prefix = "/repos/" + repository + "/git/"
        commit = mapping(client.get(self.prefix + "commits/" + source["commit"]))
        require(commit.get("sha") == source["commit"], "source-commit")
        self.root = sha(mapping(commit.get("tree")).get("sha"))
        self.trees = {}

    def tree(self, identity):
        if identity not in self.trees:
            data = mapping(self.client.get(self.prefix + "trees/" + sha(identity)))
            entries = data.get("tree")
            require(data.get("sha") == identity and data.get("truncated") is False
                    and isinstance(entries, list) and len(entries) <= 4096, "source-tree")
            indexed = {}
            for raw in entries:
                entry = mapping(raw)
                path = entry.get("path")
                require(isinstance(path, str) and 1 <= len(path) <= 1024 and path not in (".", "..")
                        and "/" not in path and "\\" not in path and path not in indexed
                        and all(ord(char) >= 32 and char != "\x7f" for char in path), "source-tree-path")
                sha(entry.get("sha"))
                require(entry.get("type") in ("tree", "blob", "commit")
                        and entry.get("mode") in ("040000", "100644", "100755", "120000", "160000"), "source-tree")
                indexed[path] = entry
            self.trees[identity] = indexed
        return self.trees[identity]

    def blob(self, binding):
        parts, identity = binding["path"].split("/"), self.root
        for index, part in enumerate(parts):
            entry = self.tree(identity).get(part)
            require(entry is not None, "source-input-missing")
            final = index == len(parts) - 1
            require(entry["type"] == ("blob" if final else "tree")
                    and entry["mode"] == (binding["mode"] if final else "040000"), "source-entry-mode")
            identity = entry["sha"]
        require(identity == binding["git_blob"] and type(entry.get("size")) is int
                and entry["size"] == binding["bytes"], "source-blob-binding")
        data = mapping(self.client.get(self.prefix + "blobs/" + identity))
        require(data.get("sha") == identity and data.get("encoding") == "base64"
                and type(data.get("size")) is int and data["size"] == binding["bytes"]
                and isinstance(data.get("content"), str) and len(data["content"]) <= MAX_RESPONSE_BYTES, "source-blob")
        try:
            content = base64.b64decode(data["content"].replace("\n", ""), validate=True)
        except (binascii.Error, ValueError):
            raise MaterializationError("source-blob") from None
        check_bytes(content, binding)
        return content


def check_bytes(content, binding):
    require(len(content) == binding["bytes"] and hashlib.sha256(content).hexdigest() == binding["sha256"],
            "source-bytes")
    if "git_blob" in binding:
        identity = hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()
        require(identity == binding["git_blob"], "source-git-blob")


def owned_path(root, relative):
    relative = Path(relative)
    require(not relative.is_absolute() and ".." not in relative.parts, "output-path")
    path = root.absolute() / relative
    require(path.is_relative_to(root.absolute()), "output-path")
    for component in (path, *path.parents):
        require(not component.is_symlink() and not component.is_junction(), "output-path-linked")
    return path


def input_bindings(catalog):
    return {source["snapshot"] + "/" + entry["path"]: entry
            for source in catalog["sources"] for entry in source["files"]}


def provider_bindings(catalog):
    bindings = {entry["path"]: entry for entry in catalog["provider_outputs"]}
    for source in catalog["sources"]:
        prefix = "source/" if source["repository"] == "PenniLogic/contracts" else "strategy/"
        bindings.update({prefix + entry["path"]: entry for entry in source["files"]})
    return bindings


def verify_directory(root, relative, bindings, receipt=None):
    base = owned_path(root, relative)
    require(base.is_dir(), "snapshot-missing")
    expected = set(bindings) | ({"materialization.json"} if receipt is not None else set())
    directories = {"/".join(path.split("/")[:index]) for path in expected
                   for index in range(1, len(path.split("/")))}
    found, pending, count = set(), [base], 0
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                count += 1
                require(count <= 128, "snapshot-inventory")
                path = owned_path(root, Path(entry.path).relative_to(root.absolute()))
                name = path.relative_to(base).as_posix()
                if entry.is_dir(follow_symlinks=False):
                    require(name in directories, "snapshot-inventory")
                    pending.append(path)
                else:
                    # Windows DirEntry.stat caches st_nlink=0; Path.stat reads the real link count.
                    metadata = path.stat(follow_symlinks=False)
                    require(name in expected and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                            "snapshot-inventory")
                    found.add(name)
    require(found == expected, "snapshot-inventory")
    for name in sorted(found):
        path = owned_path(root, relative / name)
        limit = len(receipt) if name == "materialization.json" else bindings[name]["bytes"]
        with path.open("rb") as stream:
            content = stream.read(limit + 1)
        if name == "materialization.json":
            require(content == receipt, "snapshot-receipt")
        else:
            check_bytes(content, bindings[name])


def verify_inputs(root=ROOT, catalog=None):
    catalog = validate_catalog(CATALOG if catalog is None else catalog)
    verify_directory(root, INPUTS, input_bindings(catalog), catalog_bytes(catalog))


def verify_provider(root=ROOT, catalog=None):
    catalog = validate_catalog(CATALOG if catalog is None else catalog)
    verify_directory(root, PROVIDER, provider_bindings(catalog))


def materialize(root=ROOT, client=None, authenticated_local=False):
    catalog = validate_catalog(CATALOG)
    client = client or ReadOnlyClient(catalog, authenticated_local=authenticated_local)
    target = owned_path(root, INPUTS)
    provider = owned_path(root, PROVIDER)
    if provider.exists():
        verify_provider(root, catalog)
    if target.exists():
        verify_inputs(root, catalog)
        return {"event": "money_sources", "status": "verified_existing", "inputs": 11, "requests": 0,
                "catalog_sha256": hashlib.sha256(catalog_bytes(catalog)).hexdigest()}
    if client.authenticated_local:
        user = mapping(client.get("/user"))
        require(user.get("login") == "basiltt" and type(user.get("id")) is int
                and user["id"] == 54134686, "local-personal-identity")
    contents, roots = {}, {}
    for source in catalog["sources"]:
        snapshot = GitSnapshot(client, source, catalog["consumer"]["organization_id"])
        roots[source["repository"]] = snapshot.root
        for binding in source["files"]:
            contents[source["snapshot"] + "/" + binding["path"]] = snapshot.blob(binding)
    client.budget.remaining()
    target.parent.mkdir(parents=True, exist_ok=True)
    owned_path(root, INPUTS).mkdir()
    for name, content in contents.items():
        client.budget.remaining()
        path = owned_path(root, INPUTS / name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(content)
    receipt = owned_path(root, INPUTS / "materialization.json")
    with receipt.open("xb") as stream:
        stream.write(catalog_bytes(catalog))
    verify_inputs(root, catalog)
    client.budget.remaining()
    return {"event": "money_sources", "status": "materialized", "inputs": 11,
            "catalog_sha256": hashlib.sha256(catalog_bytes(catalog)).hexdigest(), "source_trees": roots,
            "requests": client.budget.requests, "response_bytes": client.budget.bytes,
            "elapsed_seconds": round(client.budget.clock() - client.budget.started, 3)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="Verify all inputs AND native provider outputs, offline")
    parser.add_argument("--authenticated-local", action="store_true", help="Explicit process-local personal GH_TOKEN; never CI")
    args = parser.parse_args()
    try:
        if args.verify:
            require(not args.authenticated_local, "verification-mode")
            verify_inputs()
            verify_provider()
            result = {"event": "money_sources", "status": "verified", "inputs": 11, "provider_files": 14}
        else:
            result = materialize(authenticated_local=args.authenticated_local)
        print(json.dumps(result, sort_keys=True))
        return 0
    except MaterializationError as error:
        code = str(error)
    except OSError:
        code = "materialization-io"
    print(json.dumps({"event": "money_sources", "status": "refused", "code": code}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
