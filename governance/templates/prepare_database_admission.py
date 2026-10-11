"""Prepare or verify one committed database-admission installation; never execute SQL."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import types


MONEY_HELPER_SHA256 = None
AUTHORITY_SHA256 = None
ROOT = Path(__file__).absolute().parents[1]
RESOURCE = Path("src/main/resources/database-admission-installation.json")
LAUNCHER = Path("scripts/prepare_database_admission.py")
OUTPUT = Path("build/database-admission")
GATE = "T-PLT-01-DATABASE-EXTENSION-GATE"
RUNTIME = "R4_LINUX_DOCKER_NFTABLES"
MODULES = ("database_sql", "database_baseline", "database_admission")
INFRA_FILES = {"scripts/" + name + ".py" for name in MODULES}
POLICY_FILES = {"adr/ADR-025.md", "adr/embedding-policy.json",
                "adr/embedding-policy.schema.json", "adr/accepted-records.json"}
INVENTORY_FILES = {"database/admission-inventory.json", "database/admission-inventory-source.json"}
PAYLOAD_FILES = INFRA_FILES | {"database/admission-trust.json", "inputs.json"}
SOURCES = {"infra": ("PenniLogic/infra", 1394135059, INFRA_FILES),
           "policy": ("PenniLogic/docs", 1394134442, POLICY_FILES),
           "inventory": ("PenniLogic/api", 1394134582, INVENTORY_FILES),
           "evidence": ("PenniLogic/api", 1394134582, None)}
REQUEST_LIMIT = 2 * 1024 * 1024
PROCESS_SECONDS = 7
RESULT_FIELDS = {"schema", "gate", "command", "decision", "reason", "scope", "plan_sha256",
                 "scripts", "policy_commit", "inventory_commit", "provider_activation", "sql_executed"}

# Execute verified byte snapshots, not paths reopened in a mutable build directory.
EXECUTOR = r"""
import base64, json, sys, types
packet = json.loads(sys.stdin.buffer.read())
for name in ("database_sql", "database_baseline", "database_admission"):
    module = types.ModuleType(name)
    module.__file__ = packet["root"] + "/" + name + ".py"
    sys.modules[name] = module
    exec(compile(base64.b64decode(packet["modules"][name], validate=True),
                 module.__file__, "exec"), module.__dict__)
gate = sys.modules["database_admission"]
try:
    result = gate.evaluate(sys.argv[1], base64.b64decode(packet["request"], validate=True),
                           base64.b64decode(packet["trust"], validate=True))
except (gate.Refused, gate.SqlRefused) as error:
    result = gate.refusal(sys.argv[1], str(error))
except (RecursionError, UnicodeEncodeError):
    result = gate.refusal(sys.argv[1], "INPUT_LIMIT_OR_ENCODING")
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
sys.exit(0 if result["decision"] == "ADMIT" else 1)
"""


class InstallationError(ValueError):
    """Static installation refusals; never source content or subprocess diagnostics."""


def require(condition, code):
    if not condition:
        raise InstallationError(code)


def object_fields(value, fields):
    require(isinstance(value, dict) and set(value) == fields, "installation-fields")
    return value


def document_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def fixed_file(root, relative, maximum):
    path = root.absolute() / relative
    for part in (path, *path.parents):
        require(not part.is_symlink() and not part.is_junction(), "installation-link")
    metadata = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "installation-file")
    with path.open("rb") as stream:
        content = stream.read(maximum + 1)
    require(0 < len(content) <= maximum, "installation-size")
    return content


def load_helper(root):
    name = Path("scripts/materialize_money_sources.py")
    content = fixed_file(root, name, 262144)
    require(hashlib.sha256(content).hexdigest() == MONEY_HELPER_SHA256, "managed-helper-bytes")
    module = types.ModuleType("database_admission_materializer")
    module.__file__ = str(root.absolute() / name)
    exec(compile(content, module.__file__, "exec"), module.__dict__)
    return module


def file_bindings(values, helper, source=False):
    require(isinstance(values, list) and 1 <= len(values) <= 11, "installation-file-count")
    result = {}
    for entry in values:
        if source:
            helper.file_binding(entry, source=True)
        else:
            object_fields(entry, {"path", "mode", "bytes", "sha256"})
            require(entry["mode"] == "100644", "installation-mode")
            helper.file_binding({key: value for key, value in entry.items() if key != "mode"})
        key = entry["path"].lower()
        require(key not in result, "installation-path-collision")
        result[key] = entry
    require(not any(parent in result for path in result for parent in (
        "/".join(path.split("/")[:index]) for index in range(1, len(path.split("/")))
    )), "installation-path-collision")
    return {entry["path"]: entry for entry in values}


def validate_authority(value, helper):
    data = object_fields(value, {"schema", "gate", "runtime", "consumer", "binding"})
    require(data["schema"] == "pennilogic.database-admission.installation/1"
            and data["gate"] == GATE and data["runtime"] == RUNTIME, "installation-version")
    consumer = object_fields(data["consumer"], {"repository", "repository_id", "organization_id"})
    require(consumer == {"repository": "PenniLogic/api", "repository_id": 1394134582,
                         "organization_id": 335295566}
            and type(consumer["repository_id"]) is int and type(consumer["organization_id"]) is int,
            "installation-consumer")
    if data["binding"] is None:
        return data
    binding = object_fields(data["binding"], {"sources", "payloads"})
    sources = object_fields(binding["sources"], set(SOURCES))
    count = 0
    for role, (repository, repository_id, paths) in SOURCES.items():
        source = object_fields(sources[role], {"repository", "repository_id", "commit", "tree", "files"})
        require(source["repository"] == repository and type(source["repository_id"]) is int
                and source["repository_id"] == repository_id, "installation-source-identity")
        helper.sha(source["commit"])
        helper.sha(source["tree"])
        files = file_bindings(source["files"], helper, source=True)
        require(paths is None or set(files) == paths, "installation-source-files")
        count += len(files)
    require(count + 3 * len(sources) <= helper.MAX_REQUESTS, "installation-request-budget")
    payloads = file_bindings(binding["payloads"], helper)
    require(set(payloads) == PAYLOAD_FILES, "installation-payloads")
    for entry in sources["infra"]["files"]:
        require(all(payloads[entry["path"]][key] == entry[key] for key in ("mode", "bytes", "sha256")),
                "installation-source-payload")
    return data


def validate_installation(value, helper):
    data = object_fields(value, {"schema", "gate", "runtime", "consumer", "binding", "launcher"})
    validate_authority({key: item for key, item in data.items() if key != "launcher"}, helper)
    launcher = file_bindings([data["launcher"]], helper)
    require(set(launcher) == {LAUNCHER.as_posix()}, "installation-launcher")
    return data


def read_installation(root, helper):
    content = fixed_file(root, RESOURCE, 65536)
    data = validate_installation(helper.json_document(content), helper)
    authority = {key: item for key, item in data.items() if key != "launcher"}
    require(content == document_bytes(data)
            and hashlib.sha256(document_bytes(authority)).hexdigest() == AUTHORITY_SHA256, "installation-resource-bytes")
    launcher = fixed_file(root, LAUNCHER, data["launcher"]["bytes"])
    require(len(launcher) == data["launcher"]["bytes"]
            and hashlib.sha256(launcher).hexdigest() == data["launcher"]["sha256"], "launcher-bytes")
    require(stat.S_IMODE((root / LAUNCHER).stat(follow_symlinks=False).st_mode)
            == (0o666 if os.name == "nt" else 0o644), "installation-mode")
    require(data["binding"] is not None, "accepted-sources-unbound")
    return data


def source_pin(source):
    return {"repository_id": source["repository_id"], "commit": source["commit"], "files": [
        {key: entry[key] for key in ("path", "bytes", "sha256")}
        for entry in sorted(source["files"], key=lambda entry: entry["path"])
    ]}


def envelope(source, contents):
    return {"repository_id": source["repository_id"], "commit": source["commit"], "files": [
        {"path": name, "content_base64": base64.b64encode(contents[name]).decode("ascii")}
        for name in sorted(contents)
    ]}


def assemble(data, contents, helper):
    sources = data["binding"]["sources"]
    for role, source in sources.items():
        require(set(contents[role]) == {entry["path"] for entry in source["files"]}, "installation-source-files")
        for entry in source["files"]:
            helper.check_bytes(contents[role][entry["path"]], entry)
    inventory = contents["inventory"]["database/admission-inventory.json"]
    manifest = object_fields(helper.json_document(contents["inventory"]["database/admission-inventory-source.json"]),
                             {"schema", "repository_id", "commit", "tree", "inventory", "files"})
    require(manifest["schema"] == "pennilogic.api-database-admission-source/1"
            and manifest["inventory"] == "database/admission-inventory.json"
            and type(manifest["repository_id"]) is int
            and all(manifest[key] == sources["evidence"][key] for key in ("repository_id", "commit", "tree")),
            "inventory-evidence-identity")
    expected = [{key: entry[key] for key in ("path", "bytes", "sha256", "git_blob")}
                for entry in sources["evidence"]["files"]]
    require(isinstance(manifest["files"], list), "inventory-evidence-files")
    for entry in manifest["files"]:
        object_fields(entry, {"path", "bytes", "sha256", "git_blob"})
        helper.file_binding({**entry, "mode": "100644"}, source=True)
    require(sorted(manifest["files"], key=lambda entry: entry["path"])
            == sorted(expected, key=lambda entry: entry["path"]), "inventory-evidence-files")
    trust = {
        "schema": "pennilogic.database-admission.trust/1", "runtime": RUNTIME,
        "accepted_policy": source_pin(sources["policy"]),
        "accepted_inventories": [{"bytes": len(inventory), "sha256": hashlib.sha256(inventory).hexdigest(),
                                 "source": source_pin(sources["evidence"])}],
        "non_vector_extensions": [], "database_packages": [],
    }
    inputs = {"policy": envelope(sources["policy"], contents["policy"]),
              "inventory": {"content_base64": base64.b64encode(inventory).decode("ascii"),
                            "source": envelope(sources["evidence"], contents["evidence"])}}
    return {**contents["infra"], "database/admission-trust.json": document_bytes(trust),
            "inputs.json": document_bytes(inputs)}


def check_payloads(data, contents, helper):
    require(set(contents) == PAYLOAD_FILES, "installation-payloads")
    for entry in data["binding"]["payloads"]:
        helper.check_bytes(contents[entry["path"]], entry)


def verify(root, data, helper):
    bindings = {entry["path"]: entry for entry in data["binding"]["payloads"]}
    helper.verify_directory(root, OUTPUT, bindings)
    for name in ("", "scripts", "database", *sorted(bindings)):
        path = helper.owned_path(root, OUTPUT / name)
        metadata = path.stat(follow_symlinks=False)
        directory = name in {"", "scripts", "database"}
        expected_mode = (0o777 if directory else 0o666) if os.name == "nt" else (0o755 if directory else 0o644)
        require(stat.S_IMODE(metadata.st_mode) == expected_mode, "installation-mode")
    contents = {name: fixed_file(root, OUTPUT / name, entry["bytes"]) for name, entry in bindings.items()}
    check_payloads(data, contents, helper)
    object_fields(helper.json_document(contents["inputs.json"]), {"policy", "inventory"})
    return contents


def publish(root, data, contents, helper, budget):
    created = []

    def directory(relative):
        path = helper.owned_path(root, relative)
        path.mkdir(mode=0o755)
        created.append((relative, path.stat(follow_symlinks=False)))
        path.chmod(0o755)

    try:
        if not helper.owned_path(root, OUTPUT.parent).exists():
            directory(OUTPUT.parent)
        directory(OUTPUT)
        directory(OUTPUT / "scripts")
        directory(OUTPUT / "database")
        for name, content in sorted(contents.items()):
            budget.remaining()
            relative = OUTPUT / name
            with helper.owned_path(root, relative).open("xb") as stream:
                created.append((relative, os.fstat(stream.fileno())))
                stream.write(content)
            helper.owned_path(root, relative).chmod(0o644)
        verify(root, data, helper)
        budget.remaining()
    except (OSError, InstallationError, helper.MaterializationError):
        helper.rollback_attempt(root, created)
        raise


def prepare(root, data, helper, fetch=False, client=None, native_fetch=False):
    require(data["binding"] is not None, "accepted-sources-unbound")
    require(not native_fetch or fetch, "installation-native-fetch-mode")
    sources = data["binding"]["sources"]
    if native_fetch:
        client = client or helper.ReadOnlyClient({"sources": list(sources.values())}, native_fetch=True)
    if client is not None:
        require(client.native_fetch == native_fetch, "installation-native-fetch-mode")
    if helper.owned_path(root, OUTPUT).exists():
        verify(root, data, helper)
        return {"event": "database_admission_installation", "status": "verified_existing", "requests": 0}
    require(fetch, "explicit-fetch-required")
    client = client or helper.ReadOnlyClient({"sources": list(sources.values())})
    require(not client.authenticated_local, "installation-authentication-mode")
    contents = {}
    for role, source in sources.items():
        snapshot = helper.GitSnapshot(client, source, data["consumer"]["organization_id"])
        require(snapshot.root == source["tree"], "installation-source-tree")
        contents[role] = {entry["path"]: snapshot.blob(entry) for entry in source["files"]}
    payloads = assemble(data, contents, helper)
    check_payloads(data, payloads, helper)
    client.budget.remaining()
    publish(root, data, payloads, helper, client.budget)
    return {"event": "database_admission_installation", "status": "prepared", "requests": client.budget.requests}


def run(command, request, root, payloads, helper):
    require(sys.version_info[:2] == (3, 14), "managed-python-version")
    require(0 < len(request) <= REQUEST_LIMIT, "installation-request-size")
    supplied = helper.json_document(request)
    require(isinstance(supplied, dict), "installation-request")
    inputs = helper.json_document(payloads["inputs.json"])
    require(all(key in supplied and document_bytes(supplied[key]) == document_bytes(inputs[key])
                for key in ("policy", "inventory")), "installation-envelope")
    packet = {
        "root": str(root.absolute() / OUTPUT / "scripts"),
        "modules": {name: base64.b64encode(payloads["scripts/" + name + ".py"]).decode("ascii") for name in MODULES},
        "request": base64.b64encode(request).decode("ascii"),
        "trust": base64.b64encode(payloads["database/admission-trust.json"]).decode("ascii"),
    }
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", EXECUTOR, command],
            input=document_bytes(packet), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=root, env=environment, timeout=PROCESS_SECONDS, check=False,
        )
    except subprocess.TimeoutExpired:
        raise InstallationError("admission-process-timeout") from None
    require(result.returncode in (0, 1) and not result.stderr and 0 < len(result.stdout) <= 65536
            and len(result.stdout.splitlines()) == 1, "admission-process-result")
    response = object_fields(helper.json_document(result.stdout), RESULT_FIELDS)
    require(response["schema"] == "pennilogic.database-admission.result/1" and response["gate"] == GATE
            and response["command"] == command and response["provider_activation"] is False
            and response["sql_executed"] is False
            and response["decision"] == ("ADMIT" if result.returncode == 0 else "DENY"), "admission-process-result")
    return result.stdout, result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    preparation = commands.add_parser("prepare")
    preparation.add_argument("--fetch", action="store_true", help="Explicit bounded public fetch of committed sources")
    preparation.add_argument("--native-fetch", action="store_true", help="Use only the explicit API Actions source-step credential")
    commands.add_parser("verify")
    execution = commands.add_parser("run")
    execution.add_argument("command", choices=("plan", "admit-apply"))
    args = parser.parse_args()
    try:
        helper = load_helper(ROOT)
        try:
            data = read_installation(ROOT, helper)
            if args.action == "prepare":
                result = prepare(ROOT, data, helper, fetch=args.fetch, native_fetch=args.native_fetch)
            else:
                payloads = verify(ROOT, data, helper)
                if args.action == "run":
                    output, code = run(args.command, sys.stdin.buffer.read(REQUEST_LIMIT + 1), ROOT, payloads, helper)
                    sys.stdout.buffer.write(output)
                    return code
                result = {"event": "database_admission_installation", "status": "verified", "payloads": 5}
        except helper.MaterializationError as error:
            raise InstallationError(str(error)) from None
        print(json.dumps(result, sort_keys=True))
        return 0
    except InstallationError as error:
        code = str(error)
    except OSError:
        code = "installation-io"
    print(json.dumps({"event": "database_admission_installation", "status": "refused", "code": code}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
