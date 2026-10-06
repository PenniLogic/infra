"""T-PLT-01 database plan and pre-apply admission; never a SQL executor."""

import argparse
import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys

import database_baseline
from database_sql import Shape, SqlRefused, inspect_sql


GATE = "T-PLT-01-DATABASE-EXTENSION-GATE"
RUNTIME = "R4_LINUX_DOCKER_NFTABLES"
ROOT = Path(__file__).resolve().parents[1]
TRUST_FILE = ROOT / "database" / "admission-trust.json"
LIMIT = 2 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
ID = re.compile(r"[A-Za-z_][A-Za-z_0-9.-]{0,127}\Z")
COLUMN = re.compile(r"[a-z_][a-z_0-9]{0,62}(?:\.[a-z_][a-z_0-9]{0,62}){2}\Z")
SOURCE_PATH = re.compile(r"[A-Za-z_0-9.-]+(?:/[A-Za-z_0-9.-]+)*\Z")
POLICY_FILES = {
    "adr/ADR-025.md": (
        "9a7b97abeb9e8bc5a8e722561230b625f793966d34651d7f7ba68d17c7bca048", 32503,
    ),
    "adr/embedding-policy.json": (
        "ca9ed351085b5bf34a4b07f68607fb624022245700a4a230b8cd0ead5b8f8af9", 9884,
    ),
    "adr/embedding-policy.schema.json": (
        "5251d6f67d50fe5a551efc3cb620d528314f38870b4e304afd74f964326e5514", 18873,
    ),
}
KNOWN_NON_VECTOR_EXTENSIONS = {"pgcrypto", "hstore", "citext", "uuid-ossp"}
KNOWN_DATABASE_PACKAGES = {"postgresql-17"}
SOURCE_KINDS = {
    "IDENTIFIER", "INTEGER_MINOR_UNITS", "FIXED_SCALE_INTEGER", "CURRENCY_CODE",
    "DATE_TIME", "BOOLEAN", "NUMERIC_MEASUREMENT", "NON_USER_REFERENCE",
    "TRANSACTION", "MERCHANT", "MEMO", "ASSISTANT_CONVERSATION",
}
TRANSFORMS = {"EMBED", "ENCRYPT", "ENCODE", "HASH", "QUANTIZE", "ALIAS", "AGGREGATE"}
REQUEST_FIELDS = {
    "schema", "runtime", "policy", "inventory", "packages", "migrations", "selection",
}


class Refused(ValueError):
    """Only static codes cross the boundary; no SQL, data, file path or exception text."""


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def document(content: bytes) -> object:
    if not content or len(content) > LIMIT:
        raise Refused("JSON_SIZE")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refused("JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(_value):
        raise Refused("JSON_NONFINITE")

    try:
        return json.loads(content.decode("utf-8"), object_pairs_hook=unique, parse_constant=constant)
    except Refused:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refused("JSON_INVALID") from None


def obj(value: object, fields: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise Refused("OBJECT_FIELDS")
    return value


def array(value: object, maximum: int = 256) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        raise Refused("ARRAY_SHAPE")
    return value


def text(value: object, pattern: re.Pattern = ID) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise Refused("IDENTIFIER_SHAPE")
    return value


def integer(value: object, minimum: int = 0, maximum: int = LIMIT) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise Refused("INTEGER_SHAPE")
    return value


def binary(value: object) -> bytes:
    if not isinstance(value, str) or len(value) > LIMIT:
        raise Refused("SOURCE_ENCODING")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise Refused("SOURCE_ENCODING") from None
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Refused("SOURCE_ENCODING")
    return decoded


def path(value: object) -> str:
    name = text(value, SOURCE_PATH)
    if any(part in {".", ".."} for part in name.split("/")):
        raise Refused("SOURCE_PATH")
    return name


def file_pins(value: object) -> dict[str, tuple[str, int]]:
    result = {}
    for item in array(value, 64):
        record = obj(item, {"path", "sha256", "bytes"})
        name = path(record["path"])
        if name in result:
            raise Refused("SOURCE_DUPLICATE")
        result[name] = (text(record["sha256"], SHA256), integer(record["bytes"], 1))
    if not result:
        raise Refused("SOURCE_EMPTY")
    return result


def read_files(value: object, pins: dict[str, tuple[str, int]]) -> dict[str, bytes]:
    result = {}
    for item in array(value, 64):
        record = obj(item, {"path", "content_base64"})
        name = path(record["path"])
        if name in result or name not in pins:
            raise Refused("SOURCE_SET")
        content = binary(record["content_base64"])
        if (digest(content), len(content)) != pins[name]:
            raise Refused("SOURCE_BYTES")
        result[name] = content
    if set(result) != set(pins):
        raise Refused("SOURCE_SET")
    return result


def source_pin(value: object) -> dict:
    pin = obj(value, {"repository_id", "commit", "files"})
    integer(pin["repository_id"], 1, 2**63 - 1)
    text(pin["commit"], COMMIT)
    file_pins(pin["files"])
    return pin


def source(value: object, pin: dict) -> dict[str, bytes]:
    supplied = obj(value, {"repository_id", "commit", "files"})
    if type(supplied["repository_id"]) is not int or supplied["repository_id"] != pin["repository_id"] or supplied["commit"] != pin["commit"]:
        raise Refused("SOURCE_IDENTITY")
    return read_files(supplied["files"], file_pins(pin["files"]))


def trust_document(content: bytes) -> dict:
    trust = obj(document(content), {
        "schema", "runtime", "accepted_policy", "accepted_inventories",
        "non_vector_extensions", "database_packages",
    })
    if trust["schema"] != "pennilogic.database-admission.trust/1" or trust["runtime"] != RUNTIME:
        raise Refused("TRUST_VERSION")
    if trust["accepted_policy"] is not None:
        pin = source_pin(trust["accepted_policy"])
        if pin["repository_id"] != 1394134442:
            raise Refused("POLICY_REPOSITORY")
        pins = file_pins(pin["files"])
        if set(pins) != set(POLICY_FILES) | {"adr/accepted-records.json"}:
            raise Refused("POLICY_SOURCE_SET")
        if any(pins[name] != binding for name, binding in POLICY_FILES.items()):
            raise Refused("POLICY_UNSUPPORTED_VERSION")
    seen = set()
    for item in array(trust["accepted_inventories"], 64):
        pin = obj(item, {"sha256", "bytes", "source"})
        key = text(pin["sha256"], SHA256)
        integer(pin["bytes"], 1)
        if key in seen:
            raise Refused("INVENTORY_DUPLICATE")
        seen.add(key)
        if source_pin(pin["source"])["repository_id"] != database_baseline.API_REPOSITORY_ID:
            raise Refused("INVENTORY_REPOSITORY")
    for field, known in (("non_vector_extensions", KNOWN_NON_VECTOR_EXTENSIONS), ("database_packages", KNOWN_DATABASE_PACKAGES)):
        values = [text(item) for item in array(trust[field], 16)]
        if len(values) != len(set(values)) or not set(values) <= known:
            raise Refused("TRUST_EXTENSION_POLICY")
    return trust


def validate_policy(value: object, trust: dict) -> str:
    if value is None:
        raise Refused("POLICY_MISSING")
    if trust["accepted_policy"] is None:
        raise Refused("POLICY_UNACCEPTED")
    pin = trust["accepted_policy"]
    files = source(value, pin)
    policy = document(files["adr/embedding-policy.json"])
    if not isinstance(policy, dict):
        raise Refused("POLICY_INVALID")
    if (policy.get("artifact_id") != "adr-025-embedding-policy"
            or policy.get("policy_version") != "1.0.0"
            or policy.get("decision") != "PROHIBITED_DURABLE_USER_DERIVED_EMBEDDINGS"
            or policy.get("decision_date") != "2026-10-04"
            or policy.get("consumer_gate", {}).get("id") != GATE):
        raise Refused("POLICY_UNSUPPORTED_VERSION")
    consequence = policy["database"]
    if (consequence["permitted_user_derived_embedding_columns"] != []
            or consequence["other_vector_extensions"] != "PROHIBITED"
            or consequence["array_json_binary_or_renamed_columns_exempt"] is not False
            or consequence["static_prototype_label_overrides_denial"] is not False):
        raise Refused("POLICY_CONTRADICTION")
    registry = obj(document(files["adr/accepted-records.json"]), {"schema_version", "items"})
    if type(registry["schema_version"]) is not int or registry["schema_version"] != 1:
        raise Refused("POLICY_REGISTRY")
    records = array(registry["items"])
    target = []
    numbers = set()
    for item in records:
        record = obj(item, {"number", "date", "sha256", "bytes"})
        number = text(record["number"])
        if number in numbers:
            raise Refused("POLICY_REGISTRY")
        numbers.add(number)
        if number == "ADR-025":
            target.append(record)
    expected = {
        "number": "ADR-025", "date": policy["decision_date"],
        "sha256": POLICY_FILES["adr/ADR-025.md"][0], "bytes": POLICY_FILES["adr/ADR-025.md"][1],
    }
    if len(target) != 1 or canonical(target[0]) != canonical(expected):
        raise Refused("POLICY_REGISTRY")
    return pin["commit"]


@dataclass(frozen=True)
class Provenance:
    origins: frozenset[str]
    embedding: bool


def provenance(nodes_value: object, evidence: set[str]) -> dict[str, Provenance]:
    nodes = {}
    for value in array(nodes_value):
        if not isinstance(value, dict):
            raise Refused("PROVENANCE_SHAPE")
        key = text(value.get("id"))
        if key in nodes:
            raise Refused("PROVENANCE_DUPLICATE")
        nodes[key] = value
    resolved: dict[str, Provenance] = {}
    while len(resolved) < len(nodes):
        progressed = False
        for key, value in nodes.items():
            if key in resolved:
                continue
            if value.get("kind") == "SOURCE":
                obj(value, {"id", "kind", "source_kind", "evidence"})
                origin = text(value["source_kind"])
                refs = [path(item) for item in array(value["evidence"], 64)]
                if origin not in SOURCE_KINDS or not refs or len(refs) != len(set(refs)) or not set(refs) <= evidence:
                    raise Refused("PROVENANCE_SOURCE")
                resolved[key] = Provenance(frozenset({origin}), False)
            else:
                obj(value, {"id", "kind", "inputs"})
                if text(value["kind"]) not in TRANSFORMS:
                    raise Refused("PROVENANCE_TRANSFORM")
                inputs = [text(item) for item in array(value["inputs"])]
                if not inputs or len(inputs) != len(set(inputs)) or not set(inputs) <= set(nodes):
                    raise Refused("PROVENANCE_INPUT")
                if not set(inputs) <= set(resolved):
                    continue
                parents = [resolved[item] for item in inputs]
                resolved[key] = Provenance(
                    frozenset().union(*(parent.origins for parent in parents)),
                    value["kind"] == "EMBED" or any(parent.embedding for parent in parents),
                )
            progressed = True
        if not progressed:
            raise Refused("PROVENANCE_CYCLE")
    return resolved


def inventory(value: object, trust: dict) -> tuple[dict, dict[str, Provenance], str]:
    supplied = obj(value, {"content_base64", "source"})
    content = binary(supplied["content_base64"])
    matches = [pin for pin in trust["accepted_inventories"] if (pin["sha256"], pin["bytes"]) == (digest(content), len(content))]
    if len(matches) != 1:
        raise Refused("INVENTORY_UNACCEPTED")
    pin = matches[0]["source"]
    files = source(supplied["source"], pin)
    data = obj(document(content), {"schema", "nodes", "scripts"})
    if data["schema"] != "pennilogic.database-admission.inventory/1":
        raise Refused("INVENTORY_VERSION")
    graph = provenance(data["nodes"], set(files))
    scripts = {}
    for item in array(data["scripts"], 256):
        record = obj(item, {"migration", "direction", "sha256", "grammar", "columns"})
        key = (text(record["migration"]), text(record["direction"]))
        if key[1] not in {"up", "down", "compensating"} or key in scripts:
            raise Refused("INVENTORY_SCRIPT_SET")
        text(record["sha256"], SHA256)
        if text(record["grammar"]) not in {"postgresql17-ddl-v1", "api-ledger-v2-exact"}:
            raise Refused("INVENTORY_GRAMMAR")
        scripts[key] = record
    return scripts, graph, pin["commit"]


def script_shape(sql: str, record: dict, source_commit: str) -> Shape:
    if record["grammar"] == "api-ledger-v2-exact":
        key = (record["migration"], record["direction"])
        baseline = database_baseline.SCRIPTS.get(key)
        if source_commit != database_baseline.API_COMMIT or baseline is None or record["sha256"] != baseline[0]:
            raise Refused("SQL_BASELINE_BINDING")
        return baseline[1]
    return inspect_sql(sql)


def validate_columns(record: dict, shape: Shape, graph: dict[str, Provenance]) -> None:
    columns = {}
    for value in array(record["columns"], 4096):
        column = obj(value, {"name", "sql_type", "provenance"})
        name = text(column["name"], COLUMN)
        if name in columns or not isinstance(column["sql_type"], str):
            raise Refused("COLUMN_INVENTORY")
        node = graph.get(text(column["provenance"]))
        if node is None:
            raise Refused("COLUMN_PROVENANCE_MISSING")
        if node.embedding:
            raise Refused("EMBEDDING_COLUMN_DENIED")
        if node.origins & {"INTEGER_MINOR_UNITS", "FIXED_SCALE_INTEGER"} and column["sql_type"] not in {"smallint", "integer", "bigint"}:
            raise Refused("MONEY_REPRESENTATION")
        columns[name] = column["sql_type"]
    if tuple(sorted(columns.items())) != shape.columns:
        raise Refused("COLUMN_INVENTORY_MISMATCH")


def evaluate(command: str, request_bytes: bytes, trust_bytes: bytes) -> dict:
    """Validate the entire set again for either boundary; a plan digest is not authority."""
    fields = REQUEST_FIELDS | ({"plan_sha256"} if command == "admit-apply" else set())
    if command not in {"plan", "admit-apply"}:
        raise Refused("COMMAND")
    request = obj(document(request_bytes), fields)
    trust = trust_document(trust_bytes)
    if request["schema"] != "pennilogic.database-admission.request/1" or request["runtime"] != RUNTIME:
        raise Refused("REQUEST_VERSION")
    packages = [text(item) for item in array(request["packages"], 16)]
    if len(packages) != len(set(packages)) or not set(packages) <= set(trust["database_packages"]):
        raise Refused("DATABASE_PACKAGE_DENIED")
    # No request flag, hash, local ACCEPTED header or registry entry can register
    # a provider. Only a separately reviewed installation pin can do that.
    policy_commit = validate_policy(request["policy"], trust)
    scripts, graph, inventory_commit = inventory(request["inventory"], trust)
    actual = {}
    order = {}
    for index, value in enumerate(array(request["migrations"], 128)):
        migration = obj(value, {"id", "up", "reverse"})
        name = text(migration["id"])
        if name in order:
            raise Refused("MIGRATION_DUPLICATE")
        order[name] = index
        reverse = obj(migration["reverse"], {"direction", "sql"})
        if text(reverse["direction"]) not in {"down", "compensating"}:
            raise Refused("MIGRATION_DIRECTION")
        for direction, sql in (("up", migration["up"]), (reverse["direction"], reverse["sql"])):
            if not isinstance(sql, str) or not sql or len(sql.encode("utf-8")) > 262144 or "\x00" in sql:
                raise Refused("SQL_SIZE_OR_ENCODING")
            sql = sql.replace("\r\n", "\n")
            checksum = digest(sql.encode("utf-8"))
            key = (name, direction)
            record = scripts.get(key)
            if record is None:
                raise Refused("INVENTORY_SCRIPT_SET")
            if record["sha256"] != checksum:
                raise Refused("SQL_CHECKSUM")
            shape = script_shape(sql, record, inventory_commit)
            if not set(shape.extensions) <= set(trust["non_vector_extensions"]):
                raise Refused("DATABASE_EXTENSION_DENIED")
            validate_columns(record, shape, graph)
            actual[key] = {"migration_index": index, "direction": direction, "sha256": checksum}
    if not actual or set(actual) != set(scripts):
        raise Refused("INVENTORY_SCRIPT_SET")
    selected = []
    seen = set()
    for item in array(request["selection"], 128):
        choice = obj(item, {"id", "direction"})
        key = (text(choice["id"]), text(choice["direction"]))
        if key not in actual or key[0] in seen:
            raise Refused("SELECTION")
        seen.add(key[0])
        selected.append(actual[key])
    if selected:
        forward = selected[0]["direction"] == "up"
        indices = [item["migration_index"] for item in selected]
        if any((item["direction"] == "up") != forward for item in selected) or indices != sorted(indices, reverse=not forward):
            raise Refused("SELECTION")
    bound_request = {key: value for key, value in request.items() if key != "plan_sha256"}
    plan_hash = digest(canonical({
        "gate": GATE, "version": 1, "trust_sha256": digest(trust_bytes), "request": bound_request,
    }))
    if command == "admit-apply" and text(request["plan_sha256"], SHA256) != plan_hash:
        raise Refused("PLAN_CHANGED")
    return {
        "schema": "pennilogic.database-admission.result/1", "gate": GATE,
        "command": command, "decision": "ADMIT", "reason": None,
        "scope": "DATABASE_EXTENSIONS_AND_DECLARED_COLUMN_SEMANTICS",
        "plan_sha256": plan_hash, "scripts": selected,
        "policy_commit": policy_commit, "inventory_commit": inventory_commit,
        "provider_activation": False, "sql_executed": False,
    }


def refusal(command: str, code: str) -> dict:
    return {
        "schema": "pennilogic.database-admission.result/1", "gate": GATE,
        "command": command, "decision": "DENY", "reason": code,
        "scope": "DATABASE_EXTENSIONS_AND_DECLARED_COLUMN_SEMANTICS",
        "plan_sha256": None, "scripts": [], "policy_commit": None, "inventory_commit": None,
        "provider_activation": False, "sql_executed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "admit-apply"))
    args = parser.parse_args()
    try:
        request = sys.stdin.buffer.read(LIMIT + 1)
        result = evaluate(args.command, request, TRUST_FILE.read_bytes())
    except (Refused, SqlRefused) as error:
        result = refusal(args.command, str(error))
    except OSError:
        result = refusal(args.command, "ADMISSION_IO")
    except (RecursionError, UnicodeEncodeError):
        result = refusal(args.command, "INPUT_LIMIT_OR_ENCODING")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["decision"] == "ADMIT" else 1


if __name__ == "__main__":
    sys.exit(main())
