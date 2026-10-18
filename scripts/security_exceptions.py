"""Exact, expiring exceptions shared by the secret and dependency gates."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXCEPTIONS = ROOT / "security" / "exceptions.json"
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,63}", re.ASCII)
PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,95}", re.ASCII)
DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
COMMIT = re.compile(r"[0-9a-f]{40}", re.ASCII)
CREDENTIAL_METADATA = re.compile(r"(?:gh[pousr]_|github_pat_|sk-)[A-Za-z0-9_-]{16,}|-----BEGIN", re.ASCII)


class Refusal(ValueError):
    """A static error code, never input content."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Refusal(code)


def exact(value: Any, keys: set[str], code: str) -> None:
    require(type(value) is dict and set(value) == keys, code)


def matches(value: Any, pattern: re.Pattern[str]) -> bool:
    return (
        type(value) is str and pattern.fullmatch(value) is not None
        and CREDENTIAL_METADATA.search(value) is None
    )


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def identity(*parts: str) -> str:
    return hashlib.sha256(canonical(parts)).hexdigest()


def document(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            require(key not in value, "duplicate-json-key")
            value[key] = item
        return value

    def invalid_constant(_: str) -> None:
        raise Refusal("invalid-json-constant")

    def integer(value: str) -> int:
        require(len(value.lstrip("-")) <= sys.int_info.default_max_str_digits, "invalid-json-integer")
        try:
            return int(value)
        except ValueError:
            raise Refusal("invalid-json-integer") from None

    def decimal(value: str) -> float:
        number = float(value)
        require(math.isfinite(number), "invalid-json-decimal")
        return number

    require(len(raw) <= MAX_DOCUMENT_BYTES, "document-too-large")
    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid_constant,
            parse_int=integer, parse_float=decimal,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise Refusal("invalid-json") from None


def read_document(path: Path) -> Any:
    path = path.absolute()
    require(
        not any(part.is_symlink() or part.is_junction() for part in (path, *path.parents)),
        "linked-input",
    )
    require(stat.S_ISREG(path.stat().st_mode), "nonregular-input")
    with path.open("rb") as stream:
        return document(stream.read(MAX_DOCUMENT_BYTES + 1))


def utc(value: Any) -> datetime:
    require(
        type(value) is str
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value, re.ASCII) is not None,
        "invalid-utc-timestamp",
    )
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise Refusal("invalid-utc-timestamp") from None


def repository_ids() -> dict[str, int]:
    profiles = read_document(ROOT / "governance" / "repository-profiles.json")
    return {f"PenniLogic/{name}": profile["id"] for name, profile in profiles["repositories"].items()}


def repository_id(repository: str) -> int:
    repositories = repository_ids()
    require(repository in repositories, "unknown-repository")
    return repositories[repository]


class Exceptions:
    def __init__(self, value: Any, now: datetime):
        exact(value, {"schema_version", "exceptions"}, "invalid-exceptions")
        require(type(value["schema_version"]) is int and value["schema_version"] == 1, "invalid-exceptions")
        require(type(value["exceptions"]) is list and len(value["exceptions"]) <= 1000, "invalid-exceptions")
        require(now.tzinfo is not None, "naive-clock")
        self.now = now
        self.entries: list[dict[str, Any]] = value["exceptions"]
        seen_ids: set[str] = set()
        seen_targets: set[tuple[str, ...]] = set()
        for entry in self.entries:
            exact(
                entry,
                {"id", "kind", "repository", "pattern", "artifact", "reason", "owner", "expires_at"},
                "invalid-exception",
            )
            require(matches(entry["id"], IDENTIFIER), "invalid-exception-id")
            require(entry["kind"] in ("secret", "advisory"), "invalid-exception-kind")
            require(type(entry["repository"]) is str, "invalid-exception-repository")
            repository_id(entry["repository"])
            require(matches(entry["pattern"], PATTERN), "invalid-exception-pattern")
            require(matches(entry["artifact"], DIGEST), "invalid-exception-artifact")
            require(
                type(entry["reason"]) is str and 0 < len(entry["reason"]) <= 500
                and entry["reason"].strip() != ""
                and all(" " <= char <= "~" for char in entry["reason"]),
                "invalid-exception-reason",
            )
            require(
                type(entry["owner"]) is str
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", entry["owner"], re.ASCII) is not None,
                "invalid-exception-owner",
            )
            utc(entry["expires_at"])
            target = (entry["kind"], entry["repository"], entry["pattern"], entry["artifact"])
            require(entry["id"] not in seen_ids and target not in seen_targets, "duplicate-exception")
            seen_ids.add(entry["id"])
            seen_targets.add(target)

    @classmethod
    def load(cls, path: Path = DEFAULT_EXCEPTIONS, now: datetime | None = None) -> Exceptions:
        return cls(read_document(path), datetime.now(timezone.utc) if now is None else now)

    def suppression(self, kind: str, repository: str, pattern: str, artifact: str) -> str | None:
        for entry in self.entries:
            if (
                (entry["kind"], entry["repository"], entry["pattern"], entry["artifact"])
                == (kind, repository, pattern, artifact)
                and self.now < utc(entry["expires_at"])
            ):
                return entry["id"]
        return None

    def audit(self) -> dict[str, Any]:
        entries = [
            {
                "id": entry["id"],
                "kind": entry["kind"],
                "repository_id": repository_id(entry["repository"]),
                "status": "active" if self.now < utc(entry["expires_at"]) else "expired",
                "expires_at": entry["expires_at"],
            }
            for entry in self.entries
        ]
        return {
            "schema": "pennilogic.security-exceptions/1",
            "entries": entries,
            "expired_count": sum(entry["status"] == "expired" for entry in entries),
        }


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Refusal("invalid-arguments")


def emit(value: Any) -> None:
    print(canonical(value).decode("ascii"))


def main(argv: list[str] | None = None) -> int:
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("exceptions", nargs="?", type=Path, default=DEFAULT_EXCEPTIONS)
        args = parser.parse_args(argv)
        report = Exceptions.load(args.exceptions).audit()
        emit(report)
        return int(report["expired_count"] > 0)
    except Refusal as error:
        emit({"status": "refused", "code": str(error)})
        return 2
    except OSError:
        emit({"status": "refused", "code": "input-read-failed"})
        return 2


if __name__ == "__main__":
    sys.exit(main())
