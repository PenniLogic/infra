"""Reconcile native client inventories and reject vulnerable dependency additions."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urlsplit

from security_exceptions import (
    COMMIT, Exceptions, Parser, Refusal, canonical, emit, exact, identity, matches,
    read_document, repository_id, require,
)


MAVEN = re.compile(r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[0-9][A-Za-z0-9_.-]*", re.ASCII)
NPM_NAME = re.compile(r"(?:@[a-z0-9_~.-]+/)?[a-z0-9_~.-]+", re.ASCII)
NPM_VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9][A-Za-z0-9.+-]*)?", re.ASCII)
PACKAGE = re.compile(r"[A-Za-z0-9@][A-Za-z0-9_@./:+~-]{0,239}", re.ASCII)
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+~-]{0,127}", re.ASCII)
GHSA = re.compile(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}", re.ASCII)
ECOSYSTEMS = {
    "actions", "github-actions", "npm", "pip", "maven", "gradle", "go", "cargo",
    "nuget", "rubygems", "composer", "pub", "swift", "hex",
}
SEVERITIES = {"low", "moderate", "medium", "high", "critical"}


def components(value: Any) -> dict[str, list[str]]:
    exact(value, {"debug", "release"}, "invalid-android-variants")
    for entries in value.values():
        require(
            type(entries) is list and 0 < len(entries) <= 256
            and all(matches(entry, MAVEN) and len(entry) <= 240 for entry in entries),
            "invalid-android-components",
        )
        require(entries == sorted(set(entries)), "unordered-or-duplicate-components")
    return value


def inventory_report(
    repository: str, head: str, observed: dict[str, list[str]], reviewed: dict[str, list[str]],
    mode: str, source: Any, policy: Any,
) -> dict[str, Any]:
    require(matches(head, COMMIT), "invalid-head")
    require(mode in ("warn", "enforce"), "invalid-allowlist-mode")
    missing = {scope: sorted(set(items) - set(reviewed[scope])) for scope, items in observed.items()}
    unused = {scope: sorted(set(reviewed[scope]) - set(items)) for scope, items in observed.items()}
    count = sum(len(items) for items in missing.values())
    scopes: dict[str, list[str]] = {}
    for scope, entries in observed.items():
        for component in entries:
            scopes.setdefault(component, []).append(scope)
    return {
        "schema": "pennilogic.dependency-inventory/1",
        "repository": repository,
        "repository_id": repository_id(repository),
        "head": head,
        "mode": mode,
        "status": "fail" if count and mode == "enforce" else "warn" if count else "pass",
        "missing_count": count,
        "missing": missing,
        "unused": unused,
        "components": [{"coordinate": item, "scopes": sorted(scopes[item])} for item in sorted(scopes)],
        "source_sha256": hashlib.sha256(canonical(source)).hexdigest(),
        "policy_sha256": hashlib.sha256(canonical(policy)).hexdigest(),
    }


def android_inventory(source: Any, policy: Any, head: str, mode: str = "enforce") -> dict[str, Any]:
    exact(source, {"schema_version", "variants"}, "invalid-android-inventory")
    require(type(source["schema_version"]) is int and source["schema_version"] == 1, "invalid-android-inventory")
    require(
        type(policy) is dict and type(policy.get("schema_version")) is int
        and policy["schema_version"] == 1 and "components" in policy,
        "invalid-android-policy",
    )
    observed = components(source["variants"])
    reviewed = components(policy["components"])
    report = inventory_report("PenniLogic/android", head, observed, reviewed, mode, source, policy)
    report.update({
        "ecosystem": "maven",
        "coverage": "debug-and-release-runtime-classpaths",
        "android_inventory": source,
    })
    return report


def npm_coordinate(name: Any, version: Any) -> str:
    require(matches(name, NPM_NAME) and len(name) <= 214, "invalid-npm-name")
    require(matches(version, NPM_VERSION) and len(version) <= 128, "unresolved-npm-version")
    return f"{name}@{version}"


def npm_inventory(source: Any, policy: Any, repository: str, head: str) -> dict[str, Any]:
    require(repository in ("PenniLogic/web", "PenniLogic/admin"), "not-an-npm-client")
    require(
        type(source) is dict and type(source.get("lockfileVersion")) is int
        and source["lockfileVersion"] in (2, 3) and type(source.get("packages")) is dict,
        "unsupported-npm-lockfile",
    )
    packages = source["packages"]
    require("" in packages and type(packages[""]) is dict, "missing-npm-root")
    observed: set[str] = set()
    for location, package in packages.items():
        require(type(package) is dict, "invalid-npm-package")
        if location == "":
            continue
        require(
            location.startswith("node_modules/") and "\\" not in location
            and not any(part in ("", ".", "..") for part in location.split("/")),
            "unsupported-npm-package-location",
        )
        require("link" not in package or package["link"] is False, "linked-npm-package")
        if "resolved" in package:
            resolved = package["resolved"]
            require(
                type(resolved) is str and not any(char.isspace() or ord(char) < 32 for char in resolved),
                "invalid-npm-source",
            )
            try:
                url = urlsplit(resolved)
                port = url.port
            except ValueError:
                raise Refusal("unsupported-npm-source") from None
            require(
                url.scheme in ("http", "https") and bool(url.hostname)
                and url.username is None and url.password is None and port != 0,
                "unsupported-npm-source",
            )
        name = package.get("name", location.rsplit("node_modules/", 1)[-1])
        observed.add(npm_coordinate(name, package.get("version")))
    require(bool(observed), "empty-client-inventory")
    exact(policy, {"schema_version", "components"}, "invalid-npm-inventory")
    require(type(policy["schema_version"]) is int and policy["schema_version"] == 1, "invalid-npm-inventory")
    require(type(policy["components"]) is list, "invalid-npm-inventory")
    reviewed: list[str] = []
    for component in policy["components"]:
        exact(component, {"name", "version"}, "invalid-npm-inventory-entry")
        reviewed.append(npm_coordinate(component["name"], component["version"]))
    require(len(reviewed) == len(set(reviewed)), "duplicate-inventory-entry")
    report = inventory_report(
        repository, head, {"all": sorted(observed)}, {"all": sorted(reviewed)}, "enforce", source, policy,
    )
    report.update({"ecosystem": "npm", "coverage": "all-lockfile-packages"})
    return report


def dependency_review(
    comparison: Any, repository: str, base: str, head: str, exceptions: Exceptions,
) -> dict[str, Any]:
    require(matches(base, COMMIT) and matches(head, COMMIT) and base != head, "invalid-comparison-range")
    repo_id = repository_id(repository)
    exact(
        comparison,
        {"schema_version", "repository", "repository_id", "base", "head", "complete", "changes"},
        "invalid-dependency-comparison",
    )
    require(
        type(comparison["schema_version"]) is int and comparison["schema_version"] == 1
        and comparison["repository"] == repository
        and type(comparison["repository_id"]) is int and comparison["repository_id"] == repo_id
        and comparison["base"] == base and comparison["head"] == head
        and comparison["complete"] is True,
        "unbound-or-incomplete-comparison",
    )
    require(type(comparison["changes"]) is list, "invalid-dependency-changes")
    findings: dict[str, dict[str, Any]] = {}
    added = 0
    for change in comparison["changes"]:
        require(
            type(change) is dict
            and {"change_type", "ecosystem", "name", "version", "vulnerabilities"} <= set(change),
            "invalid-dependency-change",
        )
        require(change["change_type"] in ("added", "removed"), "invalid-change-type")
        require(type(change["ecosystem"]) is str and change["ecosystem"] in ECOSYSTEMS, "unsupported-ecosystem")
        require(matches(change["name"], PACKAGE) and matches(change["version"], VERSION), "invalid-package-identity")
        require(type(change["vulnerabilities"]) is list, "advisories-unavailable")
        added += change["change_type"] == "added"
        for advisory in change["vulnerabilities"]:
            require(
                type(advisory) is dict and matches(advisory.get("advisory_ghsa_id"), GHSA)
                and type(advisory.get("severity")) is str and advisory["severity"] in SEVERITIES,
                "invalid-advisory",
            )
            if change["change_type"] == "removed":
                continue
            pattern = advisory["advisory_ghsa_id"]
            key = identity(repository, change["ecosystem"], change["name"], change["version"], pattern)
            findings[key] = {
                "id": key,
                "advisory": pattern,
                "ecosystem": change["ecosystem"],
                "name": change["name"],
                "version": change["version"],
                "severity": "moderate" if advisory["severity"] == "medium" else advisory["severity"],
                "exception": exceptions.suppression("advisory", repository, pattern, key),
            }
    ordered = [findings[key] for key in sorted(findings)]
    blocking = sum(finding["exception"] is None for finding in ordered)
    return {
        "schema": "pennilogic.dependency-review/1",
        "repository": repository,
        "repository_id": repo_id,
        "base": base,
        "head": head,
        "coverage": "supplied-complete-comparison",
        "comparison_sha256": hashlib.sha256(canonical(comparison)).hexdigest(),
        "status": "fail" if blocking else "pass",
        "added_count": added,
        "blocking_count": blocking,
        "findings": ordered,
        "exception_audit": exceptions.audit(),
    }


def main(argv: list[str] | None = None) -> int:
    try:
        parser = Parser(description=__doc__)
        commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
        android = commands.add_parser("android")
        android.add_argument("--resolved", type=Path, required=True)
        android.add_argument("--policy", type=Path, required=True)
        android.add_argument("--head", required=True)
        android.add_argument("--mode", choices=("warn", "enforce"), default="enforce")
        npm = commands.add_parser("npm")
        npm.add_argument("--lockfile", type=Path, required=True)
        npm.add_argument("--inventory", type=Path, required=True)
        npm.add_argument("--repository", required=True)
        npm.add_argument("--head", required=True)
        review = commands.add_parser("review")
        review.add_argument("--comparison", type=Path, required=True)
        review.add_argument("--repository", required=True)
        review.add_argument("--base", required=True)
        review.add_argument("--head", required=True)
        review.add_argument("--exceptions", type=Path)
        args = parser.parse_args(argv)
        if args.command == "android":
            report = android_inventory(read_document(args.resolved), read_document(args.policy), args.head, args.mode)
        elif args.command == "npm":
            report = npm_inventory(
                read_document(args.lockfile), read_document(args.inventory), args.repository, args.head,
            )
        else:
            exceptions = Exceptions.load() if args.exceptions is None else Exceptions.load(args.exceptions)
            report = dependency_review(read_document(args.comparison), args.repository, args.base, args.head, exceptions)
        emit(report)
        return int(report["status"] == "fail")
    except Refusal as error:
        emit({"status": "refused", "code": str(error)})
        return 2
    except OSError:
        emit({"status": "refused", "code": "dependency-input-read-failed"})
        return 2


if __name__ == "__main__":
    sys.exit(main())
