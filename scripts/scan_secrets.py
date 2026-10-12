"""Run pinned Gitleaks over all locally available Git history; emit no raw findings."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

from security_exceptions import (
    COMMIT, PATTERN, ROOT, Exceptions, Parser, Refusal, emit, identity,
    matches, read_document, repository_id, require,
)


GITLEAKS_VERSION = "8.30.1"
CONFIG = ROOT / "security" / "gitleaks.toml"
SEVERITIES = {
    "pennilogic-database-password": ("database-password", "critical"),
    "pennilogic-private-key": ("private-key", "critical"),
    "private-key": ("private-key", "critical"),
    "pennilogic-github-token": ("source-control-token", "high"),
    "github-pat": ("source-control-token", "high"),
    "github-fine-grained-pat": ("source-control-token", "high"),
    "pennilogic-provider-key": ("provider-api-key", "high"),
}


def scanner_environment() -> dict[str, str]:
    names = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR")
    env = {key: value for key, value in os.environ.items() if key.upper() in names}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_TERMINAL_PROMPT": "0",
    })
    return env


def run(command: list[str], cwd: Path, env: dict[str, str], timeout: int = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            command, cwd=cwd, env=env, capture_output=True, check=False, timeout=timeout,
        )
    except FileNotFoundError:
        raise Refusal("scanner-or-git-missing") from None
    except subprocess.TimeoutExpired:
        raise Refusal("scanner-or-git-timeout") from None


def git(root: Path, env: dict[str, str], *args: str) -> str:
    result = run(["git", *args], root, env)
    require(result.returncode == 0, "git-history-read-failed")
    try:
        return result.stdout.decode("utf-8").strip()
    except UnicodeError:
        raise Refusal("invalid-git-output") from None


def finding_id(repository: str, finding: dict[str, Any]) -> str:
    return identity(
        repository, finding["rule"], finding["artifact"], finding["commit"],
        *(str(finding[key]) for key in ("line", "column", "end_line", "end_column")),
    )


def findings_from_gitleaks(raw: Any, repository: str, exceptions: Exceptions) -> list[dict[str, Any]]:
    require(type(raw) is list, "invalid-scanner-report")
    results: dict[str, dict[str, Any]] = {}
    for finding in raw:
        require(type(finding) is dict, "invalid-scanner-finding")
        require(matches(finding.get("RuleID"), PATTERN), "invalid-scanner-rule")
        require(matches(finding.get("Commit"), COMMIT), "invalid-scanner-commit")
        require(type(finding.get("File")) is str and 0 < len(finding["File"]) <= 4096, "invalid-scanner-artifact")
        require(type(finding.get("StartLine")) is int and finding["StartLine"] > 0, "invalid-scanner-line")
        require(
            type(finding.get("EndLine")) is int and finding["EndLine"] >= finding["StartLine"]
            and type(finding.get("StartColumn")) is int and finding["StartColumn"] > 0
            and type(finding.get("EndColumn")) is int and finding["EndColumn"] > 0
            and (finding["EndLine"] > finding["StartLine"] or finding["EndColumn"] >= finding["StartColumn"]),
            "invalid-scanner-span",
        )
        rule = finding["RuleID"]
        artifact = identity(finding["File"])
        credential_type, severity = SEVERITIES.get(rule, ("unclassified-credential", "high"))
        projected = {
            "rule": rule,
            "artifact": artifact,
            "commit": finding["Commit"],
            "line": finding["StartLine"],
            "column": finding["StartColumn"],
            "end_line": finding["EndLine"],
            "end_column": finding["EndColumn"],
            "credential_type": credential_type,
            "severity": severity,
        }
        key = finding_id(repository, projected)
        results[key] = {
            "id": key, **projected,
            "exception": exceptions.suppression("secret", repository, rule, key),
        }
    return [results[key] for key in sorted(results)]


def scan(root: Path, repository: str, scanner: str, exceptions: Exceptions) -> dict[str, Any]:
    repo_id = repository_id(repository)
    root = root.resolve(strict=True)
    env = scanner_environment()
    require(git(root, env, "rev-parse", "--is-shallow-repository") == "false", "shallow-history")
    require(not git(root, env, "replace", "-l"), "replacement-history")
    grafts = Path(git(root, env, "rev-parse", "--git-path", "info/grafts"))
    require(not (root / grafts).exists(), "grafted-history")
    head = git(root, env, "rev-parse", "--verify", "HEAD")
    require(matches(head, COMMIT), "invalid-head")
    commits = git(root, env, "rev-list", "--all", "HEAD").splitlines()
    require(bool(commits) and all(matches(commit, COMMIT) for commit in commits), "empty-history")
    version = run([scanner, "version"], root, env)
    require(version.returncode == 0 and version.stdout.strip() == GITLEAKS_VERSION.encode(), "scanner-version-mismatch")
    with tempfile.TemporaryDirectory(prefix="pennilogic-secret-scan-") as directory:
        temporary = Path(directory)
        mirror = temporary / "history.git"
        cloned = run(
            ["git", "clone", "--quiet", "--mirror", "--no-local", "--", str(root), str(mirror)],
            temporary, env, timeout=60,
        )
        require(cloned.returncode == 0, "history-snapshot-failed")
        require(
            git(mirror, env, "rev-parse", "--verify", "HEAD") == head
            and set(git(mirror, env, "rev-list", "--all", "HEAD").splitlines()) == set(commits),
            "history-snapshot-incomplete",
        )
        ignored = temporary / "empty.ignore"
        ignored.write_bytes(b"")
        defaults = temporary / "defaults.toml"
        defaults.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
        raw_findings = []
        # Gitleaks always reads source/.gitleaksignore, even with an explicit ignore
        # path. A bare mirror keeps that candidate file out of the scanner's inputs.
        # Mandatory rules run separately so upstream global path allowlists cannot
        # hide a credential in, for example, an SVG, a lockfile or gitleaks.toml.
        for index, config in enumerate((CONFIG, defaults)):
            report_path = temporary / f"redacted-{index}.json"
            command = [
                scanner, "git", str(mirror), "--config", str(config),
                "--log-opts=--all --full-history --root -m --text --no-ext-diff --no-textconv",
                "--gitleaks-ignore-path", str(ignored), "--ignore-gitleaks-allow",
                "--redact=100", "--no-banner", "--no-color", "--log-level=error",
                "--report-format=json", "--report-path", str(report_path), "--exit-code=10", "--timeout=180",
            ]
            result = run(command, temporary, env, timeout=190)
            require(result.returncode in (0, 10), "scanner-execution-failed")
            require(report_path.is_file(), "scanner-report-missing")
            raw = read_document(report_path)
            require(type(raw) is list and bool(raw) == (result.returncode == 10), "scanner-result-mismatch")
            raw_findings.extend(raw)
        findings = findings_from_gitleaks(raw_findings, repository, exceptions)
    require(git(root, env, "rev-parse", "--verify", "HEAD") == head, "head-changed-during-scan")
    require(git(root, env, "rev-list", "--all", "HEAD").splitlines() == commits, "history-changed-during-scan")
    blocking = sum(finding["exception"] is None for finding in findings)
    return {
        "schema": "pennilogic.secret-scan/1",
        "repository": repository,
        "repository_id": repo_id,
        "head": head,
        "scanner": {"name": "gitleaks", "version": GITLEAKS_VERSION},
        "coverage": {"scope": "all-local-refs", "commits": len(set(commits)), "shallow": False},
        "status": "fail" if blocking else "pass",
        "blocking_count": blocking,
        "findings": findings,
        "exception_audit": exceptions.audit(),
    }


def main(argv: list[str] | None = None) -> int:
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=ROOT)
        parser.add_argument("--repository", required=True)
        parser.add_argument("--gitleaks", default="gitleaks")
        parser.add_argument("--exceptions", type=Path)
        args = parser.parse_args(argv)
        exceptions = Exceptions.load() if args.exceptions is None else Exceptions.load(args.exceptions)
        report = scan(args.root, args.repository, args.gitleaks, exceptions)
        emit(report)
        return int(report["status"] != "pass")
    except Refusal as error:
        emit({"schema": "pennilogic.secret-scan/1", "status": "refused", "code": str(error)})
        return 2
    except OSError:
        emit({"schema": "pennilogic.secret-scan/1", "status": "refused", "code": "scanner-io-failed"})
        return 2


if __name__ == "__main__":
    sys.exit(main())
