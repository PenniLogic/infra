"""Run pinned Gitleaks over all locally available Git history; emit no raw findings."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

from security_exceptions import (
    COMMIT, DIGEST, PATTERN, ROOT, Exceptions, Parser, Refusal, emit, identity,
    matches, read_document, repository_id, require,
)

sys.path.insert(0, str(ROOT / "governance"))
from conformance import defects as processes


GITLEAKS_VERSION = "8.30.1"
SCAN_TIMEOUT_SECONDS = 180
SCANNER_PASSES = ("mandatory", "provider")
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


class ProcessRefusal(Refusal):
    def __init__(self, code: str, cleanup_confirmed: bool, *, scratch_cleanup_failed: bool = False):
        super().__init__(code)
        self.cleanup_confirmed = cleanup_confirmed
        self.scratch_cleanup_failed = scratch_cleanup_failed
        self.scratch_retained = False
        self.incident_handoff: dict[str, Any] | None = None


def trusted_tool(value: str, root: Path) -> Path:
    path = Path(value)
    require(path.is_absolute(), "absolute-tool-path-required")
    require(not path.is_relative_to(root), "untrusted-tool-location")
    try:
        path = path.resolve(strict=True)
    except FileNotFoundError:
        raise Refusal("scanner-or-git-missing") from None
    require(path.is_file() and not path.is_relative_to(root), "untrusted-tool-location")
    return path


def verify_scanner(path: Path, expected: str) -> None:
    require(matches(expected, DIGEST), "invalid-scanner-digest")
    with path.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == expected, "scanner-digest-mismatch")


def scanner_environment(git_executable: Path) -> dict[str, str]:
    names = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR")
    env = {key: value for key, value in os.environ.items() if key.upper() in names}
    env.update({
        "PATH": str(git_executable.parent),
        "PATHEXT": ".EXE",
        "NoDefaultCurrentDirectoryInExePath": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_TERMINAL_PROMPT": "0",
    })
    return env


def run(command: list[str], cwd: Path, env: dict[str, str], timeout: float = 30) -> subprocess.CompletedProcess:
    captured: list[str] = []

    def capture(text: str) -> str:
        captured.append(text)
        return ""

    try:
        if os.name == "nt":
            result = processes._windows_runner(command, cwd, env, timeout, capture)
        else:
            result = processes._posix_runner(command, cwd, env, timeout, capture)
    except processes.UnsafeProcessTreeError as error:
        code = "scanner-or-git-timeout" if error.result and error.result.timed_out else "scanner-process-interrupted"
        raise ProcessRefusal(code, cleanup_confirmed=False) from None
    except KeyboardInterrupt:
        # A raw interrupt may come from teardown itself, not a confirmed-cleanup
        # rethrow. Without a typed witness the boundary must remain conservative.
        raise ProcessRefusal("scanner-process-interrupted", cleanup_confirmed=False) from None
    except FileNotFoundError:
        raise Refusal("scanner-or-git-missing") from None
    if result.timed_out:
        raise ProcessRefusal("scanner-or-git-timeout", result.restoration_safe)
    if result.error or not result.restoration_safe:
        raise ProcessRefusal("scanner-process-failed", result.restoration_safe)
    require(type(result.exit_code) is int, "scanner-process-status-missing")
    # The existing owned runner merges streams. Preserve the entire capture before
    # its reporting tail; callers accept only protocol output, never diagnostics.
    return subprocess.CompletedProcess(command, result.exit_code, "".join(captured).encode("utf-8"), b"")


def git(executable: Path, root: Path, env: dict[str, str], *args: str) -> str:
    result = run([str(executable), *args], root, env)
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


def scanner_report(result: subprocess.CompletedProcess, report_path: Path) -> list[Any]:
    require(result.returncode in (0, 10), "scanner-execution-failed")
    require(not result.stdout and not result.stderr, "scanner-diagnostic-output")
    require(report_path.is_file(), "scanner-report-missing")
    raw = read_document(report_path)
    require(type(raw) is list and bool(raw) == (result.returncode == 10), "scanner-result-mismatch")
    return raw


def merged_findings(passes: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    findings = {finding["id"]: finding for completed in passes.values() for finding in completed}
    return [findings[key] for key in sorted(findings)]


def scan(
    root: Path, repository: str, scanner: str, exceptions: Exceptions, *,
    git_executable: str, scanner_sha256: str,
) -> dict[str, Any]:
    repo_id = repository_id(repository)
    root = root.resolve(strict=True)
    git_binary = trusted_tool(git_executable, root)
    scanner_binary = trusted_tool(scanner, root)
    require(git_binary.name == ("git.exe" if os.name == "nt" else "git"), "invalid-git-executable-name")
    verify_scanner(scanner_binary, scanner_sha256)
    env = scanner_environment(git_binary)
    require(git(git_binary, root, env, "rev-parse", "--is-shallow-repository") == "false", "shallow-history")
    require(not git(git_binary, root, env, "replace", "-l"), "replacement-history")
    grafts = Path(git(git_binary, root, env, "rev-parse", "--git-path", "info/grafts"))
    require(not (root / grafts).exists(), "grafted-history")
    head = git(git_binary, root, env, "rev-parse", "--verify", "HEAD")
    require(matches(head, COMMIT), "invalid-head")
    commits = git(git_binary, root, env, "rev-list", "--all", "HEAD").splitlines()
    require(bool(commits) and all(matches(commit, COMMIT) for commit in commits), "empty-history")
    version = run([str(scanner_binary), "version"], scanner_binary.parent, env)
    require(version.returncode == 0 and version.stdout.strip() == GITLEAKS_VERSION.encode(), "scanner-version-mismatch")
    directory = tempfile.TemporaryDirectory(prefix="pennilogic-secret-scan-", delete=False)
    cleanup_confirmed = True
    completed_passes: dict[str, list[dict[str, Any]]] = {}
    try:
        try:
            temporary = Path(directory.name).resolve(strict=True)
            require(not temporary.is_relative_to(root), "untrusted-scratch-location")
            mirror = temporary / "history.git"
            cloned = run(
                [str(git_binary), "clone", "--quiet", "--mirror", "--no-local", "--", str(root), str(mirror)],
                temporary, env, timeout=60,
            )
            require(cloned.returncode == 0, "history-snapshot-failed")
            require(
                git(git_binary, mirror, env, "rev-parse", "--verify", "HEAD") == head
                and set(git(git_binary, mirror, env, "rev-list", "--all", "HEAD").splitlines()) == set(commits),
                "history-snapshot-incomplete",
            )
            ignored = temporary / "empty.ignore"
            ignored.write_bytes(b"")
            defaults = temporary / "defaults.toml"
            defaults.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
            # Gitleaks always reads source/.gitleaksignore, even with an explicit ignore
            # path. A bare mirror keeps that candidate file out of the scanner's inputs.
            # Mandatory rules run separately so upstream global path allowlists cannot
            # hide a credential in, for example, an SVG, a lockfile or gitleaks.toml.
            for name, config in zip(SCANNER_PASSES, (CONFIG, defaults), strict=True):
                report_path = temporary / f"redacted-{name}.json"
                verify_scanner(scanner_binary, scanner_sha256)
                command = [
                    str(scanner_binary), "git", str(mirror), "--config", str(config),
                    "--log-opts=--all --full-history --root -m --text --no-ext-diff --no-textconv",
                    "--gitleaks-ignore-path", str(ignored), "--ignore-gitleaks-allow",
                    "--redact=100", "--no-banner", "--no-color", "--log-level=error",
                    "--report-format=json", "--report-path", str(report_path), "--exit-code=10", "--timeout=0",
                ]
                # 8.30.1 can silently return partial findings when its internal context
                # expires while workers drain. Only the owned external bound may cancel it.
                result = run(command, temporary, env, timeout=SCAN_TIMEOUT_SECONDS)
                verify_scanner(scanner_binary, scanner_sha256)
                completed_passes[name] = findings_from_gitleaks(
                    scanner_report(result, report_path), repository, exceptions,
                )
        except ProcessRefusal as error:
            cleanup_confirmed = error.cleanup_confirmed
            error.scratch_retained = not cleanup_confirmed
            raise
        except KeyboardInterrupt:
            cleanup_confirmed = False
            refusal = ProcessRefusal("scanner-process-interrupted", cleanup_confirmed=False)
            refusal.scratch_retained = True
            raise refusal from None
        finally:
            if cleanup_confirmed:
                original = sys.exception()
                try:
                    directory.cleanup()
                except (OSError, KeyboardInterrupt) as error:
                    code = (
                        "scanner-process-interrupted" if isinstance(error, KeyboardInterrupt)
                        else "scanner-scratch-cleanup-failed"
                    )
                    if isinstance(original, Refusal):
                        code = str(original)
                    interrupted = isinstance(error, KeyboardInterrupt)
                    refusal = ProcessRefusal(code, cleanup_confirmed=not interrupted, scratch_cleanup_failed=True)
                    refusal.scratch_retained = interrupted
                    raise refusal from None
        require(git(git_binary, root, env, "rev-parse", "--verify", "HEAD") == head, "head-changed-during-scan")
        require(git(git_binary, root, env, "rev-list", "--all", "HEAD").splitlines() == commits, "history-changed-during-scan")
        findings = merged_findings(completed_passes)
        blocking = sum(finding["exception"] is None for finding in findings)
        return {
            "schema": "pennilogic.secret-scan/1",
            "repository": repository,
            "repository_id": repo_id,
            "head": head,
            "scanner": {"name": "gitleaks", "version": GITLEAKS_VERSION},
            "coverage": {"scope": "all-local-refs", "complete": True, "commits": len(set(commits)), "shallow": False},
            "status": "fail" if blocking else "pass",
            "blocking_count": blocking,
            "findings": findings,
            "exception_audit": exceptions.audit(),
        }
    except (Refusal, OSError, KeyboardInterrupt) as error:
        if isinstance(error, ProcessRefusal):
            refusal = error
        else:
            code = "scanner-process-interrupted" if isinstance(error, KeyboardInterrupt) else "scanner-io-failed"
            refusal = ProcessRefusal(
                str(error) if isinstance(error, Refusal) else code,
                cleanup_confirmed=cleanup_confirmed and not isinstance(error, KeyboardInterrupt),
            )
        if any(completed_passes.values()):
            refusal.incident_handoff = {
                "schema": "pennilogic.secret-incident/1", "status": "incomplete",
                "repository": repository, "repository_id": repo_id, "head": head,
                "completed_passes": list(completed_passes),
                "findings": merged_findings(completed_passes),
            }
        raise refusal from None


def refusal_report(error: Refusal) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "pennilogic.secret-scan/1", "status": "refused", "code": str(error),
        "coverage": {"scope": "all-local-refs", "complete": False},
    }
    if isinstance(error, ProcessRefusal):
        report["process_cleanup"] = "confirmed" if error.cleanup_confirmed else "unconfirmed"
        if error.scratch_retained:
            report["scratch_retained"] = True
        if error.scratch_cleanup_failed:
            report["scratch_cleanup"] = "failed"
        if error.incident_handoff is not None:
            report["incident_handoff"] = error.incident_handoff
    return report


def main(argv: list[str] | None = None) -> int:
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=ROOT)
        parser.add_argument("--repository", required=True)
        parser.add_argument("--git", required=True)
        parser.add_argument("--gitleaks", required=True)
        parser.add_argument("--gitleaks-sha256", required=True)
        parser.add_argument("--exceptions", type=Path)
        args = parser.parse_args(argv)
        exceptions = Exceptions.load() if args.exceptions is None else Exceptions.load(args.exceptions)
        report = scan(
            args.root, args.repository, args.gitleaks, exceptions,
            git_executable=args.git, scanner_sha256=args.gitleaks_sha256,
        )
        emit(report)
        return int(report["status"] != "pass")
    except Refusal as error:
        emit(refusal_report(error))
        return 2
    except OSError:
        emit(refusal_report(Refusal("scanner-io-failed")))
        return 2
    except KeyboardInterrupt:
        emit(refusal_report(ProcessRefusal("scanner-process-interrupted", cleanup_confirmed=False)))
        return 2


if __name__ == "__main__":
    sys.exit(main())
