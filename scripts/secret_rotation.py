"""Build redacted, deduplicated rotation requests and an age alert; never call GitHub."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import sys
from typing import Any

from scan_secrets import SCANNER_PASSES, SEVERITIES, finding_id
from security_exceptions import (
    COMMIT, DIGEST, IDENTIFIER, PATTERN, Exceptions, Parser, Refusal, emit, exact, matches, read_document,
    repository_id, require, utc,
)


ROTATION_LABEL = "secret-rotation"
MARKER = re.compile(r"<!-- pennilogic-secret-rotation:([0-9]+):([0-9a-f]{64}) -->", re.ASCII)


def marker(repo_id: int, finding_id: str) -> str:
    return f"<!-- pennilogic-secret-rotation:{repo_id}:{finding_id} -->"


def incomplete_incident(scan: dict[str, Any]) -> dict[str, Any]:
    required = {"schema", "status", "code", "coverage", "incident_handoff"}
    require(
        required <= set(scan) <= required | {"process_cleanup", "scratch_cleanup", "scratch_retained"}
        and matches(scan.get("code"), IDENTIFIER),
        "invalid-incident-handoff",
    )
    exact(scan["coverage"], {"scope", "complete"}, "invalid-incident-coverage")
    require(
        scan["coverage"]["scope"] == "all-local-refs" and scan["coverage"]["complete"] is False,
        "invalid-incident-coverage",
    )
    if "process_cleanup" in scan:
        require(scan["process_cleanup"] in ("confirmed", "unconfirmed"), "invalid-incident-cleanup")
    if "scratch_cleanup" in scan:
        require(
            scan["scratch_cleanup"] == "failed" and (
                scan.get("process_cleanup") == "confirmed"
                or (scan.get("process_cleanup") == "unconfirmed" and scan.get("scratch_retained") is True)
            ),
            "invalid-incident-cleanup",
        )
    if "scratch_retained" in scan:
        require(
            scan["scratch_retained"] is True and scan.get("process_cleanup") == "unconfirmed",
            "invalid-incident-cleanup",
        )
    incident = scan["incident_handoff"]
    exact(
        incident, {"schema", "status", "repository", "repository_id", "head", "completed_passes", "findings"},
        "invalid-incident-handoff",
    )
    require(
        incident["schema"] == "pennilogic.secret-incident/1" and incident["status"] == "incomplete"
        and type(incident["completed_passes"]) is list
        and incident["completed_passes"] in ([SCANNER_PASSES[0]], list(SCANNER_PASSES))
        and type(incident["findings"]) is list and bool(incident["findings"]),
        "invalid-incident-handoff",
    )
    return incident


def age_alert(issues: list[dict[str, Any]], now: datetime, stale_after_seconds: int | None) -> dict[str, Any]:
    open_issues = sorted((issue for issue in issues if issue["state"] == "open"), key=lambda issue: issue["number"])
    valid_window = stale_after_seconds is None or (type(stale_after_seconds) is int and stale_after_seconds > 0)
    report = {
        "open_count": len(open_issues), "oldest_age_seconds": None,
        "staleness_window_seconds": stale_after_seconds if valid_window else None,
        "age_alert_status": "failed", "stale_count": None,
        "tickets": [{"number": issue["number"], "age_seconds": None, "stale": None} for issue in open_issues],
    }
    try:
        require(valid_window, "invalid-escalation-window")
        ages = {}
        for issue in issues:
            created = utc(issue.get("created_at"))
            require(created <= now, "future-rotation-issue")
            ages[issue["number"]] = int((now - created).total_seconds())
        tickets = [
            {
                "number": issue["number"], "age_seconds": ages[issue["number"]],
                "stale": None if stale_after_seconds is None else ages[issue["number"]] >= stale_after_seconds,
            }
            for issue in open_issues
        ]
        report.update({
            "oldest_age_seconds": max((ticket["age_seconds"] for ticket in tickets), default=None),
            "age_alert_status": "policy-required" if stale_after_seconds is None else "evaluated",
            "stale_count": None if stale_after_seconds is None else sum(ticket["stale"] for ticket in tickets),
            "tickets": tickets,
        })
    except Refusal as error:
        report["age_alert_code"] = str(error)
    return report


def plan(
    scan: Any, existing: Any, now: datetime, exceptions: Exceptions | None = None,
    *, stale_after_seconds: int | None = None,
) -> dict[str, Any]:
    require(
        type(scan) is dict and scan.get("schema") == "pennilogic.secret-scan/1"
        and scan.get("status") in ("pass", "fail", "refused"),
        "incomplete-secret-scan",
    )
    scan_status = scan["status"]
    incomplete = scan_status == "refused"
    if incomplete:
        scan = incomplete_incident(scan)
    else:
        require(
            "incident_handoff" not in scan
            and ("coverage" not in scan or (
                type(scan["coverage"]) is dict and scan["coverage"].get("complete", True) is True
            )),
            "inconsistent-secret-scan",
        )
    require(type(scan.get("repository")) is str, "invalid-scan-repository")
    repository = scan["repository"]
    repo_id = repository_id(repository)
    require(type(scan.get("repository_id")) is int and scan["repository_id"] == repo_id, "wrong-scan-repository")
    require(matches(scan.get("head"), COMMIT) and type(scan.get("findings")) is list, "invalid-secret-scan")
    if not incomplete:
        require(
            type(scan.get("blocking_count")) is int
            and scan["blocking_count"] == sum(
                type(finding) is dict and finding.get("exception") is None for finding in scan["findings"]
            )
            and scan["status"] == ("fail" if scan["blocking_count"] else "pass"),
            "inconsistent-secret-scan",
        )
    require(
        type(existing) is dict
        and set(existing) == {"repository", "repository_id", "complete", "issues"}
        and existing["repository"] == repository
        and type(existing["repository_id"]) is int and existing["repository_id"] == repo_id
        and existing["complete"] is True and type(existing["issues"]) is list,
        "incomplete-rotation-list",
    )
    require(now.tzinfo is not None, "naive-clock")
    exceptions = Exceptions.load(now=now) if exceptions is None else exceptions
    require(exceptions.now == now, "exception-clock-mismatch")
    rotation_issues = []
    tracked: dict[str, dict[str, Any]] = {}
    seen_numbers: set[int] = set()
    for issue in existing["issues"]:
        require(
            type(issue) is dict and type(issue.get("number")) is int and issue["number"] > 0
            and issue.get("state") in ("open", "closed")
            and type(issue.get("labels")) is list and type(issue.get("body")) is str,
            "invalid-rotation-issue",
        )
        require(issue["number"] not in seen_numbers, "duplicate-rotation-issue")
        seen_numbers.add(issue["number"])
        labels = issue["labels"]
        require(
            all(type(label) is dict and type(label.get("name")) is str for label in labels),
            "invalid-rotation-labels",
        )
        if not any(label["name"] == ROTATION_LABEL for label in labels):
            continue
        require("pull_request" not in issue, "rotation-label-on-pull-request")
        rotation_issues.append(issue)
        markers = list(MARKER.finditer(issue["body"]))
        require(len(markers) <= 1, "ambiguous-rotation-marker")
        for match in markers:
            require(match[1] == str(repo_id), "rotation-marker-repository-mismatch")
            require(match[2] not in tracked, "duplicate-rotation-marker")
            tracked[match[2]] = issue
    requests = []
    closed_findings = []
    seen_findings: set[str] = set()
    for finding in scan["findings"]:
        if incomplete:
            exact(
                finding,
                {"id", "artifact", "rule", "commit", "line", "column", "end_line", "end_column",
                 "credential_type", "severity", "exception"},
                "invalid-incident-finding",
            )
        require(
            type(finding) is dict
            and matches(finding.get("id"), DIGEST) and matches(finding.get("artifact"), DIGEST)
            and matches(finding.get("rule"), PATTERN) and matches(finding.get("commit"), COMMIT)
            and type(finding.get("line")) is int and finding["line"] > 0
            and type(finding.get("end_line")) is int and finding["end_line"] >= finding["line"]
            and type(finding.get("column")) is int and finding["column"] > 0
            and type(finding.get("end_column")) is int and finding["end_column"] > 0
            and (finding["end_line"] > finding["line"] or finding["end_column"] >= finding["column"])
            and "exception" in finding
            and (finding["exception"] is None or matches(finding["exception"], IDENTIFIER)),
            "invalid-rotation-finding",
        )
        if incomplete and scan["completed_passes"] == [SCANNER_PASSES[0]]:
            require(
                finding["rule"] in SEVERITIES and finding["rule"].startswith("pennilogic-"),
                "invalid-incident-pass",
            )
        key = finding["id"]
        require(key == finding_id(repository, finding), "rotation-finding-identity-mismatch")
        require(key not in seen_findings, "duplicate-rotation-finding")
        seen_findings.add(key)
        credential_type, severity = SEVERITIES.get(finding["rule"], ("unclassified-credential", "high"))
        require(
            finding.get("credential_type") == credential_type and finding.get("severity") == severity,
            "rotation-severity-mismatch",
        )
        if exceptions.suppression("secret", repository, finding["rule"], key) is not None:
            continue
        if key in tracked:
            issue = tracked[key]
            severity_labels = {label["name"] for label in issue["labels"] if label["name"].startswith("severity:")}
            require(severity_labels == {f"severity:{severity}"}, "rotation-ticket-severity-mismatch")
            if issue["state"] == "closed":
                closed_findings.append({"id": key, "number": issue["number"]})
            continue
        requests.append({
            "deduplication_key": key,
            "repository": repository,
            "repository_id": repo_id,
            "title": f"Rotate exposed {credential_type} ({key[:12]})",
            "labels": [ROTATION_LABEL, f"severity:{severity}"],
            "body": "\n".join([
                marker(repo_id, key),
                "",
                f"Credential class: `{credential_type}`. Severity: `{severity}`.",
                f"Scanner rule: `{finding['rule']}`.",
                f"Artifact identifier: `{finding['artifact']}`.",
                f"Commit: `{finding['commit']}`; line: `{finding['line']}`.",
                "",
                "No credential, matched text, path, author or commit message is included.",
                "The owner must investigate privately, revoke/rotate the credential, and record remediation.",
                "A deleted file or a passing later build does not prove revocation.",
            ]),
        })
    return {
        "schema": "pennilogic.secret-rotation/1",
        "repository": repository,
        "repository_id": repo_id,
        "scan_status": scan_status,
        "scan_coverage": "incomplete" if incomplete else "complete",
        "publication": "not-performed",
        "requests": requests,
        "closed_findings_needing_review": closed_findings,
        **age_alert(rotation_issues, now, stale_after_seconds),
    }


def main(argv: list[str] | None = None) -> int:
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("--scan", type=Path, required=True)
        parser.add_argument("--existing", type=Path, required=True)
        parser.add_argument("--exceptions", type=Path)
        parser.add_argument("--stale-after-seconds", type=int)
        args = parser.parse_args(argv)
        now = datetime.now(timezone.utc)
        exceptions = Exceptions.load(now=now) if args.exceptions is None else Exceptions.load(args.exceptions, now)
        report = plan(
            read_document(args.scan), read_document(args.existing), now, exceptions,
            stale_after_seconds=args.stale_after_seconds,
        )
        emit(report)
        if report["scan_coverage"] == "incomplete" or report["age_alert_status"] != "evaluated":
            return 2
        return int(report["stale_count"] > 0 or bool(report["closed_findings_needing_review"]))
    except Refusal as error:
        emit({"schema": "pennilogic.secret-rotation/1", "status": "refused", "code": str(error)})
        return 2
    except OSError:
        emit({"schema": "pennilogic.secret-rotation/1", "status": "refused", "code": "rotation-input-read-failed"})
        return 2


if __name__ == "__main__":
    sys.exit(main())
