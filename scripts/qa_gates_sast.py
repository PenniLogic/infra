"""SAST report ingestion and severity gate of PenniLogic/infra#28 (T-QA-04, slice 2); see QA_GATES_SCANNING.md.

    python scripts/qa_gates_sast.py --report SEMGREP.json --root SOURCE_ROOT [--policy POLICY.json]

Reads one Semgrep JSON report. A report with a non-empty `errors` list, a skipped rule or zero scanned paths is
incomplete, and incomplete fails. Every finding blocks unless its rule is in `warn` mode inside a recorded window of
at most seven days (`warn_from`..`warn_until`, judged against an injected clock); an expired or unknown rule blocks.
Exceptions are unavailable until infra#23 integrates, so no finding is ever excepted here. The rule set and this
report vocabulary are proposed, not agreed.

Fingerprints are `sha256:` over rule ID, normalized path and the SHA-256 of the matched byte span read from the
source root (Semgrep OSS reports `requires login` in place of its own fingerprint and lines). The output carries
rule IDs, scanner severities, validated paths, line numbers and fingerprints only: never messages, snippets or
metadata. Exit 0 pass, 1 gate failure (including an incomplete report), 2 refused input or usage; stdout carries
one ASCII JSON report.
"""

import datetime
import json
import os
from pathlib import Path
import re
import sys

from qa_gates_scan_common import (
    Refused, canonical_sha256, date, exact, json_document, read_bounded, relative_path, sha256_bytes, text,
)


SCRIPTS = Path(__file__).resolve().parent
RULES_DIR = SCRIPTS / "qa-gates" / "rules"
POLICY_FILE = RULES_DIR / "sast-policy.json"
RULE_SUFFIX = ".yml"
RULE_ID = re.compile(r"pennilogic-[a-z0-9]+(?:-[a-z0-9]+)*")
CHECK_ID = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,199}")
VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")
SCANNER_SEVERITIES = ("ERROR", "WARNING", "INFO", "CRITICAL", "HIGH", "MEDIUM", "LOW")
PROPOSED = "proposed, not agreed"
POLICY_SCHEMA = "pennilogic.qa-gates.sast-policy/1"
REPORT_SCHEMA = "pennilogic.qa-gates.sast-report/1"
VOCABULARY_STATUS = "proposed, pending infra#23 owner alignment"
EXCEPTIONS_STATUS = "unavailable: infra#23 not integrated"
PLANNED_EXCEPTIONS_BINDING = "security_exceptions.Exceptions.suppression"
WARN_WINDOW_DAYS = 7
RULE_FILE_LIMIT = 262144
POLICY_LIMIT = 65536
REPORT_LIMIT = 32 * 1024 * 1024
SOURCE_LIMIT = 4 * 1024 * 1024
RESULT_LIMIT = 100000


def load_rule_ids(rules_dir=RULES_DIR):
    """The sorted rule IDs of every `*.yml` rule file (JSON syntax); each rule is labelled proposed, not agreed."""
    try:
        files = sorted(entry for entry in Path(rules_dir).iterdir() if entry.suffix == RULE_SUFFIX)
    except OSError:
        raise Refused("SAST-RULES-UNREADABLE") from None
    if not files:
        raise Refused("SAST-RULES-EMPTY")
    identifiers = []
    for path in files:
        document = json_document(read_bounded(path, RULE_FILE_LIMIT, "SAST-RULES-UNREADABLE"), RULE_FILE_LIMIT,
                                 "SAST-RULES")
        rules = exact(document, ("rules",), "SAST-RULES-SHAPE")["rules"]
        if not isinstance(rules, list) or not rules:
            raise Refused("SAST-RULES-SHAPE")
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
                raise Refused("SAST-RULES-SHAPE")
            if RULE_ID.fullmatch(rule["id"]) is None:
                raise Refused("SAST-RULES-ID")
            metadata = rule.get("metadata")
            if not isinstance(metadata, dict) or metadata.get("status") != PROPOSED:
                raise Refused("SAST-RULES-STATUS")
            identifiers.append(rule["id"])
    if len(set(identifiers)) != len(identifiers):
        raise Refused("SAST-RULES-DUPLICATE")
    return tuple(sorted(identifiers))


POLICY_KEYS = ("schema", "status", "basis", "decision_ref", "rules")


def parse_policy(data, rule_ids):
    """Validate the per-rule mode policy; its rule set must equal the rule files' IDs exactly.

    `block` needs no other key. `warn` needs `warn_from` < `warn_until` at most seven days apart (the ticket's
    one-week warning window and per-rule rollback with a recorded expiry). `decision_ref` stays null: no owner
    decision on the rule set is recorded.
    """
    document = exact(json_document(data, POLICY_LIMIT, "SAST-POLICY"), POLICY_KEYS, "SAST-POLICY-KEYS")
    if document["schema"] != POLICY_SCHEMA or document["status"] != PROPOSED:
        raise Refused("SAST-POLICY-SCHEMA")
    text(document["basis"], "SAST-POLICY-BASIS")
    if document["decision_ref"] is not None:
        raise Refused("SAST-POLICY-DECISION")
    rules = document["rules"]
    if not isinstance(rules, dict) or tuple(sorted(rules)) != tuple(rule_ids):
        raise Refused("SAST-POLICY-RULES")
    modes = {}
    for rule_id in rule_ids:
        entry = rules[rule_id]
        if not isinstance(entry, dict) or entry.get("mode") not in ("block", "warn"):
            raise Refused("SAST-POLICY-MODE")
        if entry["mode"] == "block":
            exact(entry, ("mode",), "SAST-POLICY-MODE")
            modes[rule_id] = ("block", None, None)
            continue
        exact(entry, ("mode", "warn_from", "warn_until"), "SAST-POLICY-WARN")
        start = date(entry["warn_from"], "SAST-POLICY-WARN")
        until = date(entry["warn_until"], "SAST-POLICY-WARN")
        if not start < until or (until - start).days > WARN_WINDOW_DAYS:
            raise Refused("SAST-POLICY-WARN-WINDOW")
        modes[rule_id] = ("warn", start, until)
    return modes


def load_policy(path=POLICY_FILE, rules_dir=RULES_DIR):
    return parse_policy(read_bounded(path, POLICY_LIMIT, "SAST-POLICY-UNREADABLE"), load_rule_ids(rules_dir))


def rule_mode(rule_id, modes, today):
    """`warn` only for a known warn-mode rule with `warn_from` <= today <= `warn_until`; everything else blocks."""
    entry = modes.get(rule_id)
    if entry is None or entry[0] != "warn":
        return "block"
    return "warn" if entry[1] <= today <= entry[2] else "block"


def expired_warnings(modes, today):
    """Warn-mode rules whose window has ended: they block again and are listed for the rollback record."""
    return sorted(rule_id for rule_id, entry in modes.items() if entry[0] == "warn" and today > entry[2])


def _rule_id(check_id, rule_ids):
    """A known rule ID when `check_id` equals it or ends with `.<id>` (the config-path prefix); else `check_id`."""
    if not isinstance(check_id, str) or CHECK_ID.fullmatch(check_id) is None:
        raise Refused("SAST-RESULT-RULE")
    for rule_id in rule_ids:
        if check_id == rule_id or check_id.endswith("." + rule_id):
            return rule_id
    return check_id


def _position(value):
    if not isinstance(value, dict):
        raise Refused("SAST-RESULT-POSITION")
    line, offset = value.get("line"), value.get("offset")
    if type(line) is not int or type(offset) is not int or line < 1 or offset < 0:
        raise Refused("SAST-RESULT-POSITION")
    return line, offset


def parse_report(data):
    """Shape-check a Semgrep JSON report; returns (version, results, error_count, skipped_rule_count, scanned)."""
    document = json_document(data, REPORT_LIMIT, "SAST-REPORT")
    if not isinstance(document, dict) or not {"version", "results", "errors", "paths", "skipped_rules"} <= set(document):
        raise Refused("SAST-REPORT-SHAPE")
    version = document["version"]
    if not isinstance(version, str) or VERSION.fullmatch(version) is None:
        raise Refused("SAST-REPORT-VERSION")
    results, errors, skipped = document["results"], document["errors"], document["skipped_rules"]
    paths = document["paths"]
    if (not isinstance(results, list) or len(results) > RESULT_LIMIT or not isinstance(errors, list)
            or not isinstance(skipped, list) or not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list)):
        raise Refused("SAST-REPORT-SHAPE")
    scanned = [relative_path(path, "SAST-REPORT-PATH") for path in paths["scanned"]]
    if len(set(scanned)) != len(scanned):
        raise Refused("SAST-REPORT-PATH")
    return version, results, len(errors), len(skipped), tuple(sorted(scanned))


def fingerprint(rule_id, path, span):
    """`sha256:` over the canonical JSON of [rule ID, normalized path, SHA-256 of the matched byte span]."""
    return "sha256:" + canonical_sha256([rule_id, path, sha256_bytes(span)])


def _finding(result, rule_ids, scanned, root, sources, modes, today):
    if not isinstance(result, dict) or not isinstance(result.get("extra"), dict):
        raise Refused("SAST-RESULT-SHAPE")
    rule_id = _rule_id(result.get("check_id"), rule_ids)
    path = relative_path(result.get("path"), "SAST-RESULT-PATH")
    if path not in scanned:
        raise Refused("SAST-RESULT-PATH-NOT-SCANNED")
    severity = result["extra"].get("severity")
    if severity not in SCANNER_SEVERITIES:
        raise Refused("SAST-RESULT-SEVERITY")
    (line, start), (end_line, end) = _position(result.get("start")), _position(result.get("end"))
    if path not in sources:
        source = read_bounded(Path(root, *path.split("/")), SOURCE_LIMIT, "SAST-SOURCE-UNREADABLE")
        if len(source) > SOURCE_LIMIT:
            raise Refused("SAST-SOURCE-UNREADABLE")
        sources[path] = source
    if not (start < end <= len(sources[path]) and line <= end_line):
        raise Refused("SAST-RESULT-SPAN")
    return {
        "rule_id": rule_id, "scanner_severity": severity, "path": path, "line": line,
        "fingerprint": fingerprint(rule_id, path, sources[path][start:end]), "mode": rule_mode(rule_id, modes, today),
    }


def evaluate(data, root, modes, today, rule_ids=None):
    """Gate one Semgrep report: incomplete fails first, then any `block`-mode finding fails."""
    rule_ids = tuple(sorted(modes)) if rule_ids is None else tuple(rule_ids)
    version, results, error_count, skipped_count, scanned = parse_report(data)
    scanned_set, sources = set(scanned), {}
    findings = sorted(
        (_finding(result, rule_ids, scanned_set, root, sources, modes, today) for result in results),
        key=lambda item: (item["path"], item["line"], item["rule_id"], item["fingerprint"]),
    )
    blocking = sum(item["mode"] == "block" for item in findings)
    by_severity = {}
    for item in findings:
        by_severity[item["scanner_severity"]] = by_severity.get(item["scanner_severity"], 0) + 1
    if error_count:
        reason = "SAST-INCOMPLETE-ERRORS"
    elif skipped_count:
        reason = "SAST-INCOMPLETE-SKIPPED-RULES"
    elif not scanned:
        reason = "SAST-INCOMPLETE-NO-PATHS"
    elif blocking:
        reason = "SAST-BLOCKING-FINDINGS"
    else:
        reason = None
    return {
        "schema": REPORT_SCHEMA, "vocabulary_status": VOCABULARY_STATUS, "rule_set_status": PROPOSED,
        "decision": "pass" if reason is None else "fail", "reason": reason,
        "complete": not (error_count or skipped_count or not scanned),
        "scanner": {"name": "semgrep", "version": version, "kind": "sast"},
        "evaluated_on": today.isoformat(),
        "scanned_path_count": len(scanned), "error_count": error_count, "skipped_rule_count": skipped_count,
        "counts": {"blocking": blocking, "warning": len(findings) - blocking, "by_scanner_severity": by_severity},
        "expired_warnings": expired_warnings(modes, today),
        "exceptions": {"status": EXCEPTIONS_STATUS, "planned_binding": PLANNED_EXCEPTIONS_BINDING, "count": 0},
        "findings": findings,
    }


PROVENANCE_SCHEMA = "pennilogic.qa-gates.sast-canned-provenance/1"
PROVENANCE_KEYS = (
    "schema", "kind", "acceptance_evidence", "semgrep_version", "semgrep_executable", "command",
    "working_directory", "rules_dir", "rules_sha256", "fixture_dir", "fixture_sha256", "scanned_paths",
    "raw_output_sha256", "committed_form", "report_sha256", "generated_on", "generated_by",
)
REQUIRED_FLAGS = ("--metrics=off", "--disable-version-check", "--json")


def tree_files(root, relative_dir, suffix=None):
    """Sorted repository-relative POSIX paths of the regular files under ``relative_dir`` (no links, no others)."""
    base = Path(root, *relative_dir.split("/"))
    found = []
    try:
        for directory, subdirectories, names in os.walk(base, followlinks=False):
            for name in subdirectories:
                if os.path.islink(os.path.join(directory, name)):
                    raise Refused("SAST-TREE-IRREGULAR")
            for name in names:
                path = Path(directory, name)
                if path.is_symlink() or not path.is_file():
                    raise Refused("SAST-TREE-IRREGULAR")
                if suffix is None or path.suffix == suffix:
                    found.append(path.relative_to(Path(root)).as_posix())
    except OSError:
        raise Refused("SAST-TREE-UNREADABLE") from None
    if not found:
        raise Refused("SAST-TREE-EMPTY")
    return sorted(found)


def tree_sha256(root, relative_dir, suffix=None):
    """Canonical SHA-256 of [{path, sha256}] over ``tree_files``; binds rule or fixture bytes and names."""
    entries = []
    for path in tree_files(root, relative_dir, suffix):
        data = read_bounded(Path(root, *path.split("/")), SOURCE_LIMIT, "SAST-TREE-UNREADABLE")
        if len(data) > SOURCE_LIMIT:
            raise Refused("SAST-TREE-UNREADABLE")
        entries.append({"path": path, "sha256": sha256_bytes(data)})
    return canonical_sha256(entries)


def verify_canned(report_data, provenance_data, root):
    """Bind a committed local Semgrep report to its provenance and to the current rule and fixture bytes.

    The canned report is a `local-fixture` input, never acceptance evidence: a changed rule file, planted source,
    Semgrep version, command or scanned path set makes it stale. Returns the provenance document.
    """
    provenance = exact(json_document(provenance_data, POLICY_LIMIT, "SAST-CANNED"), PROVENANCE_KEYS,
                       "SAST-CANNED-KEYS")
    if (provenance["schema"] != PROVENANCE_SCHEMA or provenance["kind"] != "local-fixture"
            or provenance["acceptance_evidence"] is not False):
        raise Refused("SAST-CANNED-KIND")
    rules_dir = relative_path(provenance["rules_dir"], "SAST-CANNED-COMMAND")
    fixture_dir = relative_path(provenance["fixture_dir"], "SAST-CANNED-COMMAND")
    command = provenance["command"]
    if (not isinstance(command, list) or not all(isinstance(item, str) for item in command)
            or not all(flag in command for flag in REQUIRED_FLAGS) or "auto" in command
            or any(item.startswith("--config=") for item in command)
            or command.count("--config") != 1 or command[command.index("--config") + 1] != rules_dir
            or command[-1] != fixture_dir):
        raise Refused("SAST-CANNED-COMMAND")
    if provenance["report_sha256"] != sha256_bytes(report_data):
        raise Refused("SAST-CANNED-REPORT-DIGEST")
    if provenance["rules_sha256"] != tree_sha256(root, rules_dir, RULE_SUFFIX):
        raise Refused("SAST-CANNED-RULES-STALE")
    if provenance["fixture_sha256"] != tree_sha256(root, fixture_dir):
        raise Refused("SAST-CANNED-FIXTURE-STALE")
    version, _results, _errors, _skipped, scanned = parse_report(report_data)
    if version != provenance["semgrep_version"]:
        raise Refused("SAST-CANNED-VERSION")
    if not list(scanned) == provenance["scanned_paths"] == tree_files(root, fixture_dir):
        raise Refused("SAST-CANNED-PATHS")
    return provenance


def _print(report):
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _arguments(argv):
    """`--report` and `--root` exactly once, `--policy` at most once; anything else is a usage refusal."""
    values = {}
    if len(argv) % 2:
        raise Refused("USAGE")
    for flag, value in zip(argv[::2], argv[1::2]):
        if flag not in ("--report", "--root", "--policy") or flag in values or not value:
            raise Refused("USAGE")
        values[flag] = value
    if not {"--report", "--root"} <= set(values):
        raise Refused("USAGE")
    return values


def main(argv=None, *, clock=None):
    """CLI; ``clock`` is a test seam returning the UTC date the warn windows are judged against."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["-h"], ["--help"]):
        print(__doc__.strip())
        return 0
    today = (clock or (lambda: datetime.datetime.now(datetime.timezone.utc).date()))()
    try:
        values = _arguments(argv)
        modes = load_policy(Path(values.get("--policy", POLICY_FILE)))
        data = read_bounded(values["--report"], REPORT_LIMIT, "SAST-REPORT-UNREADABLE")
        report = evaluate(data, Path(values["--root"]), modes, today)
    except Refused as error:
        _print({"schema": REPORT_SCHEMA, "decision": "refused", "reason": error.code})
        return 2
    _print(report)
    return 0 if report["decision"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
