"""Run the ordinary Windows owning suites and emit only safe, fresh per-test outcomes."""

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from types import ModuleType
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
PYTHON_TARGET = "test_money_mutation.ProcessBudgetTest.test_budgeted_quality_admits_only_the_approved_docker_directory"
KOTLIN_CLASS = "com.pennilogic.migration.AdmissionInstallationTest"
KOTLIN_METHOD = "a symlinked launcher cannot redirect execution()"
JUNIT = Path("build/test-results/test")
LOOKUP = Path("build/diagnostics/api106-approved-shell-module-lookup.jsonl")
LOOKUP_FILE_LIMIT = 8192
LOOKUP_RECORD_LIMIT = 6144
LOOKUP_EVENT = "windows_shell_lookup_diagnostic"
OBSERVER_STATE = LOOKUP.with_name("api106-observer-collection-state.jsonl")
OBSERVER_FILES = {
    "required-boundary": (LOOKUP.with_name("api106-approved-shell-boundary.bin"), 7),
    "required-lookup": (LOOKUP, LOOKUP_FILE_LIMIT),
    "pair": (LOOKUP.with_name("api106-approved-shell-observer-pair.jsonl"), 4096),
    "enclosure": (LOOKUP.with_name("api106-approved-shell-enclosure.jsonl"), 8192),
    "auxiliary-boundary": (LOOKUP.with_name("api106-approved-shell-auxiliary-boundary.bin"), 7),
    "auxiliary-lookup": (LOOKUP.with_name("api106-approved-shell-auxiliary-module-lookup.jsonl"), LOOKUP_FILE_LIMIT),
}
OBSERVER_BUDGET_BYTES = 30820
OBSERVER_BUDGET_SHA256 = "a551e6959a2a56c91e657a7c2a5b64b04607f56fe2f55f68e9e5cc4c9270f364"
OBSERVER_COMMAND_SECONDS = 270
OBSERVER_CLOSED_SECONDS = 300
SHELL_FOCUS_TARGET = "test_money_mutation.ProcessBudgetTest.test_approved_system_shell_survives_without_inheriting_ambient_path"
SHELL_FOCUS_SOURCES = {
    "scripts/tests/test_money_mutation.py": (235983, "c237505d6d986aa6fe98472ac874f92a4be62363fa7774723ea8cb9016d2fb72"),
    "scripts/money_mutation.py": (24847, "b4e9ca3218d16af605537714b365962d94f40265d092bb5302538e7efb7de000"),
    "scripts/quality.py": (33687, "725fac94b7c4496a265260503f5492acdc28d45e7690254f1328e596a11b42cd"),
    "scripts/process_budget.py": (30820, "a551e6959a2a56c91e657a7c2a5b64b04607f56fe2f55f68e9e5cc4c9270f364"),
}
SHELL_FOCUS_REFUSALS = {
    "focus-source-binding", "focus-preexisting-diagnostic-area", "focus-preexisting-test-module",
    "focus-module-or-seam", "focus-import-identity", "focus-target-count", "focus-child-record-limit",
    "focus-child-record-write", "focus-explicit-selection", "focus-python-comparison", "focus-image-metadata",
    "focus-child-result", "focus-child-output", "focus-exception-shape", "focus-requires-prepared", "focus-report-limit",
    "observer-job-context", "observer-workspace-identity", "observer-same-job-preparation", "observer-checkout-binding",
    "observer-git-state-changed", "observer-python-selection", "observer-git-selection", "observer-java-selection",
    "observer-runtime-path", "observer-runtime-shadowed", "observer-temporary-selection",
    "observer-unadmitted-runtime-state", "observer-budget-source",
    "reparse-path", "nonregular-path", "file-limit", "file-changed",
}
PYTHON_CASE = re.compile(rb"(test[A-Za-z0-9_]*) \(([A-Za-z_][A-Za-z0-9_.]*)\)(?: \.\.\. (.*))?")
PYTHON_SUMMARY = re.compile(rb"Ran (\d+) tests? in [0-9.]+s")
PYTHON_TERMINAL = re.compile(
    rb"(?:OK|FAILED)(?: \((?:failures|errors|skipped|expected failures|unexpected successes)=[0-9]+"
    rb"(?:, (?:failures|errors|skipped|expected failures|unexpected successes)=[0-9]+)*\))?"
)
STATUSES = {b"ok": "passed", b"FAIL": "failed", b"ERROR": "error",
            b"expected failure": "expected_failure", b"unexpected success": "unexpected_success"}
DIAGNOSTIC_CASE_LIMIT = 8
DIAGNOSTIC_FRAME_LIMIT = 8
DIAGNOSTIC_BYTE_LIMIT = 4096
JUNIT_DIAGNOSTIC_INTEGER_LIMIT = 4294967295
PROCESS_BUDGET_PREFIX = b"process_budget_state="
PROCESS_BUDGET_UNAVAILABLE = {"schema": "pennilogic.process-budget-state/1", "status": "unavailable"}
PROCESS_BUDGET_JOB_PREFIX = b"process_budget_job_state="
PROCESS_BUDGET_JOB_UNAVAILABLE = {
    "schema": "pennilogic.process-budget-job-state/1",
    "accounting": {"status": "unavailable"}, "members": {"status": "unavailable"},
}
PROCESS_BUDGET_CAPTURE_PREFIX = b"process_budget_capture_state="
PROCESS_BUDGET_CAPTURE_UNAVAILABLE = {"schema": "pennilogic.process-budget-capture-state/1", "status": "unavailable"}
PYTHON_ERROR_HEADER = re.compile(
    rb"(FAIL|ERROR): (test[A-Za-z0-9_]*) \(([A-Za-z_][A-Za-z0-9_.]*)\)"
)
PYTHON_FRAME = re.compile(rb'  File "([^"\x00-\x1f\x7f]+)", line ([1-9][0-9]{0,7}), in [^\r\n]+')
PYTHON_EXCEPTIONS = (
    "OSError", "FileNotFoundError", "PermissionError", "TimeoutError", "RuntimeError", "ValueError",
    "subprocess.SubprocessError", "subprocess.TimeoutExpired", "subprocess.CalledProcessError",
)


class Refused(ValueError):
    """A static qualification refusal, never a child diagnostic or fixture value."""


class _ObserverResultRefused(Refused):
    """Retain failed captures for the existing bounded outcome projection."""

    def __init__(self, result, secondary):
        super().__init__("owning-suite-command-failed")
        self.result = result
        self.__cause__ = secondary


class _PythonOutcomeRefused(Refused):
    def __init__(self, code, diagnostic):
        super().__init__(code)
        self.diagnostic = diagnostic


class _JunitOutcomeRefused(Refused):
    def __init__(self, diagnostic):
        super().__init__("duplicate-junit-case")
        self.diagnostic = diagnostic


def outcome(suite, identity, status, target=None):
    record = {
        "event": "test_outcome", "suite": suite,
        "id_sha256": hashlib.sha256(identity.encode("utf-8")).hexdigest(), "outcome": status,
    }
    if target is not None:
        record["required_test"] = target
    return record


def python_outcomes(data):
    records, identities = [], set()
    pending, total = None, None
    lines = data.splitlines()

    def refuse(code, boundary):
        negative = [record for record in records
                    if record["outcome"] in ("failed", "error", "unexpected_success")]
        raise _PythonOutcomeRefused(code, {
            "code": code, "boundary": boundary, "line": line_number,
            "count_summary_seen": total is not None,
            # Observed text only: even a quoted terminal cannot establish an outcome.
            "terminal_summary_seen": any(PYTHON_TERMINAL.fullmatch(line) for line in lines),
            "pending_id_sha256": hashlib.sha256(pending.encode("ascii")).hexdigest() if pending else None,
            "negative_prefix": [
                {"id_sha256": record["id_sha256"], "outcome": record["outcome"]}
                for record in negative[:DIAGNOSTIC_CASE_LIMIT]
            ],
            "negative_prefix_count": len(negative),
            "negative_prefix_truncated": len(negative) > DIAGNOSTIC_CASE_LIMIT,
        })

    for line_number, line in enumerate(lines, 1):
        summary = PYTHON_SUMMARY.fullmatch(line)
        if summary:
            if total is not None or pending is not None:
                refuse("ambiguous-python-summary", "count-summary")
            try:
                total = int(summary.group(1))
            except ValueError:
                refuse("invalid-python-summary-count", "count-summary")
            continue
        case = PYTHON_CASE.fullmatch(line)
        if case:
            if pending is not None or total is not None or not case.group(2).endswith(b"." + case.group(1)):
                refuse("ambiguous-python-case", "case-prefix")
            pending = case.group(2).decode("ascii")
            status = case.group(3)
            if status is None:
                continue
        elif pending is not None:
            # unittest's optional docstring occupies exactly the next line.
            if b" ... " not in line:
                refuse("ambiguous-python-outcome", "pending-description")
            status = line.rsplit(b" ... ", 1)[-1]
        else:
            status = line.rsplit(b" ... ", 1)[-1]
            if status in STATUSES or status.startswith(b"skipped "):
                refuse("unbound-python-outcome", "unbound-status")
            if records and total is None and line not in (b"", b"-" * 70):
                refuse("ambiguous-python-outcome", "before-count-summary")
            continue
        normalized = "skipped" if status.startswith(b"skipped ") else STATUSES.get(status)
        if normalized is None:
            refuse("ambiguous-python-outcome", "case-status")
        if pending in identities:
            refuse("duplicate-python-case", "duplicate-case")
        identities.add(pending)
        records.append(outcome("python", pending, normalized, PYTHON_TARGET if pending == PYTHON_TARGET else None))
        pending = None
    line_number = len(lines) + 1
    if pending is not None or total is None or total == 0 or len(records) != total:
        refuse("incomplete-python-outcomes", "end-of-stream")
    return records


def process_budget_note(line):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate-note-key")
            result[key] = value
        return result

    unavailable = dict(PROCESS_BUDGET_UNAVAILABLE)
    if len(line) > 384 or not line.isascii() or not line.startswith(PROCESS_BUDGET_PREFIX):
        return unavailable
    try:
        value = json.loads(line[len(PROCESS_BUDGET_PREFIX):], object_pairs_hook=unique)
    except (UnicodeError, ValueError, RecursionError):
        return unavailable
    if (not isinstance(value, dict) or value.get("schema") != unavailable["schema"]
            or line != PROCESS_BUDGET_PREFIX + json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")):
        return unavailable
    if value == unavailable:
        return value
    fields = {"schema", "status", "process_running", "returncode", "capture_readers",
              "capture_readers_alive", "setup_ms", "wait_ms", "elapsed_ms"}
    if set(value) != fields or value["status"] != "observed" or type(value["process_running"]) is not bool:
        return unavailable
    code = value["returncode"]
    if (value["process_running"] and code is not None) or (
        not value["process_running"] and (type(code) is not int or not -2147483648 <= code <= 4294967295)
    ):
        return unavailable
    for key, limit in (("capture_readers", 2), ("capture_readers_alive", 2),
                       ("setup_ms", 86400000), ("wait_ms", 86400000), ("elapsed_ms", 86400000)):
        if type(value[key]) is not int or not 0 <= value[key] <= limit:
            return unavailable
    if (value["capture_readers_alive"] > value["capture_readers"]
            or value["setup_ms"] + value["wait_ms"] != value["elapsed_ms"]):
        return unavailable
    return value


def process_budget_job_note(line):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate-note-key")
            result[key] = value
        return result

    unavailable = {key: dict(value) if isinstance(value, dict) else value
                   for key, value in PROCESS_BUDGET_JOB_UNAVAILABLE.items()}
    if len(line) > 512 or not line.isascii() or not line.startswith(PROCESS_BUDGET_JOB_PREFIX):
        return unavailable
    try:
        value = json.loads(line[len(PROCESS_BUDGET_JOB_PREFIX):], object_pairs_hook=unique)
    except (UnicodeError, ValueError, RecursionError):
        return unavailable
    if (not isinstance(value, dict) or set(value) != {"schema", "accounting", "members"}
            or value["schema"] != unavailable["schema"]
            or line != PROCESS_BUDGET_JOB_PREFIX + json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")):
        return unavailable
    accounting, members = value["accounting"], value["members"]
    if not isinstance(accounting, dict) or not isinstance(members, dict):
        return unavailable
    if accounting.get("status") == "observed":
        if (set(accounting) != {"status", "total_assigned", "active"}
                or any(type(accounting[key]) is not int or not 0 <= accounting[key] <= 4294967295
                       for key in ("total_assigned", "active"))
                or accounting["active"] > accounting["total_assigned"]):
            return unavailable
    elif accounting not in ({"status": "unavailable"}, {"status": "unsupported"}):
        return unavailable
    if members.get("status") in ("observed", "partial"):
        roles = ("bootstrap", "system_approved_shell", "other", "unclassified")
        if (set(members) != {"status", "listed", *roles}
                or any(type(members[key]) is not int or not 0 <= members[key] <= 16
                       for key in ("listed", *roles))
                or members["bootstrap"] > 1 or sum(members[key] for key in roles) != members["listed"]
                or (members["status"] == "observed" and members["unclassified"] != 0)):
            return unavailable
        if accounting["status"] == "observed" and members["listed"] != accounting["active"]:
            members["status"] = "partial"
    elif members not in ({"status": "unavailable"}, {"status": "unsupported"}, {"status": "oversized"}):
        return unavailable
    return value


def process_budget_capture_note(line):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate-note-key")
            result[key] = value
        return result

    unavailable = dict(PROCESS_BUDGET_CAPTURE_UNAVAILABLE)
    if len(line) > 512 or not line.isascii() or not line.startswith(PROCESS_BUDGET_CAPTURE_PREFIX):
        return unavailable
    try:
        value = json.loads(line[len(PROCESS_BUDGET_CAPTURE_PREFIX):], object_pairs_hook=unique)
    except (UnicodeError, ValueError, RecursionError):
        return unavailable
    if (not isinstance(value, dict) or value.get("schema") != unavailable["schema"]
            or line != PROCESS_BUDGET_CAPTURE_PREFIX + json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")):
        return unavailable
    if value == unavailable:
        return value
    if (set(value) != {"schema", "status", "scope", "complete", "mode", "stdout", "stderr"}
            or value["status"] != "observed" or value["scope"] != "snapshot" or value["complete"] is not False
            or value["mode"] not in ("merged", "separate")):
        return unavailable
    empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    for name in ("stdout", "stderr"):
        stream = value[name]
        if (not isinstance(stream, dict) or set(stream) != {"bytes", "sha256"}
                or type(stream["bytes"]) is not int or not 0 <= stream["bytes"] <= 18446744073709551615
                or not isinstance(stream["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", stream["sha256"]) is None
                or (stream["bytes"] == 0 and stream["sha256"] != empty)):
            return unavailable
    if value["mode"] == "merged" and value["stderr"] != {"bytes": 0, "sha256": empty}:
        return unavailable
    return value


def python_error_diagnostics(root, data, parser):
    selected = {record["id_sha256"]: None for record in parser["negative_prefix"] if record["outcome"] == "error"}
    if not selected:
        return parser["negative_prefix"]
    prefix = (str(root).replace("\\", "/").rstrip("/") + "/").encode("utf-8", "surrogatepass")
    lines, seen = data.splitlines(), set()
    separator, divider = b"=" * 70, b"-" * 70
    traceback_header = b"Traceback (most recent call last):"
    for index in range(parser["line"] - 1, len(lines) - 3):
        if lines[index] != separator:
            continue
        header = PYTHON_ERROR_HEADER.fullmatch(lines[index + 1])
        if header is None:
            continue
        digest = hashlib.sha256(header.group(3)).hexdigest()
        if digest not in selected:
            continue
        if digest in seen:
            selected[digest] = None
            continue
        seen.add(digest)
        if header.group(1) != b"ERROR" or not header.group(3).endswith(b"." + header.group(2)):
            continue
        start = index + 2
        if lines[start] != divider:
            start += 1  # unittest may include one short-description line.
        if start + 1 >= len(lines) or lines[start:start + 2] != [divider, traceback_header]:
            continue
        start += 2
        end = start
        while end < len(lines) and lines[end] not in (separator, divider):
            end += 1
        boundary = (
            end + 2 < len(lines) and lines[end] == separator
            and PYTHON_ERROR_HEADER.fullmatch(lines[end + 1]) is not None
            and (lines[end + 2] == divider or (end + 3 < len(lines) and lines[end + 3] == divider))
        ) or (
            end + 3 < len(lines) and lines[end] == divider and PYTHON_SUMMARY.fullmatch(lines[end + 1]) is not None
            and lines[end + 2] == b"" and PYTHON_TERMINAL.fullmatch(lines[end + 3]) is not None
        )
        frames, exception, malformed, truncated = [], None, False, False
        notes, job_notes, capture_notes = [], [], []
        last_content = next((line for line in reversed(lines[start:end]) if line), b"")
        for position, line in enumerate(lines[start:end], start):
            if line in (
                traceback_header, b"During handling of the above exception, another exception occurred:",
                b"The above exception was the direct cause of the following exception:",
            ):
                malformed = True
            if line.startswith(PROCESS_BUDGET_PREFIX):
                notes.append((line, exception is not None, position))
            if line.startswith(PROCESS_BUDGET_JOB_PREFIX):
                job_notes.append((line, exception is not None, position))
            if line.startswith(PROCESS_BUDGET_CAPTURE_PREFIX):
                capture_notes.append((line, exception is not None, position))
            if exception is not None:
                continue
            if line.startswith(b"  File "):
                frame = PYTHON_FRAME.fullmatch(line)
                if frame is None:
                    malformed = True
                    continue
                path = frame.group(1).replace(b"\\", b"/")
                if not path.startswith(prefix):
                    continue
                relative = path[len(prefix):]
                if any(part in (b"", b".", b"..") for part in relative.split(b"/")):
                    malformed = True
                    continue
                location = {"path_sha256": hashlib.sha256(relative).hexdigest(), "line": int(frame.group(2))}
                if location not in frames:
                    if len(frames) == DIAGNOSTIC_FRAME_LIMIT:
                        truncated = True
                    else:
                        frames.append(location)
            elif line and not line.startswith(b" "):
                exception = next((name for name in PYTHON_EXCEPTIONS
                                  if line == name.encode("ascii") or line.startswith(name.encode("ascii") + b": ")),
                                 "unclassified")
        if malformed:
            frames = []
        if malformed or not boundary or not frames or exception is None:
            exception = "unclassified"
        detail = {"exception": exception, "source_frames": frames,
                  "incomplete": exception == "unclassified" or truncated, "truncated": truncated}
        if notes:
            valid = (len(notes) == 1 and notes[0][1] and notes[0][0] == last_content
                     and boundary and not malformed and bool(frames))
            state = process_budget_note(notes[0][0]) if valid else dict(PROCESS_BUDGET_UNAVAILABLE)
            detail["process_budget_state"] = state
            detail["incomplete"] |= state["status"] == "unavailable"
        if job_notes:
            valid = (len(job_notes) == 1 and job_notes[0][1] and len(notes) == 1 and notes[0][1]
                     and notes[0][0] == last_content and job_notes[0][2] + 1 == notes[0][2]
                     and boundary and not malformed and bool(frames))
            state = process_budget_job_note(job_notes[0][0] if valid else b"")
            detail["process_budget_job_state"] = state
            detail["incomplete"] |= any(state[part]["status"] != "observed" for part in ("accounting", "members"))
        if capture_notes:
            valid = (len(capture_notes) == 1 and capture_notes[0][1] and len(notes) == 1 and notes[0][1]
                     and notes[0][0] == last_content and boundary and not malformed and bool(frames))
            if job_notes:
                valid = (valid and len(job_notes) == 1 and job_notes[0][1]
                         and capture_notes[0][2] + 1 == job_notes[0][2] and job_notes[0][2] + 1 == notes[0][2])
            else:
                valid = valid and capture_notes[0][2] + 1 == notes[0][2]
            detail["process_budget_capture_state"] = process_budget_capture_note(capture_notes[0][0] if valid else b"")
            detail["incomplete"] = True  # Snapshot completeness is unestablished, not observed truncation.
        selected[digest] = detail
    remaining, records = DIAGNOSTIC_FRAME_LIMIT, []
    for record in parser["negative_prefix"]:
        if record["outcome"] == "error":
            detail = selected[record["id_sha256"]] or {
                "exception": "unclassified", "source_frames": [], "incomplete": True, "truncated": False,
            }
            if len(detail["source_frames"]) > remaining:
                detail.update(source_frames=detail["source_frames"][:remaining], incomplete=True, truncated=True)
            remaining -= len(detail["source_frames"])
            record = {**record, "error": detail}
        records.append(record)
    return records


def python_diagnostic_json(diagnostic):
    encoded = json.dumps(diagnostic, sort_keys=True)
    for field, unavailable in (
        ("process_budget_capture_state", PROCESS_BUDGET_CAPTURE_UNAVAILABLE),
        ("process_budget_job_state", PROCESS_BUDGET_JOB_UNAVAILABLE),
        ("process_budget_state", PROCESS_BUDGET_UNAVAILABLE),
    ):
        for replacement in (unavailable, None):
            for record in reversed(diagnostic["parser"]["negative_prefix"]):
                if len(encoded.encode("utf-8")) < DIAGNOSTIC_BYTE_LIMIT:
                    return encoded
                detail = record.get("error", {})
                if field not in detail:
                    continue
                if replacement is None:
                    del detail[field]
                elif detail[field] == replacement:
                    continue
                else:
                    detail[field] = dict(replacement)
                detail.update(incomplete=True, truncated=True)
                encoded = json.dumps(diagnostic, sort_keys=True)
    return encoded


def qualification_python_outcomes(root, result, output, errors):
    try:
        return python_outcomes(errors)
    except _PythonOutcomeRefused as error:
        print(python_diagnostic_json({
            "event": "windows_qualification_diagnostic", "diagnostic_only": True,
            "inventory_complete": False, "exit_code": result.returncode,
            "stdout": {"bytes": len(output), "sha256": hashlib.sha256(output).hexdigest()},
            "stderr": {"bytes": len(errors), "sha256": hashlib.sha256(errors).hexdigest()},
            "parser": {**error.diagnostic,
                       "negative_prefix": python_error_diagnostics(root, errors, error.diagnostic)},
        }), flush=True)
        raise


def junit_diagnostic_number(value):
    if type(value) is str and len(value) <= 32:
        try:
            value = int(value)
        except ValueError:
            return None
    return value if type(value) is int and 0 <= value <= JUNIT_DIAGNOSTIC_INTEGER_LIMIT else None


def junit_report_metadata(byte_count, digest, suite, case_count):
    # Observe later counters without changing their existing admission order.
    counts = {name: junit_diagnostic_number(suite.get(name)) for name in ("tests", "failures", "errors", "skipped")}
    size, cases = junit_diagnostic_number(byte_count), junit_diagnostic_number(case_count)
    return {
        "bytes": size, "sha256": digest,
        "testcase_count": cases, "suite_counts": counts,
        "metadata_complete": all(value is not None for value in (size, cases, *counts.values())),
    }


def junit_outcomes(root):
    directory = root / JUNIT
    if directory.is_symlink() or not directory.is_dir():
        raise Refused("missing-ordinary-junit-results")
    records, identities = [], {}
    paths = sorted(directory.glob("TEST-*.xml"))
    for report_position, path in enumerate(paths, 1):
        if path.is_symlink() or not path.is_file():
            raise Refused("invalid-junit-result-file")
        digest, byte_count, parser = hashlib.sha256(), 0, ET.XMLParser()
        with path.open("rb") as stream:
            while chunk := stream.read(65536):
                digest.update(chunk)
                byte_count += len(chunk)
                parser.feed(chunk)
        suite = parser.close()
        cases = suite.findall("testcase")
        if suite.tag != "testsuite" or int(suite.get("tests", "-1")) != len(cases):
            raise Refused("incomplete-junit-outcomes")
        report = junit_report_metadata(byte_count, digest.hexdigest(), suite, len(cases))
        counts = {"failure": 0, "error": 0, "skipped": 0}
        for case_position, case in enumerate(cases, 1):
            class_name, name = case.get("classname"), case.get("name")
            if not class_name or not name:
                raise Refused("missing-junit-identity")
            identity = class_name + "\0" + name
            if identity in identities:
                first_report, first_case, first_metadata = identities[identity]
                raise _JunitOutcomeRefused({
                    "code": "duplicate-junit-case",
                    "id_sha256": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
                    "classname_sha256": hashlib.sha256(class_name.encode("utf-8")).hexdigest(),
                    "name_sha256": hashlib.sha256(name.encode("utf-8")).hexdigest(),
                    "same_report": first_report == report_position,
                    "first": {"report_position": junit_diagnostic_number(first_report),
                              "case_position": junit_diagnostic_number(first_case), "report": first_metadata},
                    "current": {"report_position": junit_diagnostic_number(report_position),
                                "case_position": junit_diagnostic_number(case_position), "report": report},
                    "prefix": {"selected_reports": junit_diagnostic_number(len(paths)),
                               "completed_reports": junit_diagnostic_number(report_position - 1),
                               "completed_cases": junit_diagnostic_number(len(records)),
                               "encountered_cases": junit_diagnostic_number(len(records) + 1)},
                })
            identities[identity] = (report_position, case_position, report)
            flags = [tag for tag in ("failure", "error", "skipped") if case.find(tag) is not None]
            if len(flags) > 1:
                raise Refused("ambiguous-junit-outcome")
            if flags:
                counts[flags[0]] += 1
            status = {"failure": "failed", "error": "error", "skipped": "skipped"}[flags[0]] if flags else "passed"
            target = KOTLIN_CLASS + "." + KOTLIN_METHOD if (class_name, name) == (KOTLIN_CLASS, KOTLIN_METHOD) else None
            records.append(outcome("junit:test", identity, status, target))
        for tag, attribute in (("failure", "failures"), ("error", "errors"), ("skipped", "skipped")):
            if int(suite.get(attribute, "-1")) != counts[tag]:
                raise Refused("inconsistent-junit-outcome-counts")
    if not records:
        raise Refused("empty-ordinary-junit-results")
    return records


def qualification_junit_outcomes(root, result, output):
    test_tasks = [line for line in output.splitlines() if re.fullmatch(rb"> Task :test(?: .*)?", line)]
    if test_tasks not in ([b"> Task :test"], [b"> Task :test FAILED"]):
        raise Refused("ordinary-gradle-test-was-not-fresh")
    if test_tasks == [b"> Task :test FAILED"] and result.returncode == 0:
        raise Refused("inconsistent-gradle-task-result")
    try:
        junit = junit_outcomes(root)
    except _JunitOutcomeRefused as error:
        print(json.dumps({
            "event": "windows_qualification_diagnostic", "diagnostic_only": True,
            "inventory_complete": False, "exit_code": result.returncode, "junit": error.diagnostic,
        }, sort_keys=True), flush=True)
        raise
    return junit


def lookup_path_metadata(root, relative=LOOKUP):
    path = root
    for index, part in enumerate(("", *relative.parts)):
        if part:
            path = path / part
        metadata = path.lstat()
        # Windows junctions can report a directory mode and still be reparse points.
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise Refused("reparse-path")
        regular = stat.S_ISREG if index == len(relative.parts) else stat.S_ISDIR
        if not regular(metadata.st_mode):
            raise Refused("nonregular-path")
    return metadata


def diagnostic_bytes(root, relative, limit):
    def metadata():
        return lookup_path_metadata(root) if relative == LOOKUP else lookup_path_metadata(root, relative)

    prior = metadata()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(root / relative, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(prior, opened):
                raise Refused("file-changed")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
    finally:
        os.close(descriptor)
    current = metadata()
    if (any(not os.path.samestat(opened, other) for other in (after, current))
            or len({item.st_size for item in (prior, opened, after, current)}) != 1
            or len({item.st_mtime_ns for item in (prior, opened, after, current)}) != 1):
        raise Refused("file-changed")
    if len(data) != min(current.st_size, limit + 1):
        raise Refused("incomplete-read")
    return data


def lookup_before(root):
    try:
        lookup_path_metadata(root)
    except FileNotFoundError:
        return "absent"
    except Refused as error:
        return str(error)
    except OSError:
        return "preflight-unavailable"
    return "preexisting-capsule"


def lookup_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused("duplicate-json-key")
        result[key] = value
    return result


def lookup_records(data):
    if len(data) > LOOKUP_FILE_LIMIT:
        raise Refused("file-limit")
    if not data:
        return []
    if not data.isascii() or b"\r" in data or b"\x1b" in data:
        raise Refused("encoding")
    if not data.endswith(b"\n"):
        raise Refused("partial-line")
    lines = data.split(b"\n")[:-1]
    if len(lines) > 4:
        if len(lines) != 5:
            raise Refused("record-count")
        # Only an explicit v2 first record can extend the historical four-record cap.
        try:
            first = json.loads(lines[0].decode("ascii"), object_pairs_hook=lookup_json_object)
        except (Refused, ValueError, RecursionError):
            raise Refused("record-count") from None
        if type(first) is not dict or type(first.get("v")) is not int or first["v"] != 2:
            raise Refused("record-count")
    if any(len(line) + 1 > LOOKUP_RECORD_LIMIT for line in lines):
        raise Refused("record-limit")
    if any(not line.strip() for line in lines):
        raise Refused("blank-line")
    try:
        records = [json.loads(line.decode("ascii"), object_pairs_hook=lookup_json_object) for line in lines]
    except Refused:
        raise
    except (ValueError, RecursionError):
        raise Refused("invalid-json") from None

    def keys(value, expected):
        if type(value) is not dict or set(value) != set(expected):
            raise Refused("record-shape")

    def digest(value):
        return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None

    def milliseconds(value):
        return value is None or (type(value) is int and 0 <= value <= 600000)

    version = records[0].get("v") if type(records[0]) is dict else None
    phases = []
    for record in records:
        if (type(record) is not dict or type(record.get("v")) is not int
                or record["v"] not in (1, 2) or record["v"] != version
                or type(record.get("phase")) is not str or type(record.get("status")) is not str):
            raise Refused("record-shape")
        phase, status = record["phase"], record["status"]
        phases.append(phase)
        if phase == "roots" and status == "observed":
            keys(record, ("v", "phase", "status", "value", "roots"))
            roots, value = record["roots"], record["value"]
            if (type(roots) is not list or len(roots) > 32 or value not in ("present", "absent")
                    or (value == "absent") != (len(roots) == 0)):
                raise Refused("roots")
            seen = {}
            empty = hashlib.sha256(b"").hexdigest()
            for index, entry in enumerate(roots):
                keys(entry, ("i", "kind", "sha256", "duplicate_of"))
                kind, hashed, duplicate = entry["kind"], entry["sha256"], entry["duplicate_of"]
                if (type(entry["i"]) is not int or entry["i"] != index
                        or kind not in ("pshome", "unknown", "empty") or not digest(hashed)
                        or (kind == "empty") != (hashed == empty)
                        or (duplicate is not None and (type(duplicate) is not int or not 0 <= duplicate < index))):
                    raise Refused("roots")
                if hashed in seen:
                    first, first_kind = seen[hashed]
                    if duplicate != first or kind != first_kind:
                        raise Refused("roots")
                elif duplicate is not None:
                    raise Refused("roots")
                else:
                    seen[hashed] = (index, kind)
        elif phase == "observer" and status == "armed":
            keys(record, ("v", "phase", "status") + (("not_found",) if version == 2 else ()))
        elif status == "observed" and (phase == "pre" or (version == 2 and phase == "not-found")):
            keys(record, ("v", "phase", "status", "ms"))
            if not milliseconds(record["ms"]):
                raise Refused("timing")
        elif phase == "post" and status == "observed":
            keys(record, ("v", "phase", "status", "ms", "lookup_ms", "command_type", "module_kind", "module_sha256"))
            if not milliseconds(record["ms"]) or not milliseconds(record["lookup_ms"]):
                raise Refused("timing")
            kind, hashed, command = record["module_kind"], record["module_sha256"], record["command_type"]
            if (kind not in ("no-command", "none", "unknown", "pshome", "other")
                    or (kind == "no-command" and command is not None)
                    or (kind != "no-command" and (type(command) is not int or command not in (1, 2, 4, 8, 16, 32, 64, 128, 256)))
                    or (kind in ("pshome", "other") and not digest(hashed))
                    or (kind not in ("pshome", "other") and hashed is not None)):
                raise Refused("provenance")
        else:
            keys(record, ("v", "phase", "status", "code")
                 + (("not_found",) if version == 2 and phase == "observer" else ()))
            allowed = {
                ("roots", "refused"): ("input-limit", "encoding", "snapshot"),
                ("observer", "unavailable"): ("roots-refused", "existing-hooks", "unsupported-api"),
                ("observer", "refused"): ("install",),
                ("post", "unavailable"): ("observer-unavailable", "no-pre", "no-post", "nested-target", "post-without-pre"),
                ("post", "refused"): ("command-type", "module-path-limit", "callback"),
            }
            if record["code"] not in allowed.get((phase, status), ()):
                raise Refused("record-shape")
        if version == 2 and phase == "observer":
            negative = record["not_found"]
            if type(negative) is not dict or type(negative.get("status")) is not str:
                raise Refused("record-shape")
            if negative["status"] == "armed":
                keys(negative, ("status",))
            else:
                keys(negative, ("status", "code"))
                allowed = {
                    "unavailable": ("existing-hook", "unsupported-api", "observer-unavailable"),
                    "refused": ("install",),
                }
                if negative["code"] not in allowed.get(negative["status"], ()):
                    raise Refused("record-shape")
            if (status != "armed") != (negative.get("code") == "observer-unavailable"):
                raise Refused("record-order")
    tails = ((), ("pre",), ("post",), ("pre", "post"))
    if version == 2:
        tails += (("pre", "not-found"), ("pre", "not-found", "post"))
    if (phases[:1] != ["roots"] or (len(phases) >= 2 and phases[1] != "observer")
            or tuple(phases[2:]) not in tails):
        raise Refused("record-order")
    if len(records) >= 2:
        roots, observer = records[:2]
        if (roots["status"] == "refused") != (observer.get("code") == "roots-refused"):
            raise Refused("record-order")
        armed = observer["status"] == "armed"
        pre = records[2] if len(records) >= 3 and phases[2] == "pre" else None
        negative = records[3] if len(records) >= 4 and phases[3] == "not-found" else None
        post = records[-1] if phases[-1] == "post" else None
        if pre is not None and not armed:
            raise Refused("record-order")
        if negative is not None:
            if observer["not_found"]["status"] != "armed":
                raise Refused("record-order")
            samples = [pre["ms"], negative["ms"]]
            if post is not None and post["status"] == "observed":
                samples.append(post["ms"])
            available = [sample for sample in samples if sample is not None]
            if any(first > second for first, second in zip(available, available[1:])):
                raise Refused("timing")
        if post is not None:
            code = post.get("code")
            if not armed:
                if code != "observer-unavailable":
                    raise Refused("record-order")
            elif post["status"] == "observed":
                if pre is None:
                    raise Refused("record-order")
                start, end, elapsed = pre["ms"], post["ms"], post["lookup_ms"]
                if start is None or end is None:
                    if elapsed is not None:
                        raise Refused("timing")
                elif end < start or elapsed != end - start:
                    raise Refused("timing")
            elif (code == "observer-unavailable"
                  or (code in ("no-pre", "post-without-pre") and pre is not None)
                  or (code in ("no-post", "nested-target", "command-type", "module-path-limit") and pre is None)):
                raise Refused("record-order")
    return records


def lookup_projection(records):
    projected = []
    for record in records:
        if record["phase"] == "roots" and record["status"] == "observed":
            columns = ["i", "kind", "sha256", "duplicate_of"]
            record = {**record, "root_columns": columns,
                      "roots": [[entry[key] for key in columns] for entry in record["roots"]]}
        projected.append(record)
    return projected


def lookup_diagnostic_json(root, before):
    base = {"event": LOOKUP_EVENT, "diagnostic_only": True, "capsule_complete": False}
    result = dict(base)
    try:
        if before != "absent":
            known = ("preexisting-capsule", "preflight-unavailable", "reparse-path", "nonregular-path")
            raise Refused(before if type(before) is str and before in known else "freshness-unavailable")
        data = diagnostic_bytes(root, LOOKUP, LOOKUP_FILE_LIMIT)
        records = lookup_records(data)
        complete = bool(records and records[-1]["phase"] == "post")
        result.update(status="observed" if complete else "partial", capsule_complete=complete,
                      records=lookup_projection(records))
        if not complete:
            result["code"] = "incomplete-prefix" if records else "empty-prefix"
    except FileNotFoundError:
        result.update(status="unavailable", code="not-observed")
    except Refused as error:
        result.update(status="refused", code=str(error))
    except OSError:
        result.update(status="unavailable", code="read-error")
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("ascii")) + len(os.linesep) > DIAGNOSTIC_BYTE_LIMIT:
        return json.dumps({**base, "status": "refused", "code": "projection-limit"},
                          sort_keys=True, separators=(",", ":"))
    return encoded


def observer_require(condition, code="observer-record-shape"):
    if not condition:
        raise Refused(code)


def observer_integer(value, lower=0, upper=4294967295):
    return type(value) is int and lower <= value <= upper


def observer_digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def observer_json_lines(data, byte_limit, record_limit):
    observer_require(len(data) <= byte_limit, "file-limit")
    if not data:
        return []
    observer_require(data.isascii() and b"\r" not in data and b"\x1b" not in data, "encoding")
    observer_require(data.endswith(b"\n"), "partial-line")
    lines = data.split(b"\n")[:-1]
    observer_require(len(lines) <= record_limit, "record-count")
    observer_require(all(0 < len(line) and len(line) + 1 <= 1024 for line in lines), "record-limit")
    try:
        return [json.loads(line, object_pairs_hook=lookup_json_object) for line in lines]
    except Refused:
        raise
    except (ValueError, RecursionError):
        raise Refused("invalid-json") from None


def observer_envelope(record, event, fields):
    observer_require(type(record) is dict and set(record) == {"event", "v", "diagnostic_only", "phase", *fields})
    observer_require(record["event"] == event and type(record["v"]) is int and record["v"] == 1
                     and record["diagnostic_only"] is True)


def observer_pair_records(data):
    records = observer_json_lines(data, 4096, 6)
    roles = ("required", "auxiliary-no-lookup-delegates")
    outcomes, started = {}, None
    event = "api106_approved_shell_observer_pair"
    for index, record in enumerate(records):
        observer_require(type(record) is dict and type(record.get("phase")) is str)
        phase = record["phase"]
        if index == 0:
            observer_envelope(record, event, (
                "order", "enclosing_seconds", "cleanup_reserve_seconds", "arm_work_seconds", "arm_cleanup_seconds",
            ))
            observer_require(phase == "begin" and record["order"] == "required-then-auxiliary")
            for key, value in (("enclosing_seconds", 60), ("cleanup_reserve_seconds", 12),
                               ("arm_work_seconds", 10), ("arm_cleanup_seconds", 10)):
                observer_require(type(record[key]) is int and record[key] == value)
        elif phase == "complete":
            observer_envelope(record, event, ("required", "auxiliary", "acceptance"))
            observer_require(index == len(records) - 1 and started is None and len(outcomes) == 2,
                             "observer-record-order")
            observer_require(record["acceptance"] is False and record["required"] == outcomes[roles[0]]
                             and record["auxiliary"] == outcomes[roles[1]])
        else:
            observer_require(len(outcomes) < 2 and record.get("role") == roles[len(outcomes)],
                             "observer-record-order")
            role = record["role"]
            if role == roles[1] and outcomes[roles[0]] == "process-or-cleanup-error":
                observer_require(phase == "arm" and record.get("outcome") == "not-executed"
                                 and record.get("reason") == "required-process-or-cleanup-error",
                                 "observer-record-order")
            if phase == "started":
                observer_envelope(record, event, ("role",))
                observer_require(started is None, "observer-record-order")
                started = role
            else:
                observer_require(phase == "arm", "observer-record-order")
                outcome = record.get("outcome")
                if outcome == "not-executed":
                    observer_envelope(record, event, ("role", "outcome", "reason"))
                    reason = record["reason"]
                    observer_require(reason == "insufficient-complete-arm-budget" or (
                        reason == "required-process-or-cleanup-error" and role == roles[1]
                        and started is None and outcomes[roles[0]] == "process-or-cleanup-error"))
                    observer_require(index == len(records) - 1 or (
                        reason == "required-process-or-cleanup-error" and index == len(records) - 2),
                        "observer-record-order")
                else:
                    observer_envelope(record, event, ("role", "outcome", "elapsed_ms", "returncode", "stdout"))
                    observer_require(started == role and outcome in (
                        "passed", "work-budget-exceeded", "output-budget-exceeded",
                        "assertion-failed", "process-or-cleanup-error",
                    ), "observer-record-order")
                    observer_require(observer_integer(record["elapsed_ms"]))
                    observer_require(record["returncode"] is None
                                     or observer_integer(record["returncode"], -2147483648))
                    captured = record["stdout"]
                    if captured is not None:
                        observer_require(type(captured) is dict and set(captured) == {"text_bytes", "sha256"})
                        observer_require(observer_integer(captured["text_bytes"]) and observer_digest(captured["sha256"]))
                        observer_require(captured["text_bytes"] != 0
                                         or captured["sha256"] == hashlib.sha256(b"").hexdigest())
                    if outcome == "passed":
                        observer_require(record["returncode"] == 0 and captured is not None)
                outcomes[role], started = outcome, None
    return records, bool(records and records[-1]["phase"] == "complete")


def observer_enclosure_records(data):
    records = observer_json_lines(data, 8192, 8)
    order = ("admitted", "armed", "body-left", "case-closed", "suite-exit")
    position, last_ms = 0, None
    for index, record in enumerate(records):
        observer_require(type(record) is dict and type(record.get("phase")) is str)
        phase = record["phase"]
        event = "api106_approved_shell_enclosure"
        if phase == "cleanup":
            observer_envelope(record, event, ("owned_tree_and_control_released", "report_close_not_attested_by_this_record"))
            observer_require(index == len(records) - 1, "observer-record-order")
            observer_require(type(record["owned_tree_and_control_released"]) is bool
                             and record["report_close_not_attested_by_this_record"] is True)
            continue
        observer_require(position < len(order) and phase == order[position], "observer-record-order")
        position += 1
        if phase == "admitted":
            observer_envelope(record, event, ("binding_sha256", "sources", "python", "work_seconds",
                                              "total_seconds", "cleanup_reserve_seconds"))
            observer_require(observer_digest(record["binding_sha256"]) and observer_digest(record["python"])
                             and observer_integer(record["sources"], 1))
            for key, value in (("work_seconds", 48), ("total_seconds", 60), ("cleanup_reserve_seconds", 12)):
                observer_require(type(record[key]) is int and record[key] == value)
        elif phase == "suite-exit":
            observer_envelope(record, event, ("exit_code", "tests_run", "tests_discovered", "inventory_complete"))
            observer_require(type(record["exit_code"]) is int and record["exit_code"] in (0, 1)
                             and observer_integer(record["tests_run"])
                             and observer_integer(record["tests_discovered"], 1))
            complete = record["tests_run"] == record["tests_discovered"]
            observer_require(record["inventory_complete"] is complete
                             and (record["exit_code"] != 0 or complete))
        else:
            observer_envelope(record, event, ("elapsed_ms", "known_live_discovery_members", "suite_job_retained"))
            observer_require(observer_integer(record["elapsed_ms"]) and (
                last_ms is None or record["elapsed_ms"] >= last_ms))
            observer_require(type(record["known_live_discovery_members"]) is int
                             and record["known_live_discovery_members"] == 1 and record["suite_job_retained"] is True)
            last_ms = record["elapsed_ms"]
    complete = bool(records and position == len(order) and records[-1]["phase"] == "cleanup")
    return records, complete


def observer_context(root, *, shell_focus=False):
    observer_require(type(shell_focus) is bool, "observer-job-context")
    for path in (root, *root.parents):
        metadata = path.lstat()
        observer_require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
                         and not getattr(metadata, "st_file_attributes", 0) & 0x400, "reparse-path")
    metadata = root.lstat()
    observer_require(type(metadata.st_ino) is int and metadata.st_ino > 0, "observer-workspace-identity")
    context = [metadata.st_dev, metadata.st_ino]
    actions = os.environ.get("GITHUB_ACTIONS")
    observer_require(actions in (None, "false", "true"), "observer-job-context")
    if actions == "true":
        for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
            value = os.environ.get(key, "")
            observer_require(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None, "observer-job-context")
            context.append(value)
        observer_require(os.environ.get("GITHUB_REPOSITORY") == "PenniLogic/api"
                         and os.environ.get("GITHUB_REPOSITORY_ID") == "1394134582"
                         and os.environ.get("GITHUB_REPOSITORY_OWNER_ID") == "335295566"
                         and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                         and os.environ.get("GITHUB_JOB") == ("api106-shell-focus" if shell_focus else "windows"),
                         "observer-job-context")
        sha = os.environ.get("GITHUB_SHA", "")
        observer_require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "observer-job-context")
        context.append(sha)
    else:
        observer_require(not any(key in os.environ for key in (
            "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REPOSITORY_ID",
            "GITHUB_REPOSITORY_OWNER_ID", "GITHUB_JOB", "GITHUB_SHA",
        )), "observer-job-context")
        context.append("local-workspace-only")
    if shell_focus:
        observer_require(actions == "true", "observer-job-context")
        context.append("api106-shell-focus")
    return hashlib.sha256(json.dumps(context, separators=(",", ":")).encode("ascii")).hexdigest()


def observer_state_record(stream, root, fields):
    opened = os.fstat(stream.fileno())
    current = lookup_path_metadata(root, OBSERVER_STATE)
    observer_require(os.path.samestat(opened, current) and opened.st_nlink == 1
                     and opened.st_size == current.st_size == stream.tell(), "file-changed")
    data = (json.dumps({"v": 1, **fields}, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    observer_require(len(data) <= 512 and stream.tell() + len(data) <= 1024, "record-limit")
    observer_require(stream.write(data) == len(data), "observer-state-short-write")
    stream.flush()


def observer_budget_module(root):
    relative = Path("scripts/process_budget.py")
    data = diagnostic_bytes(root, relative, OBSERVER_BUDGET_BYTES)
    observer_require(len(data) == OBSERVER_BUDGET_BYTES and hashlib.sha256(data).hexdigest() == OBSERVER_BUDGET_SHA256,
                     "observer-budget-source")
    module = ModuleType("api106_qualification_budget")
    module.__file__ = str(root / relative)
    exec(compile(data, module.__file__, "exec"), module.__dict__)
    return module


def observer_runtime_path(value, *, directory):
    observer_require(type(value) is str and value and re.search(r"[\x00-\x1f\x7f]", value) is None,
                     "observer-runtime-path")
    path = Path(value)
    observer_require(path.is_absolute() and ".." not in path.parts, "observer-runtime-path")
    for current in (path, *path.parents):
        metadata = current.lstat()
        observer_require(not stat.S_ISLNK(metadata.st_mode)
                         and not getattr(metadata, "st_file_attributes", 0) & 0x400, "observer-runtime-path")
        observer_require((stat.S_ISDIR if current != path or directory else stat.S_ISREG)(metadata.st_mode),
                         "observer-runtime-path")
    return path


def observer_runtime_bytes(path, limit):
    data = diagnostic_bytes(path.parent, Path(path.name), limit)
    observer_require(len(data) <= limit, "observer-runtime-input-limit")
    return data


def observer_java_version_operand(value):
    if type(value) is str and len(value) <= 20 \
            and re.fullmatch(r"21(?:\.(?:0|[1-9][0-9]{0,4})){1,3}", value) is not None:
        return value
    return "unavailable"


def observer_java_require(condition, check, *, versions=None):
    if condition:
        return
    primary = Refused("observer-java-selection")
    try:
        print(json.dumps({"event": "windows_observer_java_selection", "diagnostic_only": True,
                          "check": check, "matched": False}, sort_keys=True), file=sys.stderr, flush=True)
        if versions is not None:
            print(json.dumps({"event": "windows_observer_java_versions", "diagnostic_only": True,
                              "release_version": observer_java_version_operand(versions[0]),
                              "selected_version": observer_java_version_operand(versions[1])},
                             sort_keys=True), file=sys.stderr, flush=True)
    except (OSError, ValueError):
        observer_secondary_failure(primary, "java-selection-report-unavailable")
    raise primary


def observer_java_version_matches(version, version_build, selected, release):
    if observer_java_version_operand(version) == "unavailable" or type(selected) is not str or len(selected) > 32:
        return False
    parts = version.split(".")
    if len(parts) not in (3, 4) or (len(parts) == 4 and parts[3] == "0"):
        return False
    setup = re.fullmatch(r"(21(?:\.(?:0|[1-9][0-9]{0,4})){2})\+([1-9][0-9]{0,6})(?:\.0)?", selected)
    if setup is None or setup[1] != ".".join(parts[:3]):
        return False
    runtimes = re.findall(r"^[ \t]*JAVA_RUNTIME_VERSION\b[^\n]*$", release, re.MULTILINE)
    if len(runtimes) != 1 or len(runtimes[0]) > 64:
        return False
    runtime = re.fullmatch(
        r'JAVA_RUNTIME_VERSION="(21(?:\.(?:0|[1-9][0-9]{0,4})){2,3})\+([1-9][0-9]?)(?:-LTS)?"', runtimes[0])
    if runtime is None or runtime[1] != version:
        return False
    if version_build is not None and version_build not in (runtime[2], runtime[2] + "-LTS"):
        return False
    # Adoptium adds patch * 100 to the build; builds 1..99 keep this mapping unambiguous.
    patch = int(parts[3]) if len(parts) == 4 else 0
    return int(setup[2]) == patch * 100 + int(runtime[2])


def observer_runtime_inputs(root, budget, *, shell_focus=False):
    observer_require(type(shell_focus) is bool, "observer-job-context")
    observer_require(os.environ.get("GITHUB_ACTIONS") == "true"
                     and os.environ.get("PENNILOGIC_API106_MONEY") == "success"
                     and os.environ.get("PENNILOGIC_API106_PREPARED") == "verified",
                     "observer-same-job-preparation")
    checkout = os.environ.get("PENNILOGIC_API106_CHECKOUT", "")
    tree = os.environ.get("PENNILOGIC_API106_TREE", "")
    observer_require(re.fullmatch(r"[0-9a-f]{40}", checkout) is not None
                     and checkout == os.environ.get("GITHUB_SHA")
                     and re.fullmatch(r"[0-9a-f]{40}", tree) is not None, "observer-checkout-binding")
    observer_require(observer_runtime_path(os.environ.get("GITHUB_WORKSPACE"), directory=True) == root,
                     "observer-checkout-binding")
    metadata = observer_runtime_path(str(root / ".git"), directory=True)
    observer_runtime_path(str(metadata / "objects"), directory=True)
    for name, limit in (("HEAD", 1024), ("index", 4 * 1024 * 1024), ("config", 65536)):
        expected = os.environ.get("PENNILOGIC_API106_" + name.upper() + "_SHA256", "")
        observer_require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None
                         and hashlib.sha256(observer_runtime_bytes(metadata / name, limit)).hexdigest() == expected,
                         "observer-git-state-changed")
    python = observer_runtime_path(os.environ.get("PENNILOGIC_API106_PYTHON"), directory=False)
    version = os.environ.get("PENNILOGIC_API106_PYTHON_VERSION", "")
    observer_require(sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 14)
                     and version == ".".join(map(str, sys.version_info[:3]))
                     and python.name.lower() == "python.exe" and python == Path(sys.executable)
                     and python.parent == Path(sys.prefix) == Path(sys.base_prefix)
                     and Path(budget.sys.executable) == python and Path(budget.sys.base_prefix) == python.parent,
                     "observer-python-selection")
    git = observer_runtime_path(os.environ.get("PENNILOGIC_API106_GIT"), directory=False)
    expected = os.environ.get("PENNILOGIC_API106_GIT_SHA256", "")
    observer_require(git.name.lower() == "git.exe" and re.fullmatch(r"[0-9a-f]{64}", expected) is not None
                     and hashlib.sha256(observer_runtime_bytes(git, 32 * 1024 * 1024)).hexdigest() == expected,
                     "observer-git-selection")
    java = observer_runtime_path(os.environ.get("PENNILOGIC_API106_JAVA"), directory=True)
    observer_java_require(java == observer_runtime_path(os.environ.get("JAVA_HOME"), directory=True), "home-match")
    observer_java_require("," not in str(java), "home-single-path")
    for name in ("java.exe", "javac.exe"):
        observer_runtime_path(str(java / "bin" / name), directory=False)
    release = observer_runtime_bytes(java / "release", 16384).decode("utf-8").replace("\r\n", "\n")
    version_lines = re.findall(r"^[ \t]*JAVA_VERSION\b[^\n]*$", release, re.MULTILINE)
    versions = [match for line in version_lines if (
        match := re.fullmatch(r'JAVA_VERSION="(21(?:\.[0-9]+){1,3})(?:\+([0-9A-Za-z.-]+))?"', line))]
    selected_label = os.environ.get("PENNILOGIC_API106_JAVA_VERSION", "")
    selected = selected_label.split("+", 1)[0]
    observer_java_require(len(version_lines) == 1 and len(versions) == 1, "release-version-single-match")
    observer_java_require(observer_java_version_matches(versions[0][1], versions[0][2], selected_label, release),
                          "selected-version-match", versions=(versions[0][1], selected))
    observer_java_require(re.findall(r'^IMPLEMENTOR="([^"\r\n]+)"$', release, re.MULTILINE) == ["Eclipse Adoptium"],
                          "release-implementor")
    for relative in ("build/source-materialization", "build/contracts-money",
                     "build/money-client-interop/inputs", "build/database-admission"):
        observer_runtime_path(str(root / relative), directory=True)
    for relative in (".gradle", ".kotlin", "git.exe", "python.exe", "java.exe"):
        observer_require(not (root / relative).exists() and not (root / relative).is_symlink(),
                         "observer-unadmitted-runtime-state")
    temporary = observer_runtime_path(os.environ.get("PENNILOGIC_API106_TEMP"), directory=True)
    observer_require(temporary == observer_runtime_path(os.environ.get("RUNNER_TEMP"), directory=True)
                     and not temporary.is_relative_to(root), "observer-temporary-selection")
    context = observer_context(root, shell_focus=True) if shell_focus else observer_context(root)
    owned = temporary / (("api106-shell-focus-" if shell_focus else "api106-observer-") + context)
    owned.mkdir()
    for name in ("home", "temp", "gradle"):
        (owned / name).mkdir()
    # Select the setup-java JDK, without admitting user init scripts or another toolchain.
    java_property = str(java).replace("\\", "\\\\")
    with (owned / "gradle" / "gradle.properties").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write("org.gradle.java.installations.auto-detect=false\n"
                     "org.gradle.java.installations.auto-download=false\n"
                     "org.gradle.java.installations.paths=" + java_property + "\n")
    supplied = {
        "HOME": str(owned / "home"), "USERPROFILE": str(owned / "home"),
        "TEMP": str(owned / "temp"), "TMP": str(owned / "temp"), "TMPDIR": str(owned / "temp"),
        "JAVA_HOME": str(java), "GRADLE_USER_HOME": str(owned / "gradle"),
        "CI": "true", "GITHUB_ACTIONS": "true",
    }
    return supplied, [git.parent]


def observer_secondary_failure(primary, code):
    primary.add_note("Observer secondary failure: " + code)
    try:
        print(json.dumps({"event": "windows_observer_secondary_failure", "diagnostic_only": True,
                          "code": code}, sort_keys=True), file=sys.stderr, flush=True)
    except (OSError, ValueError):
        primary.add_note("Observer secondary failure reporting also failed")


def observer_result_failure(result, secondary):
    if result is not None and result.returncode != 0:
        return _ObserverResultRefused(result, secondary)
    return secondary


def observer_owning_command(root):
    observer_require(type(OBSERVER_COMMAND_SECONDS) is int and OBSERVER_COMMAND_SECONDS == 270
                     and type(OBSERVER_CLOSED_SECONDS) is int and OBSERVER_CLOSED_SECONDS == 300,
                     "observer-whole-command-budget-unapproved")
    context = observer_context(root)
    for relative in (OBSERVER_STATE, *(path for path, _ in OBSERVER_FILES.values())):
        try:
            lookup_path_metadata(root, relative)
        except FileNotFoundError:
            continue
        raise Refused("observer-preexisting-diagnostic")
    budget = observer_budget_module(root)
    supplied, directories = observer_runtime_inputs(root, budget)
    started = time.monotonic_ns()
    returned = False
    try:
        result = observer_run_and_settle(root, budget, supplied, directories, context)
        returned = True
        return result
    finally:
        elapsed = time.monotonic_ns() - started
        within = type(elapsed) is int and 0 <= elapsed < OBSERVER_CLOSED_SECONDS * 1_000_000_000
        primary = None if returned else sys.exception()
        late = None
        if not within:
            if primary is not None:
                observer_secondary_failure(primary, "closed-command-budget-exceeded")
            else:
                late = observer_result_failure(result, Refused("observer-closed-command-budget-exceeded"))
                if result.returncode != 0:
                    observer_secondary_failure(late, "closed-command-budget-exceeded")
        try:
            print(json.dumps({"event": "windows_observer_owning_interval", "diagnostic_only": True,
                              "elapsed_ns": elapsed, "limit_seconds": OBSERVER_CLOSED_SECONDS,
                              "within_limit": within}, sort_keys=True), flush=True)
        except (OSError, ValueError) as error:
            if primary is not None:
                primary.add_note("Closed observer interval reporting also failed")
                observer_secondary_failure(primary, "interval-report-unavailable")
            else:
                if late is None:
                    late = observer_result_failure(result, error)
                observer_secondary_failure(late, "interval-report-unavailable")
        if late is not None:
            raise late


def observer_run_and_settle(root, budget, supplied, directories, context):
    environment = budget.environment(supplied=supplied, runtime_dirs=directories)
    for name, expected in (("python", Path(sys.executable)), ("git", directories[0] / "git.exe"),
                           ("java", Path(supplied["JAVA_HOME"]) / "bin" / "java.exe")):
        observer_require(Path(budget.resolve_command([name], environment)[0]) == expected,
                         "observer-runtime-shadowed")
    system = Path(environment["COMSPEC"]).parent
    observer_runtime_path(str(system / "cmd.exe"), directory=False)
    observer_runtime_path(str(system / "WindowsPowerShell" / "v1.0" / "powershell.exe"), directory=False)
    command = [sys.executable, str(root / "scripts/quality.py"), "test", "--require-prepared", "--api106-observer-pair"]
    (root / OBSERVER_STATE).parent.mkdir(parents=True, exist_ok=True)
    completed = None
    with ExitStack() as resources:
        state = (root / OBSERVER_STATE).open("xb", buffering=0)

        def close_state(error_type, primary, traceback):
            try:
                state.close()
            except OSError as error:
                if primary is None:
                    failure = observer_result_failure(completed, error)
                    observer_secondary_failure(failure, "state-close-unconfirmed")
                    raise failure
                observer_secondary_failure(primary, "state-close-unconfirmed")

        resources.push(close_state)
        observer_state_record(state, root, {"phase": "prepared", "context_sha256": context, "all_six_absent": True})
        try:
            result = budget.run(command, root, OBSERVER_COMMAND_SECONDS, capture=True, separate=True,
                                env=environment)
        except budget.BudgetExceeded as error:
            reason = "output-budget-exceeded" if isinstance(error, budget.OutputExceeded) else "work-budget-exceeded"
            primary = Refused("observer-owning-" + reason)
            diagnostic = {"event": "windows_observer_owning_failure", "diagnostic_only": True, "code": reason,
                          "job": dict(PROCESS_BUDGET_JOB_UNAVAILABLE), "state": dict(PROCESS_BUDGET_UNAVAILABLE),
                          "capture": process_budget_capture_note(
                              budget.capture_observation(error.streams, separate=True).encode("ascii"))}
            notes = getattr(error, "__notes__", [])
            if (type(notes) is list and len(notes) == 3
                    and all(type(note) is str and note.isascii() and len(note) <= 1024 for note in notes)):
                diagnostic["job"] = process_budget_job_note(notes[1].encode("ascii"))
                diagnostic["state"] = process_budget_note(notes[2].encode("ascii"))
            try:
                print(json.dumps(diagnostic, sort_keys=True), flush=True)
            except (OSError, ValueError):
                observer_secondary_failure(primary, "owning-failure-report-unavailable")
            try:
                observer_state_record(state, root, {"phase": "settled", "status": reason, "returncode": None})
            except (OSError, Refused):
                observer_secondary_failure(primary, "state-finalization")
            raise primary from error
        except OSError as error:
            try:
                print('{"event":"windows_observer_owning_failure","diagnostic_only":true,'
                      '"code":"process-or-cleanup-error","owner_release":"unconfirmed"}', flush=True)
            except (OSError, ValueError):
                observer_secondary_failure(error, "owning-failure-report-unavailable")
            raise
        observer_require(observer_integer(result.returncode, -2147483648)
                         and type(result.stdout) is bytes and type(result.stderr) is bytes, "observer-command-result")
        completed, failure = result, None
        try:
            print(json.dumps({"event": "windows_owning_suite_command", "exit_code": result.returncode}, sort_keys=True), flush=True)
        except (OSError, ValueError) as error:
            failure = observer_result_failure(result, error)
            observer_secondary_failure(failure, "owning-command-report-unavailable")
        try:
            observer_state_record(state, root, {"phase": "settled", "status": "exited", "returncode": result.returncode})
        except (OSError, Refused) as error:
            if failure is None:
                failure = observer_result_failure(result, error)
            observer_secondary_failure(failure, "state-finalization")
        if failure is not None:
            raise failure
        return result


def observer_boundary(data):
    observer_require(len(data) <= 7, "file-limit")
    observer_require(re.fullmatch(rb"(?:|E|EU|EUX|ES[01]{3}C?X?)", data) is not None, "boundary-shape")
    flags = re.fullmatch(rb"ES([01])([01])([01])C?X?", data)
    return {
        "checkpoint": ("none-observed" if not data else "after-write-output" if data.endswith(b"X")
                       else "command-entry" if data == b"E" else "before-write-output"),
        "console_redirected": (dict(zip(("stdin", "stdout", "stderr"),
                                       (value == b"1" for value in flags.groups()), strict=True)) if flags else None),
        "pre_record_writer_return": "observed" if b"C" in data else "not-observed",
    }


def collect_observer_diagnostics(root):
    base = {"event": "windows_observer_pair_diagnostic", "diagnostic_only": True, "acceptance": False}
    try:
        state = observer_json_lines(diagnostic_bytes(root, OBSERVER_STATE, 1024), 1024, 2)
        observer_require(lookup_path_metadata(root, OBSERVER_STATE).st_nlink == 1, "nonregular-path")
        observer_require(len(state) == 2, "observer-owner-not-settled")
        prepared, settled = state
        observer_require(prepared == {"v": 1, "phase": "prepared", "context_sha256": observer_context(root),
                                      "all_six_absent": True}, "observer-freshness-unavailable")
        observer_require(type(prepared["v"]) is int and prepared["all_six_absent"] is True
                         and type(settled) is dict and set(settled) == {
            "v", "phase", "status", "returncode",
        })
        observer_require(type(settled["v"]) is int and settled["v"] == 1 and settled["phase"] == "settled")
        observer_require((settled["status"] == "exited" and observer_integer(settled["returncode"], -2147483648))
                         or (settled["status"] in ("work-budget-exceeded", "output-budget-exceeded")
                             and settled["returncode"] is None))
    except (OSError, Refused) as error:
        code = str(error) if isinstance(error, Refused) else "observer-state-unavailable"
        print(json.dumps({**base, "carrier": "collection", "status": "refused", "code": code}, sort_keys=True), flush=True)
        return 2
    base["owning_command"] = {"status": settled["status"], "returncode": settled["returncode"]}
    refused = False
    for carrier, (relative, limit) in OBSERVER_FILES.items():
        record = {**base, "carrier": carrier, "carrier_complete": False}
        try:
            observer_require(observer_context(root) == prepared["context_sha256"], "observer-freshness-unavailable")
            data = diagnostic_bytes(root, relative, limit)
            observer_require(len(data) <= limit, "file-limit")
            metadata = lookup_path_metadata(root, relative)
            observer_require(metadata.st_nlink == 1, "nonregular-path")
            observer_require(observer_context(root) == prepared["context_sha256"], "observer-freshness-unavailable")
            if carrier.endswith("-boundary"):
                record.update(observation=observer_boundary(data), carrier_complete=True)
            elif carrier.endswith("-lookup"):
                records = lookup_records(data)
                complete = bool(records and records[-1]["phase"] == "post")
                if carrier == "auxiliary-lookup":
                    observer_require(len(records) <= 1, "observer-auxiliary-records")
                record.update(records=lookup_projection(records), capsule_complete=complete,
                              carrier_complete=bool(records) if carrier == "auxiliary-lookup" else complete)
            else:
                parser = observer_pair_records if carrier == "pair" else observer_enclosure_records
                records, complete = parser(data)
                record.update(records=records, carrier_complete=complete)
            record["status"] = "observed" if record["carrier_complete"] else "partial"
        except FileNotFoundError:
            record.update(status="unavailable", code="not-observed")
        except Refused as error:
            record.update(status="refused", code=str(error))
        except OSError:
            record.update(status="unavailable", code="read-error")
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("ascii")) + len(os.linesep) > DIAGNOSTIC_BYTE_LIMIT:
            record = {**base, "carrier": carrier, "carrier_complete": False,
                      "status": "refused", "code": "projection-limit"}
            encoded = json.dumps(record, sort_keys=True, separators=(",", ":"))
        refused |= record["status"] != "observed"
        print(encoded, flush=True)
    return 2 if refused else 0


def observer_failed_result_outcomes(root, primary, include_junit=False):
    result = primary.result
    try:
        records = qualification_python_outcomes(root, result, result.stdout, result.stderr)
        for record in records:
            print(json.dumps(record, sort_keys=True))
    except _PythonOutcomeRefused:
        observer_secondary_failure(primary, "captured-python-outcomes-incomplete")
        return
    except (OSError, ValueError):
        observer_secondary_failure(primary, "captured-python-outcome-report-unavailable")
        return
    if include_junit:
        try:
            for record in qualification_junit_outcomes(root, result, result.stdout):
                print(json.dumps(record, sort_keys=True))
        except _JunitOutcomeRefused:
            observer_secondary_failure(primary, "captured-junit-outcomes-incomplete")
        except Refused:
            observer_secondary_failure(primary, "captured-gradle-or-junit-outcomes-unavailable")
        except (OSError, ValueError, ET.ParseError):
            observer_secondary_failure(primary, "captured-junit-outcome-report-unavailable")


def shell_focus_sources(root):
    for relative, (size, digest) in SHELL_FOCUS_SOURCES.items():
        data = diagnostic_bytes(root, Path(relative), size)
        observer_require(len(data) == size and hashlib.sha256(data).hexdigest() == digest, "focus-source-binding")
    return {name: {"bytes": size, "sha256": digest} for name, (size, digest) in SHELL_FOCUS_SOURCES.items()}


def shell_focus_absent(root):
    observer_runtime_path(str(root / "build"), directory=True)
    try:
        (root / "build" / "diagnostics").lstat()
    except FileNotFoundError:
        return
    raise Refused("focus-preexisting-diagnostic-area")


def shell_focus_exception(error, budget, *, separate=True):
    def kind(value):
        if budget is not None and isinstance(value, budget.OutputExceeded):
            return "output-budget-exceeded"
        if budget is not None and isinstance(value, budget.BudgetExceeded):
            return "work-budget-exceeded"
        if isinstance(value, Refused):
            return "admission-or-result-refused"
        if isinstance(value, OSError):
            return "process-capture-or-cleanup-error"
        return "unexpected-error"

    chain, seen, current = [], set(), error
    capture, capture_index = dict(PROCESS_BUDGET_CAPTURE_UNAVAILABLE), None
    while current is not None and len(chain) < 4 and id(current) not in seen:
        seen.add(id(current))
        if capture_index is None and budget is not None and isinstance(current, budget.BudgetExceeded):
            observed = process_budget_capture_note(
                budget.capture_observation(getattr(current, "streams", None), separate=separate).encode("ascii"))
            if observed["status"] == "observed":
                capture, capture_index = observed, len(chain)
        chain.append(kind(current))
        current = current.__cause__ if current.__cause__ is not None else current.__context__
    code = (error.args[0] if isinstance(error, Refused) and len(error.args) == 1
            and type(error.args[0]) is str and len(error.args[0]) <= 64 and error.args[0] in SHELL_FOCUS_REFUSALS else None)
    return {"kind": kind(error), "code": code, "chain": chain, "chain_truncated": current is not None,
            "capture": capture, "capture_from_chain_index": capture_index}


def shell_focus_module(root):
    import importlib.util

    shell_focus_sources(root)
    observer_require("test_money_mutation" not in sys.modules, "focus-preexisting-test-module")
    path = root / "scripts" / "tests" / "test_money_mutation.py"
    spec = importlib.util.spec_from_file_location("test_money_mutation", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    observer_require(module.__name__ == "test_money_mutation" and Path(module.__file__) == path
                     and module.SCRIPTS == root / "scripts"
                     and module.APPROVED_SHELL_PAIR_ENCLOSURE is None, "focus-module-or-seam")
    for imported, relative in ((module.mutation, "money_mutation.py"), (module.quality, "quality.py"),
                               (module.process_budget, "process_budget.py")):
        observer_require(Path(imported.__file__) == root / "scripts" / relative, "focus-import-identity")
    shell_focus_sources(root)
    return module


def shell_focus_child(root):
    import unittest

    module = shell_focus_module(root)
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(SHELL_FOCUS_TARGET.removeprefix("test_money_mutation."), module)
    cases = list(suite)
    observer_require(not loader.errors and suite.countTestCases() == len(cases) == 1
                     and cases[0].id() == SHELL_FOCUS_TARGET, "focus-target-count")

    class Result(unittest.TestResult):
        observation = None

        def addError(self, test, error):
            self.observation = shell_focus_exception(error[1], module.process_budget, separate=False)
            super().addError(test, error)

        def addFailure(self, test, error):
            self.observation = shell_focus_exception(error[1], module.process_budget, separate=False)
            super().addFailure(test, error)

    result = Result()
    started = time.monotonic_ns()
    suite.run(result)
    elapsed = time.monotonic_ns() - started
    shell_focus_sources(root)
    observer_require(module.APPROVED_SHELL_PAIR_ENCLOSURE is None and result.testsRun == 1, "focus-target-count")
    counts = {name: len(getattr(result, name)) for name in (
        "failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses")}
    record = {"v": 1, "event": "api106_shell_focus_target", "target": SHELL_FOCUS_TARGET,
              "tests_run": result.testsRun, "elapsed_ns": elapsed, **counts, "exception": result.observation}
    data = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    observer_require(len(data) <= 4096, "focus-child-record-limit")
    observer_require(sys.stdout.buffer.write(data) == len(data), "focus-child-record-write")
    sys.stdout.buffer.flush()
    return int(not result.wasSuccessful() or any(counts.values()))


def shell_focus_command(root, environment):
    path = root / "scripts" / "qualify_windows.py"
    source = observer_runtime_bytes(path, 1024 * 1024)
    cache = observer_runtime_path(environment["TEMP"], directory=True) / "api106-python-cache"
    cache.mkdir()
    observer_runtime_path(str(cache), directory=True)
    # The fixed child rebinds its controller before importing the unchanged target.
    bootstrap = (
        "import hashlib,pathlib,sys;"
        "p=pathlib.Path(" + repr(str(path)) + ");"
        "f=p.open('rb');b=f.read(" + str(len(source) + 1) + ");f.close();"
        "(len(b)==" + str(len(source)) + " and hashlib.sha256(b).hexdigest()=="
        + repr(hashlib.sha256(source).hexdigest()) + ") or sys.exit(1);"
        "n={'__name__':'api106_fixed_shell_focus','__file__':str(p)};"
        "exec(compile(b,str(p),'exec'),n);sys.exit(n['shell_focus_child'](p.parents[1]))"
    )
    return [sys.executable, "-I", "-S", "-B", "-X", "pycache_prefix=" + str(cache), "-c", bootstrap]


def shell_focus_runtime(root, budget):
    observer_require(os.environ.get("PENNILOGIC_API106_SHELL_FOCUS") == "true", "focus-explicit-selection")
    context = observer_context(root, shell_focus=True)
    observer_require(sys.version_info[:3] == (3, 14, 8)
                     and os.environ.get("PENNILOGIC_API106_PYTHON_VERSION") == "3.14.8", "focus-python-comparison")
    image_os, image_version = os.environ.get("ImageOS"), os.environ.get("ImageVersion", "")
    observer_require(image_os in ("win25", "win25-vs2026")
                     and re.fullmatch(r"[0-9]{8}\.[0-9]{1,4}\.[0-9]{1,4}", image_version) is not None,
                     "focus-image-metadata")
    supplied, directories = observer_runtime_inputs(root, budget, shell_focus=True)
    environment = budget.environment(supplied=supplied, runtime_dirs=directories)
    for name, expected in (("python", Path(sys.executable)), ("git", directories[0] / "git.exe"),
                           ("java", Path(supplied["JAVA_HOME"]) / "bin" / "java.exe")):
        observer_require(Path(budget.resolve_command([name], environment)[0]) == expected, "observer-runtime-shadowed")
    system = Path(environment["COMSPEC"]).parent
    images = {}
    for name, path in (("python", Path(sys.executable)), ("cmd", system / "cmd.exe"),
                       ("powershell", system / "WindowsPowerShell" / "v1.0" / "powershell.exe")):
        observer_runtime_path(str(path), directory=False)
        data = observer_runtime_bytes(path, 32 * 1024 * 1024)
        images[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    return environment, {
        "context_sha256": context, "checkout": os.environ["PENNILOGIC_API106_CHECKOUT"],
        "tree": os.environ["PENNILOGIC_API106_TREE"], "python_version": "3.14.8",
        "python_matches_comparison": True, "image_os": image_os, "image_version": image_version,
        "image_metadata_sha256": hashlib.sha256((image_os + "\n" + image_version).encode("ascii")).hexdigest(),
        "image_evidence": "runner-metadata-only", "historical_image_equivalence": "unavailable",
        "images": images, "fixture_source_commit": "6ccd4eda3f424f22825ef20d27622005ed3f1144",
        "whole_checkout_equivalence": "not-claimed",
    }


def shell_focus_result(result):
    observer_require(type(result.returncode) is int and result.returncode in (0, 1)
                     and type(result.stdout) is bytes and type(result.stderr) is bytes, "focus-child-result")
    data = result.stdout
    observer_require(len(data) <= 4096 and data.isascii() and b"\r" not in data and b"\x1b" not in data
                     and data.endswith(b"\n") and data.count(b"\n") == 1 and result.stderr == b"", "focus-child-output")
    record = json.loads(data, object_pairs_hook=lookup_json_object)
    counters = ("failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses")
    observer_require(type(record) is dict and set(record) == {
        "v", "event", "target", "tests_run", "elapsed_ns", "exception", *counters,
    }, "focus-child-result")
    observer_require(type(record["v"]) is int and record["v"] == 1
                     and record["event"] == "api106_shell_focus_target" and record["target"] == SHELL_FOCUS_TARGET
                     and type(record["tests_run"]) is int and record["tests_run"] == 1
                     and observer_integer(record["elapsed_ns"], 0, 150_000_000_000)
                     and all(type(record[name]) is int and record[name] in (0, 1) for name in counters)
                     and sum(record[name] for name in counters) <= 1, "focus-child-result")
    failure = any(record[name] for name in counters)
    observer_require(result.returncode == int(failure), "focus-child-result")
    exception = record["exception"]
    observer_require((exception is not None) == bool(record["errors"] or record["failures"]), "focus-child-result")
    if exception is not None:
        shell_focus_exception_shape(exception)
    return record, not failure


def shell_focus_exception_shape(value):
    kinds = {"output-budget-exceeded", "work-budget-exceeded", "admission-or-result-refused",
             "process-capture-or-cleanup-error", "unexpected-error"}
    observer_require(type(value) is dict and set(value) == {
        "kind", "code", "chain", "chain_truncated", "capture", "capture_from_chain_index",
    } and type(value["kind"]) is str and value["kind"] in kinds
                     and type(value["chain"]) is list and 1 <= len(value["chain"]) <= 4
                     and all(type(item) is str and item in kinds for item in value["chain"])
                     and value["chain"][0] == value["kind"] and type(value["chain_truncated"]) is bool,
                     "focus-exception-shape")
    observer_require(value["code"] is None or (
        value["kind"] == "admission-or-result-refused" and type(value["code"]) is str
        and value["code"] in SHELL_FOCUS_REFUSALS), "focus-exception-shape")
    capture = process_budget_capture_note(
        PROCESS_BUDGET_CAPTURE_PREFIX + json.dumps(value["capture"], sort_keys=True, separators=(",", ":")).encode("ascii"))
    observer_require(capture == value["capture"], "focus-exception-shape")
    index = value["capture_from_chain_index"]
    observer_require((capture["status"] == "unavailable" and index is None) or (
        capture["status"] == "observed" and observer_integer(index, 0, len(value["chain"]) - 1)
        and value["chain"][index] in ("output-budget-exceeded", "work-budget-exceeded")), "focus-exception-shape")


def shell_focus_lookup_evidence(lookup):
    # The shared reader's terminal "observed" status does not establish availability.
    records = lookup.get("records", [])
    if (lookup["status"] == "refused" or lookup.get("code") == "read-error"
            or any(record["status"] == "refused" or record.get("not_found", {}).get("status") == "refused"
                   for record in records)):
        return "refused"
    phases = [record["phase"] for record in records]
    if (lookup["status"] != "observed" or lookup["capsule_complete"] is not True
            or phases not in (["roots", "observer", "pre", "post"],
                              ["roots", "observer", "pre", "not-found", "post"])):
        return "inconclusive"
    for record in records:
        if (record["status"] != ("armed" if record["phase"] == "observer" else "observed")
                or ("not_found" in record and record["not_found"]["status"] != "armed")
                or any(key in record and record[key] is None for key in ("ms", "lookup_ms"))):
            return "inconclusive"
    if records[-1]["module_kind"] == "unknown":
        return "inconclusive"
    return "complete-observed"


def shell_focus(root, require_prepared=False):
    report = {"event": "windows_shell_focus", "diagnostic_only": True, "status": "refused",
              "work_seconds": 150, "single_cleanup_seconds": 10, "hard_end_to_end_deadline": False,
              "interval_scope": "one-helper-call-not-preparation-admission-or-reporting",
              "synchronous_calls_preempted": False, "inherit_tree": "shipped-default-false",
              "owner_release": "not-started", "phase": "admission", "runtime": None, "target": None,
              "target_status": "unavailable", "lookup_evidence": "unavailable",
              "error": None, "capture": None, "carriers": None, "owned_call_elapsed_ns": None,
              "native_qualification": False, "physical_cleanup_attestation": False}
    budget, started, before = None, None, "absent"
    try:
        observer_require(require_prepared is True, "focus-requires-prepared")
        observer_context(root, shell_focus=True)
        shell_focus_absent(root)
        sources = shell_focus_sources(root)
        budget = observer_budget_module(root)
        environment, report["runtime"] = shell_focus_runtime(root, budget)
        report["runtime"]["sources"] = sources
        command = shell_focus_command(root, environment)
        (root / "build" / "diagnostics").mkdir()
        report["phase"], report["owner_release"] = "owner", "unconfirmed"
        started = time.monotonic_ns()
        try:
            result = budget.run(command, root, 150, capture=True, separate=True, env=environment)
        except budget.OutputExceeded:
            report["owner_release"] = "helper-settled"
            raise
        except budget.BudgetExceeded:
            report["owner_release"] = "helper-settled"
            raise
        finally:
            report["owned_call_elapsed_ns"] = time.monotonic_ns() - started
        report["owner_release"], report["phase"] = "helper-settled", "result"
        report["capture"] = {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                             for name, data in (("stdout", result.stdout), ("stderr", result.stderr))
                             if type(data) is bytes}
        report["target"], passed = shell_focus_result(result)
        report["target_status"] = "passed" if passed else "failed"
        shell_focus_sources(root)
        report["status"] = report["target_status"]
    except (Exception, KeyboardInterrupt) as error:
        # A cleanup error may replace the original budget error and have no captures.
        report["error"] = shell_focus_exception(error, budget)
        report["status"] = "failed"
    if report["owner_release"] == "helper-settled":
        try:
            boundary = diagnostic_bytes(root, OBSERVER_FILES["required-boundary"][0], 7)
            report["carriers"] = {"boundary": observer_boundary(boundary),
                                  "lookup": json.loads(lookup_diagnostic_json(root, before))}
            report["lookup_evidence"] = shell_focus_lookup_evidence(report["carriers"]["lookup"])
            if report["lookup_evidence"] == "refused":
                report["status"] = "failed"
            elif report["lookup_evidence"] != "complete-observed" and report["status"] == "passed":
                report["status"] = "inconclusive"
        except (OSError, ValueError):
            report["carriers"] = {"status": "unavailable"}
            report["lookup_evidence"] = "refused"
            report["status"] = "failed"
    data = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    observer_require(len(data.encode("ascii")) + len(os.linesep) <= 16384, "focus-report-limit")
    print(data, flush=True)
    return 0 if report["status"] == "passed" else 1


def qualify(root, require_prepared=False, api106_observer_pair=False):
    if api106_observer_pair and not require_prepared:
        raise Refused("observer-pair-requires-prepared")
    if (root / JUNIT).exists() or (root / JUNIT).is_symlink():
        raise Refused("preexisting-ordinary-junit-results")
    before = lookup_before(root)
    arguments = ["--require-prepared"] if require_prepared else []
    print("+ python scripts\\quality.py test" + (" --require-prepared" if require_prepared else "")
          + (" --api106-observer-pair" if api106_observer_pair else ""), flush=True)
    if api106_observer_pair:
        try:
            result = observer_owning_command(root)
        except _ObserverResultRefused as error:
            observer_failed_result_outcomes(root, error)
            raise
        if result.returncode != 0:
            primary = _ObserverResultRefused(result, None)
            observer_failed_result_outcomes(root, primary, include_junit=True)
            raise primary
        output, errors = result.stdout, result.stderr
        records = qualification_python_outcomes(root, result, output, errors)
    else:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                result = subprocess.run(
                    [sys.executable, str(root / "scripts" / "quality.py"), "test", *arguments],
                    cwd=root, stdout=stdout, stderr=stderr, check=False,
                )
                stdout.seek(0)
                stderr.seek(0)
                print(json.dumps({"event": "windows_owning_suite_command", "exit_code": result.returncode}, sort_keys=True))
            finally:
                print(lookup_diagnostic_json(root, before), flush=True)
            output = stdout.read()
            errors = stderr.read()
            records = qualification_python_outcomes(root, result, output, errors)
    for record in records:
        print(json.dumps(record, sort_keys=True))
    junit = qualification_junit_outcomes(root, result, output)
    for record in junit:
        print(json.dumps(record, sort_keys=True))
    if result.returncode != 0:
        raise Refused("owning-suite-command-failed")
    if any(record["outcome"] in ("failed", "error", "unexpected_success") for record in records):
        raise Refused("ordinary-python-tests-did-not-pass")
    for target in (PYTHON_TARGET, KOTLIN_CLASS + "." + KOTLIN_METHOD):
        selected = [record for record in records + junit if record.get("required_test") == target]
        if len(selected) != 1 or selected[0]["outcome"] != "passed":
            raise Refused("required-windows-test-did-not-pass")
    if any(record["outcome"] != "passed" for record in junit):
        raise Refused("ordinary-gradle-tests-did-not-all-pass")
    print(json.dumps({"event": "windows_qualification", "ok": True,
                      "python_tests": len(records), "junit_tests": len(junit)}, sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-prepared", action="store_true", help="Require existing verified interop inputs; never acquire")
    observer = parser.add_mutually_exclusive_group()
    observer.add_argument("--api106-observer-pair", action="store_true", help="Explicit diagnostic owning-suite route")
    observer.add_argument("--collect-api106-observer-pair", action="store_true", help="Read only the settled fixed diagnostic files")
    observer.add_argument("--api106-shell-focus", action="store_true", help="Explicit isolated single-target diagnostic, never qualification")
    args = parser.parse_args(argv)
    try:
        if sys.platform != "win32":
            raise Refused("windows-owning-suites-require-windows")
        if args.api106_shell_focus:
            return shell_focus(ROOT, require_prepared=args.require_prepared)
        if args.collect_api106_observer_pair:
            if args.require_prepared:
                parser.error("collection does not accept --require-prepared")
            return collect_observer_diagnostics(ROOT)
        if args.api106_observer_pair:
            qualify(ROOT, require_prepared=args.require_prepared, api106_observer_pair=True)
        else:
            qualify(ROOT, require_prepared=args.require_prepared)
        return 0
    except Refused as error:
        print(json.dumps({"event": "windows_qualification_refused", "code": str(error)}), file=sys.stderr)
    except (OSError, ValueError, ET.ParseError):
        print(json.dumps({"event": "windows_qualification_refused", "code": "process-or-report-error"}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
