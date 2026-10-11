"""Run the ordinary Windows owning suites and emit only safe, fresh per-test outcomes."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
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


def lookup_path_metadata(root):
    path = root
    for index, part in enumerate(("", *LOOKUP.parts)):
        if part:
            path = path / part
        metadata = path.lstat()
        # Windows junctions can report a directory mode and still be reparse points.
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise Refused("reparse-path")
        regular = stat.S_ISREG if index == len(LOOKUP.parts) else stat.S_ISDIR
        if not regular(metadata.st_mode):
            raise Refused("nonregular-path")
    return metadata


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

    phases = []
    for record in records:
        if (type(record) is not dict or type(record.get("v")) is not int or record["v"] != 1
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
            keys(record, ("v", "phase", "status"))
        elif phase == "pre" and status == "observed":
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
            keys(record, ("v", "phase", "status", "code"))
            allowed = {
                ("roots", "refused"): ("input-limit", "encoding", "snapshot"),
                ("observer", "unavailable"): ("roots-refused", "existing-hooks", "unsupported-api"),
                ("observer", "refused"): ("install",),
                ("post", "unavailable"): ("observer-unavailable", "no-pre", "no-post", "nested-target", "post-without-pre"),
                ("post", "refused"): ("command-type", "module-path-limit", "callback"),
            }
            if record["code"] not in allowed.get((phase, status), ()):
                raise Refused("record-shape")
    if (phases[:1] != ["roots"] or (len(phases) >= 2 and phases[1] != "observer")
            or (len(phases) >= 3 and phases[2] not in ("pre", "post"))
            or (len(phases) == 4 and phases[2:] != ["pre", "post"])):
        raise Refused("record-order")
    if len(records) >= 2:
        roots, observer = records[:2]
        if (roots["status"] == "refused") != (observer.get("code") == "roots-refused"):
            raise Refused("record-order")
        armed = observer["status"] == "armed"
        pre = records[2] if len(records) >= 3 and phases[2] == "pre" else None
        post = records[-1] if phases[-1] == "post" else None
        if pre is not None and not armed:
            raise Refused("record-order")
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


def lookup_diagnostic_json(root, before):
    base = {"event": LOOKUP_EVENT, "diagnostic_only": True, "capsule_complete": False}
    result = dict(base)
    try:
        if before != "absent":
            known = ("preexisting-capsule", "preflight-unavailable", "reparse-path", "nonregular-path")
            raise Refused(before if type(before) is str and before in known else "freshness-unavailable")
        metadata = lookup_path_metadata(root)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(root / LOOKUP, flags)
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(metadata, opened):
                    raise Refused("file-changed")
                data = stream.read(LOOKUP_FILE_LIMIT + 1)
                after = os.fstat(stream.fileno())
        finally:
            os.close(descriptor)
        current = lookup_path_metadata(root)
        if (any(not os.path.samestat(opened, other) for other in (after, current))
                or len({item.st_size for item in (metadata, opened, after, current)}) != 1
                or len({item.st_mtime_ns for item in (metadata, opened, after, current)}) != 1):
            raise Refused("file-changed")
        if len(data) != min(current.st_size, LOOKUP_FILE_LIMIT + 1):
            raise Refused("incomplete-read")
        records = lookup_records(data)
        projected = []
        for record in records:
            if record["phase"] == "roots" and record["status"] == "observed":
                columns = ["i", "kind", "sha256", "duplicate_of"]
                record = {**record, "root_columns": columns,
                          "roots": [[entry[key] for key in columns] for entry in record["roots"]]}
            projected.append(record)
        complete = bool(records and records[-1]["phase"] == "post")
        result.update(status="observed" if complete else "partial", capsule_complete=complete, records=projected)
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


def qualify(root, require_prepared=False):
    if (root / JUNIT).exists() or (root / JUNIT).is_symlink():
        raise Refused("preexisting-ordinary-junit-results")
    before = lookup_before(root)
    arguments = ["--require-prepared"] if require_prepared else []
    print("+ python scripts\\quality.py test" + (" --require-prepared" if require_prepared else ""), flush=True)
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
        try:
            records = python_outcomes(errors)
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
    for record in records:
        print(json.dumps(record, sort_keys=True))
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
    args = parser.parse_args(argv)
    try:
        if sys.platform != "win32":
            raise Refused("windows-owning-suites-require-windows")
        qualify(ROOT, require_prepared=args.require_prepared)
        return 0
    except Refused as error:
        print(json.dumps({"event": "windows_qualification_refused", "code": str(error)}), file=sys.stderr)
    except (OSError, ValueError, ET.ParseError):
        print(json.dumps({"event": "windows_qualification_refused", "code": "process-or-report-error"}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
