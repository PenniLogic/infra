"""Run the ordinary Windows owning suites and emit only safe, fresh per-test outcomes."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
PYTHON_TARGET = "test_money_mutation.ProcessBudgetTest.test_budgeted_quality_admits_only_the_approved_docker_directory"
KOTLIN_CLASS = "com.pennilogic.migration.AdmissionInstallationTest"
KOTLIN_METHOD = "a symlinked launcher cannot redirect execution()"
JUNIT = Path("build/test-results/test")
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
        for line in lines[start:end]:
            if line in (
                traceback_header, b"During handling of the above exception, another exception occurred:",
                b"The above exception was the direct cause of the following exception:",
            ):
                malformed = True
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
        selected[digest] = {"exception": exception, "source_frames": frames,
                            "incomplete": exception == "unclassified" or truncated, "truncated": truncated}
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


def junit_outcomes(root):
    directory = root / JUNIT
    if directory.is_symlink() or not directory.is_dir():
        raise Refused("missing-ordinary-junit-results")
    records, identities = [], set()
    for path in sorted(directory.glob("TEST-*.xml")):
        if path.is_symlink() or not path.is_file():
            raise Refused("invalid-junit-result-file")
        suite = ET.parse(path).getroot()
        cases = suite.findall("testcase")
        if suite.tag != "testsuite" or int(suite.get("tests", "-1")) != len(cases):
            raise Refused("incomplete-junit-outcomes")
        counts = {"failure": 0, "error": 0, "skipped": 0}
        for case in cases:
            class_name, name = case.get("classname"), case.get("name")
            if not class_name or not name:
                raise Refused("missing-junit-identity")
            identity = class_name + "\0" + name
            if identity in identities:
                raise Refused("duplicate-junit-case")
            identities.add(identity)
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


def qualify(root):
    if (root / JUNIT).exists() or (root / JUNIT).is_symlink():
        raise Refused("preexisting-ordinary-junit-results")
    print("+ python scripts\\quality.py test", flush=True)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        result = subprocess.run(
            [sys.executable, str(root / "scripts" / "quality.py"), "test"],
            cwd=root, stdout=stdout, stderr=stderr, check=False,
        )
        stdout.seek(0)
        stderr.seek(0)
        print(json.dumps({"event": "windows_owning_suite_command", "exit_code": result.returncode}, sort_keys=True))
        output = stdout.read()
        errors = stderr.read()
        try:
            records = python_outcomes(errors)
        except _PythonOutcomeRefused as error:
            print(json.dumps({
                "event": "windows_qualification_diagnostic", "diagnostic_only": True,
                "inventory_complete": False, "exit_code": result.returncode,
                "stdout": {"bytes": len(output), "sha256": hashlib.sha256(output).hexdigest()},
                "stderr": {"bytes": len(errors), "sha256": hashlib.sha256(errors).hexdigest()},
                "parser": {**error.diagnostic,
                           "negative_prefix": python_error_diagnostics(root, errors, error.diagnostic)},
            }, sort_keys=True), flush=True)
            raise
    for record in records:
        print(json.dumps(record, sort_keys=True))
    test_tasks = [line for line in output.splitlines() if re.fullmatch(rb"> Task :test(?: .*)?", line)]
    if test_tasks not in ([b"> Task :test"], [b"> Task :test FAILED"]):
        raise Refused("ordinary-gradle-test-was-not-fresh")
    if test_tasks == [b"> Task :test FAILED"] and result.returncode == 0:
        raise Refused("inconsistent-gradle-task-result")
    junit = junit_outcomes(root)
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


def main():
    try:
        if sys.platform != "win32":
            raise Refused("windows-owning-suites-require-windows")
        qualify(ROOT)
        return 0
    except Refused as error:
        print(json.dumps({"event": "windows_qualification_refused", "code": str(error)}), file=sys.stderr)
    except (OSError, ValueError, ET.ParseError):
        print(json.dumps({"event": "windows_qualification_refused", "code": "process-or-report-error"}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
