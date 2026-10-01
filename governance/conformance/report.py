"""Assemble the machine-readable conformance report and its Markdown summary.

The report is the published artifact: one record per repository with its identity, generated
baseline, checker result, detected steps, required checks, last ``main`` CI run and planted-defect
records, plus the per-repository and overall result. ``redact`` removes every local path and
credential-shaped string before anything is written; the summary is rendered from the redacted
document only, so both files carry the same facts.
"""

import ctypes
import getpass
import json
import os
import re
import sys
import tempfile
from pathlib import Path


SCHEMA = "pennilogic.infra.conformance/1"
SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
OUTCOME_MARK = {
    "proved": "proved", "recorded": "recorded", "consumer_evidence": "consumer evidence",
    "not_exercised": "not exercised", "not_proved": "NOT PROVED", "error": "ERROR", None: "-",
}
USER_PLACEHOLDER = "<user>"
# An absolute drive path that survived redaction (a letter that is not part of a longer word such as
# the `s` of `https:`, a colon, then a separator in plain, repr or JSON spelling).
DRIVE_PATH = re.compile(r"(?<![A-Za-z])[A-Za-z]:(?:\\\\|\\|/)")


def spellings(text):
    """Every spelling a tool may print for one path: plain, repr/JSON-escaped (doubled backslashes)
    and POSIX separators. Matching is case-insensitive, so case variants need no entry."""
    forms = {text, text.replace("\\", "/"), text.replace("\\", "\\\\"), json.dumps(text)[1:-1]}
    return {form for form in forms if form and form not in ("/", "\\", "\\\\")}


def short_path(path):
    """The Windows 8.3 form of an existing path (``C:\\Users\\TTBASI~1``), or ``None`` elsewhere."""
    if os.name != "nt":
        return None
    try:
        buffer = ctypes.create_unicode_buffer(1024)
        length = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, 1024)
    except (AttributeError, OSError, ValueError):
        return None
    return buffer.value if 0 < length < 1024 else None


def current_user():
    try:
        return getpass.getuser()
    except (OSError, ImportError, KeyError):
        return None


def path_replacements(scratch=None, infra_root=None):
    """Ordered (needle, placeholder) pairs for every local path that must not reach the report.

    Every spelling a tool may print is covered: native and POSIX separators, the resolved path, the
    Windows 8.3 short form, and the repr/JSON-escaped form with doubled backslashes that a failed
    command's repr carries; matching is case-insensitive. The last pair redacts the account name
    wherever it appears as a path component, as defence in depth against a spelling not listed.
    """
    pairs = []
    if scratch is not None:
        pairs.append((Path(scratch), "<scratch>"))
    if infra_root is not None:
        pairs.append((Path(infra_root), "<infra>"))
    pairs.append((Path(tempfile.gettempdir()), "<tmp>"))
    pairs.append((Path.home(), "<home>"))
    replacements = []
    for path, placeholder in pairs:
        variants = {str(path), str(path.resolve())}
        short = short_path(path)
        if short:
            variants.add(short)
        for variant in variants:
            for spelling in spellings(variant):
                replacements.append((spelling, placeholder))
    for spelling in spellings(sys.executable):
        replacements.append((spelling, "python"))
    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    return replacements


def _user_pattern():
    user = current_user()
    if not user:
        return None
    # A component between separators in plain, repr/JSON-escaped or POSIX spelling.
    return re.compile(r"(?<=[\\/])" + re.escape(user) + r"(?=[\\/])", re.IGNORECASE)


USER_IN_PATH = _user_pattern()


def credential_values(environ=None):
    environ = os.environ if environ is None else environ
    return tuple(value for name in ("GH_TOKEN", "GITHUB_TOKEN") for value in (environ.get(name),)
                 if isinstance(value, str) and value.strip())


def redact_text(text, replacements, credentials=()):
    for credential in credentials:
        text = text.replace(credential, "[redacted]")
    for needle, placeholder in replacements:
        text = re.sub(re.escape(needle), lambda match: placeholder, text, flags=re.IGNORECASE)
    if USER_IN_PATH is not None:
        text = USER_IN_PATH.sub(USER_PLACEHOLDER, text)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text


def strings_of(value):
    """Every key and string of a JSON-like structure, at any depth."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from strings_of(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings_of(item)
    elif isinstance(value, str):
        yield value


def redaction_survivors(value, replacements, credentials=()):
    """Fail-closed self-scan of a redacted document: the kinds of local marker that still appear.

    Returns kinds only (including ``credential``), never the text, so the caller can refuse to
    write the document without echoing what leaked.
    """
    survivors = set()
    needles = [needle.lower() for needle, _ in replacements]
    for text in strings_of(value):
        lowered = text.lower()
        if any(needle in lowered for needle in needles):
            survivors.add("path needle")
        if USER_IN_PATH is not None and USER_IN_PATH.search(text):
            survivors.add("user in path")
        if DRIVE_PATH.search(text):
            survivors.add("drive path")
        if any(credential in text for credential in credentials) or any(pattern.search(text) for pattern in SECRET_PATTERNS):
            survivors.add("credential")
    return sorted(survivors)


def redact(value, replacements, credentials=()):
    """Apply ``redact_text`` to every string in a JSON-like structure (keys included)."""
    if isinstance(value, dict):
        return {redact_text(key, replacements, credentials): redact(item, replacements, credentials)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, replacements, credentials) for item in value]
    if isinstance(value, str):
        return redact_text(value, replacements, credentials)
    return value


def evaluate_repository(record, budget_minutes=10):
    """Fill ``failures``, ``warnings`` and ``result`` of one repository record in place."""
    failures, warnings = [], []
    identity = record.get("identity") or {}
    if record.get("job_error"):
        # Nothing else was inspected; one line says why instead of a cascade of missing sections.
        record["failures"] = [f"the conformance job itself failed for this repository: {record['job_error']}"]
        record["warnings"] = []
        record["result"] = "fail"
        return record
    if record.get("api_error"):
        failures.append(f"read-only API unavailable: {record['api_error']}")
    if identity.get("verified") is False:
        failures.append("repository id does not match the generator profile")
    if record.get("clone_error"):
        failures.append(f"scratch checkout unavailable: {record['clone_error']}")
    baseline = record.get("generated_baseline") or {}
    if baseline.get("workflow_files_identical") is False:
        failures.append("generated workflow files differ from the generator rendering: "
                        + ", ".join(baseline.get("workflow_differences", [])))
    if baseline.get("stale_files"):
        warnings.append("generated non-workflow files predate the current generator: "
                        + ", ".join(baseline["stale_files"]))
    checker = record.get("repository_check") or {}
    if checker.get("exit_code") not in (0, None):
        failures.append("the repository's own scripts/check_repository.py failed")
    elif checker.get("exit_code") is None and not record.get("clone_error"):
        failures.append("the repository's own scripts/check_repository.py did not run")
    detected = record.get("detected_steps") or {}
    if not detected.get("test"):
        failures.append("no test step detected in the profile commands")
    required = record.get("required_checks") or {}
    if required.get("required") == []:
        failures.append("the main branch ruleset requires no status check")
    if required.get("missing"):
        failures.append("required check(s) no generated workflow produces: "
                        + ", ".join(str(check.get("context")) for check in required["missing"]))
    if required.get("strict_up_to_date") is False:
        warnings.append("the ruleset does not require branches to be up to date before merging")
    registry = record.get("registry") or {}
    if registry.get("entry") is None:
        failures.append("no check-name registry entry")
    elif registry.get("check_name_produced") is False:
        failures.append("the registry check name is not produced by the rendered workflow")
    if registry.get("workflow_ref_renders_current_workflow") is False:
        failures.append("the registry workflow_ref does not render the workflow on main")
    elif registry.get("workflow_ref_renders_current_workflow") == "unverifiable":
        warnings.append("registry workflow_ref not verifiable in this run: "
                        + (registry.get("note") or "no local history or checkout to render it against"))
    for defect in record.get("planted_defects") or []:
        if defect["outcome"] in ("not_proved", "error"):
            failures.append(f"planted defect {defect['id']}: {defect['outcome']} ({defect.get('reason') or 'see probes'})")
    coverage = record.get("language_coverage") or {}
    for language, outcome in sorted(coverage.items()):
        if outcome == "not_exercised":
            warnings.append(f"{language} planted defects not exercised in this run; evidence is the consumer's last main CI run")
    run = record.get("last_main_run")
    if run is None:
        warnings.append("no completed main CI run found for the required workflow")
    else:
        if run.get("conclusion") != "success":
            failures.append(f"last main CI run concluded {run.get('conclusion')}")
        if run.get("within_budget") is False:
            message = (f"last main CI run took {run.get('wall_clock_seconds')} s, over the "
                       f"{budget_minutes}-minute budget (profile timeout {record.get('profile_timeout_minutes')} min)")
            if (record.get("profile_timeout_minutes") or budget_minutes) > budget_minutes:
                warnings.append(message)
            else:
                failures.append(message)
        if run.get("head_sha") and record.get("main_sha") and run["head_sha"] != record["main_sha"]:
            warnings.append("main moved since the last completed CI run; results describe the cloned commit")
    record["failures"] = failures
    record["warnings"] = warnings
    record["result"] = "fail" if failures else "pass"
    return record


def build_report(records, generator_commit, github_client, exercised, budget_minutes=10,
                 generated_at=None, api_requests=None, rate_limit_remaining=None, not_run=None):
    for record in records:
        evaluate_repository(record, budget_minutes)
    failures = [f"{record['repository']}: {failure}" for record in records for failure in record["failures"]]
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "generator_commit": generator_commit,
        "github_client": github_client,
        "api_requests": api_requests,
        "api_rate_limit_remaining": rate_limit_remaining,
        "exercised_toolchains": sorted(exercised),
        "budget_minutes": budget_minutes,
        "repository_count": len(records),
        "result": "fail" if failures else "pass",
        "failures": failures,
        "not_run": list(not_run or []),
        "repositories": records,
    }


def to_json(report):
    return json.dumps(report, indent=2, ensure_ascii=True) + "\n"


def _seconds(value):
    if value is None:
        return "-"
    minutes, seconds = divmod(int(value), 60)
    return f"{minutes} min {seconds:02d} s"


def _short(sha):
    return sha[:12] if isinstance(sha, str) else "-"


def render_markdown(report):
    lines = [
        "# CI conformance report",
        "",
        f"- Result: **{report['result'].upper()}** across {report['repository_count']} repositories",
        f"- Generator commit (PenniLogic/infra): `{report['generator_commit'] or 'unknown'}`",
        f"- GitHub reads: `{report['github_client']}` client, {report['api_requests']} requests"
        + (f", {report['api_rate_limit_remaining']} anonymous requests remaining" if report.get("api_rate_limit_remaining") is not None else ""),
        f"- Planted-defect toolchains exercised: {', '.join(report['exercised_toolchains']) or 'none'}",
        f"- Wall-clock budget: {report['budget_minutes']} minutes per main CI run",
        f"- Generated at: {report['generated_at'] or 'not recorded'}",
        "",
        "A passing row is a repository-foundation result; it is not product, release or security acceptance.",
        "",
        "| Repository | main | Generated workflow | Own checker | Required check | Last main CI | Wall-clock | Planted defects | Result |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for record in report["repositories"]:
        baseline = record.get("generated_baseline") or {}
        checker = record.get("repository_check") or {}
        required = record.get("required_checks") or {}
        run = record.get("last_main_run") or {}
        defects = record.get("planted_defects") or []
        proved = sum(1 for defect in defects if defect["outcome"] == "proved")
        consumer = sum(1 for defect in defects if defect["outcome"] == "consumer_evidence")
        exercised = sum(1 for defect in defects if defect["outcome"] not in ("not_exercised", "consumer_evidence"))
        contexts = ", ".join(f"`{check['context']}`" for check in required.get("required", [])) or "none"
        if required.get("missing"):
            contexts += " (MISSING PRODUCER)"
        lines.append(
            f"| {record['repository']} | `{_short(record.get('main_sha'))}` | "
            f"{'identical' if baseline.get('workflow_files_identical') else 'DIFFERS'}"
            + (f" ({len(baseline['stale_files'])} stale non-workflow files)" if baseline.get("stale_files") else "")
            + f" | {'passed' if checker.get('exit_code') == 0 else 'FAILED' if checker.get('exit_code') is not None else 'not run'}"
            f" | {contexts}"
            f" | {run.get('conclusion') or 'none'}"
            f" | {_seconds(run.get('wall_clock_seconds'))}"
            + ("" if run.get("within_budget") in (True, None) else " (OVER BUDGET)")
            + f" | {proved}/{exercised} proved, {len(defects) - exercised - consumer} not exercised"
            + (f", {consumer} consumer evidence" if consumer else "")
            + f" | **{record['result'].upper()}** |"
        )
    lines += ["", "## Findings", ""]
    if not report["failures"]:
        lines.append("No failures.")
    for failure in report["failures"]:
        lines.append(f"- FAIL {failure}")
    warnings = [f"{record['repository']}: {warning}" for record in report["repositories"] for warning in record.get("warnings", [])]
    if warnings:
        lines.append("")
        for warning in warnings:
            lines.append(f"- warning {warning}")
    lines += ["", "## Branch rulesets on main (read-only)", "",
              "| Repository | Rulesets | Required checks (integration) | Up to date | PR only | Approvals | Threads resolved | Linear | Force push | Deletion | Bypass actors |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for record in report["repositories"]:
        required = record.get("required_checks") or {}
        rules = required.get("branch_rules") or {}
        rulesets = required.get("rulesets") or []
        names = ", ".join(f"{ruleset['name']} ({ruleset['enforcement']})" for ruleset in rulesets) or "none"
        checks = ", ".join(f"`{check['context']}` ({check.get('integration_id')})" for check in required.get("required", [])) or "none"
        bypass = sum(len(ruleset.get("bypass_actors", [])) for ruleset in rulesets)
        lines.append(
            f"| {record['repository']} | {names} | {checks} | {rules.get('strict_required_status_checks_policy')} "
            f"| {rules.get('pull_request')} | {rules.get('required_approving_review_count')} "
            f"| {rules.get('required_review_thread_resolution')} | {rules.get('required_linear_history')} "
            f"| {'blocked' if rules.get('non_fast_forward') else 'allowed'} | {'blocked' if rules.get('deletion') else 'allowed'} | {bypass} |"
        )
    lines += ["", "## Planted defects", ""]
    for record in report["repositories"]:
        lines += [f"### {record['repository']}", "", "| Fixture | Language | Toolchain | Outcome | Probes |", "| --- | --- | --- | --- | --- |"]
        for defect in record.get("planted_defects") or []:
            probes = "; ".join(
                f"{probe['label']} -> exit {probe['exit_code']} ({probe['outcome']}"
                + (", rule text surfaced" if probe.get("detail_surfaced") is True else
                   ", refused without rule text: checker predates PR E" if probe.get("detail_surfaced") is False else "")
                + ")"
                for probe in defect.get("probes", [])
            ) or (defect.get("reason") or "-")
            lines.append(f"| `{defect['id']}` | {defect['language']} | {defect['toolchain']} | {OUTCOME_MARK.get(defect['outcome'], defect['outcome'])} | {probes} |")
        steps = record.get("detected_steps") or {}
        lines += ["", f"Detected steps - build: {len(steps.get('build', []))}, test: {len(steps.get('test', []))}, "
                  f"lint: {len(steps.get('lint', []))}, consumer self-tests: {len(steps.get('consumer_self_tests', []))}.", ""]
    if report.get("not_run"):
        lines += ["## Not run in this report", ""]
        for item in report["not_run"]:
            lines.append(f"- {item}")
    while lines and lines[-1] == "":
        lines.pop()  # exactly one newline at the end of the file
    return "\n".join(lines) + "\n"
