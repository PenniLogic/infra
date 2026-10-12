"""Qualify Infra's complete ordinary discovery on the two reviewed hosted platforms."""

import contextlib
import functools
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from templates.qualify_windows import Refused, python_outcomes


ROOT = Path(__file__).resolve().parents[1]
UNITTEST_DISCOVERY = """import sys
import unittest

with open(sys.argv[1], "x", encoding="utf-8", newline="\\n") as report:
    class ReportRunner(unittest.TextTestRunner):
        def __init__(self, **kwargs):
            super().__init__(stream=report, **kwargs)

    sys.argv = ["unittest", "discover", "-s", sys.argv[2], "-v"]
    unittest.main(module=None, testRunner=ReportRunner)
"""
WINDOWS_GOVERNANCE = frozenset(
    "test_conformance_processes.WindowsProcessTests." + name for name in (
        "test_finite_shell_and_argv_descendants_are_terminated_before_the_runner_returns",
        "test_successful_command_does_not_leave_a_redirected_descendant_running_during_restore",
        "test_consumer_code_is_not_released_until_process_ownership_is_established",
        "test_job_creation_refusal_starts_nothing_and_reports_the_ownership_failure",
        "test_assignment_refusal_kills_only_the_idle_gate_and_never_executes_the_consumer",
        "test_interrupt_during_gate_assignment_cannot_start_or_leave_a_consumer",
        "test_unreleased_pipes_have_a_bounded_teardown_and_cannot_be_claimed_safe",
        "test_unreadable_job_membership_cannot_be_claimed_safe",
        "test_refused_tree_termination_is_bounded_and_reported_before_kill_on_close",
    )
) | {
    "test_conformance_capture_redaction.CaptureRedactionTests."
    "test_windows_unconfirmed_normal_capture_still_redacts_and_retains_the_unsafe_flag",
    "test_conformance_defects.FakeRunnerTests.test_a_real_locked_backup_directory_cannot_be_reported_as_proved",
    "test_conformance_defects.EnvironmentTests.test_shell_probes_do_not_resolve_commands_from_the_consumer_working_directory",
}
LINUX_GOVERNANCE = frozenset({
    "test_conformance_processes.LinuxProcessTests."
    "test_timeout_stops_shell_and_argv_group_members_but_keeps_restoration_fail_closed",
    "test_conformance_processes.LinuxProcessTests."
    "test_an_escaped_descendant_is_not_mistaken_for_a_terminated_owned_tree",
})
WINDOWS_SCRIPTS = frozenset("test_bootstrap.DockerCommandTests." + name for name in (
    "test_failed_job_assignment_fails_closed_and_stops_the_command",
    "test_refused_job_creation_fails_closed_before_anything_starts",
    "test_failing_cleanup_keeps_the_timeout_primary_and_kill_on_close_still_applies",
    "test_refused_termination_with_failing_kill_releases_the_pinned_handles",
    "test_interrupt_inside_the_unowned_window_kills_the_started_command",
    "test_command_that_exits_before_it_can_be_owned_is_reported_with_its_result",
    "test_windows_job_owns_the_whole_tree_and_terminates_it",
    "test_process_exits_awaits_the_process_objects_not_the_job_accounting",
))
WINDOWS_SECURITY = frozenset({
    "test_security_controls.ScannerBoundaryTests.test_interrupted_teardown_never_claims_confirmed_cleanup",
    "test_security_controls.ScannerBoundaryTests.test_timeout_terminates_actual_descendants_holding_pipes_and_files",
    "test_security_controls.GitleaksIntegrationTests."
    "test_confirmed_interruption_keeps_public_cleanup_unconfirmed_and_incidents",
})
STACK_TESTS = frozenset("test_integration_stack.StackLifecycleTests." + name for name in (
    "test_01_fresh_stack_becomes_healthy_with_smoke_and_artifact",
    "test_02_second_run_is_idempotent",
    "test_03_down_keeps_data_and_recreate_restores_it",
    "test_04_existing_volume_with_other_credentials_is_named_not_wiped",
    "test_05_reset_removes_everything_and_recreate_needs_no_manual_step",
    "test_06_occupied_postgres_port_fails_fast_naming_the_port",
    "test_07_status_is_read_only",
    "test_08_docker_bind_failure_after_preflight_is_named_and_rolled_back",
    "test_09_two_simultaneous_first_runs_share_one_env_and_one_stack",
))
FLOCK = "test_bootstrap.ReadinessTests.test_project_lock_three_overlapping_holders_never_overlap"
NATIVE_LINKS = {
    "test_database_admission_installation.InstallationTests.test_symlinked_payload_is_refused_before_execution",
    "test_money_source_materialization.MaterializationTests."
    "test_symbolic_file_input_is_refused_when_native_symlinks_are_available",
}
REQUIRED = {
    "governance": WINDOWS_GOVERNANCE | LINUX_GOVERNANCE | NATIVE_LINKS,
    "scripts": WINDOWS_SCRIPTS | WINDOWS_SECURITY | STACK_TESTS | {FLOCK},
}
SKIPS = {
    "win32": {"governance": LINUX_GOVERNANCE, "scripts": STACK_TESTS | {FLOCK}},
    "linux": {"governance": WINDOWS_GOVERNANCE, "scripts": WINDOWS_SCRIPTS | WINDOWS_SECURITY},
}
SECURITY_SOURCE_FILES = frozenset({
    "governance/generate.py", "governance/qualify.py", "governance/templates/qualify_windows.py",
    "governance/repository-profiles.json", "governance/conformance/__init__.py",
    "governance/conformance/defects.py", "governance/conformance/generator.py",
    "governance/conformance/report.py", "governance/conformance/steps.py",
    "scripts/bootstrap.py", "scripts/smoke_infra.py", "scripts/scan_secrets.py",
    "scripts/secret_rotation.py", "scripts/check_dependencies.py", "scripts/security_exceptions.py",
    "scripts/tests/test_security_controls.py", "security/gitleaks.toml",
    "security/exceptions.json", "security/exceptions.schema.json",
})
HOST_GIT = {"win32": r"C:\Program Files\Git\cmd\git.exe", "linux": "/usr/bin/git"}
GITLEAKS_ARCHIVE_PINS = {
    "win32": "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
    "linux": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
}
POWERSHELL_FIXTURE_PREFIX = b"PENNILOGIC_POWERSHELL_FIXTURE_V1 "
POWERSHELL_FIXTURE_COUNTS = {
    "test_api_windows_qualification.ApiWindowsWorkflowTests."
    "test_windows_powershell_stops_at_each_failed_native_command": (9,),
    "test_infra_qualification.InfraQualificationWorkflowTests."
    "test_both_ordinary_suites_preserve_the_linux_graph_and_windows_preparation": (1, 4),
}


def emit(event, **values):
    print(json.dumps({"event": event, **values}, sort_keys=True), flush=True)


def identifier(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def checked(command, root, *, bindings=None):
    if bindings is not None:
        if command[0] not in (bindings["git"], bindings["gitleaks"]):
            raise Refused("security-tool-command-is-not-bound")
        security_tools(root, expected=bindings)
    succeeded = False
    try:
        result = subprocess.run(command, cwd=root, capture_output=True, check=False)
        if result.returncode != 0:
            raise Refused("qualification-prerequisite-command-failed")
        succeeded = True
        return result.stdout
    finally:
        if bindings is not None:
            try:
                security_tools(root, expected=bindings)
            except (Refused, OSError, ValueError):
                if succeeded:
                    raise
                emit("qualification_tool_recheck_refused", code="post-use-security-tool-binding-invalid")


def security_tools(root, *, expected=None):
    if sys.platform not in HOST_GIT:
        raise Refused("security-tools-platform-is-unsupported")
    root = root.resolve(strict=True)

    def external(value, directory=False):
        if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise Refused("security-tool-binding-is-missing-or-invalid")
        path = Path(value)
        if (not path.is_absolute() or path != path.resolve(strict=True) or path.is_relative_to(root)
                or any(part.is_symlink() or part.is_junction() for part in (path, *path.parents))
                or not (path.is_dir() if directory else path.is_file())):
            raise Refused("security-tool-binding-is-not-external-and-regular")
        return path

    temporary = external(os.environ.get("RUNNER_TEMP"), directory=True)
    git = external(os.environ.get("PENNILOGIC_TEST_GIT"))
    scanner = external(os.environ.get("PENNILOGIC_TEST_GITLEAKS"))
    expected_scanner = temporary / "pennilogic-gitleaks-8.30.1" / (
        "gitleaks.exe" if sys.platform == "win32" else "gitleaks"
    )
    if git != Path(HOST_GIT[sys.platform]) or scanner != expected_scanner:
        raise Refused("security-tools-do-not-match-prepared-locations")
    values = {"git": str(git), "gitleaks": str(scanner)}
    for name, path in (("git", git), ("gitleaks", scanner)):
        digest = os.environ.get(f"PENNILOGIC_TEST_{name.upper()}_SHA256", "")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise Refused("security-tool-digest-binding-is-missing")
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != digest:
            raise Refused("security-tool-digest-changed")
        values[name + "_sha256"] = actual
    if expected is not None and values != expected:
        raise Refused("security-tool-original-binding-changed")
    return values


def source_inventory(root, bound_tools=None):
    bindings = security_tools(root) if bound_tools is None else bound_tools()
    git = [bindings["git"], "--no-pager"]
    head = checked([*git, "rev-parse", "HEAD"], root, bindings=bindings).decode("ascii").strip()
    if (not re.fullmatch(r"[0-9a-f]{40}", head) or head != os.environ.get("GITHUB_SHA")
            or checked([*git, "rev-parse", "--is-shallow-repository"], root, bindings=bindings).strip() != b"false"):
        raise Refused("source-must-match-the-full-native-checkout")
    if checked([*git, "status", "--porcelain", "--untracked-files=normal"], root, bindings=bindings):
        raise Refused("qualification-source-is-not-clean")
    tree = checked([*git, "rev-parse", "HEAD^{tree}"], root, bindings=bindings).decode("ascii").strip()
    files, paths = [], set()
    for entry in checked([*git, "ls-tree", "-r", "-z", "HEAD"], root, bindings=bindings).split(b"\0"):
        if not entry:
            continue
        fields, path = entry.split(b"\t", 1)
        mode, kind, blob = fields.decode("ascii").split()
        if mode not in ("100644", "100755") or kind != "blob" or not re.fullmatch(r"[0-9a-f]{40}", blob):
            raise Refused("source-inventory-is-not-regular")
        name = path.decode("utf-8")
        if name in paths:
            raise Refused("source-inventory-has-duplicate-paths")
        paths.add(name)
        files.append({"path_sha256": identifier(name), "mode": mode, "git_blob": blob})
    if not re.fullmatch(r"[0-9a-f]{40}", tree) or not files:
        raise Refused("source-inventory-is-incomplete")
    if not SECURITY_SOURCE_FILES <= paths:
        raise Refused("security-source-closure-is-incomplete")
    return head, tree, files


def versions(root, bound_tools=None):
    system = {"win32": "Windows", "linux": "Linux"}.get(sys.platform)
    images = {"win32": {"win25", "win25-vs2026"}, "linux": {"ubuntu24"}}.get(sys.platform, set())
    image = os.environ.get("ImageOS")
    if (system is None or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("RUNNER_OS") != system or os.environ.get("RUNNER_ARCH") != "X64"
            or os.environ.get("GITHUB_REPOSITORY") != "PenniLogic/infra"
            or os.environ.get("GITHUB_REPOSITORY_ID") != "1394135059"
            or os.environ.get("GITHUB_REPOSITORY_OWNER_ID") != "335295566"
            or image not in images
            or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", os.environ.get("ImageVersion", ""))
            or len(os.environ["ImageVersion"]) > 64):
        raise Refused("expected-standard-hosted-infra-platform-metadata")
    if sys.version_info[:2] != (3, 14):
        raise Refused("python-3-14-is-required")
    if any(name.upper() in {"NODE_OPTIONS", "NODE_PATH", "NPM_CONFIG_NODE_OPTIONS", "NPM_CONFIG_NODE-OPTIONS"}
           for name in os.environ):
        raise Refused("node-startup-overrides-are-not-admitted")
    bindings = security_tools(root) if bound_tools is None else bound_tools()
    tools = {name: shutil.which(name) for name in ("node", "uv", "bash")}
    tools["git"] = bindings["git"]
    if not all(tools.values()):
        raise Refused("a-required-qualification-tool-is-missing")
    node = Path(tools["node"])
    npm = (node.parent / "node_modules/npm/bin/npm-cli.js" if sys.platform == "win32"
           else node.parent.parent / "lib/node_modules/npm/bin/npm-cli.js")
    if (not npm.is_file() or checked([str(node), "--version"], root).strip() != b"v24.14.0"
            or checked([str(node), str(npm), "--version"], root).strip() != b"11.9.0"):
        raise Refused("node-or-bundled-npm-version-mismatch")
    uv = checked([tools["uv"], "--version"], root).split()
    git = checked([tools["git"], "--version"], root, bindings=bindings).decode("ascii").strip()
    bash = re.match(rb"GNU bash, version ([0-9]+(?:\.[0-9]+)+)", checked(
        [tools["bash"], "--noprofile", "--norc", "--version"], root,
    ))
    if (uv[:2] != [b"uv", b"0.11.33"]
            or not re.fullmatch(r"git version [0-9]+\.[0-9]+(?:\.[0-9]+)?(?:\.windows\.[0-9]+)?", git)
            or bash is None):
        raise Refused("uv-git-or-bash-version-evidence-is-invalid")
    if checked([bindings["gitleaks"], "version"], root, bindings=bindings).strip() != b"8.30.1":
        raise Refused("gitleaks-version-mismatch")
    return {"python": ".".join(map(str, sys.version_info[:3])), "node": "24.14.0", "npm": "11.9.0",
            "uv": "0.11.33", "git": git, "bash": bash.group(1).decode("ascii"),
            "git_sha256": bindings["git_sha256"], "gitleaks": "8.30.1",
            "gitleaks_sha256": bindings["gitleaks_sha256"],
            "gitleaks_archive_pin": GITLEAKS_ARCHIVE_PINS[sys.platform],
            "runner_os": system, "image_family": image, "image_version": os.environ["ImageVersion"]}


def discovery_inventory(root, suite):
    loader = unittest.TestLoader()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        tests = loader.discover(str(root / suite / "tests"))
    if loader.errors:
        raise Refused("full-discovery-inventory-has-import-errors")

    def identities(group):
        for item in group:
            if isinstance(item, unittest.TestSuite):
                yield from identities(item)
            elif isinstance(item, unittest.TestCase):
                yield item.id()
            else:
                raise Refused("unknown-discovery-inventory-entry")

    names = list(identities(tests))
    if not names or len(set(names)) != len(names) or not REQUIRED[suite] <= set(names):
        raise Refused("full-discovery-inventory-is-incomplete")
    return {identifier(name): name for name in names}


def _powershell_diagnostic(data, identity, counts):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate-diagnostic-field")
            value[key] = item
        return value

    def integer(value, lower, upper):
        return type(value) is int and lower <= value <= upper

    malformed = {"state": "malformed"}
    if len(data) > 2048 or not data.startswith(POWERSHELL_FIXTURE_PREFIX):
        return malformed
    try:
        value = json.loads(data[len(POWERSHELL_FIXTURE_PREFIX):], object_pairs_hook=unique)
        if (not isinstance(value, dict) or set(value) != {
                "test_id_sha256", "count", "fail_at", "completed_cases", "elapsed_seconds", "timeout_seconds",
                "boundary", "exception_category", "errno", "exit_code", "stdout", "stderr",
            } or value["test_id_sha256"] != identity
                or not integer(value["count"], 1, 9) or value["count"] not in counts
                or not integer(value["fail_at"], 0, value["count"])
                or type(value["completed_cases"]) is not list
                or any(type(number) is not int for number in value["completed_cases"])
                or value["completed_cases"] != list(range(value["fail_at"]))
                or type(value["elapsed_seconds"]) not in (int, float)
                or not math.isfinite(value["elapsed_seconds"]) or value["elapsed_seconds"] < 0
                or type(value["timeout_seconds"]) is not int or value["timeout_seconds"] != 15
                or value["boundary"] not in ("invoke", "assertions")
                or value["exception_category"] not in (
                    "timeout", "os-error", "assertion", "unicode-error", "subprocess-error", "other-exception")
                or (value["errno"] is not None and not integer(value["errno"], -(2 ** 31), 2 ** 31 - 1))
                or (value["exit_code"] is not None and not integer(value["exit_code"], -(2 ** 31), 2 ** 32 - 1))):
            return malformed
        for key in ("stdout", "stderr"):
            stream = value[key]
            if not isinstance(stream, dict) or set(stream) != {"state", "bytes", "sha256"}:
                return malformed
            if stream["state"] in ("unavailable", "malformed"):
                if stream["bytes"] is not None or stream["sha256"] is not None:
                    return malformed
            elif (stream["state"] != ("partial" if value["boundary"] == "invoke" else "complete")
                  or not integer(stream["bytes"], 0, 2 ** 63 - 1) or not isinstance(stream["sha256"], str)
                  or not re.fullmatch(r"[0-9a-f]{64}", stream["sha256"])
                  or (stream["bytes"] == 0 and stream["sha256"] != identifier(""))):
                return malformed
    except (ValueError, UnicodeError, OverflowError, RecursionError):
        return malformed
    return {"state": "available", **value}


def discovery_diagnostics(root, suite, data, inventory, files):
    known = {("test", name): digest for digest, name in inventory.items()}
    for name in inventory.values():
        parts = name.rsplit(".", 2)
        if len(parts) != 3:
            continue
        module, class_name, _ = parts
        for scope in ("setUpClass", "tearDownClass"):
            known[scope, module + "." + class_name] = identifier(module + "." + class_name)
        for scope in ("setUpModule", "tearDownModule"):
            known[scope, module] = identifier(module)
    paths = {entry["path_sha256"] for entry in files}
    fixture_counts = ({identifier(name): counts for name, counts in POWERSHELL_FIXTURE_COUNTS.items()}
                      if suite == "governance" else {})
    prefix = os.fsencode(root).replace(b"\\", b"/").rstrip(b"/") + b"/"
    reports, current, unrecognized, truncated = [], None, 0, False
    for line in data.splitlines():
        if line.startswith((b"FAIL:", b"ERROR:")):
            current = None
            header = re.fullmatch(
                rb"(FAIL|ERROR): (test[A-Za-z0-9_]*|setUpClass|tearDownClass|setUpModule|tearDownModule)"
                rb" \(([A-Za-z_][A-Za-z0-9_.]*)\)(?: \(.*\))?", line,
            )
            if header is None:
                unrecognized += 1
                continue
            method, name = header.group(2).decode("ascii"), header.group(3).decode("ascii")
            scope = "test" if method.startswith("test") else method
            digest = known.get((scope, name))
            if digest is None or (scope == "test" and not name.endswith("." + method)):
                unrecognized += 1
                continue
            if len(reports) == 20:
                truncated = True
                continue
            current = {"reported_status": header.group(1).decode("ascii"), "scope": scope,
                       "reported_id_sha256": digest, "source_frames": []}
            if scope == "test" and digest in fixture_counts:
                current["powershell_fixture"] = {"state": "unavailable"}
            reports.append(current)
            continue
        if current is None:
            continue
        if "powershell_fixture" in current and line.startswith(b"PENNILOGIC_POWERSHELL_FIXTURE_"):
            current["powershell_fixture"] = (
                _powershell_diagnostic(line, current["reported_id_sha256"],
                                       fixture_counts[current["reported_id_sha256"]])
                if current["powershell_fixture"]["state"] == "unavailable" else {"state": "malformed"}
            )
            continue
        frame = re.fullmatch(rb'  File "([^"\r\n]+)", line ([1-9][0-9]{0,7}), in [^\r\n]+', line)
        if frame is None:
            continue
        path = frame.group(1).replace(b"\\", b"/")
        if not path.startswith(prefix):
            continue
        digest = hashlib.sha256(path[len(prefix):]).hexdigest()
        if digest not in paths:
            continue
        location = {"path_sha256": digest, "line": int(frame.group(2))}
        if location not in current["source_frames"]:
            if len(current["source_frames"]) == 8:
                truncated = True
            else:
                current["source_frames"].append(location)
    # These are untrusted failure hints, never inputs to outcome admission.
    emit("ordinary_discovery_diagnostics", suite=suite, diagnostic_only=True,
         reports=reports, unrecognized_headers=unrecognized, truncated=truncated)


def cleanup_evidence(data, required):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Refused("duplicate-owned-stack-cleanup-field")
            value[key] = item
        return value

    projects, removed = {}, []
    for line in data.splitlines():
        for prefix, temporary in ((b"INFRA_STACK_CLEANUP ", False), (b"INFRA_STACK_CLEANUP_TEMP ", True)):
            if not line.startswith(prefix):
                continue
            value = json.loads(line[len(prefix):], object_pairs_hook=unique)
            if (not isinstance(value, dict) or not isinstance(value.get("project"), str)
                    or not re.fullmatch(r"pennilogic-test-[0-9a-f]{8}(?:-conflict|-bind|-race)?", value["project"])):
                raise Refused("invalid-owned-stack-cleanup-evidence")
            if temporary:
                if set(value) != {"project", "removed"} or value["removed"] is not True:
                    raise Refused("owned-stack-temporary-cleanup-not-confirmed")
                removed.append(value["project"])
            else:
                if (set(value) != {"project", "containers", "volumes", "networks"}
                        or any(type(value[key]) is not int or value[key] != 0
                               for key in ("containers", "volumes", "networks"))
                        or value["project"] in projects):
                    raise Refused("owned-stack-resource-absence-not-confirmed")
                projects[value["project"]] = value
    if required:
        if (len(removed) != 1 or set(projects) != {
                removed[0] + suffix for suffix in ("", "-conflict", "-bind", "-race")}):
            raise Refused("owned-stack-cleanup-evidence-is-incomplete")
    elif projects or removed:
        raise Refused("unexpected-owned-stack-cleanup-evidence")
    for value in projects.values():
        emit("owned_stack_cleanup", **value)
    if removed:
        emit("owned_stack_temporary_cleanup", project=removed[0], removed=True)


def qualify(root, suite):
    if "PENNILOGIC_SKIP_DOCKER_TESTS" in os.environ:
        raise Refused("ambient-docker-test-skip-is-not-admitted")
    bound_tools = functools.cache(lambda: security_tools(root))
    runtime = versions(root, bound_tools)
    source = source_inventory(root, bound_tools)
    emit("qualification_source", suite=suite, commit=source[0], tree=source[1], **runtime)
    for entry in source[2]:
        emit("source_file", suite=suite, **entry)
    if sys.platform == "win32" and suite == "scripts":
        os.environ["PENNILOGIC_SKIP_DOCKER_TESTS"] = "1"
    inventory = discovery_inventory(root, suite)
    for digest in sorted(inventory):
        emit("test_inventory", suite=suite, id_sha256=digest)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="infra-unittest-report-") as directory, \
            tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        report = Path(directory) / "unittest.txt"
        result = subprocess.run(
            [sys.executable, "-c", UNITTEST_DISCOVERY, str(report), str(Path(suite) / "tests")],
            cwd=root, stdout=stdout, stderr=stderr, check=False,
        )
        emit("ordinary_discovery", suite=suite, exit_code=result.returncode,
             wall_seconds=round(time.monotonic() - started, 6))
        stdout.seek(0)
        stderr.seek(0)
        if report.is_file() and not report.is_symlink():
            data = report.read_bytes()
        elif result.returncode == 0:
            raise Refused("missing-ordinary-unittest-report")
        else:
            data = stderr.read()
        if result.returncode != 0:
            discovery_diagnostics(root, suite, data, inventory, source[2])
            raise Refused("ordinary-discovery-or-setup-teardown-failed")
        records = python_outcomes(data)
        skipped = sum(record["outcome"] == "skipped" for record in records)
        summary = f"OK (skipped={skipped})".encode("ascii") if skipped else b"OK"
        if data.splitlines()[-1] != summary:
            raise Refused("ordinary-discovery-summary-does-not-match-outcomes")
        output = stdout.read()
    for record in records:
        emit("test_outcome", suite=suite, id_sha256=record["id_sha256"], outcome=record["outcome"])
    if {record["id_sha256"] for record in records} != set(inventory):
        raise Refused("executed-test-ids-differ-from-full-discovery")
    allowed = SKIPS[sys.platform][suite]
    for record in records:
        name = inventory[record["id_sha256"]]
        expected = "skipped" if name in allowed else "passed"
        if record["outcome"] != expected:
            raise Refused("test-outcome-differs-from-exact-platform-applicability")
    cleanup_evidence(output, required=sys.platform == "linux" and suite == "scripts")
    if source_inventory(root, bound_tools) != source:
        raise Refused("qualification-source-changed-during-discovery")
    emit("infra_qualification", suite=suite, ok=True, tests=len(records), skipped=len(allowed))


def main():
    try:
        command = sys.argv[1:]
        if command:
            command[-1] = command[-1].replace("\\", "/")
        if command not in (["--", "python", "-m", "unittest", "discover", "-s", "governance/tests"],
                           ["--", "python", "-m", "unittest", "discover", "-s", "scripts/tests"]):
            raise Refused("only-complete-canonical-discovery-commands-are-admitted")
        qualify(ROOT, command[-1].split("/")[0])
        return 0
    except Refused as error:
        emit("infra_qualification_refused", code=str(error))
    except KeyboardInterrupt:
        emit("infra_qualification_refused", code="qualification-interrupted")
        return 130
    except (OSError, ValueError, subprocess.SubprocessError):
        emit("infra_qualification_refused", code="process-or-evidence-error")
    return 1


if __name__ == "__main__":
    sys.exit(main())
