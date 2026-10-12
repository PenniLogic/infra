"""Synthetic-only controls, including actual Gitleaks against disposable Git histories."""

import copy
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from support import ROOT, run_script
import check_dependencies as dependencies
import scan_secrets
import secret_rotation
import security_exceptions as security


NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)
HEAD = "a" * 40
BASE = "b" * 40
REPOSITORY = "PenniLogic/android"
ANDROID_ID = 1394134737


def scanner_tools():
    names = ("PENNILOGIC_TEST_GIT", "PENNILOGIC_TEST_GITLEAKS", "PENNILOGIC_TEST_GITLEAKS_SHA256")
    values = tuple(os.environ.get(name, "") for name in names)
    if not all(values):
        raise AssertionError("Explicit trusted Git/Gitleaks paths and verified scanner digest are required.")
    return values


def empty_exceptions(now=NOW):
    return security.Exceptions({"schema_version": 1, "exceptions": []}, now)


def exception_for(kind, repository, pattern, artifact, expiry="2026-10-13T12:00:00Z"):
    return {
        "id": "synthetic-false-positive", "kind": kind, "repository": repository,
        "pattern": pattern, "artifact": artifact, "reason": "Synthetic nonfunctional test only.",
        "owner": "basiltt", "expires_at": expiry,
    }


def with_exception(entry, now=NOW):
    return security.Exceptions({"schema_version": 1, "exceptions": [entry]}, now)


def comparison(changes=None):
    return {
        "schema_version": 1, "repository": REPOSITORY, "repository_id": ANDROID_ID,
        "base": BASE, "head": HEAD, "complete": True, "changes": [] if changes is None else changes,
    }


def vulnerable_change(change_type="added", severity="high"):
    return {
        "change_type": change_type, "ecosystem": "maven", "name": "invalid.synthetic:example",
        "version": "1.0.0", "vulnerabilities": [
            {"advisory_ghsa_id": "GHSA-2222-3333-4444", "severity": severity,
             "advisory_summary": "Raw metadata is deliberately not exported."},
        ],
    }


class ExceptionTests(unittest.TestCase):
    def test_checked_in_exceptions_are_valid_and_empty(self):
        self.assertEqual([], security.Exceptions.load().entries)
        schema = security.read_document(ROOT / "security" / "exceptions.schema.json")
        required = set(schema["properties"]["exceptions"]["items"]["required"])
        self.assertEqual(required, set(exception_for("secret", REPOSITORY, "example-rule", "c" * 64)))

    def test_exact_exception_and_expiry_boundary(self):
        entry = exception_for("secret", REPOSITORY, "example-rule", "c" * 64)
        active = with_exception(entry)
        self.assertEqual(entry["id"], active.suppression("secret", REPOSITORY, "example-rule", "c" * 64))
        for changes in (
            ("advisory", REPOSITORY, "example-rule", "c" * 64),
            ("secret", "PenniLogic/api", "example-rule", "c" * 64),
            ("secret", REPOSITORY, "different-rule", "c" * 64),
            ("secret", REPOSITORY, "example-rule", "d" * 64),
        ):
            self.assertIsNone(active.suppression(*changes))
        expired = with_exception(entry, security.utc(entry["expires_at"]))
        self.assertIsNone(expired.suppression("secret", REPOSITORY, "example-rule", "c" * 64))
        self.assertEqual(1, expired.audit()["expired_count"])

    def test_exception_audit_never_copies_reason_or_owner(self):
        entry = exception_for("secret", REPOSITORY, "example-rule", "c" * 64)
        report = security.canonical(with_exception(entry).audit())
        self.assertNotIn(entry["reason"].encode(), report)
        self.assertNotIn(entry["owner"].encode(), report)

    def test_malformed_expiry_broad_patterns_and_duplicates_refuse(self):
        valid = exception_for("secret", REPOSITORY, "example-rule", "c" * 64)
        mutations = [
            ("expires_at", "2026-02-30T00:00:00Z"), ("expires_at", "2027-01-01"),
            ("expires_at", "2027-01-01T00:00:00+01:00"), ("pattern", ".*"),
            ("artifact", "*"), ("owner", ""), ("reason", "\n"),
            ("kind", "component"), ("repository", "PenniLogic-old/android"),
            ("id", "sk-" + "a" * 32),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                entry = {**valid, key: value}
                with self.assertRaises(security.Refusal):
                    with_exception(entry)
        with self.assertRaisesRegex(security.Refusal, "duplicate-exception"):
            security.Exceptions({"schema_version": 1, "exceptions": [valid, valid]}, NOW)
        with self.assertRaises(security.Refusal):
            security.Exceptions({"schema_version": True, "exceptions": []}, NOW)

    def test_json_rejects_duplicates_bom_nonfinite_and_oversize(self):
        for raw in (
            b'{"a":1,"a":2}', b'\xef\xbb\xbf{}', b'{"a":NaN}', b'{"a":Infinity}', b"\xff",
            b'{"a":1e9999}', b'{"a":' + b"9" * 5000 + b"}",
        ):
            with self.subTest(raw=raw), self.assertRaises(security.Refusal):
                security.document(raw)
        with mock.patch.object(security, "MAX_DOCUMENT_BYTES", 2):
            with self.assertRaisesRegex(security.Refusal, "document-too-large"):
                security.document(b'{"a":1}')


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.source = {
            "schema_version": 1,
            "variants": {
                "debug": ["invalid.synthetic:base:1.0.0", "invalid.synthetic:debug:1.0.0"],
                "release": ["invalid.synthetic:base:1.0.0"],
            },
        }
        self.policy = {"schema_version": 1, "components": copy.deepcopy(self.source["variants"])}

    def test_android_preserves_existing_privacy_consumer_shape(self):
        report = dependencies.android_inventory(self.source, self.policy, HEAD)
        self.assertEqual("pass", report["status"])
        self.assertEqual(self.source, report["android_inventory"])
        self.assertEqual(self.policy["components"], report["android_inventory"]["variants"])
        self.assertEqual(
            {"coordinate": "invalid.synthetic:base:1.0.0", "scopes": ["debug", "release"]},
            report["components"][0],
        )

    def test_android_unlisted_transitive_and_changed_version_fail_and_name_coordinate(self):
        for variant in ("debug", "release"):
            source = copy.deepcopy(self.source)
            source["variants"][variant].append("invalid.synthetic:unlisted:9.0.0")
            source["variants"][variant].sort()
            report = dependencies.android_inventory(source, self.policy, HEAD)
            self.assertEqual("fail", report["status"])
            self.assertEqual(["invalid.synthetic:unlisted:9.0.0"], report["missing"][variant])
        self.source["variants"]["release"] = ["invalid.synthetic:base:2.0.0"]
        report = dependencies.android_inventory(self.source, self.policy, HEAD)
        self.assertEqual("fail", report["status"])
        self.assertEqual(["invalid.synthetic:base:1.0.0"], report["unused"]["release"])

    def test_warn_mode_keeps_findings_and_does_not_accept_missing_inventory(self):
        self.source["variants"]["release"].append("invalid.synthetic:unlisted:1.0.0")
        report = dependencies.android_inventory(self.source, self.policy, HEAD, "warn")
        self.assertEqual("warn", report["status"])
        self.assertEqual(1, report["missing_count"])
        self.source["variants"].pop("debug")
        with self.assertRaises(security.Refusal):
            dependencies.android_inventory(self.source, self.policy, HEAD, "warn")

    def test_android_requires_resolved_complete_sorted_unique_variants(self):
        for bad in (
            [], ["invalid.synthetic:base:+"], ["invalid.synthetic:base:latest"],
            ["invalid.synthetic:base:1.0.0"] * 2, [12],
            ["invalid.synthetic:debug:1.0.0", "invalid.synthetic:base:1.0.0"],
            ["invalid.synthetic:" + "sk-" + "a" * 32 + ":1.0.0"],
        ):
            source = copy.deepcopy(self.source)
            source["variants"]["debug"] = bad
            with self.subTest(bad=bad), self.assertRaises(security.Refusal):
                dependencies.android_inventory(source, self.policy, HEAD)
        self.source["schema_version"] = True
        with self.assertRaises(security.Refusal):
            dependencies.android_inventory(self.source, self.policy, HEAD)

    @staticmethod
    def npm_source():
        return {
            "lockfileVersion": 3, "packages": {
                "": {"name": "synthetic-client", "version": "0.0.0"},
                "node_modules/example": {
                    "version": "1.0.0", "dev": True,
                    "resolved": "https://registry.example.invalid/example/-/example-1.0.0.tgz",
                },
                "node_modules/example/node_modules/@synthetic/child": {"version": "2.0.0"},
            },
        }

    def test_npm_all_transitive_and_dev_packages_need_inventory(self):
        source = self.npm_source()
        policy = {"schema_version": 1, "components": [{"name": "example", "version": "1.0.0"}]}
        for repository in ("PenniLogic/web", "PenniLogic/admin"):
            report = dependencies.npm_inventory(source, policy, repository, HEAD)
            self.assertEqual("fail", report["status"])
            self.assertEqual(["@synthetic/child@2.0.0"], report["missing"]["all"])
        policy["components"].append({"name": "@synthetic/child", "version": "2.0.0"})
        self.assertEqual("pass", dependencies.npm_inventory(source, policy, "PenniLogic/web", HEAD)["status"])
        source["lockfileVersion"] = 2
        self.assertEqual("pass", dependencies.npm_inventory(source, policy, "PenniLogic/web", HEAD)["status"])

    def test_npm_alias_uses_resolved_package_name_and_deduplicates_install_locations(self):
        source = self.npm_source()
        source["packages"] = {
            "": {}, "node_modules/alias": {"name": "actual-package", "version": "1.2.3"},
            "node_modules/parent/node_modules/alias": {"name": "actual-package", "version": "1.2.3"},
        }
        policy = {"schema_version": 1, "components": [{"name": "actual-package", "version": "1.2.3"}]}
        report = dependencies.npm_inventory(source, policy, "PenniLogic/web", HEAD)
        self.assertEqual(["actual-package@1.2.3"], [item["coordinate"] for item in report["components"]])

    def test_npm_unresolved_versions_workspaces_and_links_refuse(self):
        source = self.npm_source()
        policy = {"schema_version": 1, "components": []}
        for bad in ({"version": "file:../local"}, {"version": "*"}, {"link": True}, {"version": "1.0.0", "link": 0}):
            source["packages"]["node_modules/example"] = bad
            with self.subTest(bad=bad), self.assertRaises(security.Refusal):
                dependencies.npm_inventory(source, policy, "PenniLogic/web", HEAD)
        for resolved in (
            "file:../local.tgz", "../local.tgz", "git+https://example.invalid/source",
            "https://[", "https://example.invalid:not-a-port/package",
            "https://synthetic:nonfunctional@example.invalid/package", "\nhttps://example.invalid/package", None,
        ):
            source["packages"]["node_modules/example"] = {"version": "1.0.0", "resolved": resolved}
            with self.subTest(resolved=resolved), self.assertRaises(security.Refusal):
                dependencies.npm_inventory(source, policy, "PenniLogic/web", HEAD)
        source = self.npm_source()
        source["packages"]["packages/workspace"] = {"version": "1.0.0"}
        with self.assertRaises(security.Refusal):
            dependencies.npm_inventory(source, policy, "PenniLogic/web", HEAD)

    def test_real_dependency_cli_exit_and_machine_readable_output(self):
        with tempfile.TemporaryDirectory(prefix="dependency-cli-") as directory:
            resolved = Path(directory) / "resolved.json"
            policy = Path(directory) / "policy.json"
            resolved.write_bytes(security.canonical(self.source))
            policy.write_bytes(security.canonical(self.policy))
            args = ("android", "--resolved", resolved, "--policy", policy, "--head", HEAD)
            result = run_script("check_dependencies.py", *args)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("pass", json.loads(result.stdout)["status"])
            self.source["variants"]["release"].append("invalid.synthetic:unlisted:1.0.0")
            resolved.write_bytes(security.canonical(self.source))
            result = run_script("check_dependencies.py", *args)
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertIn("invalid.synthetic:unlisted:1.0.0", result.stdout)
            result = run_script("check_dependencies.py", *args, "--mode", "warn")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("warn", json.loads(result.stdout)["status"])


class DependencyReviewTests(unittest.TestCase):
    def review(self, value, exceptions=None):
        return dependencies.dependency_review(value, REPOSITORY, BASE, HEAD, exceptions or empty_exceptions())

    def test_clean_comparison_and_removed_vulnerability_pass(self):
        for value in (comparison(), comparison([vulnerable_change("removed")])):
            self.assertEqual("pass", self.review(value)["status"])

    def test_each_known_vulnerability_severity_blocks_additions(self):
        for severity in sorted(dependencies.SEVERITIES):
            with self.subTest(severity=severity):
                report = self.review(comparison([vulnerable_change(severity=severity)]))
                self.assertEqual("fail", report["status"])
                self.assertEqual(1, report["blocking_count"])
                self.assertNotIn(b"Raw metadata", security.canonical(report))

    def test_expired_advisory_exception_retriggers_same_finding(self):
        value = comparison([vulnerable_change()])
        original = self.review(value)["findings"][0]
        entry = exception_for("advisory", REPOSITORY, original["advisory"], original["id"])
        self.assertEqual("pass", self.review(value, with_exception(entry))["status"])
        report = self.review(value, with_exception(entry, security.utc(entry["expires_at"])))
        self.assertEqual("fail", report["status"])
        self.assertEqual(original["id"], report["findings"][0]["id"])
        self.assertIsNone(report["findings"][0]["exception"])

    def test_wrong_repo_stale_head_incomplete_and_malformed_fail_closed(self):
        for key, value in (
            ("head", BASE), ("base", HEAD), ("complete", False), ("complete", 1),
            ("repository_id", 1), ("repository_id", True), ("repository", "PenniLogic/api"),
            ("schema_version", True), ("changes", None),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(security.Refusal):
                self.review({**comparison(), key: value})
        for changes in (
            [None], [{**vulnerable_change(), "vulnerabilities": None}],
            [{**vulnerable_change(), "ecosystem": "unknown"}],
            [{**vulnerable_change(), "name": "gh" + "p_" + "a" * 32}],
            [{**vulnerable_change(), "vulnerabilities": [{"advisory_ghsa_id": "GHSA-2222-3333-4444"}]}],
        ):
            with self.subTest(changes=changes), self.assertRaises(security.Refusal):
                self.review(comparison(changes))

    def test_repeated_advisory_in_multiple_manifests_has_one_finding(self):
        self.assertEqual(1, self.review(comparison([vulnerable_change(), vulnerable_change()]))["blocking_count"])

    def test_real_review_cli_blocks_advisory_and_refuses_missing_input(self):
        with tempfile.TemporaryDirectory(prefix="advisory-cli-") as directory:
            path = Path(directory) / "comparison.json"
            args = ("review", "--repository", REPOSITORY, "--comparison", path, "--base", BASE, "--head", HEAD)
            result = run_script("check_dependencies.py", *args)
            self.assertEqual(2, result.returncode, result.stderr)
            self.assertEqual("dependency-input-read-failed", json.loads(result.stdout)["code"])
            path.write_bytes(security.canonical(comparison([vulnerable_change()])))
            result = run_script("check_dependencies.py", *args)
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertEqual("GHSA-2222-3333-4444", json.loads(result.stdout)["findings"][0]["advisory"])
            path.write_bytes(security.canonical(comparison()))
            result = run_script("check_dependencies.py", *args)
            self.assertEqual(0, result.returncode, result.stderr)


class ScannerBoundaryTests(unittest.TestCase):
    def test_scanner_environment_removes_credentials_and_candidate_configuration(self):
        git_executable = Path(scanner_tools()[0])
        with mock.patch.dict(os.environ, {
            "GH_TOKEN": "synthetic-credential", "GITHUB_TOKEN": "synthetic-credential",
            "GITLEAKS_CONFIG": "untrusted.toml", "GITLEAKS_CONFIG_TOML": "untrusted",
            "GIT_CONFIG_PARAMETERS": "untrusted", "GIT_CONFIG_KEY_0": "untrusted",
            "PATH": str(ROOT), "GIT_EXEC_PATH": str(ROOT), "PATHEXT": ".CMD;.EXE",
            "NoDefaultCurrentDirectoryInExePath": "",
        }):
            env = scan_secrets.scanner_environment(git_executable)
        for name in (
            "GH_TOKEN", "GITHUB_TOKEN", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML",
            "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_KEY_0", "GIT_EXEC_PATH",
        ):
            self.assertNotIn(name, env)
        self.assertEqual(str(git_executable.parent), env["PATH"])
        self.assertEqual(".EXE", env["PATHEXT"])
        self.assertEqual("1", env["NoDefaultCurrentDirectoryInExePath"])
        self.assertEqual("file", env["GIT_ALLOW_PROTOCOL"])
        self.assertEqual("1", env["GIT_NO_LAZY_FETCH"])

    def test_timeout_and_cleanup_failure_keep_the_primary_code_without_child_output(self):
        token = "sk-" + "M4" * 20
        runner = "_windows_runner" if os.name == "nt" else "_posix_runner"

        def failed(*args):
            args[-1](token)
            return scan_secrets.processes.Result(
                None, token, timed_out=True, error=token, restoration_safe=False,
            )

        with mock.patch.object(scan_secrets.processes, runner, side_effect=failed):
            with self.assertRaisesRegex(scan_secrets.ProcessRefusal, "^scanner-or-git-timeout$") as caught:
                scan_secrets.run(["synthetic"], ROOT, {}, timeout=1)
        self.assertFalse(caught.exception.cleanup_confirmed)
        output = io.StringIO()
        with mock.patch.object(scan_secrets, "scan", side_effect=caught.exception), redirect_stdout(output):
            code = scan_secrets.main([
                "--repository", "PenniLogic/infra", "--git", "unused",
                "--gitleaks", "unused", "--gitleaks-sha256", "a" * 64,
            ])
        self.assertEqual(2, code)
        self.assertEqual("scanner-or-git-timeout", json.loads(output.getvalue())["code"])
        self.assertEqual("unconfirmed", json.loads(output.getvalue())["process_cleanup"])
        self.assertNotIn(token, output.getvalue())

    def test_interruption_without_a_cleanup_witness_never_claims_confirmed_exit(self):
        private = "private interruption path and child output"
        runner = "_windows_runner" if os.name == "nt" else "_posix_runner"
        with mock.patch.object(
            scan_secrets.processes, runner,
            side_effect=scan_secrets.processes.UnsafeProcessTreeError(private),
        ):
            with self.assertRaisesRegex(scan_secrets.ProcessRefusal, "^scanner-process-interrupted$") as caught:
                scan_secrets.run(["synthetic"], ROOT, {})
        self.assertFalse(caught.exception.cleanup_confirmed)
        for error in (caught.exception, KeyboardInterrupt(private)):
            with self.subTest(error=type(error).__name__):
                stdout, stderr = io.StringIO(), io.StringIO()
                with mock.patch.object(scan_secrets, "scan", side_effect=error), \
                        redirect_stdout(stdout), redirect_stderr(stderr):
                    code = scan_secrets.main([
                        "--repository", "PenniLogic/infra", "--git", "unused",
                        "--gitleaks", "unused", "--gitleaks-sha256", "a" * 64,
                    ])
                self.assertEqual(2, code)
                report = json.loads(stdout.getvalue())
                self.assertEqual("unconfirmed", report["process_cleanup"])
                self.assertIs(False, report["coverage"]["complete"])
                self.assertNotIn("incident_handoff", report)
                self.assertEqual("", stderr.getvalue())
                self.assertNotIn(private, stdout.getvalue())

    @unittest.skipUnless(os.name == "nt", "Windows interruption during owned teardown")
    def test_interrupted_teardown_never_claims_confirmed_cleanup(self):
        helpers = scan_secrets.processes.windows_helpers()
        env = scan_secrets.scanner_environment(Path(scanner_tools()[0]))
        processes = []
        original_popen = subprocess.Popen

        def remember_process(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process

        with tempfile.TemporaryDirectory(prefix="synthetic-interrupted-cleanup-") as directory:
            root = Path(directory)
            pid_file = root / "child.pid"
            command = [
                sys.executable, "-c",
                "from pathlib import Path; import subprocess, sys; "
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(3)'], "
                "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
                f"Path({str(pid_file)!r}).write_text(str(child.pid), encoding='ascii'); "
                "print('private child output')",
            ]
            try:
                with mock.patch.object(subprocess, "Popen", side_effect=remember_process), \
                        mock.patch.object(scan_secrets.processes, "_finish_windows_tree",
                                          side_effect=KeyboardInterrupt("private cleanup path")):
                    with self.assertRaisesRegex(scan_secrets.ProcessRefusal, "^scanner-process-interrupted$") as caught:
                        scan_secrets.run(command, root, env)
                self.assertFalse(caught.exception.cleanup_confirmed)
                report = scan_secrets.refusal_report(caught.exception)
                self.assertNotIn("private", json.dumps(report))
            finally:
                for process in processes:
                    self.assertTrue(helpers.release_pipes(process, helpers.TEARDOWN_SECONDS))
                    process.wait(timeout=helpers.TEARDOWN_SECONDS)
                if pid_file.is_file():
                    with helpers.ProcessExits() as exits:
                        exits.add([int(pid_file.read_text(encoding="ascii"))])
                        self.assertEqual(1, exits.wait(4), "The finite owned fixture must not survive this test.")

    def test_owned_runner_preserves_complete_metadata_before_reporting_tail(self):
        env = scan_secrets.scanner_environment(Path(scanner_tools()[0]))
        result = scan_secrets.run([sys.executable, "-c", "print('a' * 9000, end='')"], ROOT, env)
        self.assertEqual(0, result.returncode)
        self.assertEqual(b"a" * 9000, result.stdout)

    def test_partial_reports_with_success_or_leak_exit_and_error_diagnostics_refuse(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-scanner-output-") as directory:
            report = Path(directory) / "report.json"
            diagnostic = "Synthetic private diagnostic, not public output."
            env = scan_secrets.scanner_environment(Path(scanner_tools()[0]))
            for exit_code, findings in ((0, []), (10, [{"RuleID": "synthetic-partial-finding"}])):
                with self.subTest(exit_code=exit_code):
                    command = [
                        sys.executable, "-c",
                        "from pathlib import Path; import sys; "
                        f"Path({str(report)!r}).write_text({json.dumps(findings)!r}, encoding='utf-8'); "
                        f"print({diagnostic!r}, file=sys.stderr); sys.exit({exit_code})",
                    ]
                    result = scan_secrets.run(command, Path(directory), env)
                    self.assertEqual(exit_code, result.returncode)
                    self.assertEqual(findings, security.read_document(report))
                    with self.assertRaisesRegex(security.Refusal, "^scanner-diagnostic-output$"):
                        scan_secrets.scanner_report(result, report)

    @unittest.skipUnless(os.name == "nt", "Windows descendant ownership and handle release")
    def test_timeout_terminates_actual_descendants_holding_pipes_and_files(self):
        worker = """import os
from pathlib import Path
import subprocess
import sys
import time

state, mode = Path(sys.argv[1]), sys.argv[2]
(state / (mode + '.pid')).write_text(str(os.getpid()), encoding='ascii')
if mode == 'child':
    with (state / 'held.txt').open('w') as held:
        held.write('nonfunctional synthetic content')
        held.flush()
        time.sleep(9)
else:
    subprocess.Popen([sys.executable, __file__, str(state), 'child'])
    time.sleep(9)
"""
        helpers = scan_secrets.processes.windows_helpers()
        env = scan_secrets.scanner_environment(Path(scanner_tools()[0]))
        with tempfile.TemporaryDirectory(prefix="synthetic-scanner-tree-") as directory:
            root = Path(directory)
            script = root / "worker.py"
            script.write_text(worker, encoding="utf-8")
            started = time.monotonic()
            with self.assertRaisesRegex(scan_secrets.ProcessRefusal, "^scanner-or-git-timeout$") as caught:
                scan_secrets.run([sys.executable, str(script), str(root), "parent"], root, env, timeout=1)
            elapsed = time.monotonic() - started
            pids = [int(path.read_text(encoding="ascii")) for path in root.glob("*.pid")]
            with helpers.ProcessExits() as exits:
                exits.add(pids)
                try:
                    self.assertEqual(2, len(pids), "Both finite fixture processes must start before the deadline.")
                    self.assertTrue(caught.exception.cleanup_confirmed)
                    self.assertLess(elapsed, 1 + helpers.TEARDOWN_SECONDS + 0.75)
                    self.assertEqual(2, exits.wait(0), "Owned descendants must exit before timeout is returned.")
                    (root / "held.txt").unlink()
                finally:
                    self.assertEqual(len(pids), exits.wait(10), "Finite fixture processes must not survive cleanup.")

    def test_malformed_scanner_output_refuses_not_an_empty_pass(self):
        valid = {
            "RuleID": "pennilogic-provider-key", "Commit": HEAD, "File": "synthetic.txt",
            "StartLine": 1, "StartColumn": 1, "EndLine": 1, "EndColumn": 20,
        }
        for key, value in (
            ("RuleID", "sk-" + "a" * 32), ("Commit", "bad"), ("File", None),
            ("StartLine", True), ("StartColumn", 0), ("StartColumn", 21), ("EndLine", 0), ("EndColumn", "1"),
        ):
            with self.subTest(key=key), self.assertRaises(security.Refusal):
                scan_secrets.findings_from_gitleaks([{**valid, key: value}], REPOSITORY, empty_exceptions())
        with self.assertRaises(security.Refusal):
            scan_secrets.findings_from_gitleaks({}, REPOSITORY, empty_exceptions())

    def test_cli_argument_errors_and_json_errors_do_not_echo_payloads(self):
        token = "sk-" + "P5" * 20
        result = run_script("scan_secrets.py", "--unexpected", token)
        self.assertEqual(2, result.returncode)
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertEqual("", result.stderr)

    def test_nonregular_documents_refuse_and_linked_ancestors_are_checked(self):
        with tempfile.TemporaryDirectory(prefix="security-input-") as directory:
            path = Path(directory)
            with self.assertRaisesRegex(security.Refusal, "nonregular-input"):
                security.read_document(path)
            file = path / "input.json"
            file.write_bytes(b"{}")
            with mock.patch.object(Path, "is_junction", lambda item: item == path):
                with self.assertRaisesRegex(security.Refusal, "linked-input"):
                    security.read_document(file)


class GitleaksIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.git_executable, cls.scanner, cls.scanner_sha256 = scanner_tools()
        scan_secrets.verify_scanner(Path(cls.scanner), cls.scanner_sha256)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-secret-history-")
        self.addCleanup(self.temporary.cleanup)
        self.initialize(Path(self.temporary.name) / "repository")

    def initialize(self, root, clean_commit=True):
        self.root = root
        self.root.mkdir()
        self.git("init", "--quiet", "-b", "main")
        self.git("config", "user.name", "Synthetic Fixture")
        self.git("config", "user.email", "synthetic@example.invalid")
        if clean_commit:
            (self.root / "safe.txt").write_text("Only synthetic content.\n", encoding="utf-8")
            self.commit()

    def git(self, *args):
        result = scan_secrets.run(
            [self.git_executable, *args], self.root,
            scan_secrets.scanner_environment(Path(self.git_executable)),
        )
        self.assertEqual(0, result.returncode, "Synthetic Git setup failed.")
        return result.stdout.decode("utf-8").strip()

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", "Synthetic fixture")

    def scan(self, exceptions=None):
        return scan_secrets.scan(
            self.root, "PenniLogic/infra", self.scanner, exceptions or empty_exceptions(),
            git_executable=self.git_executable, scanner_sha256=self.scanner_sha256,
        )

    def cli_arguments(self):
        return (
            "--root", self.root, "--repository", "PenniLogic/infra",
            "--git", self.git_executable, "--gitleaks", self.scanner, "--gitleaks-sha256", self.scanner_sha256,
        )

    def plant(self, content):
        path = self.root / "synthetic.txt"
        path.write_text(content + "\n", encoding="utf-8")
        self.commit()
        return path

    def test_clean_history_passes_real_scanner(self):
        report = self.scan()
        self.assertEqual("pass", report["status"])
        self.assertEqual(1, report["coverage"]["commits"])
        self.assertEqual([], report["findings"])

    def test_deleted_secret_is_found_in_full_history_and_never_echoed(self):
        token = "gh" + "p_" + "A9" * 18
        path = self.plant(token)
        planted_commit = self.git("rev-parse", "HEAD")
        path.unlink()
        self.commit()
        report = self.scan()
        self.assertEqual("fail", report["status"])
        finding = next(item for item in report["findings"] if item["rule"] == "pennilogic-github-token")
        self.assertEqual(planted_commit, finding["commit"])
        self.assertEqual(3, report["coverage"]["commits"])
        encoded = security.canonical(report)
        for raw in (token, "synthetic.txt", "Synthetic Fixture", "synthetic@example.invalid"):
            self.assertNotIn(raw.encode(), encoded)

    def test_secret_present_only_in_root_commit_is_found_after_removal(self):
        self.initialize(Path(self.temporary.name) / "root-only", clean_commit=False)
        path = self.plant("sk-" + "R7" * 20)
        root_commit = self.git("rev-parse", "HEAD")
        self.assertEqual(root_commit, self.git("rev-list", "--parents", "-1", "HEAD"))
        path.unlink()
        self.commit()
        report = self.scan()
        self.assertEqual("fail", report["status"])
        self.assertEqual(2, report["coverage"]["commits"])
        findings = [item for item in report["findings"] if item["rule"] == "pennilogic-provider-key"]
        self.assertEqual({root_commit}, {item["commit"] for item in findings})

    def test_secret_introduced_only_by_merge_resolution_is_found_after_removal(self):
        path = self.root / "merge.txt"
        path.write_text("clean base\n", encoding="utf-8")
        self.commit()
        self.git("switch", "--quiet", "-c", "synthetic-side")
        path.write_text("clean side\n", encoding="utf-8")
        self.commit()
        side = self.git("rev-parse", "HEAD")
        self.git("switch", "--quiet", "main")
        path.write_text("clean main\n", encoding="utf-8")
        self.commit()
        main = self.git("rev-parse", "HEAD")
        merge = scan_secrets.run(
            [self.git_executable, "merge", "--no-commit", "synthetic-side"], self.root,
            scan_secrets.scanner_environment(Path(self.git_executable)),
        )
        self.assertEqual(1, merge.returncode, "The synthetic clean parents must require a merge resolution.")
        token = "sk-" + "S8" * 20
        path.write_text(token + "\n", encoding="utf-8")
        self.commit()
        merge_commit = self.git("rev-parse", "HEAD")
        self.assertEqual(f"{merge_commit} {main} {side}", self.git("rev-list", "--parents", "-1", "HEAD"))
        for parent in (main, side):
            self.assertFalse(token in self.git("show", f"{parent}:merge.txt"))
        path.unlink()
        self.commit()
        report = self.scan()
        self.assertEqual("fail", report["status"])
        findings = [item for item in report["findings"] if item["rule"] == "pennilogic-provider-key"]
        self.assertEqual({merge_commit}, {item["commit"] for item in findings})

    def test_default_cli_refuses_ambient_shadows_and_explicit_tools_bind_child_git(self):
        git_shadow = self.root / ("git.exe" if os.name == "nt" else "git")
        scanner_shadow = self.root / ("gitleaks.exe" if os.name == "nt" else "gitleaks")
        shutil.copyfile(self.scanner, git_shadow)
        shutil.copyfile(sys.executable, scanner_shadow)
        git_shadow.chmod(0o700)
        scanner_shadow.chmod(0o700)
        env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ.get("PATH", ""))
        command = [sys.executable, str(ROOT / "scripts" / "scan_secrets.py")]
        result = scan_secrets.run(
            [*command, "--root", str(self.root), "--repository", "PenniLogic/infra"], self.root, env,
        )
        self.assertEqual(2, result.returncode)
        self.assertEqual("invalid-arguments", json.loads(result.stdout)["code"])
        path = self.root / "synthetic.txt"
        path.write_text("sk-" + "T9" * 20 + "\n", encoding="utf-8")
        self.git("add", "synthetic.txt")
        self.git("commit", "--quiet", "-m", "Synthetic shadow fixture")
        result = scan_secrets.run([*command, *map(str, self.cli_arguments())], self.root, env)
        self.assertEqual(1, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual("fail", report["status"])
        self.assertIn("pennilogic-provider-key", {item["rule"] for item in report["findings"]})
        for option, replacement in (("--git", str(git_shadow)), ("--gitleaks", str(scanner_shadow)), ("--git", "git")):
            args = list(map(str, self.cli_arguments()))
            args[args.index(option) + 1] = replacement
            result = scan_secrets.run([*command, *args], self.root, env)
            self.assertEqual(2, result.returncode)
            self.assertIn(
                json.loads(result.stdout)["code"], ("untrusted-tool-location", "absolute-tool-path-required"),
            )

    def test_verified_tool_digest_is_checked_before_any_tool_execution(self):
        with mock.patch.object(scan_secrets, "run") as run:
            with self.assertRaisesRegex(security.Refusal, "^scanner-digest-mismatch$"):
                scan_secrets.scan(
                    self.root, "PenniLogic/infra", self.scanner, empty_exceptions(),
                    git_executable=self.git_executable, scanner_sha256="0" * 64,
                )
        run.assert_not_called()

    def test_real_scanner_swallowed_git_error_is_not_an_empty_success(self):
        original = scan_secrets.run
        outcomes = []

        def invalid_log(command, cwd, env, timeout=30):
            is_scan = command[:2] == [self.scanner, "git"]
            if is_scan:
                with (Path(command[2]) / "config").open("a", encoding="utf-8") as config:
                    config.write("\n[core]\n\tabbrev = synthetic-invalid-integer\n")
            result = original(command, cwd, env, timeout)
            if is_scan:
                report = Path(command[command.index("--report-path") + 1])
                outcomes.append((result.returncode, bool(result.stdout), security.read_document(report)))
            return result

        with mock.patch.object(scan_secrets, "run", side_effect=invalid_log):
            with self.assertRaisesRegex(security.Refusal, "^scanner-diagnostic-output$"):
                self.scan()
        self.assertEqual([(0, True, [])], outcomes)

    def test_late_fragment_detection_and_external_deadline_never_accept_partial_output(self):
        token = "sk-" + "U1" * 20
        self.plant("x" * (4 * 1024 * 1024) + "\n" + token)
        planted = self.git("rev-parse", "HEAD")
        self.assertIn(
            planted,
            {item["commit"] for item in self.scan()["findings"] if item["rule"] == "pennilogic-provider-key"},
        )
        config = Path(self.temporary.name) / "slow-synthetic.toml"
        config.write_text("\n".join(
            f"[[rules]]\nid = 'synthetic-slow-{index}'\nregex = '''[a-z0-9]{{32}}[A-Z]'''"
            for index in range(32)
        ), encoding="utf-8")
        original = scan_secrets.run
        calls = []
        active_processes = []

        def observe(command, cwd, env, timeout=30):
            if command[:2] == [self.scanner, "git"]:
                calls.append((command, cwd, timeout))
                if os.name == "nt":
                    finish = scan_secrets.processes._finish_windows_tree

                    def observe_finish(helpers, job, process):
                        active_processes.append(len(job.process_ids() or []))
                        return finish(helpers, job, process)

                    with mock.patch.object(scan_secrets.processes, "_finish_windows_tree", observe_finish):
                        return original(command, cwd, env, timeout)
            return original(command, cwd, env, timeout)

        with mock.patch.object(scan_secrets, "CONFIG", config), \
                mock.patch.object(scan_secrets, "SCAN_TIMEOUT_SECONDS", 1), \
                mock.patch.object(scan_secrets, "run", side_effect=observe):
            with self.assertRaisesRegex(scan_secrets.ProcessRefusal, "^scanner-or-git-timeout$") as caught:
                self.scan()
        self.assertEqual(1, len(calls))
        self.assertIn("--timeout=0", calls[0][0])
        self.assertEqual(1, calls[0][2])
        if os.name == "nt":
            self.assertTrue(active_processes and active_processes[0] >= 2, "The actual scanner must start before cancellation.")
            self.assertTrue(caught.exception.cleanup_confirmed)
            self.assertFalse(calls[0][1].exists(), "Confirmed termination must release the scan scratch tree.")
        else:
            self.assertFalse(caught.exception.cleanup_confirmed)
            self.assertTrue(calls[0][1].exists(), "Unconfirmed POSIX descendants require retained scratch.")

    def test_scratch_cleanup_failure_does_not_replace_the_primary_timeout(self):
        scratch = []
        directories = []
        temporary = tempfile.TemporaryDirectory

        def failing_cleanup(*args, **kwargs):
            directory = temporary(*args, **kwargs)
            directories.append((directory, directory.cleanup))
            directory.cleanup = mock.Mock(side_effect=PermissionError("synthetic"))
            return directory

        def timed_out(result, report_path):
            scratch.append(report_path.parent)
            raise scan_secrets.ProcessRefusal("scanner-or-git-timeout", cleanup_confirmed=True)

        try:
            with mock.patch.object(scan_secrets, "scanner_report", side_effect=timed_out), \
                    mock.patch.object(scan_secrets.tempfile, "TemporaryDirectory", side_effect=failing_cleanup):
                with self.assertRaisesRegex(scan_secrets.ProcessRefusal, "^scanner-or-git-timeout$") as caught:
                    self.scan()
            self.assertTrue(caught.exception.cleanup_confirmed)
            self.assertTrue(caught.exception.scratch_cleanup_failed)
            self.assertEqual(1, len(scratch))
            self.assertTrue(scratch[0].is_dir())
        finally:
            for directory, cleanup in directories:
                cleanup()

    def test_side_branch_secret_is_found(self):
        self.git("switch", "--quiet", "-c", "synthetic-side")
        self.plant("sk-" + "B8" * 20)
        self.git("switch", "--quiet", "main")
        self.assertEqual("fail", self.scan()["status"])

    def test_all_mandatory_rules_use_the_real_scanner(self):
        content = "\n".join([
            "gh" + "p_" + "C7" * 18,
            "sk-" + "D6" * 20,
            "-" * 5 + "BEGIN PRIVATE KEY" + "-" * 5,
            "database" + "_password = 'SYNTHETIC_NONFUNCTIONAL_42'",
        ])
        self.plant(content)
        report = self.scan()
        rules = {item["rule"] for item in report["findings"]}
        self.assertTrue({
            "pennilogic-github-token", "pennilogic-provider-key",
            "pennilogic-private-key", "pennilogic-database-password",
        } <= rules)
        self.assertEqual(
            "critical", next(item["severity"] for item in report["findings"] if item["rule"] == "pennilogic-database-password"),
        )

    def test_repo_and_inline_suppressions_cannot_disable_mandatory_rules(self):
        token = "sk-" + "E5" * 20
        self.plant(token + " # gitleaks:allow")
        commit = self.git("rev-parse", "HEAD")
        (self.root / ".gitleaksignore").write_text(
            f"{commit}:synthetic.txt:pennilogic-provider-key:1\n", encoding="utf-8",
        )
        (self.root / ".gitleaks.toml").write_text(
            'title="untrusted"\n[allowlist]\nregexes=[".*"]\n', encoding="utf-8",
        )
        self.commit()
        with mock.patch.dict(os.environ, {"GITLEAKS_CONFIG_TOML": '[allowlist]\nregexes=[".*"]\n'}):
            self.assertEqual("fail", self.scan()["status"])

    def test_same_line_secrets_have_distinct_exception_targets(self):
        self.plant("sk-" + "F4" * 20 + " " + "sk-" + "G3" * 20)
        findings = [item for item in self.scan()["findings"] if item["rule"] == "pennilogic-provider-key"]
        self.assertEqual(2, len(findings))
        self.assertNotEqual(findings[0]["id"], findings[1]["id"])
        entry = exception_for("secret", "PenniLogic/infra", findings[0]["rule"], findings[0]["id"])
        self.assertEqual("fail", self.scan(with_exception(entry))["status"])

    def test_mandatory_rules_ignore_upstream_filename_exclusions_and_binary_attributes(self):
        token = "sk-" + "N4" * 20
        for filename in ("asset.svg", "gitleaks.toml", "opaque.bin"):
            (self.root / filename).write_bytes(token.encode() + b"\x00\n")
        (self.root / ".gitattributes").write_text("* -diff\n", encoding="utf-8")
        self.commit()
        report = self.scan()
        detected = {item["artifact"] for item in report["findings"] if item["rule"] == "pennilogic-provider-key"}
        self.assertEqual({security.identity(name) for name in ("asset.svg", "gitleaks.toml", "opaque.bin")}, detected)

    def test_expired_exception_retriggers_real_scanner_finding(self):
        self.plant("sk-" + "H2" * 20)
        original = self.scan()
        entries = [
            {**exception_for("secret", "PenniLogic/infra", item["rule"], item["id"]), "id": f"synthetic-{index}"}
            for index, item in enumerate(original["findings"])
        ]
        active = security.Exceptions({"schema_version": 1, "exceptions": entries}, NOW)
        self.assertEqual("pass", self.scan(active)["status"])
        expired = security.Exceptions({"schema_version": 1, "exceptions": entries}, NOW + timedelta(days=1))
        self.assertEqual("fail", self.scan(expired)["status"])

    def test_shallow_history_refuses_instead_of_scanning_only_tip(self):
        self.plant("sk-" + "J1" * 20)
        clone = Path(self.temporary.name) / "shallow"
        self.git("clone", "--quiet", "--depth=1", self.root.as_uri(), str(clone))
        with self.assertRaisesRegex(security.Refusal, "shallow-history"):
            scan_secrets.scan(
                clone, "PenniLogic/infra", self.scanner, empty_exceptions(),
                git_executable=self.git_executable, scanner_sha256=self.scanner_sha256,
            )

    def test_replacement_and_grafted_history_refuse(self):
        first = self.git("rev-parse", "HEAD")
        self.plant("sk-" + "Q6" * 20)
        self.git("replace", "HEAD", first)
        with self.assertRaisesRegex(security.Refusal, "replacement-history"):
            self.scan()
        self.git("replace", "-d", "HEAD")
        grafts = self.root / ".git" / "info" / "grafts"
        grafts.write_text(self.git("rev-parse", "HEAD") + "\n", encoding="utf-8")
        with self.assertRaisesRegex(security.Refusal, "grafted-history"):
            self.scan()

    def test_actual_detection_drives_the_rotation_cli_without_raw_egress(self):
        token = "SYNTHETIC_NONFUNCTIONAL_73"
        self.plant("database" + "_password = '" + token + "'")
        report = self.scan()
        scan_path = Path(self.temporary.name) / "scan.json"
        issues_path = Path(self.temporary.name) / "issues.json"
        scan_path.write_bytes(security.canonical(report))
        issues_path.write_bytes(security.canonical({
            "repository": "PenniLogic/infra", "repository_id": 1394135059, "complete": True, "issues": [],
        }))
        result = run_script("secret_rotation.py", "--scan", scan_path, "--existing", issues_path)
        self.assertEqual(2, result.returncode, result.stderr)
        rotation = json.loads(result.stdout)
        request = next(item for item in rotation["requests"] if "database-password" in item["title"])
        self.assertEqual(["secret-rotation", "severity:critical"], request["labels"])
        self.assertEqual("not-performed", rotation["publication"])
        self.assertEqual("policy-required", rotation["age_alert_status"])
        self.assertIsNone(rotation["stale_count"])
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertNotIn("synthetic.txt", result.stdout + result.stderr)
        result = run_script(
            "secret_rotation.py", "--scan", scan_path, "--existing", issues_path,
            "--stale-after-seconds", "60",
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("evaluated", json.loads(result.stdout)["age_alert_status"])

    def test_completed_pass_incidents_survive_later_failures_and_feed_rotation(self):
        token = "SYNTHETIC_NONFUNCTIONAL_INCIDENT_23"
        provider_token = "sk-" + "Z2" * 20
        self.plant("database" + "_password = '" + token + "'\n" + provider_token)
        detected_commit = self.git("rev-parse", "HEAD")
        original_run = scan_secrets.run
        temporary = tempfile.TemporaryDirectory
        for failure, expected_code in (
            ("diagnostic", "scanner-diagnostic-output"),
            ("timeout", "scanner-or-git-timeout"),
            ("invalid-report", "invalid-scanner-line"),
            ("cleanup", "scanner-scratch-cleanup-failed"),
            ("cleanup-interruption", "scanner-process-interrupted"),
            ("unconfirmed-cleanup", "scanner-process-failed"),
            ("head-change", "head-changed-during-scan"),
            ("history-change", "history-changed-during-scan"),
        ):
            with self.subTest(failure=failure):
                calls = []
                cleanup = []
                rejected_payload = []
                completed_findings = []

                def observe_scratch(*args, **kwargs):
                    directory = temporary(*args, **kwargs)
                    cleanup.append(directory.cleanup)
                    if failure == "cleanup":
                        directory.cleanup = mock.Mock(side_effect=PermissionError("private scratch path"))
                    elif failure == "cleanup-interruption":
                        directory.cleanup = mock.Mock(side_effect=KeyboardInterrupt("private scratch interruption"))
                    return directory

                def fail_later(command, cwd, env, timeout=30):
                    is_scan = command[:2] == [self.scanner, "git"]
                    if is_scan:
                        calls.append(command)
                    if is_scan and len(calls) == 2 and failure in ("diagnostic", "timeout", "invalid-report"):
                        report_path = Path(command[command.index("--report-path") + 1])
                        partial = [{
                            "RuleID": "synthetic-rejected-provider", "Commit": detected_commit,
                            "File": "private-provider-payload.txt", "StartLine": 1, "EndLine": 1,
                            "StartColumn": 1, "EndColumn": 20, "Secret": token,
                        }]
                        if failure == "invalid-report":
                            partial.append({**partial[0], "StartLine": 0})
                        script = (
                            "from pathlib import Path; import sys, time; "
                            f"Path({str(report_path)!r}).write_text({json.dumps(partial)!r}, encoding='utf-8'); "
                            + ("" if failure == "invalid-report" else "print('private scanner diagnostic', flush=True); ")
                            + ("time.sleep(3)" if failure == "timeout" else "sys.exit(10)")
                        )
                        try:
                            return original_run([sys.executable, "-c", script], cwd, env, timeout=1)
                        finally:
                            rejected_payload.append(security.read_document(report_path))
                    if is_scan and len(calls) == 2 and failure == "unconfirmed-cleanup":
                        if os.name == "nt":
                            finish = scan_secrets.processes._finish_windows_tree

                            def unconfirmed(*args):
                                self.assertIsNone(finish(*args), "The synthetic fixture must actually be stopped.")
                                return "synthetic unconfirmed cleanup"

                            with mock.patch.object(scan_secrets.processes, "_finish_windows_tree", unconfirmed):
                                return original_run(command, cwd, env, timeout)
                        result = original_run(command, cwd, env, timeout)
                        raise scan_secrets.ProcessRefusal("scanner-process-failed", cleanup_confirmed=False)
                    result = original_run(command, cwd, env, timeout)
                    if is_scan and len(calls) == 1:
                        report_path = Path(command[command.index("--report-path") + 1])
                        completed_findings.extend(scan_secrets.findings_from_gitleaks(
                            scan_secrets.scanner_report(result, report_path), "PenniLogic/infra", empty_exceptions(),
                        ))
                    if is_scan and len(calls) == 2:
                        if failure == "head-change":
                            self.git("commit", "--quiet", "--allow-empty", "-m", "Synthetic head movement")
                        elif failure == "history-change":
                            commit = self.git("commit-tree", "HEAD^{tree}", "-m", "Synthetic extra root")
                            self.git("update-ref", "refs/heads/synthetic-extra", commit)
                    return result

                stdout, stderr = io.StringIO(), io.StringIO()
                try:
                    with ExitStack() as stack:
                        stack.enter_context(mock.patch.object(scan_secrets, "run", side_effect=fail_later))
                        stack.enter_context(mock.patch.object(
                            scan_secrets.tempfile, "TemporaryDirectory", side_effect=observe_scratch,
                        ))
                        stack.enter_context(redirect_stdout(stdout))
                        stack.enter_context(redirect_stderr(stderr))
                        code = scan_secrets.main(list(map(str, self.cli_arguments())))
                    self.assertEqual(2, code)
                    report = json.loads(stdout.getvalue())
                    self.assertEqual("refused", report["status"])
                    self.assertEqual(expected_code, report["code"])
                    self.assertEqual(2, len(calls))
                    self.assertTrue(any(
                        item["rule"] == "pennilogic-database-password" and item["commit"] == detected_commit
                        for item in completed_findings
                    ), "The first actual scanner pass must contain a validated detection before later failure.")
                    self.assertGreaterEqual(len(completed_findings), 2)
                    incomplete_pass = failure in ("diagnostic", "timeout", "invalid-report", "unconfirmed-cleanup")
                    if failure in ("diagnostic", "timeout", "invalid-report"):
                        self.assertEqual(1, len(rejected_payload), "The failed pass must have written partial JSON.")
                    self.assertIn("incident_handoff", report, "Completed detections must survive a refused scan.")
                    self.assertEqual({"scope": "all-local-refs", "complete": False}, report.get("coverage"))
                    incident = report["incident_handoff"]
                    self.assertEqual("pennilogic.secret-incident/1", incident["schema"])
                    self.assertEqual("incomplete", incident["status"])
                    self.assertEqual(
                        ["mandatory"] if incomplete_pass else ["mandatory", "provider"],
                        incident["completed_passes"],
                    )
                    if failure in ("unconfirmed-cleanup", "cleanup-interruption"):
                        self.assertEqual("unconfirmed", report["process_cleanup"])
                        self.assertIs(True, report["scratch_retained"])
                    if failure in ("cleanup", "cleanup-interruption"):
                        self.assertEqual("failed", report["scratch_cleanup"])
                    self.assertTrue(any(
                        finding["rule"] == "pennilogic-database-password"
                        and finding["commit"] == detected_commit for finding in incident["findings"]
                    ))
                    if incomplete_pass:
                        self.assertEqual(completed_findings, incident["findings"])
                    else:
                        for finding in completed_findings:
                            self.assertIn(finding, incident["findings"])
                    self.assertNotIn("synthetic-rejected-provider", {item["rule"] for item in incident["findings"]})
                    scan_path = Path(self.temporary.name) / "incomplete-scan.json"
                    issues_path = Path(self.temporary.name) / "issues.json"
                    scan_path.write_bytes(security.canonical(report))
                    issues_path.write_bytes(security.canonical({
                        "repository": "PenniLogic/infra", "repository_id": 1394135059,
                        "complete": True, "issues": [],
                    }))
                    result = run_script("secret_rotation.py", "--scan", scan_path, "--existing", issues_path)
                    self.assertEqual(2, result.returncode, result.stderr)
                    rotation = json.loads(result.stdout)
                    self.assertEqual("incomplete", rotation["scan_coverage"])
                    self.assertEqual("policy-required", rotation["age_alert_status"])
                    self.assertTrue(any("severity:critical" in item["labels"] for item in rotation["requests"]))
                    self.assertEqual(
                        {item["id"] for item in incident["findings"]},
                        {item["deduplication_key"] for item in rotation["requests"]},
                    )
                    evaluated = run_script(
                        "secret_rotation.py", "--scan", scan_path, "--existing", issues_path,
                        "--stale-after-seconds", "60",
                    )
                    self.assertEqual(2, evaluated.returncode, "Age evaluation cannot turn incomplete scanning green.")
                    self.assertEqual("evaluated", json.loads(evaluated.stdout)["age_alert_status"])
                    public = stdout.getvalue() + stderr.getvalue() + result.stdout + result.stderr + evaluated.stdout
                    for private in (
                        token, provider_token, str(self.root), "synthetic.txt", "private-provider-payload.txt",
                        "private scanner diagnostic", "private scratch path", "private scratch interruption", "Traceback",
                    ):
                        self.assertNotIn(private, public)
                    self.assertEqual("", stderr.getvalue() + result.stderr + evaluated.stderr)
                finally:
                    for clean in cleanup:
                        clean()

    def test_invalid_first_pass_never_exports_its_valid_prefix_as_an_incident(self):
        self.plant("sk-" + "W9" * 20)
        original_run = scan_secrets.run
        scans = []

        def corrupt_report(command, cwd, env, timeout=30):
            result = original_run(command, cwd, env, timeout)
            if command[:2] == [self.scanner, "git"]:
                scans.append(command)
                path = Path(command[command.index("--report-path") + 1])
                findings = scan_secrets.scanner_report(result, path)
                self.assertTrue(findings, "The completed process must have detected the synthetic exposure.")
                path.write_bytes(security.canonical([*findings, {**findings[0], "StartLine": 0}]))
            return result

        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(scan_secrets, "run", side_effect=corrupt_report), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = scan_secrets.main(list(map(str, self.cli_arguments())))
        self.assertEqual(2, code)
        self.assertEqual(1, len(scans))
        report = json.loads(stdout.getvalue())
        self.assertEqual("invalid-scanner-line", report["code"])
        self.assertIs(False, report["coverage"]["complete"])
        self.assertNotIn("incident_handoff", report)
        self.assertNotIn("findings", report)
        self.assertEqual("", stderr.getvalue())

    @unittest.skipUnless(os.name == "nt", "Windows confirmed interruption cleanup")
    def test_confirmed_interruption_keeps_public_cleanup_unconfirmed_and_incidents(self):
        self.plant("sk-" + "V8" * 20)
        original_run = scan_secrets.run
        original_communicate = subprocess.Popen.communicate
        original_finish = scan_secrets.processes._finish_windows_tree
        passes = []
        stopped = []
        interrupted = []
        directories = []
        temporary = tempfile.TemporaryDirectory

        def observe_scratch(*args, **kwargs):
            directory = temporary(*args, **kwargs)
            directories.append(directory)
            return directory

        def interrupt(process, input=None, timeout=None):
            if not interrupted:
                try:
                    original_communicate(process, input, timeout=0.25)
                except subprocess.TimeoutExpired:
                    interrupted.append(True)
                    raise KeyboardInterrupt("private operator path") from None
                self.fail("The finite interruption fixture must still be running.")
            return original_communicate(process, input, timeout=timeout)

        def observe_finish(*args):
            result = original_finish(*args)
            stopped.append(result)
            return result

        def interrupt_later(command, cwd, env, timeout=30):
            if command[:2] == [self.scanner, "git"]:
                passes.append(command)
                if len(passes) == 2:
                    with mock.patch.object(subprocess.Popen, "communicate", interrupt), \
                            mock.patch.object(scan_secrets.processes, "_finish_windows_tree", observe_finish):
                        return original_run([
                            sys.executable, "-c",
                            "import time; print('private child output', flush=True); time.sleep(3)",
                        ], cwd, env)
            return original_run(command, cwd, env, timeout)

        stdout, stderr = io.StringIO(), io.StringIO()
        try:
            with mock.patch.object(scan_secrets, "run", side_effect=interrupt_later), \
                    mock.patch.object(scan_secrets.tempfile, "TemporaryDirectory", side_effect=observe_scratch), \
                    redirect_stdout(stdout), redirect_stderr(stderr):
                try:
                    code = scan_secrets.main(list(map(str, self.cli_arguments())))
                except KeyboardInterrupt:
                    self.assertEqual([None], stopped, "The real helper must have confirmed process cleanup.")
                    self.fail("KeyboardInterrupt escaped the public scanner boundary after confirmed cleanup.")
            self.assertEqual([None], stopped)
            self.assertEqual(2, code)
            report = json.loads(stdout.getvalue())
            self.assertEqual("scanner-process-interrupted", report["code"])
            self.assertEqual("unconfirmed", report["process_cleanup"], "A raw interrupt is not a typed witness.")
            self.assertIs(True, report["scratch_retained"])
            self.assertTrue(all(Path(directory.name).is_dir() for directory in directories))
            self.assertIs(False, report["coverage"]["complete"])
            self.assertEqual(["mandatory"], report["incident_handoff"]["completed_passes"])
            self.assertTrue(report["incident_handoff"]["findings"])
            self.assertEqual("", stderr.getvalue())
            for private in ("Traceback", "private operator path", "private child output", str(ROOT), str(self.root)):
                self.assertNotIn(private, stdout.getvalue() + stderr.getvalue())
        finally:
            if stopped == [None]:
                for directory in directories:
                    directory.cleanup()

    def test_missing_and_wrong_version_scanners_refuse(self):
        with self.assertRaisesRegex(security.Refusal, "scanner-or-git-missing"):
            scan_secrets.scan(
                self.root, "PenniLogic/infra", str(Path(self.temporary.name) / "absent-scanner"), empty_exceptions(),
                git_executable=self.git_executable, scanner_sha256=self.scanner_sha256,
            )
        with Path(sys.executable).open("rb") as stream:
            wrong_version_digest = hashlib.file_digest(stream, "sha256").hexdigest()
        with self.assertRaisesRegex(security.Refusal, "scanner-version-mismatch"):
            scan_secrets.scan(
                self.root, "PenniLogic/infra", sys.executable, empty_exceptions(),
                git_executable=self.git_executable, scanner_sha256=wrong_version_digest,
            )

    def test_secret_cli_produces_failing_redacted_json(self):
        token = "sk-" + "K2" * 20
        self.plant(token)
        result = run_script("scan_secrets.py", *self.cli_arguments())
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("fail", json.loads(result.stdout)["status"])
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertEqual("", result.stderr)


class RotationTests(unittest.TestCase):
    def setUp(self):
        self.finding = {
            "artifact": "d" * 64, "rule": "pennilogic-database-password",
            "commit": HEAD, "line": 1, "credential_type": "database-password",
            "column": 1, "end_line": 1, "end_column": 30,
            "severity": "critical", "exception": None,
        }
        self.finding["id"] = scan_secrets.finding_id(REPOSITORY, self.finding)
        self.scan = {
            "schema": "pennilogic.secret-scan/1", "repository": REPOSITORY,
            "repository_id": ANDROID_ID, "head": HEAD, "status": "fail", "blocking_count": 1,
            "findings": [self.finding],
        }
        self.existing = {"repository": REPOSITORY, "repository_id": ANDROID_ID, "complete": True, "issues": []}

    def issue(self, state="open", created="2026-10-05T12:00:00Z"):
        return {
            "number": 1, "state": state, "created_at": created,
            "labels": [{"name": "secret-rotation"}, {"name": "severity:critical"}],
            "body": secret_rotation.marker(ANDROID_ID, self.finding["id"]),
        }

    def incomplete_scan(self):
        return {
            "schema": "pennilogic.secret-scan/1", "status": "refused", "code": "scanner-diagnostic-output",
            "coverage": {"scope": "all-local-refs", "complete": False}, "process_cleanup": "confirmed",
            "incident_handoff": {
                "schema": "pennilogic.secret-incident/1", "status": "incomplete",
                "repository": REPOSITORY, "repository_id": ANDROID_ID, "head": HEAD,
                "completed_passes": ["mandatory"], "findings": [copy.deepcopy(self.finding)],
            },
        }

    def test_rotation_payload_is_redacted_and_type_sets_severity(self):
        self.finding["Secret"] = "sk-" + "L3" * 20
        self.finding["File"] = "raw/private-name.txt"
        result = secret_rotation.plan(self.scan, self.existing, NOW)
        request = result["requests"][0]
        self.assertEqual(["secret-rotation", "severity:critical"], request["labels"])
        self.assertEqual("not-performed", result["publication"])
        self.assertNotIn(self.finding["Secret"], json.dumps(result))
        self.assertNotIn(self.finding["File"], json.dumps(result))
        self.finding.update({"rule": "pennilogic-provider-key", "credential_type": "provider-api-key", "severity": "high"})
        self.finding["id"] = scan_secrets.finding_id(REPOSITORY, self.finding)
        self.assertEqual(
            ["secret-rotation", "severity:high"],
            secret_rotation.plan(self.scan, self.existing, NOW)["requests"][0]["labels"],
        )

    def test_existing_open_ticket_deduplicates_and_alerts_at_exact_staleness_boundary(self):
        self.existing["issues"] = [self.issue(created="2026-10-12T11:59:00Z")]
        result = secret_rotation.plan(self.scan, self.existing, NOW, stale_after_seconds=60)
        self.assertEqual([], result["requests"])
        self.assertEqual(1, result["open_count"])
        self.assertEqual(60, result["oldest_age_seconds"])
        self.assertEqual(1, result["stale_count"])
        self.assertEqual(
            0, secret_rotation.plan(self.scan, self.existing, NOW - timedelta(seconds=1), stale_after_seconds=60)["stale_count"],
        )

    def test_missing_escalation_policy_never_delays_new_rotation_requests(self):
        report = secret_rotation.plan(self.scan, self.existing, NOW)
        self.assertEqual(1, len(report["requests"]))
        self.assertEqual("policy-required", report["age_alert_status"])
        self.assertIsNone(report["staleness_window_seconds"])
        self.assertIsNone(report["stale_count"])
        self.existing["issues"] = [self.issue()]
        report = secret_rotation.plan(self.scan, self.existing, NOW)
        self.assertEqual(1, report["open_count"])
        self.assertGreater(report["oldest_age_seconds"], 0)
        self.assertIsNone(report["stale_count"])
        self.assertIsNone(report["tickets"][0]["stale"])
        for value in (False, 0, -1, 1.5):
            with self.subTest(value=value):
                report = secret_rotation.plan(self.scan, self.existing, NOW, stale_after_seconds=value)
                self.assertEqual("failed", report["age_alert_status"])
                self.assertEqual("invalid-escalation-window", report["age_alert_code"])
                self.assertIsNone(report["staleness_window_seconds"])
                self.assertEqual([], report["requests"], "Age failure must not bypass deduplication.")

    def test_failed_age_evaluation_keeps_immediate_requests_and_visible_failure(self):
        unrelated = self.issue()
        unrelated["body"] = secret_rotation.marker(ANDROID_ID, "f" * 64)
        for created, window, error in (
            ("not-a-timestamp", 60, "invalid-utc-timestamp"),
            ("2027-01-01T00:00:00Z", 60, "future-rotation-issue"),
            ("2026-10-05T12:00:00Z", 0, "invalid-escalation-window"),
        ):
            with self.subTest(error=error):
                self.existing["issues"] = [{**unrelated, "created_at": created}]
                report = secret_rotation.plan(self.scan, self.existing, NOW, stale_after_seconds=window)
                self.assertEqual(1, len(report["requests"]))
                self.assertEqual("failed", report["age_alert_status"])
                self.assertEqual(error, report["age_alert_code"])
                self.assertEqual(1, report["open_count"])
                self.assertIsNone(report["oldest_age_seconds"])
                self.assertIsNone(report["stale_count"])
                self.assertEqual([{"number": 1, "age_seconds": None, "stale": None}], report["tickets"])

    def test_incomplete_handoff_rechecks_current_exceptions_and_deduplicates(self):
        self.finding["exception"] = "synthetic-false-positive"
        incomplete = self.incomplete_scan()
        report = secret_rotation.plan(incomplete, self.existing, NOW, empty_exceptions())
        self.assertEqual(1, len(report["requests"]), "A reported exception is not current policy.")
        self.assertEqual("refused", report["scan_status"])
        self.assertEqual("incomplete", report["scan_coverage"])
        entry = exception_for("secret", REPOSITORY, self.finding["rule"], self.finding["id"])
        self.assertEqual(
            [], secret_rotation.plan(incomplete, self.existing, NOW, with_exception(entry))["requests"],
        )
        expiry = security.utc(entry["expires_at"])
        self.assertEqual(
            1, len(secret_rotation.plan(incomplete, self.existing, expiry, with_exception(entry, expiry))["requests"]),
        )
        for changed in ({"artifact": "f" * 64}, {"repository": "PenniLogic/api"}, {"pattern": "unrelated-rule"}):
            with self.subTest(changed=changed):
                self.assertEqual(
                    1, len(secret_rotation.plan(
                        incomplete, self.existing, NOW, with_exception({**entry, **changed}),
                    )["requests"]),
                )
        self.existing["issues"] = [self.issue()]
        self.assertEqual([], secret_rotation.plan(incomplete, self.existing, NOW)["requests"])
        self.existing["issues"] = [self.issue(state="closed")]
        closed = secret_rotation.plan(incomplete, self.existing, NOW)
        self.assertEqual([], closed["requests"])
        self.assertEqual([{"id": self.finding["id"], "number": 1}], closed["closed_findings_needing_review"])
        self.existing["issues"] = [self.issue(), {**self.issue(), "number": 2}]
        with self.assertRaisesRegex(security.Refusal, "duplicate-rotation-marker"):
            secret_rotation.plan(incomplete, self.existing, NOW)
        self.existing["issues"] = [{**self.issue(), "body": secret_rotation.marker(1394135059, self.finding["id"])}]
        with self.assertRaisesRegex(security.Refusal, "rotation-marker-repository-mismatch"):
            secret_rotation.plan(incomplete, self.existing, NOW)
        self.existing["issues"] = [self.issue()]
        self.existing["issues"][0]["labels"] = [{"name": "secret-rotation"}, {"name": "severity:low"}]
        with self.assertRaisesRegex(security.Refusal, "rotation-ticket-severity-mismatch"):
            secret_rotation.plan(incomplete, self.existing, NOW)
        self.existing["issues"] = []
        incomplete["incident_handoff"]["findings"] *= 2
        with self.assertRaisesRegex(security.Refusal, "duplicate-rotation-finding"):
            secret_rotation.plan(incomplete, self.existing, NOW)
        with self.assertRaisesRegex(security.Refusal, "exception-clock-mismatch"):
            secret_rotation.plan(incomplete, self.existing, NOW, with_exception(entry, NOW + timedelta(seconds=1)))

    def test_completed_provider_incidents_keep_derived_conservative_severity(self):
        for rule, credential_type, severity in (
            ("private-key", "private-key", "critical"),
            ("synthetic-provider-rule", "unclassified-credential", "high"),
        ):
            with self.subTest(rule=rule):
                scan = self.incomplete_scan()
                incident = scan["incident_handoff"]
                incident["completed_passes"] = ["mandatory", "provider"]
                finding = incident["findings"][0]
                finding.update({"rule": rule, "credential_type": credential_type, "severity": severity})
                finding["id"] = scan_secrets.finding_id(REPOSITORY, finding)
                report = secret_rotation.plan(scan, self.existing, NOW)
                self.assertEqual(["secret-rotation", f"severity:{severity}"], report["requests"][0]["labels"])
                self.assertEqual("incomplete", report["scan_coverage"])
                finding["severity"] = "low"
                with self.assertRaisesRegex(security.Refusal, "rotation-severity-mismatch"):
                    secret_rotation.plan(scan, self.existing, NOW)

    def test_rotation_cli_rejects_forged_or_raw_incomplete_envelopes(self):
        valid = self.incomplete_scan()
        private = "private raw incident payload"
        cases = [
            {**valid, "status": "pass"}, {**valid, "status": "fail"},
            {key: value for key, value in valid.items() if key != "incident_handoff"},
            {**valid, "findings": [self.finding]}, {**valid, "code": private},
            {**valid, "scratch_retained": True}, {**valid, "process_cleanup": "invented"},
        ]
        for complete in (True, 0, None):
            cases.append({**valid, "coverage": {"scope": "all-local-refs", "complete": complete}})
        incident = valid["incident_handoff"]
        for key, value in (
            ("schema", "pennilogic.secret-scan/1"), ("status", "complete"),
            ("completed_passes", []), ("completed_passes", ["provider"]),
            ("completed_passes", ["mandatory", "mandatory"]), ("completed_passes", ["mandatory", "provider", "extra"]),
            ("repository_id", 1), ("repository_id", True), ("repository", "PenniLogic/api"),
            ("head", "bad"), ("findings", []), ("raw", private),
        ):
            cases.append({**valid, "incident_handoff": {**incident, key: value}})
        for key, value in (
            ("id", "f" * 64), ("severity", "low"), ("credential_type", "provider-api-key"),
            ("rule", "private-key"), ("exception", "*"), ("line", True), ("column", 31),
            ("Secret", private), ("File", private), ("commit", "invalid"),
        ):
            cases.append({**valid, "incident_handoff": {
                **incident, "findings": [{**self.finding, key: value}],
            }})
        with tempfile.TemporaryDirectory(prefix="synthetic-incident-validation-") as directory:
            scan_path, issues_path = Path(directory) / "scan.json", Path(directory) / "issues.json"
            issues_path.write_bytes(security.canonical(self.existing))
            for index, candidate in enumerate(cases):
                with self.subTest(case=index):
                    scan_path.write_bytes(security.canonical(candidate))
                    result = run_script(
                        "secret_rotation.py", "--scan", scan_path, "--existing", issues_path,
                        "--stale-after-seconds", "60",
                    )
                    self.assertEqual(2, result.returncode, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual("refused", report["status"])
                    self.assertNotIn("requests", report)
                    self.assertNotIn(private, result.stdout + result.stderr)
                    self.assertEqual("", result.stderr)
            for key, value in (
                ("repository", "PenniLogic/api"), ("repository_id", 1), ("complete", False),
            ):
                with self.subTest(existing_key=key), self.assertRaises(security.Refusal):
                    secret_rotation.plan(valid, {**self.existing, key: value}, NOW)

    def test_rotation_cli_emits_immediate_requests_even_when_age_evaluation_fails(self):
        unrelated = self.issue(created="private invalid age input")
        unrelated["body"] = secret_rotation.marker(ANDROID_ID, "f" * 64)
        self.existing["issues"] = [unrelated]
        with tempfile.TemporaryDirectory(prefix="synthetic-incident-age-") as directory:
            scan_path, issues_path = Path(directory) / "scan.json", Path(directory) / "issues.json"
            issues_path.write_bytes(security.canonical(self.existing))
            for scan in (self.scan, self.incomplete_scan()):
                with self.subTest(status=scan["status"]):
                    scan_path.write_bytes(security.canonical(scan))
                    result = run_script(
                        "secret_rotation.py", "--scan", scan_path, "--existing", issues_path,
                        "--stale-after-seconds", "60",
                    )
                    self.assertEqual(2, result.returncode, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual("failed", report["age_alert_status"])
                    self.assertEqual("invalid-utc-timestamp", report["age_alert_code"])
                    self.assertEqual(1, len(report["requests"]))
                    self.assertEqual("not-performed", report["publication"])
                    self.assertNotIn(unrelated["created_at"], result.stdout)
                    self.assertEqual("", result.stderr)

    def test_closed_ticket_needs_review_without_duplicate_publication_or_suppression(self):
        self.existing["issues"] = [self.issue(state="closed")]
        report = secret_rotation.plan(self.scan, self.existing, NOW)
        self.assertEqual([], report["requests"])
        self.assertEqual(
            [{"id": self.finding["id"], "number": 1}], report["closed_findings_needing_review"],
        )
        self.assertEqual(0, report["open_count"])
        self.assertIsNone(report["oldest_age_seconds"])

    def test_reported_exception_is_not_authority_and_expiry_is_rechecked(self):
        self.finding["exception"] = "synthetic-false-positive"
        self.scan.update({"status": "pass", "blocking_count": 0})
        self.assertEqual(1, len(secret_rotation.plan(self.scan, self.existing, NOW)["requests"]))
        entry = exception_for("secret", REPOSITORY, self.finding["rule"], self.finding["id"])
        self.assertEqual([], secret_rotation.plan(self.scan, self.existing, NOW, with_exception(entry))["requests"])
        expiry = security.utc(entry["expires_at"])
        self.assertEqual(
            1, len(secret_rotation.plan(self.scan, self.existing, expiry, with_exception(entry, expiry))["requests"]),
        )

    def test_duplicate_marker_and_wrong_existing_severity_refuse(self):
        self.existing["issues"] = [self.issue(), {**self.issue(), "number": 2}]
        with self.assertRaisesRegex(security.Refusal, "duplicate-rotation-marker"):
            secret_rotation.plan(self.scan, self.existing, NOW)
        self.existing["issues"] = [self.issue()]
        self.existing["issues"][0]["labels"] = [{"name": "secret-rotation"}, {"name": "severity:low"}]
        with self.assertRaisesRegex(security.Refusal, "rotation-ticket-severity-mismatch"):
            secret_rotation.plan(self.scan, self.existing, NOW)

    def test_incomplete_or_wrong_repo_input_and_wrong_severity_refuse(self):
        for key, value in (("complete", False), ("repository_id", 1), ("repository", "PenniLogic/api")):
            with self.subTest(key=key), self.assertRaises(security.Refusal):
                secret_rotation.plan(self.scan, {**self.existing, key: value}, NOW)
        self.finding["severity"] = "low"
        with self.assertRaisesRegex(security.Refusal, "rotation-severity-mismatch"):
            secret_rotation.plan(self.scan, self.existing, NOW)
        self.finding.update({"severity": "critical", "column": 31})
        with self.assertRaisesRegex(security.Refusal, "invalid-rotation-finding"):
            secret_rotation.plan(self.scan, self.existing, NOW)

    def test_future_age_failure_does_not_bypass_repository_markers(self):
        self.existing["issues"] = [self.issue(created="2027-01-01T00:00:00Z")]
        report = secret_rotation.plan(self.scan, self.existing, NOW)
        self.assertEqual("failed", report["age_alert_status"])
        self.assertEqual("future-rotation-issue", report["age_alert_code"])
        self.assertEqual([], report["requests"])
        self.existing["issues"] = [self.issue()]
        for repo_id in ("1394135059", "9" * 5000, "0" + str(ANDROID_ID)):
            self.existing["issues"][0]["body"] = (
                f"<!-- pennilogic-secret-rotation:{repo_id}:{self.finding['id']} -->"
            )
            with self.subTest(length=len(repo_id)), self.assertRaisesRegex(
                security.Refusal, "rotation-marker-repository-mismatch",
            ):
                secret_rotation.plan(self.scan, self.existing, NOW)


if __name__ == "__main__":
    unittest.main()
