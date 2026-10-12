"""Synthetic-only controls, including actual Gitleaks against disposable Git histories."""

import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
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
        with mock.patch.dict(os.environ, {
            "GH_TOKEN": "synthetic-credential", "GITHUB_TOKEN": "synthetic-credential",
            "GITLEAKS_CONFIG": "untrusted.toml", "GITLEAKS_CONFIG_TOML": "untrusted",
            "GIT_CONFIG_PARAMETERS": "untrusted", "GIT_CONFIG_KEY_0": "untrusted",
        }):
            env = scan_secrets.scanner_environment()
        for name in ("GH_TOKEN", "GITHUB_TOKEN", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_KEY_0"):
            self.assertNotIn(name, env)
        self.assertEqual("file", env["GIT_ALLOW_PROTOCOL"])
        self.assertEqual("1", env["GIT_NO_LAZY_FETCH"])

    def test_timeout_never_copies_child_output(self):
        token = "sk-" + "M4" * 20
        error = subprocess.TimeoutExpired("synthetic", 1, output=token.encode(), stderr=token.encode())
        with mock.patch.object(scan_secrets.subprocess, "run", side_effect=error):
            with self.assertRaisesRegex(security.Refusal, "^scanner-or-git-timeout$"):
                scan_secrets.run(["synthetic"], ROOT, {}, timeout=1)

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
        cls.scanner = shutil.which("gitleaks")
        if cls.scanner is None:
            raise AssertionError("Gitleaks 8.30.1 is required; scanner tests cannot be skipped.")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-secret-history-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repository"
        self.root.mkdir()
        self.git("init", "--quiet", "-b", "main")
        self.git("config", "user.name", "Synthetic Fixture")
        self.git("config", "user.email", "synthetic@example.invalid")
        (self.root / "safe.txt").write_text("Only synthetic content.\n", encoding="utf-8")
        self.commit()

    def git(self, *args):
        result = subprocess.run(
            ["git", *args], cwd=self.root, env=scan_secrets.scanner_environment(),
            capture_output=True, timeout=30, check=False,
        )
        self.assertEqual(0, result.returncode, "Synthetic Git setup failed.")
        return result.stdout.decode("utf-8").strip()

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", "Synthetic fixture")

    def scan(self, exceptions=None):
        return scan_secrets.scan(self.root, "PenniLogic/infra", self.scanner, exceptions or empty_exceptions())

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
            scan_secrets.scan(clone, "PenniLogic/infra", self.scanner, empty_exceptions())

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

    def test_missing_and_wrong_version_scanners_refuse(self):
        with self.assertRaisesRegex(security.Refusal, "scanner-or-git-missing"):
            scan_secrets.scan(self.root, "PenniLogic/infra", str(self.root / "absent-scanner"), empty_exceptions())
        with self.assertRaisesRegex(security.Refusal, "scanner-version-mismatch"):
            scan_secrets.scan(self.root, "PenniLogic/infra", sys.executable, empty_exceptions())

    def test_secret_cli_produces_failing_redacted_json(self):
        token = "sk-" + "K2" * 20
        self.plant(token)
        result = run_script("scan_secrets.py", "--root", self.root, "--repository", "PenniLogic/infra")
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
            with self.subTest(value=value), self.assertRaisesRegex(security.Refusal, "invalid-escalation-window"):
                secret_rotation.plan(self.scan, self.existing, NOW, stale_after_seconds=value)

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

    def test_future_timestamp_and_cross_repository_markers_refuse(self):
        self.existing["issues"] = [self.issue(created="2027-01-01T00:00:00Z")]
        with self.assertRaisesRegex(security.Refusal, "future-rotation-issue"):
            secret_rotation.plan(self.scan, self.existing, NOW)
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
