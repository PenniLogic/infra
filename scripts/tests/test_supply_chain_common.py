"""Tests for scripts/supply_chain_common.py: strict JSON, bounded reads, the finding vocabulary."""

import ast
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import support  # noqa: F401  (puts scripts/ on sys.path)
import supply_chain_common as common
from supply_chain_common import Refused


class JsonDocumentTests(unittest.TestCase):
    def refused(self, data, code):
        with self.assertRaises(Refused) as caught:
            common.json_document(data, 64, "SC-T")
        self.assertEqual(caught.exception.code, code)

    def test_control_parses(self):
        self.assertEqual(common.json_document(b'{"a": [1, 2.5]}', 64, "SC-T"), {"a": [1, 2.5]})

    def test_duplicate_key_is_refused(self):
        self.refused(b'{"a": 1, "a": 2}', "SC-T-JSON")

    def test_bom_is_refused(self):
        self.refused(b"\xef\xbb\xbf{}", "SC-T-JSON")

    def test_non_finite_constant_is_refused(self):
        self.refused(b'{"a": NaN}', "SC-T-JSON")

    def test_overflowing_float_is_refused(self):
        self.refused(b'{"a": 1e999}', "SC-T-JSON")

    def test_invalid_utf8_is_refused(self):
        self.refused(b'{"a": "\xff"}', "SC-T-JSON")

    def test_size_boundary(self):
        common.json_document(b'"' + b"a" * 62 + b'"', 64, "SC-T")
        self.refused(b'"' + b"a" * 63 + b'"', "SC-T-SIZE")

    def test_empty_is_refused(self):
        self.refused(b"", "SC-T-SIZE")


class ReadBoundedTests(unittest.TestCase):
    def test_regular_file_is_read_and_directory_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "report.json")
            with open(path, "wb") as handle:
                handle.write(b"{}")
            self.assertEqual(common.read_bounded(path, 10, "SC-T-READ"), b"{}")
            with self.assertRaises(Refused) as caught:
                common.read_bounded(directory, 10, "SC-T-READ")
            self.assertEqual(caught.exception.code, "SC-T-READ")

    def test_missing_and_nul_paths_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            for path in (os.path.join(directory, "absent.json"), "bad\x00name"):
                with self.assertRaises(Refused) as caught:
                    common.read_bounded(path, 10, "SC-T-READ")
                self.assertEqual(caught.exception.code, "SC-T-READ")

    def test_read_stops_one_byte_past_the_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "big.json")
            with open(path, "wb") as handle:
                handle.write(b"x" * 100)
            self.assertEqual(len(common.read_bounded(path, 10, "SC-T-READ")), 11)

    def test_fifo_swapped_in_after_the_stat_check_is_refused_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            regular = os.path.join(directory, "report.json")
            with open(regular, "wb") as handle:
                handle.write(b"{}")
            self.assertEqual(common.read_bounded(regular, 10, "SC-T-READ"), b"{}")
            if not hasattr(os, "mkfifo"):  # no FIFOs on Windows: the control above is the whole case there
                return
            fifo = os.path.join(directory, "fifo")
            os.mkfifo(fifo)
            real_stat = os.stat
            # Simulate the race: the pre-open check sees a regular file, the opened descriptor is a FIFO.
            with mock.patch.object(common.os, "stat", lambda _path: real_stat(regular)):
                for read in (lambda: common.read_bounded(fifo, 10, "SC-T-READ"),
                             lambda: common.sha256_file(fifo, "SC-T-READ")):
                    with self.assertRaises(Refused) as caught:
                        read()
                    self.assertEqual(caught.exception.code, "SC-T-READ")


class PrintableTests(unittest.TestCase):
    def test_printable_text(self):
        self.assertTrue(common.printable("synthetic-lib 1.0"))
        for value in ("", " ", "\u200b", "a\tb", "a\x00", "\u202e", "x" * 4097, None, 1):
            with self.subTest(value=repr(value)[:20]):
                self.assertFalse(common.printable(value))


class Sha256FileTests(unittest.TestCase):
    def test_digest_and_size_of_a_regular_file(self):
        data = b"synthetic" * 300000
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "artifact.bin")
            with open(path, "wb") as handle:
                handle.write(data)
            self.assertEqual(common.sha256_file(path, "SC-T-ARTIFACT"),
                             (hashlib.sha256(data).hexdigest(), len(data)))

    def test_directory_missing_and_oversized_files_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "artifact.bin")
            with open(path, "wb") as handle:
                handle.write(b"x" * 100)
            self.assertEqual(common.sha256_file(path, "SC-T-ARTIFACT", 100)[1], 100)
            for target, limit in ((path, 99), (directory, 100), (path + ".absent", 100), ("bad\x00name", 100)):
                with self.subTest(limit=limit), self.assertRaises(Refused) as caught:
                    common.sha256_file(target, "SC-T-ARTIFACT", limit)
                self.assertEqual(caught.exception.code, "SC-T-ARTIFACT")


class FindingTests(unittest.TestCase):
    def build(self, **changes):
        values = {"scanner": "trivy", "rule_id": "SYNTHETIC-VULN-0001", "severity": "high",
                  "artifact_id": "web/image", "location_class": "image.package"}
        values.update(changes)
        return common.finding(values["scanner"], values["rule_id"], values["severity"],
                              values["artifact_id"], values["location_class"], "pkg", "1.0")

    def test_control_shape(self):
        self.assertEqual(set(self.build()), {"scanner", "rule_id", "severity", "artifact_id",
                                             "location_class", "severity_basis", "fingerprint"})
        self.assertEqual(self.build()["severity_basis"], "rule")

    def test_unknown_severity_basis_is_refused(self):
        common.finding("trivy", "SYNTHETIC-VULN-0001", "high", "web/image", "image.package", basis="unrated")
        with self.assertRaises(Refused) as caught:
            common.finding("trivy", "SYNTHETIC-VULN-0001", "high", "web/image", "image.package", basis="guess")
        self.assertEqual(caught.exception.code, "SC-FINDING-BASIS")

    def test_each_field_is_validated(self):
        cases = {
            "SC-FINDING-SCANNER": {"scanner": "grype"},
            "SC-FINDING-RULE": {"rule_id": "SYNTHETIC VULN"},
            "SC-FINDING-SEVERITY": {"severity": "unknown"},
            "SC-FINDING-ARTIFACT": {"artifact_id": "Web/Image"},
            "SC-FINDING-LOCATION": {"location_class": "Image"},
        }
        for code, change in cases.items():
            with self.subTest(code=code), self.assertRaises(Refused) as caught:
                self.build(**change)
            self.assertEqual(caught.exception.code, code)

    def test_fingerprint_binds_location_parts_without_ambiguity(self):
        self.assertNotEqual(common.fingerprint("ab", "c"), common.fingerprint("a", "bc"))
        self.assertRegex(common.fingerprint("x"), r"\Asha256:[0-9a-f]{64}\Z")

    def test_never_exceptable_prefixes(self):
        self.assertTrue(common.never_exceptable("SC-SIG-UNSIGNED"))
        self.assertTrue(common.never_exceptable("SC-SUBJECT-MISMATCH"))
        self.assertFalse(common.never_exceptable("SC-ANDROID-DEBUGGABLE"))


class PolicyTests(unittest.TestCase):
    def load(self, document):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "policy.json")
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(document, handle)
            return common.load_policy(path)

    def control(self):
        with open(common.POLICY_PATH, encoding="utf-8") as handle:
            return json.load(handle)

    def refused(self, change, code):
        document = self.control()
        change(document)
        with self.assertRaises(Refused) as caught:
            self.load(document)
        self.assertEqual(caught.exception.code, code)

    def test_committed_policy_is_proposed_with_high_threshold(self):
        self.assertEqual(common.load_policy(), "high")
        self.assertEqual(self.control()["status"], "proposed, not agreed")
        self.assertEqual(self.load(self.control()), "high")

    def test_threshold_cannot_be_weakened_below_high(self):
        self.refused(lambda document: document.__setitem__("blocking_threshold", "critical"), "SC-POLICY-THRESHOLD")

    def test_no_report_only_or_signature_switch_exists(self):
        for key, value in (("mode", "report-only"), ("signature_verification", "report"), ("rules", {})):
            with self.subTest(key=key):
                self.refused(lambda document, key=key, value=value: document.__setitem__(key, value),
                             "SC-POLICY-SHAPE")

    def test_schema_and_status(self):
        self.refused(lambda document: document.__setitem__("schema", "other/1"), "SC-POLICY-SCHEMA")
        self.refused(lambda document: document.__setitem__("status", "approved by owner"), "SC-POLICY-STATUS")

    def test_missing_policy_file_is_refused(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(Refused) as caught:
            common.load_policy(os.path.join(directory, "absent.json"))
        self.assertEqual(caught.exception.code, "SC-POLICY-READ")


class ImportBoundaryTests(unittest.TestCase):
    """The gate modules stay offline and keyless: no network, process, crypto-signing or environment access."""

    ALLOWED = {"hashlib", "json", "math", "os", "posixpath", "re", "stat", "xml.etree"}  # posixpath: pure strings
    # Only the command line may import sys (argv and exit status).
    CLI_ALLOWED = ALLOWED | {"sys"}

    def test_gate_modules_import_only_the_allowed_standard_library(self):
        modules = sorted(Path(common.__file__).resolve().parent.glob("supply_chain_*.py"))
        self.assertGreaterEqual(len(modules), 5)
        for module in modules:
            tree = ast.parse(module.read_text(encoding="utf-8"))
            names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    names.add(node.module)
            allowed = self.CLI_ALLOWED if module.name == "supply_chain_cli.py" else self.ALLOWED
            foreign = {name for name in names if not name.startswith("supply_chain_")} - allowed
            with self.subTest(module=module.name):
                self.assertEqual(foreign, set())
                self.assertNotIn("environ", module.read_text(encoding="utf-8"))

    def test_test_fakes_hold_no_key_material(self):
        """Plan 8.5: a Verifier port with a fake in tests, no hand-written crypto and no keys."""
        source = (Path(__file__).resolve().parent / "supply_chain_support.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.add(node.module)
        self.assertEqual(names & {"hmac", "secrets", "random", "ssl", "cryptography"}, set())
        self.assertNotIn("token_bytes", source)


if __name__ == "__main__":
    unittest.main()
