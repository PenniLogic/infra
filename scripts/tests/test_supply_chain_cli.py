"""In-process tests of scripts/supply_chain_cli.py: exit 0 pass / 1 gate failure / 2 usage or refused input, one
ASCII JSON line, no echo of values, paths or contents. All inputs are written to a temporary directory outside the
repository."""

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
import supply_chain_cli as cli
import supply_chain_support as fakes


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "supply_chain"


class CliCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="supply-chain-cli-")
        self.addCleanup(shutil.rmtree, self.directory)
        self.fake = fakes.IssuedTableFakeVerifier()
        self.sha = fakes.sha256(fakes.ARTIFACT)
        self.sbom = fakes.encode(fakes.sbom_document(self.sha))
        self.provenance = fakes.encode(fakes.provenance_statement(self.sha))
        self.paths = {
            "artifact": self.write("artifact.bin", fakes.ARTIFACT),
            "sbom": self.write("sbom.cdx.json", self.sbom),
            "provenance": self.write("provenance.intoto.json", self.provenance),
            "signatures": self.write("signatures.json", fakes.encode({
                "artifact": self.fake.sign(self.sha), "sbom": self.fake.sign(fakes.sha256(self.sbom)),
                "provenance": self.fake.sign(fakes.sha256(self.provenance))})),
        }

    def write(self, name, data):
        path = os.path.join(self.directory, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def run_cli(self, argv, **ports):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli.main(argv, **ports)
        output = buffer.getvalue()
        self.assertTrue(output.endswith("\n"))
        self.assertEqual(output.count("\n"), 1)
        output.encode("ascii")
        for value in argv:
            if isinstance(value, str) and (self.directory in value or "\x00" in value):
                self.assertNotIn(value, output)
        return code, json.loads(output)

    def deploy_argv(self, **override):
        paths = {**self.paths, **override}
        return ["deploy", "--artifact-id", "web/bundle", "--artifact", paths["artifact"], "--sbom", paths["sbom"],
                "--provenance", paths["provenance"], "--signatures", paths["signatures"]]

    def rules(self, report):
        return sorted(item["rule_id"] for item in report["findings"])


class DeployCliTests(CliCase):
    def test_control_passes_with_the_test_fake_verifier(self):
        code, report = self.run_cli(self.deploy_argv(), verifier=self.fake)
        self.assertEqual((code, report["decision"], report["gate"]), (0, "pass", "deploy"))
        self.assertEqual(report["exceptions"]["reason"], "exceptions unavailable (infra#23 not integrated)")

    def test_production_binding_fails_closed(self):
        code, report = self.run_cli(self.deploy_argv())
        self.assertEqual((code, report["decision"]), (1, "fail"))
        self.assertEqual(report["counts"]["by_rule"], {"SC-SIG-VERIFIER-UNAVAILABLE": 3})

    def test_tampered_artifact_is_rejected(self):
        tampered = self.write("tampered.bin", fakes.ARTIFACT + b"!")
        code, report = self.run_cli(self.deploy_argv(artifact=tampered), verifier=self.fake)
        self.assertEqual(code, 1)
        self.assertEqual(self.rules(report), ["SC-SIG-INVALID", "SC-SUBJECT-PROVENANCE-MISMATCH",
                                              "SC-SUBJECT-SBOM-MISMATCH"])

    def test_unsigned_artifact_is_rejected(self):
        unsigned = self.write("unsigned.json", fakes.encode({
            "sbom": self.fake.sign(fakes.sha256(self.sbom)),
            "provenance": self.fake.sign(fakes.sha256(self.provenance))}))
        code, report = self.run_cli(self.deploy_argv(signatures=unsigned), verifier=self.fake)
        self.assertEqual((code, self.rules(report)), (1, ["SC-SIG-UNSIGNED"]))

    def test_incomplete_sbom_is_rejected(self):
        document = fakes.sbom_document(self.sha)
        document["components"][0].pop("hashes")
        incomplete = self.write("incomplete.cdx.json", fakes.encode(document))
        code, report = self.run_cli(["sbom", "--artifact-id", "web/bundle", "--artifact", self.paths["artifact"],
                                     "--sbom", incomplete])
        self.assertEqual((code, self.rules(report)), (1, ["SC-SBOM-COMPONENT-HASH"]))

    def test_sbom_and_provenance_gates_pass_their_controls(self):
        for gate in ("sbom", "provenance"):
            with self.subTest(gate=gate):
                code, report = self.run_cli([gate, "--artifact-id", "web/bundle", "--artifact",
                                             self.paths["artifact"], "--" + gate, self.paths[gate]])
                self.assertEqual((code, report["decision"]), (0, "pass"))

    def test_missing_input_is_refused_with_the_option_name_only(self):
        absent = os.path.join(self.directory, "absent.cdx.json")
        code, report = self.run_cli(self.deploy_argv(sbom=absent), verifier=self.fake)
        self.assertEqual((code, report["decision"], report["code"], report["option"]),
                         (2, "refused", "SC-CLI-READ", "sbom"))

    def test_directory_as_artifact_is_refused(self):
        code, report = self.run_cli(self.deploy_argv(artifact=self.directory), verifier=self.fake)
        self.assertEqual((code, report["code"], report["option"]), (2, "SC-CLI-READ", "artifact"))

    def test_malformed_sbom_is_refused(self):
        malformed = self.write("malformed.cdx.json", b'{"bomFormat": "CycloneDX", "bomFormat": "SPDX"}')
        code, report = self.run_cli(self.deploy_argv(sbom=malformed), verifier=self.fake)
        self.assertEqual((code, report["code"]), (2, "SC-SBOM-JSON"))


class ScannerGateCliTests(CliCase):
    def fixture(self, name):
        return str(FIXTURES / name)

    def test_compose_control_passes_and_planted_privileged_fails(self):
        for name, expected in (("compose-rendered-control.json", 0), ("compose-rendered-planted-privileged.json", 1)):
            with self.subTest(name=name):
                code, report = self.run_cli(["compose", "--artifact-id", "infra/compose", "--input",
                                             self.fixture(name)])
                self.assertEqual((code, report["gate"]), (expected, "compose"))

    def test_android_control_passes_and_planted_insecure_fails(self):
        code, report = self.run_cli(["android", "--artifact-id", "android/release", "--manifest",
                                     self.fixture("android-manifest-release-control.xml"), "--network-config",
                                     self.fixture("android-network-security-config-control.xml")])
        self.assertEqual((code, report["decision"]), (0, "pass"))
        code, report = self.run_cli(["android", "--artifact-id", "android/release", "--manifest",
                                     self.fixture("android-manifest-planted-insecure.xml")])
        self.assertEqual((code, report["decision"]), (1, "fail"))

    def test_planted_vulnerable_image_report_blocks(self):
        code, report = self.run_cli(["trivy", "--artifact-id", "web/image", "--kind", "image", "--input",
                                     self.fixture("trivy-image-planted-vulnerable.json"), "--expected-digest",
                                     "sha256:" + "c" * 64])
        self.assertEqual((code, self.rules(report)), (1, ["SYNTHETIC-VULN-0001"]))

    def test_image_report_for_another_digest_is_refused(self):
        code, report = self.run_cli(["trivy", "--artifact-id", "web/image", "--kind", "image", "--input",
                                     self.fixture("trivy-image-planted-vulnerable.json"), "--expected-digest",
                                     "sha256:" + "e" * 64])
        self.assertEqual((code, report["code"]), (2, "SC-TRIVY-SUBJECT"))

    def test_planted_checkov_report_blocks(self):
        code, report = self.run_cli(["checkov", "--artifact-id", "infra/dockerfile", "--input",
                                     self.fixture("checkov-planted-high.json")])
        self.assertEqual((code, report["decision"]), (1, "fail"))

    def test_weaker_policy_file_is_refused(self):
        policy = self.write("policy.json", fakes.encode({"schema": "pennilogic.supply-chain.policy/1",
                                                         "status": "agreed", "blocking_threshold": "critical"}))
        code, report = self.run_cli(["compose", "--artifact-id", "infra/compose", "--policy", policy, "--input",
                                     self.fixture("compose-rendered-control.json")])
        self.assertEqual((code, report["code"]), (2, "SC-POLICY-THRESHOLD"))


class UsageTests(CliCase):
    def test_control_usage_is_accepted(self):
        code, _report = self.run_cli(["sbom", "--artifact-id", "web/bundle", "--artifact", self.paths["artifact"],
                                      "--sbom", self.paths["sbom"]])
        self.assertEqual(code, 0)

    def test_usage_errors_exit_2_with_a_static_code(self):
        base = ["sbom", "--artifact-id", "web/bundle", "--artifact", self.paths["artifact"], "--sbom",
                self.paths["sbom"]]
        cases = (
            ([], "SC-CLI-USAGE-GATE"), (["publish"] + base[1:], "SC-CLI-USAGE-GATE"), ([["sbom"]], "SC-CLI-USAGE-GATE"),
            (base[:-1], "SC-CLI-USAGE-ARITY"), (base + ["--verifier", "fake"], "SC-CLI-USAGE-OPTION"),
            (base + ["--report-only", "true"], "SC-CLI-USAGE-OPTION"), (base + ["-x", "1"], "SC-CLI-USAGE-OPTION"),
            (base + ["--sbom", self.paths["sbom"]], "SC-CLI-USAGE-REPEATED"),
            (base[:-2] + ["--sbom", "--x"], "SC-CLI-USAGE-VALUE"), (base[:-2] + ["--sbom", ""], "SC-CLI-USAGE-VALUE"),
            (base[:-2], "SC-CLI-USAGE-MISSING"), (base[:2] + ["Web Bundle"] + base[3:], "SC-CLI-USAGE-ARTIFACT"),
            (base[:3] + ["--artifact", "bad\x00name"] + base[5:], "SC-CLI-READ"),
        )
        for argv, expected in cases:
            with self.subTest(code=expected, size=len(argv)):
                code, report = self.run_cli(argv)
                self.assertEqual((code, report["decision"], report["code"]), (2, "refused", expected))

    def test_malformed_expected_digest_is_a_usage_error(self):
        code, report = self.run_cli(["trivy", "--artifact-id", "web/image", "--kind", "image", "--input",
                                     str(FIXTURES / "trivy-image-planted-vulnerable.json"), "--expected-digest",
                                     "c" * 64])
        self.assertEqual((code, report["code"]), (2, "SC-CLI-USAGE-DIGEST"))

    def test_image_report_without_expected_digest_is_refused(self):
        code, report = self.run_cli(["trivy", "--artifact-id", "web/image", "--kind", "image", "--input",
                                     str(FIXTURES / "trivy-image-planted-vulnerable.json")])
        self.assertEqual((code, report["code"]), (2, "SC-TRIVY-SUBJECT"))

    def test_unexpected_port_error_is_refused_without_echo(self):
        class Broken:
            available = "maybe"

        code, report = self.run_cli(["sbom", "--artifact-id", "web/bundle", "--artifact", self.paths["artifact"],
                                     "--sbom", self.paths["sbom"]], exceptions_port=Broken())
        self.assertEqual((code, report["code"]), (2, "SC-EXCEPTIONS-PORT"))

    def test_output_is_deterministic(self):
        argv = self.deploy_argv()
        first = self.run_cli(argv)
        self.assertEqual(self.run_cli(argv), first)



class GuideTests(unittest.TestCase):
    """SUPPLY_CHAIN.md documents every gate and option of the command line (drift check)."""

    def test_every_gate_and_option_is_documented(self):
        guide = (support.ROOT / "SUPPLY_CHAIN.md").read_text(encoding="utf-8")
        for gate, options in cli.GATES.items():
            with self.subTest(gate=gate):
                self.assertIn("| `%s` |" % gate, guide)
                usage = [line for line in guide.splitlines() if line.startswith(gate + " ")]
                self.assertEqual(len(usage), 1)
                for option in options:
                    self.assertIn("--" + option + " ", usage[0] + " ")
        for option in cli.COMMON:
            self.assertIn("--" + option, guide)


if __name__ == "__main__":
    unittest.main()
