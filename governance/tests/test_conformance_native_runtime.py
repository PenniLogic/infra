"""PR59's real fixture dependencies are provisioned in native CI/setup, never skipped as green."""

import json
import unittest
from unittest import mock

import conformance_support as support
import test_conformance_runtime_fixtures as fixtures


class NativeRuntimeTests(unittest.TestCase):
    def test_infra_native_ci_and_setup_provision_the_existing_pinned_node_and_uv_before_checks(self):
        for setup in (False, True):
            workflow = json.loads(support.generator.workflow("infra", setup=setup))
            job = workflow["jobs"]["copilot-setup-steps" if setup else "ci"]
            steps = job["steps"]
            with self.subTest(setup=setup):
                self.assertEqual(["Checkout", "Python", "Node", "Install uv"], [step["name"] for step in steps[:4]])
                self.assertEqual({
                    "name": "Node",
                    "uses": "actions/setup-node@" + support.generator.PROFILES["actions"]["setup-node"],
                    "with": {"node-version-file": ".nvmrc"},
                }, steps[2])
                self.assertEqual({
                    "name": "Install uv", "run": support.generator.profile_for("ai-service")["install"][0],
                }, steps[3])
                self.assertEqual("Verify repository" if setup else "Run checks", steps[4]["name"])
                self.assertEqual({"contents": "read"}, workflow["permissions"])
                self.assertNotIn("env", job)
                self.assertNotIn("GH_TOKEN", json.dumps(workflow))
                self.assertEqual(10, job["timeout-minutes"])

    def test_native_ci_setup_and_conformance_use_the_same_runtime_pins_without_bypasses(self):
        documents = [
            json.loads(support.generator.workflow("infra", setup=setup)) for setup in (False, True)
        ] + [json.loads(support.generator.conformance_workflow())]
        for document in documents:
            steps = next(iter(document["jobs"].values()))["steps"]
            with self.subTest(workflow=document["name"]):
                node = next(step for step in steps if step["name"] == "Node")
                uv = next(step for step in steps if step["name"] == "Install uv")
                self.assertEqual({"node-version-file": ".nvmrc"}, node["with"])
                self.assertEqual(support.generator.profile_for("ai-service")["install"][0], uv["run"])
                for bypass in ("--legacy-peer-deps", "--force", "cache clean", "|| true"):
                    self.assertNotIn(bypass, json.dumps(steps))

    def test_missing_fixture_runtimes_fail_before_scratch_or_commands_instead_of_skipping(self):
        available = lambda name: "/synthetic/bin/" + name
        for case, names in ((fixtures.RealNodeFixtureTests, ("node", "npm")),
                            (fixtures.RealUvFixtureTests, ("uv",))):
            for missing in names:
                with self.subTest(case=case.__name__, missing=missing), \
                        mock.patch.object(fixtures.shutil, "which",
                                          side_effect=lambda name: None if name == missing else available(name)), \
                        mock.patch.object(fixtures.tempfile, "TemporaryDirectory",
                                          side_effect=AssertionError("missing tool must stop before scratch creation")), \
                        mock.patch.object(fixtures, "execute",
                                          side_effect=AssertionError("missing tool must stop before execution")):
                    with self.assertRaisesRegex(RuntimeError, "requires.*" + missing):
                        case.setUpClass()

    def test_preparation_failure_keeps_real_stderr_and_never_returns_success(self):
        error = "npm error Cannot read properties of null (reading 'edgesOut')"
        with mock.patch.object(fixtures.defects, "subprocess_runner",
                               return_value=fixtures.defects.Result(1, error)):
            with self.assertRaisesRegex(AssertionError, "edgesOut"):
                fixtures.execute("npm install --package-lock-only --ignore-scripts --no-audit --no-fund", ".")


if __name__ == "__main__":
    unittest.main()
