"""The additive, base-trusted PR workflow, not a candidate-controlled assertion."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import conformance_support as support
from conformance import steps


GATE = ".github/workflows/pr-workflow-integrity.yml"
SOURCE = "65d0a95b9dd06dae7145c14e6952a6cdb6dd7f19"
generator = support.generator


def historical_generator(root):
    for relative in ("governance/generate.py", "governance/repository-profiles.json",
                     "governance/templates/check_repository.py", "governance/templates/setup.py"):
        result = subprocess.run(
            ["git", "show", f"{SOURCE}:{relative}"], cwd=support.GOVERNANCE.parent,
            capture_output=True, check=False, timeout=30, env=support.defects.probe_environment(),
        )
        if result.returncode:
            raise AssertionError("accepted generator source is unavailable; no skipped baseline proof")
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(result.stdout)
    return support.generator_module.load(root / "governance" / "generate.py", name="accepted_pr_gate_baseline")


class GeneratedPRWorkflowTests(unittest.TestCase):
    def test_actual_accepted_checker_cli_stays_green_but_external_drift_cli_refuses_the_gap(self):
        with tempfile.TemporaryDirectory(prefix="pr-integrity-original-gap-") as directory:
            root = Path(directory)
            accepted = historical_generator(root / "source")
            for name, profile in accepted.PROFILES["repositories"].items():
                consumer = root / "consumers" / name
                accepted.generate(name, consumer)
                (consumer / "migration-source.json").write_text("{}\n", encoding="utf-8")
                env = support.defects.probe_environment()
                initialized = subprocess.run(["git", "init", "-q", str(consumer)], capture_output=True,
                                             check=False, timeout=20, env=env)
                self.assertEqual(0, initialized.returncode)
                checker = [sys.executable, "-B", "scripts/check_repository.py"]
                drift = [sys.executable, "-B", str(accepted.HERE / "generate.py"), "--repository", name,
                         "--root", str(consumer), "--check"]
                for command in (checker, drift):
                    result = subprocess.run(command, cwd=consumer, capture_output=True,
                                            check=False, timeout=20, env=env)
                    self.assertEqual(0, result.returncode, name)
                test_command = next(command for command in profile["commands"] if "test" in steps.classify(command))
                for stub in (False, True):
                    value = json.loads(accepted.workflow(name))
                    run = next(step for step in value["jobs"]["ci"]["steps"] if step.get("name") == "Run checks")
                    lines = run["run"].split("\n")
                    position = lines.index(test_command)
                    if stub:
                        lines[position] = "echo tests skipped"
                    else:
                        del lines[position]
                    run["run"] = "\n".join(lines)
                    (consumer / ".github" / "workflows" / "ci.yml").write_bytes(
                        accepted.encoded(value).encode("utf-8"),
                    )
                    observed = subprocess.run(checker, cwd=consumer, capture_output=True,
                                              check=False, timeout=20, env=env)
                    refused = subprocess.run(drift, cwd=consumer, capture_output=True,
                                             check=False, timeout=20, env=env)
                    with self.subTest(profile=name, stub=stub):
                        self.assertEqual(0, observed.returncode)
                        self.assertEqual(1, refused.returncode)
                        self.assertIn(b".github/workflows/ci.yml", refused.stderr)

    def test_only_infra_opts_in_and_the_gate_is_actionless(self):
        for name in generator.PROFILES["repositories"]:
            output = generator.artifacts(name)
            with self.subTest(profile=name):
                self.assertEqual(name == "infra", GATE in output)
        value = json.loads(generator.artifacts("infra")[GATE])
        self.assertEqual("PR workflow integrity", value["name"])
        self.assertEqual({"pull_request_target": {
            "branches": ["main"],
            "types": ["opened", "synchronize", "reopened", "ready_for_review", "edited"],
        }}, value["on"])
        self.assertEqual({"contents": "read"}, value["permissions"])
        self.assertEqual({"pr-workflow-integrity"}, set(value["jobs"]))
        job = value["jobs"]["pr-workflow-integrity"]
        self.assertEqual({"name", "runs-on", "timeout-minutes", "steps"}, set(job))
        self.assertEqual("PR workflow integrity", job["name"])
        self.assertEqual("ubuntu-24.04", job["runs-on"])
        self.assertEqual(5, job["timeout-minutes"])
        self.assertEqual(1, len(job["steps"]))
        step = job["steps"][0]
        self.assertEqual({"name", "run", "env"}, set(step))
        self.assertEqual("Validate candidate workflow bindings", step["name"])
        self.assertEqual({"GH_TOKEN": "${{ github.token }}"}, step["env"])
        self.assertTrue(step["run"].startswith("python3 -I -S - <<'PY'\n"))
        self.assertTrue(step["run"].endswith("\nPY"))
        for forbidden in ("eval(", "exec(", "subprocess", "importlib", "os.system(", "workflow_call"):
            self.assertNotIn(forbidden, step["run"])
        self.assertEqual(1, generator.artifacts("infra")[GATE].count("${{ github.token }}"))

    def test_all_nine_have_a_profile_bound_renderer_and_invalid_opt_ins_fail(self):
        for name, profile in generator.PROFILES["repositories"].items():
            with self.subTest(profile=name):
                contract = generator.pr_integrity_contract(name)
                self.assertEqual(f"PenniLogic/{name}", contract["repository"])
                self.assertEqual(profile["id"], contract["repository_id"])
                self.assertEqual(335295566, contract["organization_id"])
                ci = generator.workflow(name).encode("utf-8")
                self.assertEqual(hashlib.sha256(ci).hexdigest(),
                                 contract["files"][".github/workflows/ci.yml"])
                value = json.loads(generator.pr_integrity_workflow(name))
                self.assertEqual("PR workflow integrity", value["jobs"]["pr-workflow-integrity"]["name"])
                for invalid in ("true", 1, None, {}, []):
                    with mock.patch.dict(profile, {"pr_workflow_integrity": invalid}):
                        with self.assertRaises(ValueError):
                            generator.artifacts(name)

    def test_160_unopted_artifacts_and_all_18_existing_native_workflows_are_identical(self):
        with tempfile.TemporaryDirectory(prefix="pr-integrity-baseline-") as directory:
            accepted = historical_generator(Path(directory))
            unchanged = 0
            for name in generator.PROFILES["repositories"]:
                old, new = accepted.artifacts(name), generator.artifacts(name)
                for relative in (".github/workflows/ci.yml", ".github/workflows/copilot-setup-steps.yml"):
                    self.assertEqual(old[relative], new[relative], (name, relative))
                if name != "infra":
                    self.assertEqual(old, new, name)
                    unchanged += len(new)
                else:
                    self.assertEqual(23, len(new))
                    self.assertEqual({GATE, "scripts/check_repository.py"},
                                     {path for path in set(old) | set(new) if old.get(path) != new.get(path)})
                    self.assertEqual(old[".github/workflows/conformance.yml"],
                                     new[".github/workflows/conformance.yml"])
            self.assertEqual(160, unchanged)

    def test_exact_opt_in_checker_extension_never_widens_the_common_template(self):
        original = (support.GOVERNANCE / "templates" / "check_repository.py").read_bytes()
        with tempfile.TemporaryDirectory(prefix="pr-integrity-checker-") as directory:
            accepted = historical_generator(Path(directory))
            self.assertEqual(original, (accepted.HERE / "templates" / "check_repository.py").read_bytes())
        for name, profile in generator.PROFILES["repositories"].items():
            with self.subTest(profile=name), mock.patch.dict(profile, {"pr_workflow_integrity": True}):
                files = {path: value.encode("utf-8") for path, value in generator.artifacts(name).items()}
                files["migration-source.json"] = b"{}\n"
                with tempfile.TemporaryDirectory(prefix="pr-integrity-import-") as directory:
                    path = Path(directory) / "check_repository.py"
                    path.write_bytes(files["scripts/check_repository.py"])
                    spec = importlib.util.spec_from_file_location("opted_checker", path)
                    checker = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(checker)
                    self.assertEqual([], checker.check(files))
                    checker.validate_workflow(GATE, files[GATE])
                    for mutation in ("token", "event", "condition", "name", "run", "permission", "action"):
                        value = json.loads(files[GATE])
                        job = value["jobs"]["pr-workflow-integrity"]
                        step = job["steps"][0]
                        if mutation == "token":
                            step["env"]["OTHER"] = "${{ github.token }}"
                        elif mutation == "event":
                            value["on"] = {"pull_request": {"branches": ["main"]}}
                        elif mutation == "condition":
                            job["if"] = "false"
                        elif mutation == "name":
                            job["name"] = "CI"
                        elif mutation == "run":
                            step["run"] = "echo skipped"
                        elif mutation == "permission":
                            value["permissions"]["contents"] = "write"
                        else:
                            step["uses"] = "actions/github-script@" + "a" * 40
                        with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                            checker.validate_workflow(GATE, json.dumps(value).encode("utf-8"))
                    del files[GATE]
                    self.assertIn("Missing required repository file: " + GATE, checker.check(files))


if __name__ == "__main__":
    unittest.main()
