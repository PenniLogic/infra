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
from test_api_node_runtime import NODE_ARGUMENT
from test_baseline import CONTRACTS_STATE


GATE = ".github/workflows/pr-workflow-integrity.yml"
SOURCE = "f3331d5bc24556d11b9f3ad0b517db37e9caac9d"
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

    def test_only_scoped_api_android_and_infra_gate_deltas_change_the_historical_baseline(self):
        with tempfile.TemporaryDirectory(prefix="pr-integrity-baseline-") as directory:
            accepted = historical_generator(Path(directory))
            unchanged = 0
            for name in generator.PROFILES["repositories"]:
                old, new = accepted.artifacts(name), generator.artifacts(name)
                if name == "android":
                    changed = {
                        "AGENTS.md", "README.md", "CONTRIBUTING.md", ".github/agent-policy.json",
                        ".github/workflows/ci.yml", ".github/workflows/copilot-setup-steps.yml",
                        "scripts/check_privacy_components.py",
                    }
                    self.assertEqual(changed, {
                        path for path in set(old) | set(new) if old.get(path) != new.get(path)
                    })
                    unchanged += len(set(old) & set(new) - changed)
                    continue
                for relative in (".github/workflows/ci.yml", ".github/workflows/copilot-setup-steps.yml"):
                    expected = old[relative]
                    actual = new[relative]
                    if name == "api" and relative == ".github/workflows/ci.yml":
                        value = json.loads(expected)
                        run_checks = next(step for step in value["jobs"]["ci"]["steps"]
                                          if step["name"] == "Run checks")
                        run_checks["run"] = "\n".join(generator.profile_for("api")["commands"])
                        expected = json.dumps(value, indent=2) + "\n"
                    if name == "api":
                        value = json.loads(expected)
                        native_steps = next(iter(value["jobs"].values()))["steps"]
                        native_steps.insert(2, {
                            "name": "Node",
                            "uses": "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
                            "with": {"node-version-file": ".nvmrc"},
                        })
                        if relative == ".github/workflows/ci.yml":
                            preparation = json.loads(actual)["jobs"]["ci"]["steps"][4]
                            self.assertEqual({"name", "run"}, set(preparation))
                            self.assertEqual("Prepare API Node SDK", preparation["name"])
                            # Bind C's exact added program without duplicating its shell fixture.
                            self.assertEqual(
                                "d194c5568ed1a7dbb44440a1a88e4ceec07d34196535bb10d2426b18955cb55a",
                                hashlib.sha256(preparation["run"].encode("utf-8")).hexdigest(),
                            )
                            native_steps.insert(4, preparation)
                            for step in native_steps:
                                if step["name"] == "Run checks":
                                    commands = step["run"].split("\n")
                                    self.assertEqual(1, commands.count("python scripts/quality.py build"))
                                    commands[commands.index("python scripts/quality.py build")] += NODE_ARGUMENT
                                    step["run"] = "\n".join(commands)
                                elif step["name"] == "Coverage against explicit base":
                                    step["run"] += NODE_ARGUMENT
                        expected = generator.encoded(value)
                    self.assertEqual(expected, actual, (name, relative))
                if name == "api":
                    self.assertEqual({
                        "AGENTS.md", "README.md", "CONTRIBUTING.md", ".github/agent-policy.json",
                        ".github/workflows/ci.yml", ".github/workflows/copilot-setup-steps.yml", ".nvmrc",
                        "scripts/materialize_money_sources.py",
                        "scripts/prepare_database_admission.py", "src/main/resources/database-admission-installation.json",
                    }, {path for path in set(old) | set(new) if old.get(path) != new.get(path)})
                    self.assertNotIn(".nvmrc", old)
                    self.assertEqual("24.14.0\n", new[".nvmrc"])
                    unchanged += sum(old[path] == new.get(path) for path in old)
                elif name == "contracts":
                    previous_state = accepted.PROFILES["repositories"][name]["state"]
                    expected = dict(old)
                    for relative in ("AGENTS.md", "README.md", "CONTRIBUTING.md"):
                        self.assertEqual(1, old[relative].count(previous_state))
                        expected[relative] = old[relative].replace(previous_state, CONTRACTS_STATE, 1)
                    self.assertEqual(expected, new, name)
                    unchanged += sum(old[path] == new.get(path) for path in old)
                elif name != "infra":
                    self.assertEqual(old, new, name)
                    unchanged += len(new)
                else:
                    self.assertEqual(23, len(new))
                    self.assertEqual({GATE, "scripts/check_repository.py"},
                                     {path for path in set(old) | set(new) if old.get(path) != new.get(path)})
                    self.assertEqual(old[".github/workflows/conformance.yml"],
                                     new[".github/workflows/conformance.yml"])
            self.assertEqual(145, unchanged)

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
