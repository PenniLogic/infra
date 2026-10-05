"""Infra#24's generated report workflow, guarded token channel and failure publication."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parents[1]
CI = ".github/workflows/ci.yml"
SETUP = ".github/workflows/copilot-setup-steps.yml"
CONFORMANCE = ".github/workflows/conformance.yml"
PR_GATE = ".github/workflows/pr-workflow-integrity.yml"
UPLOAD_PIN = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
RUN = """mkdir -p conformance-report
if [ "$GITHUB_REF" != "refs/heads/main" ] || [ "$GITHUB_REF_PROTECTED" != "true" ]; then
  echo "::error::Conformance requires protected main; no harness was executed."
  touch conformance-report/FAILED
else
  python governance/conformance/run.py --scratch "$RUNNER_TEMP/conformance-scratch" --output conformance-report --github-client gh --exercise python,node,uv || touch conformance-report/FAILED
fi"""


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load("generated_conformance_generator", HERE / "generate.py")


def document():
    return json.loads(generator.artifacts("infra")[CONFORMANCE])


def step_of(value, name):
    return next(step for step in value["jobs"]["conformance"]["steps"] if step.get("name") == name)


def without_token(value):
    step_of(value, "Run conformance").pop("env", None)
    return value


def rendered_checker(repo):
    module = types.ModuleType(f"conformance_checker_{repo.strip('.')}")
    module.__file__ = str(HERE.parent / "scripts" / "check_repository.py")
    exec(compile(generator.artifacts(repo)["scripts/check_repository.py"], module.__file__, "exec"), module.__dict__)
    return module


def validate(value, repo="infra", name=CONFORMANCE):
    rendered_checker(repo).validate_workflow(name, json.dumps(value).encode("utf-8"))


class GeneratedConformanceTests(unittest.TestCase):
    def test_only_infra_gets_the_third_generated_workflow(self):
        for repo in generator.PROFILES["repositories"]:
            with self.subTest(repo=repo):
                output = generator.artifacts(repo)
                self.assertEqual(23 if repo == "infra" else 21 if repo in ("api", "android") else 20, len(output))
                self.assertEqual({CI, SETUP, CONFORMANCE, PR_GATE} if repo == "infra" else {CI, SETUP},
                                 {name for name in output if name.startswith(".github/workflows/")})

    def test_workflow_matches_the_preserved_request_and_explicit_safety_additions(self):
        self.assertEqual({
            "name": "Conformance",
            "on": {"workflow_dispatch": {}, "schedule": [{"cron": "17 5 * * 1"}]},
            "permissions": {"contents": "read"},
            "concurrency": {"group": "${{ github.workflow }}", "cancel-in-progress": True},
            "jobs": {"conformance": {
                "name": "Conformance", "runs-on": "ubuntu-24.04", "timeout-minutes": 60,
                "steps": [
                    {"name": "Checkout", "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                     "with": {"persist-credentials": False, "fetch-depth": 0}},
                    {"name": "Python", "uses": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
                     "with": {"python-version": "3.14"}},
                    {"name": "Node", "uses": "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
                     "with": {"node-version-file": ".nvmrc"}},
                    {"name": "Install uv", "run": generator.PROFILES["repositories"]["ai-service"]["install"][0]},
                    {"name": "Run conformance", "env": {"GH_TOKEN": "${{ github.token }}"}, "run": RUN},
                    {"name": "Upload report", "uses": f"actions/upload-artifact@{UPLOAD_PIN}",
                     "with": {"name": "conformance-report", "path": "conformance-report",
                              "retention-days": 3, "if-no-files-found": "error"}},
                    {"name": "Fail on findings", "run": "test ! -f conformance-report/FAILED"},
                ],
            }},
        }, document())
        self.assertEqual(UPLOAD_PIN, generator.PROFILES["actions"]["upload-artifact"])
        validate(document())

    def test_repository_binding_is_rendered_from_the_profile_not_trusted_from_the_template(self):
        template = (HERE / "templates/check_repository.py").read_text(encoding="utf-8")
        line = 'WORKFLOW_REPOSITORY = "infra"\n'
        self.assertIn(line, template)
        for stale in (template.replace(line, 'WORKFLOW_REPOSITORY = "web"\n'),
                      template.replace(line, 'WORKFLOW_REPOSITORY = ""\n')):
            with mock.patch.object(generator.Path, "read_text", return_value=stale):
                self.assertEqual(template, generator.checker("infra", integrity=False))
        for invalid in (template.replace(line, ""), template.replace(line, line + line)):
            with mock.patch.object(generator.Path, "read_text", return_value=invalid):
                with self.assertRaisesRegex(ValueError, "WORKFLOW_REPOSITORY exactly once"):
                    generator.checker("infra", integrity=False)
        for repo in generator.PROFILES["repositories"]:
            with self.subTest(repo=repo):
                checker = rendered_checker(repo)
                self.assertEqual(repo, checker.WORKFLOW_REPOSITORY)
                if repo == "infra":
                    checker.validate_workflow(CONFORMANCE, json.dumps(document()).encode())
                else:
                    with self.assertRaises(ValueError):
                        checker.validate_workflow(CONFORMANCE, json.dumps(document()).encode())
                    with self.assertRaisesRegex(ValueError, "workflow file outside"):
                        checker.validate_workflow(CONFORMANCE, generator.workflow(repo).encode())

    def test_schedule_is_only_allowed_in_the_infra_conformance_file(self):
        for repo in generator.PROFILES["repositories"]:
            for name, setup in ((CI, False), (SETUP, True)):
                with self.subTest(repo=repo, name=name):
                    value = json.loads(generator.workflow(repo, setup=setup))
                    value["on"]["schedule"] = [{"cron": "17 5 * * 1"}]
                    with self.assertRaisesRegex(ValueError, "unreviewed workflow trigger"):
                        validate(value, repo, name)
        for repo in generator.PROFILES["repositories"]:
            for name in (".github/workflows/extra.yml", ".github/workflows/conformance.yaml",
                         ".github/workflows/Conformance.yml", ".github/workflows/sub/conformance.yml"):
                with self.subTest(repo=repo, name=name):
                    value = json.loads(generator.workflow(repo))
                    value["on"]["schedule"] = [{"cron": "17 5 * * 1"}]
                    with self.assertRaisesRegex(ValueError, "unreviewed workflow trigger"):
                        validate(value, repo, name)

    def test_conformance_requires_exactly_schedule_and_manual_dispatch(self):
        for events in ({}, {"workflow_dispatch": {}}, {"schedule": [{"cron": "17 5 * * 1"}]},
                       {"workflow_dispatch": {}, "schedule": [{"cron": "17 5 * * 1"}], "push": {}},
                       {"workflow_dispatch": {}, "schedule": [{"cron": "17 5 * * 1"}], "pull_request": {}},
                       {"workflow_dispatch": {}, "schedule": [{"cron": "17 5 * * 1"}], "workflow_call": {}},
                       None, ["workflow_dispatch", "schedule"]):
            with self.subTest(events=events):
                value = document()
                value["on"] = events
                with self.assertRaisesRegex(ValueError, "trigger|Conformance must run"):
                    validate(value)

    def test_weekly_schedule_and_input_free_dispatch_are_exact(self):
        for schedule in (None, {}, [], "17 5 * * 1", [{"cron": 17}], [{"cron": "0 * * * *"}],
                         [{"cron": "17 5 * * 1", "timezone": "UTC"}],
                         [{"cron": "17 5 * * 1"}, {"cron": "17 5 * * 1"}], [{"CRON": "17 5 * * 1"}]):
            with self.subTest(schedule=schedule):
                value = document()
                value["on"]["schedule"] = schedule
                with self.assertRaisesRegex(ValueError, "weekly cron and input-free manual dispatch"):
                    validate(value)
        for dispatch in (None, [], True, {"inputs": {}}, {"branches": ["main"]}):
            with self.subTest(dispatch=dispatch):
                value = document()
                value["on"]["workflow_dispatch"] = dispatch
                with self.assertRaisesRegex(ValueError, "weekly cron and input-free manual dispatch"):
                    validate(value)

    def test_conformance_job_set_and_both_names_are_exact(self):
        job = without_token(document())["jobs"]["conformance"]
        for jobs in ({"other": job}, {"Conformance": job}, {"conformance ": job},
                     {"conformance": job, "other": copy.deepcopy(job)}):
            with self.subTest(jobs=list(jobs)):
                value = document()
                value["jobs"] = jobs
                with self.assertRaisesRegex(ValueError, "Conformance must contain its documented single job"):
                    validate(value)
        for target in ("workflow", "job"):
            for name in ("CI", "conformance", "Conformance ", "", None):
                with self.subTest(target=target, name=name):
                    value = document()
                    (value if target == "workflow" else value["jobs"]["conformance"])["name"] = name
                    with self.assertRaisesRegex(ValueError, "Conformance workflow and job names stable"):
                        validate(value)

    def test_conformance_timeout_is_the_bounded_integer_sixty(self):
        for timeout in (None, True, False, 0, 10, 61, 360, "60", 60.0):
            with self.subTest(timeout=timeout):
                value = document()
                value["jobs"]["conformance"]["timeout-minutes"] = timeout
                with self.assertRaisesRegex(ValueError, "Conformance must keep its bounded 60-minute timeout"):
                    validate(value)

    def test_artifact_upload_is_reserved_for_infra_conformance(self):
        upload = step_of(document(), "Upload report")
        for repo in generator.PROFILES["repositories"]:
            for name, setup in ((CI, False), (SETUP, True)):
                with self.subTest(repo=repo, name=name):
                    value = json.loads(generator.workflow(repo, setup=setup))
                    next(iter(value["jobs"].values()))["steps"].append(copy.deepcopy(upload))
                    with self.assertRaisesRegex(ValueError, "artifact upload is reserved for infra conformance"):
                        validate(value, repo, name)

    def test_upload_and_other_actions_keep_exact_immutable_pins(self):
        for uses in ("actions/upload-artifact@v7.0.1", "actions/upload-artifact@main",
                     f"actions/upload-artifact@{'0' * 40}", f"actions/upload-artifact@{UPLOAD_PIN.upper()}",
                     f"actions/upload-artifact@{UPLOAD_PIN[:7]}", f"actions/download-artifact@{UPLOAD_PIN}",
                     f"actions/github-script@{UPLOAD_PIN}", "./.github/actions/upload", "docker://alpine:3.20"):
            with self.subTest(uses=uses):
                value = document()
                step_of(value, "Upload report")["uses"] = uses
                with self.assertRaisesRegex(ValueError, "immutable|generated pin"):
                    validate(value)
        for index in (0, 1):
            value = document()
            step = value["jobs"]["conformance"]["steps"][index]
            step["uses"] = step["uses"].partition("@")[0] + "@" + UPLOAD_PIN
            with self.assertRaisesRegex(ValueError, "generated pin"):
                validate(value)

    def test_upload_inputs_only_allow_the_four_documented_rendered_inputs(self):
        checker = rendered_checker("infra")
        self.assertEqual({"name", "path", "retention-days", "if-no-files-found"},
                         checker.WORKFLOW_ACTIONS["actions/upload-artifact"])
        for key in ("token", "overwrite", "include-hidden-files", "compression-level", "archive", "path ", "Name"):
            with self.subTest(key=key):
                value = document()
                step_of(value, "Upload report")["with"][key] = "x"
                with self.assertRaisesRegex(ValueError, "unreviewed action input"):
                    validate(value)
        for inputs in (None, [], "path: conformance-report", True):
            value = document()
            step_of(value, "Upload report")["with"] = inputs
            with self.assertRaisesRegex(ValueError, "unreviewed action input"):
                validate(value)

    def test_secret_and_whole_context_expression_evasions_stay_refused(self):
        forms = ("${{ github.token }}", "${{ github\n.token }}", "${{ github['token'] }}",
                 "${{ toJSON(\tgithub) }}", "${{ secrets.X }}", "${{ toJSON(secrets) }}",
                 "${{ github[format('to{0}', 'ken')] }}", "github\n.token", "secrets.X")
        for form in forms:
            for placement in ("run", "env", "upload", "cron"):
                with self.subTest(form=form, placement=placement):
                    value = document()
                    if placement == "run":
                        step_of(value, "Run conformance")["run"] += "\n" + form
                    elif placement == "env":
                        step_of(value, "Run conformance")["env"] = {"GH_TOKEN": form}
                        if form == "${{ github.token }}":
                            validate(value)
                            continue
                    elif placement == "upload":
                        step_of(value, "Upload report")["with"]["path"] = form
                    else:
                        value["on"]["schedule"][0]["cron"] = form
                    with self.assertRaisesRegex(ValueError, "secrets"):
                        validate(value)

    def test_if_keys_stay_refused_at_every_generated_mapping(self):
        def mappings(value, path=()):
            if isinstance(value, dict):
                yield path
                for key, item in value.items():
                    yield from mappings(item, path + (key,))
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    yield from mappings(item, path + (index,))

        for path in mappings(document()):
            with self.subTest(path=path):
                value = document()
                target = value
                for key in path:
                    target = target[key]
                target["if"] = "always()"
                rule = ("read-only workflow token" if path == ("permissions",)
                        else "conditions|unreviewed action input|secrets")
                with self.assertRaisesRegex(ValueError, rule):
                    validate(value)

    def test_writable_permissions_and_reusable_jobs_stay_refused(self):
        for permissions in ({"contents": "write"}, {"contents": "read", "actions": "write"},
                            {"id-token": "write"}, "write-all", {}):
            value = document()
            value["permissions"] = permissions
            with self.assertRaisesRegex(ValueError, "read-only workflow token"):
                validate(value)
        for extra in ({"uses": f"octo/repo/.github/workflows/x.yml@{UPLOAD_PIN}"},
                      {"permissions": {"contents": "read"}}, {"continue-on-error": True},
                      {"container": {"image": "alpine:3.20"}}, {"strategy": {"matrix": {"x": [1]}}}):
            value = document()
            value["jobs"]["conformance"].update(extra)
            with self.assertRaises(ValueError):
                validate(value)
        for extra in ({"shell": "bash"}, {"working-directory": "sub"}, {"id": "probe"},
                      {"continue-on-error": True}):
            value = without_token(document())
            step_of(value, "Run conformance").update(extra)
            with self.assertRaisesRegex(ValueError, "step-level key"):
                validate(value)

    def test_all_nine_generated_baselines_are_deterministic_and_pass_their_own_checker(self):
        for repo in generator.PROFILES["repositories"]:
            with self.subTest(repo=repo), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                generator.generate(repo, root)
                first = {path.relative_to(root).as_posix(): path.read_bytes()
                         for path in root.rglob("*") if path.is_file()}
                generator.generate(repo, root)
                second = {path.relative_to(root).as_posix(): path.read_bytes()
                          for path in root.rglob("*") if path.is_file()}
                self.assertEqual(first, second)
                generator.generate(repo, root, check=True)
                self.assertEqual([], rendered_checker(repo).check({**first, "migration-source.json": b"{}\n"}))

    def test_policy_edits_cannot_enable_the_consumer_exception(self):
        files = {name: text.encode() for name, text in generator.artifacts("web").items()}
        files["migration-source.json"] = b"{}\n"
        files[".github/agent-policy.json"] = generator.artifacts("infra")[".github/agent-policy.json"].encode()
        files[CONFORMANCE] = generator.artifacts("infra")[CONFORMANCE].encode()
        self.assertTrue(any("Invalid or unsafe workflow" in line for line in rendered_checker("web").check(files)))

    def test_only_infra_readme_discloses_report_upload_and_short_retention(self):
        old = "No release publishing, artifact upload or cache allowance increase is configured."
        for repo in generator.PROFILES["repositories"]:
            with self.subTest(repo=repo):
                readme = generator.artifacts(repo)["README.md"]
                if repo == "infra":
                    self.assertNotIn(old, readme)
                    self.assertIn("three-day retention", readme)
                    self.assertIn("report-only", readme)
                else:
                    self.assertIn(old, readme)
                    self.assertNotIn("three-day retention", readme)


@unittest.skipUnless(shutil.which("bash"), "Bash is required to execute the generated hosted-runner steps")
class ConformanceRunStepTests(unittest.TestCase):
    def exercise(self, ref="refs/heads/main", protected="true", code=0, report=True):
        value = document()
        run_step = step_of(value, "Run conformance")
        upload_step = step_of(value, "Upload report")
        final_step = step_of(value, "Fail on findings")
        env = {key: value for key, value in os.environ.items()
               if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "HOME", "TEMP", "TMP"}}
        env.update({"GITHUB_REF": ref, "GITHUB_REF_PROTECTED": protected, "RUNNER_TEMP": "/tmp/synthetic-runner",
                    "HARNESS_RC": str(code), "HARNESS_REPORT": "yes" if report else "no"})
        fixture = """python() {
  printf '%s\\n' "$*" > harness-arguments.txt
  if [ "$HARNESS_REPORT" = "yes" ]; then
    printf '%s\\n' '{"result": "synthetic"}' > conformance-report/conformance-report.json
  fi
  return "$HARNESS_RC"
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            run = subprocess.run([shutil.which("bash"), "-e", "-c", fixture + run_step["run"]],
                                 cwd=tmp, env=env, capture_output=True, text=True, check=False, timeout=15)
            root = Path(tmp)
            invoked = (root / "harness-arguments.txt").exists()
            arguments = (root / "harness-arguments.txt").read_text() if invoked else None
            self.assertEqual(0, run.returncode, run.stderr)
            self.assertEqual("conformance-report", upload_step["with"]["path"])
            failed = (root / "conformance-report" / "FAILED").exists()
            written = (root / "conformance-report" / "conformance-report.json").exists()
            final = subprocess.run([shutil.which("bash"), "-e", "-c", final_step["run"]],
                                   cwd=tmp, env=env, capture_output=True, check=False, timeout=15)
        self.assertEqual(1 if failed else 0, final.returncode)
        if invoked:
            self.assertEqual("governance/conformance/run.py --scratch /tmp/synthetic-runner/conformance-scratch "
                             "--output conformance-report --github-client gh --exercise python,node,uv\n", arguments)
        return invoked, failed, written, run.stdout

    def test_protected_main_success_uploads_the_report_then_succeeds(self):
        self.assertEqual((True, False, True, ""), self.exercise())

    def test_findings_preserve_the_report_and_fail_after_the_upload_step(self):
        self.assertEqual((True, True, True, ""), self.exercise(code=1))

    def test_harness_error_without_a_report_still_records_failure(self):
        self.assertEqual((True, True, False, ""), self.exercise(code=2, report=False))

    def test_off_main_manual_dispatch_does_not_execute_the_harness(self):
        for ref in ("refs/heads/topic", "refs/tags/main", "refs/pull/1/merge", ""):
            with self.subTest(ref=ref):
                invoked, failed, written, message = self.exercise(ref=ref)
                self.assertEqual((False, True, False), (invoked, failed, written))
                self.assertIn("::error::Conformance requires protected main; no harness was executed.", message)

    def test_unprotected_main_does_not_execute_the_harness(self):
        for protected in ("false", "", "TRUE"):
            with self.subTest(protected=protected):
                invoked, failed, written, message = self.exercise(protected=protected)
                self.assertEqual((False, True, False), (invoked, failed, written))
                self.assertIn("no harness was executed", message)


if __name__ == "__main__":
    unittest.main()
