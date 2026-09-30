"""Key allowlists, surfaced rule messages and json_document hardening of the generated
repository checker (PenniLogic/infra#50, notes S3/C1 of PR #48): only the top-level, job-level
and step-level keys the generator emits are accepted, check() names the refusing rule without
echoing file content, and a BOM, a non-object document or malformed input fails closed.
Since PenniLogic/infra#54 (note C3 of PR #51) each generated workflow file is also bound to
its trigger set and single job. PR G adds only infra's reviewed conformance workflow."""

import importlib.util
import json
from pathlib import Path
import re
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parents[1]
SHA = "0123456789abcdef0123456789abcdef01234567"
CI = ".github/workflows/ci.yml"
SETUP = ".github/workflows/copilot-setup-steps.yml"
# A token that must never appear in a check() message, planted as key and as value.
MARKER = "MARKER-7f3a9c-DO-NOT-ECHO"
TOP_RULE = "top-level key outside the generated workflow keys name, on, permissions, concurrency, jobs"
JOB_RULE = "job-level key outside the generated job keys name, runs-on, timeout-minutes, env, steps"
STEP_RULE = "step-level key outside the generated step keys name, uses, with, run, env"
PIN_RULE = "action commit differs from the generated pin; regenerate instead of editing it"
CI_TRIGGER_RULE = "CI must run on exactly main pushes, pull requests and manual dispatch"
CI_JOB_RULE = "CI must contain its documented single job"
SETUP_TRIGGER_RULE = "Copilot setup must run on manual dispatch only"
SETUP_JOB_RULE = "Copilot setup must contain its documented single job"
FILE_RULE = "workflow file outside the generated pair or infra-only conformance.yml"
UNPARSEABLE = "not a parseable UTF-8 JSON-syntax document"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load("shape_generator", HERE / "generate.py")
checker = load("shape_checker", HERE / "templates/check_repository.py")

# Job-level keys named by #50 and S3, with an innocuous value each; the value is never the
# reason for refusal (no `${{`, no token, no unlisted action) unless noted.
REFUSED_JOB_KEYS = {
    "container": {"image": "ghcr.io/octo/evil"},
    "services": {"db": {"image": "postgres:17"}},
    "snapshot": {"image-name": "ubuntu-custom"},
    "environment": "production",
    "strategy": {"matrix": {"node": ["24"]}},
    "outputs": {"value": "1"},
    "defaults": {"run": {"shell": "bash"}},
    "needs": ["other"],
    "continue-on-error": True,
    "if": "true",  # the condition rule fires first through validate_workflow
    "uses": f"octo/x/.github/workflows/y.yml@{SHA}",  # the action rule fires first
    "with": {"ref": "main"},
    "secrets": "inherit",  # the tripwire fires first
    "permissions": {"contents": "read"},  # not emitted at job level, so refused even read-only
    "concurrency": {"group": "x"},
    "id": "ci",
    "<<": {"runs-on": "ubuntu-24.04"},
    "Name": "CI",
    "RUNS-ON": "ubuntu-24.04",
    "steps ": [],
    " env": {},
    "na\u00a0me": "CI",
    "steps\u200b": [],
    "": "x",
}
REFUSED_STEP_KEYS = {
    "id": "checkout",
    "shell": "bash",
    "working-directory": "app",
    "timeout-minutes": 5,
    "continue-on-error": True,
    "if": "true",  # the condition rule fires first through validate_workflow
    "<<": {"run": "true"},
    "Run": "true",
    "RUN": "true",
    "run ": "true",
    "ru\u00a0n": "true",
    "": "x",
}
REFUSED_TOP_KEYS = {
    "env": {"NPM_CONFIG_LOGLEVEL": "silent"},
    "defaults": {"run": {"shell": "bash"}},
    "run-name": "CI run",
    "<<": {"name": "CI"},
    "Name": "CI",
    "jobs ": {},
    "na\u00a0me": "CI",
    "": "x",
}


def workflow(repo="web", setup=False):
    return json.loads(generator.workflow(repo, setup=setup))


def job_of(document):
    return next(iter(document["jobs"].values()))


def encoded(document):
    return json.dumps(document).encode()


def validate(document, name=CI):
    checker.validate_workflow(name, encoded(document))


def tripwire_hits(document):
    return any(checker.WORKFLOW_SECRET_ACCESS.search(text) for text in checker.workflow_strings(document))


def complete_repository(repo="web"):
    files = {name: content.encode("utf-8") for name, content in generator.artifacts(repo).items()}
    files["migration-source.json"] = b"{}\n"
    return files


class KeyAllowlistTests(unittest.TestCase):
    def test_allowlists_equal_the_keys_the_generator_emits(self):
        top, job_keys, step_keys = set(), set(), set()
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                document = workflow(repo, setup)
                top.update(document)
                for job in document["jobs"].values():
                    job_keys.update(job)
                    for step in job["steps"]:
                        step_keys.update(step)
                name = SETUP if setup else CI
                with self.subTest(repo=repo, name=name):
                    checker.validate_workflow(name, generator.workflow(repo, setup=setup).encode())
                    checker.validate_shape(document)
        self.assertEqual(checker.WORKFLOW_KEYS, top)
        self.assertEqual(checker.JOB_KEYS, job_keys)
        self.assertEqual(checker.STEP_KEYS, step_keys)
        self.assertEqual({"name", "on", "permissions", "concurrency", "jobs"}, checker.WORKFLOW_KEYS)
        self.assertEqual({"name", "runs-on", "timeout-minutes", "env", "steps"}, checker.JOB_KEYS)
        self.assertEqual({"name", "uses", "with", "run", "env"}, checker.STEP_KEYS)
        # Nothing in the three lists is a condition, a container, a reusable workflow or a credential field.
        for refused in ("if", "container", "services", "snapshot", "environment", "strategy", "outputs", "defaults",
                        "needs", "continue-on-error", "secrets", "permissions", "concurrency", "id", "shell",
                        "working-directory"):
            self.assertNotIn(refused, checker.JOB_KEYS | checker.STEP_KEYS)
        self.assertNotIn("env", checker.WORKFLOW_KEYS)

    def test_every_listed_job_level_key_is_refused_at_job_placement_for_every_profile(self):
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                for key, value in REFUSED_JOB_KEYS.items():
                    with self.subTest(repo=repo, setup=setup, key=key):
                        document = workflow(repo, setup)
                        job_of(document)[key] = value
                        # The allowlist alone refuses the key, whatever earlier rule also applies.
                        with self.assertRaisesRegex(ValueError, "job-level key outside the generated job keys"):
                            checker.validate_shape(document)
                        with self.assertRaises(ValueError):
                            validate(document, SETUP if setup else CI)
                        if key not in ("if", "uses", "secrets"):
                            self.assertFalse(tripwire_hits(document))
                            with self.assertRaisesRegex(ValueError, "job-level key outside the generated job keys"):
                                validate(document, SETUP if setup else CI)
        # A second job with only refused keys, and a job made entirely of allowed keys plus one refused key.
        document = workflow()
        document["jobs"]["other"] = {"runs-on": "ubuntu-24.04", "needs": "ci", "steps": [{"run": "true"}]}
        with self.assertRaisesRegex(ValueError, "job-level key"):
            validate(document)

    def test_container_with_an_attacker_image_is_refused_by_the_key_rule_alone(self):
        # S3: the generated JavaScript actions would run inside this image via docker exec carrying
        # INPUT_TOKEN; no `${{`, `if`, unlisted action or input appears, so only the key rule can refuse it.
        containers = (
            {"image": "ghcr.io/octo/evil"},
            "ghcr.io/octo/evil:latest",
            {"image": "ghcr.io/octo/evil", "options": "--privileged"},
            {"image": "ghcr.io/octo/evil", "volumes": ["/:/host"]},
            {"image": "ghcr.io/octo/evil", "credentials": {"username": "octo", "password": "hunter2"}},
            {"image": "ghcr.io/octo/evil", "env": {"LD_PRELOAD": "/evil.so"}, "ports": [80]},
            {"image": "node:24", "options": "--user root"},
        )
        for repo in generator.PROFILES["repositories"]:
            for container in containers:
                with self.subTest(repo=repo, container=container):
                    document = workflow(repo)
                    document["jobs"]["ci"]["container"] = container
                    self.assertFalse(tripwire_hits(document))
                    with self.assertRaisesRegex(ValueError, "^job-level key outside the generated job keys "
                                                            "name, runs-on, timeout-minutes, env, steps$"):
                        validate(document)
        # The same image through `services` or `snapshot` is refused by the same rule.
        for key, value in (("services", {"evil": {"image": "ghcr.io/octo/evil"}}),
                           ("snapshot", {"image-name": "ghcr.io/octo/evil"})):
            document = workflow()
            document["jobs"]["ci"][key] = value
            with self.assertRaisesRegex(ValueError, "job-level key"):
                validate(document)

    def test_step_level_keys_outside_the_generated_set_are_refused_at_every_step(self):
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                document = workflow(repo, setup)
                for index in range(len(job_of(document)["steps"])):
                    for key, value in REFUSED_STEP_KEYS.items():
                        with self.subTest(repo=repo, setup=setup, index=index, key=key):
                            planted = workflow(repo, setup)
                            job_of(planted)["steps"][index][key] = value
                            with self.assertRaisesRegex(ValueError, "step-level key outside the generated step keys"):
                                checker.validate_shape(planted)
                            with self.assertRaises(ValueError):
                                validate(planted, SETUP if setup else CI)
                            if key != "if":
                                self.assertFalse(tripwire_hits(planted))
                                with self.assertRaisesRegex(ValueError, "^step-level key outside the generated "
                                                                        "step keys name, uses, with, run, env$"):
                                    validate(planted, SETUP if setup else CI)
        # An appended step made only of refused keys, and a step that is not a mapping.
        document = workflow()
        document["jobs"]["ci"]["steps"].append({"id": "x", "shell": "bash"})
        with self.assertRaisesRegex(ValueError, "step-level key"):
            validate(document)
        for step in ("run: true", ["run"], 1, None, True):
            with self.subTest(step=step):
                document = workflow()
                document["jobs"]["ci"]["steps"].append(step)
                with self.assertRaisesRegex(ValueError, "steps must be a list of step mappings"):
                    validate(document)

    def test_top_level_keys_outside_the_generated_set_are_refused(self):
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                for key, value in REFUSED_TOP_KEYS.items():
                    with self.subTest(repo=repo, setup=setup, key=key):
                        document = workflow(repo, setup)
                        document[key] = value
                        self.assertFalse(tripwire_hits(document))
                        with self.assertRaisesRegex(ValueError, "^top-level key outside the generated workflow keys "
                                                                "name, on, permissions, concurrency, jobs$"):
                            validate(document, SETUP if setup else CI)
        # A workflow-level env with a token is still reported by the tripwire first.
        document = workflow()
        document["env"] = {"NPM_TOKEN": "${{ github.token }}"}
        with self.assertRaisesRegex(ValueError, "secrets"):
            validate(document)

    def test_malformed_structure_fails_closed_with_a_rule_instead_of_a_traceback(self):
        for jobs in ([], [{"runs-on": "ubuntu-24.04"}], {}, "ci", 1, None, True):
            with self.subTest(jobs=jobs):
                document = workflow()
                document["jobs"] = jobs
                with self.assertRaisesRegex(ValueError, "jobs must be a mapping of job ids with at least one job"):
                    validate(document)
        document = workflow()
        del document["jobs"]
        with self.assertRaisesRegex(ValueError, "jobs must be a mapping of job ids"):
            validate(document)
        for job in ("ci", 1, None, True, [], [{"runs-on": "ubuntu-24.04"}], ["steps"]):
            with self.subTest(job=job):
                document = workflow()
                document["jobs"]["ci"] = job
                with self.assertRaisesRegex(ValueError, "^job must be a mapping$"):
                    validate(document)
                document = workflow()
                document["jobs"]["other"] = job
                with self.assertRaisesRegex(ValueError, "^job must be a mapping$"):
                    validate(document)
        for steps in ([], {}, {"run": "true"}, "run: true", 1, None, True, [1], [None], [[]], ["run"],
                      [{"run": "true"}, "x"]):
            with self.subTest(steps=steps):
                document = workflow()
                document["jobs"]["ci"]["steps"] = steps
                with self.assertRaisesRegex(ValueError, "steps must be a list of step mappings with at least one"):
                    validate(document)
        document = workflow()
        del document["jobs"]["ci"]["steps"]
        with self.assertRaisesRegex(ValueError, "steps must be a list of step mappings"):
            validate(document)
        # Every failure above is a Refused, never a TypeError or AttributeError.
        for document in (b"[]", b'"ci"', b"null", encoded({**workflow(), "jobs": []}),
                         encoded({**workflow(), "jobs": {"ci": "x"}})):
            with self.assertRaises(checker.Refused):
                checker.validate_workflow(CI, document)

    def test_runner_and_credential_rules_still_apply_behind_the_key_allowlist(self):
        for runs_on in ("self-hosted", ["self-hosted", "linux"], "ubuntu-latest", "windows-2025",
                        {"group": "big"}, None):
            with self.subTest(runs_on=runs_on):
                document = workflow()
                if runs_on is None:
                    del document["jobs"]["ci"]["runs-on"]
                else:
                    document["jobs"]["ci"]["runs-on"] = runs_on
                self.assertEqual(set(), set(document["jobs"]["ci"]) - checker.JOB_KEYS)
                with self.assertRaisesRegex(ValueError, "only the standard hosted Ubuntu runner"):
                    validate(document)
        # A job-level `permissions` is refused by the allowlist even when read-only; were JOB_KEYS ever
        # widened to admit it by mistake, the credential tripwire behind the allowlist still refuses
        # anything but read-only.
        for permissions in ({"contents": "read"}, {"contents": "write"}, {"id-token": "write"}, "write-all", {}):
            with self.subTest(permissions=permissions):
                document = workflow()
                document["jobs"]["ci"]["permissions"] = permissions
                with self.assertRaisesRegex(ValueError, "job-level key"):
                    validate(document)
                with mock.patch.object(checker, "JOB_KEYS", checker.JOB_KEYS | {"permissions"}):
                    if permissions == {"contents": "read"}:
                        validate(document)
                    else:
                        with self.assertRaisesRegex(ValueError, "writable job credentials are not permitted"):
                            validate(document)
        # The CI job name and the single setup job stay required for an allowlisted shape.
        document = workflow()
        document["jobs"]["ci"]["name"] = "Checks"
        with self.assertRaisesRegex(ValueError, "native CI job name"):
            validate(document)
        document = workflow(setup=True)
        document["jobs"]["ci"] = document["jobs"]["copilot-setup-steps"]
        with self.assertRaisesRegex(ValueError, "documented single job"):
            validate(document, SETUP)

    def test_rule_order_reports_secrets_and_conditions_before_the_key_rule(self):
        # A token anywhere is the first reason named, so the message points at the secret; a
        # condition at a refused placement is named as a condition; both are still refused as keys.
        document = workflow()
        document["jobs"]["ci"]["container"] = {"image": "x", "credentials": {"password": "${{ secrets.P }}"}}
        with self.assertRaisesRegex(ValueError, "secrets"):
            validate(document)
        document = workflow()
        document["jobs"]["ci"]["services"] = {"db": {"env": {"PW": "${{ github.token }}"}}}
        with self.assertRaisesRegex(ValueError, "secrets"):
            validate(document)
        document = workflow()
        document["jobs"]["ci"]["if"] = "true"
        document["jobs"]["ci"]["container"] = {"image": "x"}
        with self.assertRaisesRegex(ValueError, "conditions are not part of the generated workflows"):
            validate(document)
        with self.assertRaisesRegex(ValueError, "job-level key"):
            checker.validate_shape(document)
        document = workflow()
        document["jobs"]["ci"]["steps"][-1]["if"] = "always()"
        with self.assertRaisesRegex(ValueError, "conditions"):
            validate(document)
        with self.assertRaisesRegex(ValueError, "step-level key"):
            checker.validate_shape(document)
        # An unlisted action in an otherwise refused step shape is named as an action first.
        document = workflow()
        document["jobs"]["ci"]["steps"].append({"uses": f"actions/github-script@{SHA}", "id": "s"})
        with self.assertRaisesRegex(ValueError, "immutable and one of the generated GitHub-owned actions"):
            validate(document)


class FileRuleTests(unittest.TestCase):
    """C3 of PR #51: each generated workflow file is bound to its own trigger set and single job."""

    def assert_only_a_file_rule_refuses(self, document):
        # Every rule before the per-file rules accepts the document, so the per-file rule alone
        # is the reason the planted drift is refused.
        self.assertFalse(tripwire_hits(document))
        checker.validate_expressions(document)
        checker.validate_mappings(document)
        checker.validate_shape(document)
        self.assertEqual(set(), set(document.get("on", {})) - {"push", "pull_request", "workflow_dispatch"})

    def test_generated_workflows_carry_exactly_the_sets_the_checker_binds(self):
        for repo in generator.PROFILES["repositories"]:
            with self.subTest(repo=repo):
                ci, setup = workflow(repo), workflow(repo, setup=True)
                self.assertEqual({"push", "pull_request", "workflow_dispatch"}, set(ci["on"]))
                self.assertEqual({"ci"}, set(ci["jobs"]))
                self.assertEqual("CI", ci["jobs"]["ci"]["name"])
                self.assertEqual({"workflow_dispatch"}, set(setup["on"]))
                self.assertEqual({"copilot-setup-steps"}, set(setup["jobs"]))
                validate(ci, CI)
                validate(setup, SETUP)
                names = sorted(name for name in generator.artifacts(repo) if name.startswith(".github/workflows/"))
                self.assertEqual([CI, ".github/workflows/conformance.yml", SETUP] if repo == "infra" else [CI, SETUP], names)

    def test_ci_with_a_job_set_other_than_ci_is_refused_for_every_profile(self):
        plain = {"name": "Extra", "runs-on": "ubuntu-24.04", "timeout-minutes": 10,
                 "steps": [{"name": "Run", "run": "true"}]}
        for repo in generator.PROFILES["repositories"]:
            document = workflow(repo)
            generated = json.loads(json.dumps(document["jobs"]["ci"]))
            for label, jobs in (("extra plain job", {"ci": generated, "other": plain}),
                                ("second copy of the generated job", {"ci": generated, "ci2": generated}),
                                ("renamed job id", {"build": generated}),
                                ("upper-case job id", {"CI": generated}),
                                ("padded job id", {"ci ": generated}),
                                ("zero-width job id", {"ci\u200b": generated}),
                                ("extra job before ci", {"other": plain, "ci": generated})):
                with self.subTest(repo=repo, label=label):
                    document = workflow(repo)
                    document["jobs"] = jobs
                    self.assert_only_a_file_rule_refuses(document)
                    with self.assertRaisesRegex(ValueError, f"^{CI_JOB_RULE}$"):
                        validate(document)
        # The job set is checked before the job name: a second job hides nothing behind a renamed `ci`.
        document = workflow()
        document["jobs"]["ci"]["name"] = "Checks"
        document["jobs"]["other"] = plain
        with self.assertRaisesRegex(ValueError, f"^{CI_JOB_RULE}$"):
            validate(document)
        del document["jobs"]["other"]
        with self.assertRaisesRegex(ValueError, "^Keep the required native CI job name stable$"):
            validate(document)
        # The setup document saved under the CI name fails the CI trigger set first, then the job set.
        document = workflow(setup=True)
        with self.assertRaisesRegex(ValueError, f"^{CI_TRIGGER_RULE}$"):
            validate(document, CI)
        document["on"] = workflow()["on"]
        with self.assertRaisesRegex(ValueError, f"^{CI_JOB_RULE}$"):
            validate(document, CI)

    def test_ci_trigger_set_must_be_exactly_the_generated_one(self):
        main = {"branches": ["main"]}
        for repo in generator.PROFILES["repositories"]:
            for events, rule in (({"push": main, "pull_request": main}, CI_TRIGGER_RULE),
                                 ({"workflow_dispatch": {}, "push": main}, CI_TRIGGER_RULE),
                                 ({"workflow_dispatch": {}, "pull_request": main}, CI_TRIGGER_RULE),
                                 ({"workflow_dispatch": {}}, CI_TRIGGER_RULE),
                                 ({"push": main}, CI_TRIGGER_RULE),
                                 ({}, CI_TRIGGER_RULE),
                                 (None, CI_TRIGGER_RULE),
                                 ({"push": main, "pull_request": main, "workflow_dispatch": {}, "pull_request_target": main},
                                  "unreviewed workflow trigger"),
                                 ({"push": main, "pull_request": main, "workflow_dispatch": {}, "schedule": [{"cron": "0 0 * * *"}]},
                                  "unreviewed workflow trigger"),
                                 ({"push": main, "pull_request": main, "workflow_dispatch": {}, "workflow_call": {}},
                                  "unreviewed workflow trigger"),
                                 ({"Push": main, "pull_request": main, "workflow_dispatch": {}}, "unreviewed workflow trigger"),
                                 ({"push ": main, "pull_request": main, "workflow_dispatch": {}}, "unreviewed workflow trigger"),
                                 (["push", "pull_request", "workflow_dispatch"], "unreviewed workflow trigger"),
                                 ("push", "unreviewed workflow trigger"),
                                 (1, "unreviewed workflow trigger")):
                with self.subTest(repo=repo, events=events):
                    document = workflow(repo)
                    if events is None:
                        del document["on"]
                    else:
                        document["on"] = events
                    if rule == CI_TRIGGER_RULE:
                        self.assert_only_a_file_rule_refuses(document)
                    with self.assertRaisesRegex(ValueError, f"^{rule}$"):
                        validate(document)

    def test_setup_workflow_must_keep_manual_dispatch_only_and_its_single_job(self):
        main = {"branches": ["main"]}
        for repo in generator.PROFILES["repositories"]:
            for events, rule in (({"workflow_dispatch": {}, "push": main}, SETUP_TRIGGER_RULE),
                                 ({"workflow_dispatch": {}, "pull_request": main}, SETUP_TRIGGER_RULE),
                                 ({"workflow_dispatch": {}, "push": main, "pull_request": main}, SETUP_TRIGGER_RULE),
                                 ({"workflow_dispatch": {}, "push": {}}, SETUP_TRIGGER_RULE),
                                 ({"push": main}, SETUP_TRIGGER_RULE),
                                 ({"pull_request": main}, SETUP_TRIGGER_RULE),
                                 ({}, SETUP_TRIGGER_RULE),
                                 (None, SETUP_TRIGGER_RULE),
                                 ({"workflow_dispatch": {}, "pull_request_target": main}, "unreviewed workflow trigger"),
                                 ({"workflow_dispatch": {}, "schedule": [{"cron": "0 0 * * *"}]}, "unreviewed workflow trigger"),
                                 ({"Workflow_Dispatch": {}}, "unreviewed workflow trigger"),
                                 (["workflow_dispatch"], "unreviewed workflow trigger"),
                                 ("workflow_dispatch", "unreviewed workflow trigger")):
                with self.subTest(repo=repo, events=events):
                    document = workflow(repo, setup=True)
                    if events is None:
                        del document["on"]
                    else:
                        document["on"] = events
                    if rule == SETUP_TRIGGER_RULE:
                        self.assert_only_a_file_rule_refuses(document)
                    with self.assertRaisesRegex(ValueError, f"^{rule}$"):
                        validate(document, SETUP)
            generated = workflow(repo, setup=True)["jobs"]["copilot-setup-steps"]
            plain = {"runs-on": "ubuntu-24.04", "steps": [{"run": "true"}]}
            for label, jobs in (("extra plain job", {"copilot-setup-steps": generated, "other": plain}),
                                ("renamed job id", {"setup": generated}),
                                ("upper-case job id", {"Copilot-Setup-Steps": generated}),
                                ("ci job copied in", {"copilot-setup-steps": generated, "ci": workflow(repo)["jobs"]["ci"]})):
                with self.subTest(repo=repo, label=label):
                    document = workflow(repo, setup=True)
                    document["jobs"] = jobs
                    self.assert_only_a_file_rule_refuses(document)
                    with self.assertRaisesRegex(ValueError, f"^{SETUP_JOB_RULE}$"):
                        validate(document, SETUP)
        # The CI document saved under the setup name fails the setup trigger set first.
        with self.assertRaisesRegex(ValueError, f"^{SETUP_TRIGGER_RULE}$"):
            validate(workflow(), SETUP)

    def test_any_third_workflow_file_is_refused(self):
        names = (".github/workflows/extra.yml", ".github/workflows/release.yml", ".github/workflows/deploy.json",
                 ".github/workflows/ci.yaml", ".github/workflows/CI.yml", ".github/workflows/Ci.yml",
                 ".github/workflows/ci.yml.yml", ".github/workflows/ci.yml ", ".github/workflows/ ci.yml",
                 ".github/workflows/copilot-setup-steps.yaml", ".github/workflows/Copilot-Setup-Steps.yml",
                 ".github/workflows/copilot_setup_steps.yml", ".github/workflows/sub/ci.yml",
                 ".github/workflows/sub/copilot-setup-steps.yml", ".github/workflows/./ci.yml",
                 ".github/workflows//ci.yml", ".github/workflows/ci\u200b.yml")
        for name in names:
            for document in (workflow(), workflow(setup=True)):
                with self.subTest(name=name, jobs=list(document["jobs"])):
                    self.assert_only_a_file_rule_refuses(document)
                    with self.assertRaisesRegex(ValueError, f"^{FILE_RULE}$"):
                        validate(document, name)
                    files = complete_repository()
                    files[name] = encoded(document)
                    problems = checker.check(files)
                    self.assertEqual([f"Invalid or unsafe workflow: {name if name.isprintable() else '[non-printable path]'}: "
                                      f"{FILE_RULE}"], problems)
        # The earlier rules still come first in a third file: a token is named before the file rule.
        document = workflow(setup=True)
        document["jobs"]["copilot-setup-steps"]["steps"][-1]["run"] += "\necho ${{ github.token }}"
        with self.assertRaisesRegex(ValueError, "secrets"):
            validate(document, ".github/workflows/extra.yml")
        document = workflow(setup=True)
        document["jobs"]["copilot-setup-steps"]["container"] = {"image": "ghcr.io/octo/evil"}
        with self.assertRaisesRegex(ValueError, "job-level key"):
            validate(document, ".github/workflows/extra.yml")

    def test_duplicate_job_ids_and_events_are_refused_before_any_set_is_computed(self):
        # JSON syntax has no anchors or merge keys, so the only way to name `ci` twice is a duplicate
        # key; rule 2 refuses it before a job or trigger set exists (a parser keeping the last value
        # would otherwise see one job), and a null `on` is not a mapping.
        for setup in (False, True):
            name = SETUP if setup else CI
            document = workflow(setup=setup)
            job_id = "copilot-setup-steps" if setup else "ci"
            text = json.dumps(document)
            job = json.dumps(document["jobs"][job_id])
            twice = text.replace('"jobs": {', f'"jobs": {{"{job_id}": {job}, ', 1)
            self.assertEqual(2, twice.count(f'"{job_id}": {{'))
            with self.assertRaisesRegex(ValueError, "^Duplicate JSON key$"):
                checker.validate_workflow(name, twice.encode())
            event = "workflow_dispatch"
            twice = text.replace('"on": {', f'"on": {{"{event}": {{}}, ', 1)
            with self.assertRaisesRegex(ValueError, "^Duplicate JSON key$"):
                checker.validate_workflow(name, twice.encode())
            document["on"] = None
            with self.assertRaisesRegex(ValueError, "^unreviewed workflow trigger$"):
                validate(document, name)

    def test_trigger_filters_and_dispatch_inputs_stay_outside_the_set_rules(self):
        # Disclosed residual of #54: the per-file rules bind the event names, not the filters
        # under them; a branch, path or type filter or a dispatch input is still walked by the
        # expression rule and the tripwire, so no token can hide there.
        document = workflow()
        document["on"]["push"]["branches"] = ["*"]
        document["on"]["pull_request"] = {"types": ["opened"], "paths-ignore": ["docs/**"]}
        document["on"]["workflow_dispatch"] = {"inputs": {"ref": {"default": "main", "type": "string"}}}
        validate(document)
        document["on"]["workflow_dispatch"]["inputs"]["ref"]["default"] = "${{ github.token }}"
        with self.assertRaisesRegex(ValueError, "secrets"):
            validate(document)
        document["on"]["workflow_dispatch"]["inputs"]["ref"]["default"] = "github\n.token"
        with self.assertRaisesRegex(ValueError, "secrets"):
            validate(document)
        document["on"]["workflow_dispatch"]["inputs"]["ref"]["default"] = "${{ github.ref }}"
        with self.assertRaisesRegex(ValueError, "unreviewed workflow expression"):
            validate(document)


class RuleMessageTests(unittest.TestCase):
    def test_check_appends_the_refusing_rule_and_never_file_content(self):
        files = complete_repository()
        self.assertEqual([], checker.check(files))
        plants = []
        document = workflow()
        document["jobs"]["ci"]["container"] = {"image": MARKER}
        plants.append((document, JOB_RULE))
        document = workflow()
        document["jobs"]["ci"][MARKER] = MARKER
        plants.append((document, JOB_RULE))
        document = workflow()
        document["jobs"]["ci"]["steps"][0][MARKER] = MARKER
        plants.append((document, STEP_RULE))
        document = workflow()
        document[MARKER] = MARKER
        plants.append((document, TOP_RULE))
        document = workflow()
        document["jobs"] = {MARKER: MARKER}
        plants.append((document, "job must be a mapping"))
        document = workflow()
        document["jobs"]["ci"]["steps"] = [MARKER]
        plants.append((document, "steps must be a list of step mappings with at least one step"))
        document = workflow()
        document["jobs"]["ci"]["steps"][-1]["if"] = MARKER
        plants.append((document, "conditions are not part of the generated workflows"))
        document = workflow()
        document["jobs"]["ci"]["steps"][-1]["run"] += f"\necho github.token {MARKER}"
        plants.append((document, "public candidate jobs must not receive secrets"))
        document = workflow()
        document["jobs"]["ci"]["steps"][-1]["run"] += f"\necho ${{{{ github.{MARKER} }}}}"
        plants.append((document, "unreviewed workflow expression; public jobs must not receive secrets"))
        document = workflow()
        document["jobs"]["ci"]["steps"].append({"uses": f"octo/{MARKER}@{SHA}"})
        plants.append((document, "action must be immutable and one of the generated GitHub-owned actions"))
        document = workflow()
        document["jobs"]["ci"]["steps"][0]["with"][MARKER] = MARKER
        plants.append((document, "unreviewed action input; only the generated inputs are accepted"))
        document = workflow()
        document["jobs"]["ci"]["steps"][0]["with"]["persist-credentials"] = True
        plants.append((document, "checkout must not retain credentials"))
        document = workflow()
        document["on"][MARKER] = {}
        plants.append((document, "unreviewed workflow trigger"))
        document = workflow()
        document["jobs"]["ci"]["runs-on"] = MARKER
        plants.append((document, "only the standard hosted Ubuntu runner is configured"))
        document = workflow()
        document["permissions"] = {"contents": MARKER}
        plants.append((document, "expected read-only workflow token"))
        document = workflow()
        document["jobs"]["ci"]["name"] = MARKER
        plants.append((document, "Keep the required native CI job name stable"))
        document = workflow()
        del document["on"]["pull_request"]
        plants.append((document, CI_TRIGGER_RULE))
        document = workflow()
        del document["on"]["workflow_dispatch"]
        plants.append((document, CI_TRIGGER_RULE))
        document = workflow()
        document["jobs"][MARKER] = {"name": MARKER, "runs-on": "ubuntu-24.04", "steps": [{"run": MARKER}]}
        plants.append((document, CI_JOB_RULE))
        document = workflow()
        document["jobs"]["ci"]["steps"][0]["name"] = MARKER
        document["jobs"]["ci"]["steps"][0]["uses"] = f"actions/checkout@{SHA}"
        plants.append((document, PIN_RULE))
        for document, rule in plants:
            with self.subTest(rule=rule):
                files[CI] = encoded(document)
                problems = checker.check(files)
                self.assertEqual([f"Invalid or unsafe workflow: {CI}: {rule}"], problems)
                self.assertNotIn(MARKER, "\n".join(problems))
                self.assertTrue(all(line.isascii() and line.isprintable() for line in problems))
        # Raw documents that are not rules: the same one static line, still without content.
        for raw, rule in ((b'["' + MARKER.encode() + b'"]', "workflow document must be one JSON object"),
                          (b'"' + MARKER.encode() + b'"', "workflow document must be one JSON object"),
                          (b"null", "workflow document must be one JSON object"),
                          (b"\xef\xbb\xbf" + encoded(workflow()), "UTF-8 byte order mark before the JSON document"),
                          (b'{"name": "' + MARKER.encode() + b'", "name": 1}', "Duplicate JSON key"),
                          (b"", UNPARSEABLE), (b"{" + MARKER.encode(), UNPARSEABLE),
                          (b"\xff\xfe" + MARKER.encode(), UNPARSEABLE), (b"[" * 100000, UNPARSEABLE)):
            with self.subTest(rule=rule):
                files[CI] = raw
                problems = [line for line in checker.check(files) if line.startswith("Invalid or unsafe workflow")]
                self.assertEqual([f"Invalid or unsafe workflow: {CI}: {rule}"], problems)
                self.assertNotIn(MARKER, "\n".join(problems))
        # The setup workflow is reported under its own name with the same shape.
        files = complete_repository()
        document = workflow(setup=True)
        document["jobs"]["copilot-setup-steps"]["services"] = {MARKER: {"image": MARKER}}
        files[SETUP] = encoded(document)
        self.assertEqual([f"Invalid or unsafe workflow: {SETUP}: {JOB_RULE}"], checker.check(files))
        for events, rule in (({"workflow_dispatch": {}, "push": {"branches": [MARKER]}}, SETUP_TRIGGER_RULE),
                             ({"workflow_dispatch": {}, "pull_request": {"branches": [MARKER]}}, SETUP_TRIGGER_RULE),
                             ({MARKER: {}}, "unreviewed workflow trigger")):
            document = workflow(setup=True)
            document["on"] = events
            files[SETUP] = encoded(document)
            self.assertEqual([f"Invalid or unsafe workflow: {SETUP}: {rule}"], checker.check(files))
        document = workflow(setup=True)
        document["jobs"][MARKER] = {"runs-on": "ubuntu-24.04", "steps": [{"run": MARKER}]}
        files[SETUP] = encoded(document)
        self.assertEqual([f"Invalid or unsafe workflow: {SETUP}: {SETUP_JOB_RULE}"], checker.check(files))
        # A third workflow file is named by its path (as every problem line is) and refused as a
        # whole; the document's content is still not echoed.
        files = complete_repository()
        document = workflow(setup=True)
        document["jobs"]["copilot-setup-steps"]["steps"][-1]["name"] = MARKER
        files[".github/workflows/extra.yml"] = encoded(document)
        self.assertEqual([f"Invalid or unsafe workflow: .github/workflows/extra.yml: {FILE_RULE}"], checker.check(files))
        self.assertNotIn(MARKER, "\n".join(checker.check(files)))

    def test_non_printable_workflow_path_is_not_echoed(self):
        name = ".github/workflows/ci\x1b[31m.yml"
        problems = checker.check({name: b"[]"})
        self.assertIn("Invalid or unsafe workflow: [non-printable path]: workflow document must be one JSON object",
                      problems)
        self.assertNotIn("\x1b", "\n".join(problems))

    def test_every_refusal_message_is_static_text(self):
        source = (HERE / "templates/check_repository.py").read_text(encoding="utf-8")
        messages = re.findall(r'raise Refused\("([^"\\{}]*)"\)', source)
        self.assertEqual(source.count("raise Refused("), len(messages))
        self.assertEqual(32, len(messages))
        readme = (HERE / "README.md").read_text(encoding="utf-8")
        for message in messages:
            with self.subTest(message=message):
                self.assertTrue(message.isascii() and message.isprintable())
                self.assertEqual(message, message.strip())
                self.assertLessEqual(len(message), 110)
                # The rule list in governance/README.md carries every rule text verbatim.
                self.assertIn(f"`{message}`", readme)
        self.assertEqual(len(set(messages)), len(messages))
        self.assertNotIn("raise ValueError(", source.split("def json_document")[1].split("def check(")[0])
        # check() prints rule text only through Refused; the other failure classes get one static line.
        self.assertIn("except Refused as error:", source)
        self.assertIn("Invalid or unsafe workflow: {safe_name}: {error}", source)
        self.assertIn("Invalid or unsafe workflow: {safe_name}: not a parseable UTF-8 JSON-syntax document", source)
        self.assertIn("Invalid JSON in {safe_name}: {error}", source)
        self.assertTrue(issubclass(checker.Refused, ValueError))

    def test_json_files_report_their_rule_and_a_top_level_array_stays_valid_json(self):
        files = complete_repository()
        bom = "Invalid JSON in data.json: UTF-8 byte order mark before the JSON document"
        duplicate = "Invalid JSON in data.json: Duplicate JSON key"
        for content, expected in ((b"\xef\xbb\xbf{}\n", [bom]),
                                  (b'{"a": 1, "a": 2}', [duplicate]),
                                  (b'{"a": {"b": 1, "b": 2}}', [duplicate]),
                                  (b"{", ["Invalid JSON in data.json"]),
                                  (b"", ["Invalid JSON in data.json"]),
                                  (b"[" * 100000, ["Invalid JSON in data.json"]),
                                  (b"\xff\xfe{\x00}\x00", ["Invalid UTF-8 in data.json", "Invalid JSON in data.json"]),
                                  (b"[1, 2]\n", []), (b'"text"\n', []), (b"null\n", []),
                                  (b'{"a": [1, {"b": 2}]}\n', [])):
            with self.subTest(content=content):
                files["data.json"] = content
                self.assertEqual(expected, checker.check(files))


class JsonDocumentTests(unittest.TestCase):
    def test_bom_before_valid_json_is_refused_for_every_generated_workflow(self):
        # json.loads(bytes) used to strip the BOM through encoding detection and the file passed check().
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                with self.subTest(repo=repo, setup=setup):
                    content = generator.workflow(repo, setup=setup).encode()
                    checker.json_document(content)
                    with self.assertRaisesRegex(ValueError, "UTF-8 byte order mark before the JSON document"):
                        checker.json_document(b"\xef\xbb\xbf" + content)
                    with self.assertRaisesRegex(ValueError, "UTF-8 byte order mark"):
                        checker.validate_workflow(SETUP if setup else CI, b"\xef\xbb\xbf" + content)
                    # What json.loads(bytes) alone would have accepted as the same document.
                    self.assertEqual(json.loads(content), json.loads(b"\xef\xbb\xbf" + content))
        files = complete_repository()
        files[CI] = b"\xef\xbb\xbf" + files[CI]
        self.assertEqual([f"Invalid or unsafe workflow: {CI}: UTF-8 byte order mark before the JSON document"],
                         checker.check(files))

    def test_bom_with_a_token_read_is_refused(self):
        document = workflow()
        document["jobs"]["ci"]["steps"][-1]["run"] += "\necho ${{ github.token }}"
        content = b"\xef\xbb\xbf" + encoded(document)
        with self.assertRaises(ValueError):
            checker.validate_workflow(CI, content)
        self.assertTrue(tripwire_hits(document))
        files = complete_repository()
        files[CI] = content
        self.assertEqual(1, len(checker.check(files)))
        self.assertTrue(checker.check(files)[0].startswith(f"Invalid or unsafe workflow: {CI}: "))

    def test_bom_after_a_leading_newline_and_utf16_or_utf32_documents_are_refused(self):
        content = encoded(workflow())
        for raw in (b"\n\xef\xbb\xbf" + content, b" \xef\xbb\xbf" + content, b"\xef\xbb\xbf\xef\xbb\xbf" + content,
                    content.decode().encode("utf-16"), content.decode().encode("utf-16-le"),
                    content.decode().encode("utf-16-be"), content.decode().encode("utf-32"),
                    b"\xff\xfe" + content, b"\xfe\xff" + content, b"\x00" + content, content + b"\x00"):
            with self.subTest(raw=raw[:8]):
                with self.assertRaises((ValueError, UnicodeDecodeError)):
                    checker.json_document(raw)
                with self.assertRaises((ValueError, UnicodeDecodeError)):
                    checker.validate_workflow(CI, raw)
                files = complete_repository()
                files[CI] = raw
                problems = [line for line in checker.check(files) if line.startswith("Invalid or unsafe workflow")]
                self.assertEqual(1, len(problems), problems)
        # json.loads(bytes) would have parsed the UTF-16 document as the same workflow.
        self.assertEqual(json.loads(content), json.loads(content.decode().encode("utf-16")))

    def test_non_object_documents_are_refused_with_the_normal_message(self):
        for raw in (b"[]", b"[1]", b'[{"name": "CI"}]', b'"x"', b"null", b"1", b"true", b"false", b"1.5",
                    b' \n[]\n', b"[" + encoded(workflow()) + b"]"):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, "^workflow document must be one JSON object$"):
                    checker.validate_workflow(CI, raw)
                with self.assertRaisesRegex(ValueError, "^workflow document must be one JSON object$"):
                    checker.validate_workflow(SETUP, raw)
                files = complete_repository()
                files[CI] = raw
                self.assertEqual([f"Invalid or unsafe workflow: {CI}: workflow document must be one JSON object"],
                                 checker.check(files))

    def test_empty_and_malformed_documents_fail_closed_with_one_static_line(self):
        for raw in (b"", b" ", b"\n", b"{", b"}", b"{}x", b"{} {}", b'{"name": }', b"{'name': 'CI'}",
                    b"name: CI\n", b"jobs:\n  ci: &a {}\n  other: *a\n", b"\xff", b"\xc3\x28", b"\xed\xa0\x80",
                    b"{}\xef\xbb\xbf", b"[" * 100000, b"{" + b'"a":{' * 100000):
            with self.subTest(raw=raw[:12]):
                with self.assertRaises((ValueError, UnicodeDecodeError, RecursionError)):
                    checker.validate_workflow(CI, raw)
                files = complete_repository()
                files[CI] = raw
                problems = [line for line in checker.check(files) if line.startswith("Invalid or unsafe workflow")]
                self.assertEqual([f"Invalid or unsafe workflow: {CI}: not a parseable UTF-8 JSON-syntax document"],
                                 problems)
        # An empty mapping is an object and fails a rule, not the parser; Python's json accepts the
        # non-standard NaN literal, which the object rule then refuses at the top level.
        with self.assertRaisesRegex(ValueError, "expected read-only workflow token"):
            checker.validate_workflow(CI, b"{}")
        with self.assertRaisesRegex(ValueError, "workflow document must be one JSON object"):
            checker.validate_workflow(CI, b"NaN")

    def test_deeply_nested_and_very_long_documents_fail_closed_or_pass_without_a_traceback(self):
        document = workflow()
        nested = {"a": "1"}
        for _ in range(3000):
            nested = {"a": nested}
        document["jobs"]["ci"]["env"] = nested
        files = complete_repository()
        files[CI] = encoded(document)
        problems = checker.check(files)
        self.assertEqual([f"Invalid or unsafe workflow: {CI}: not a parseable UTF-8 JSON-syntax document"], problems)
        # A long but shallow document is walked without error: it passes when it is otherwise generated.
        document = workflow()
        document["jobs"]["ci"]["steps"][-1]["run"] += "\n" + "echo ok\n" * 200000
        validate(document)
        document["jobs"]["ci"]["steps"].extend({"name": f"Step {i}", "run": "true"} for i in range(20000))
        validate(document)
        document["jobs"]["ci"]["steps"][-1]["timeout-minutes"] = 1
        with self.assertRaisesRegex(ValueError, "step-level key"):
            validate(document)

    def test_json_document_keeps_accepting_plain_utf8_documents(self):
        self.assertEqual({}, checker.json_document(b"{}"))
        self.assertEqual([1, 2], checker.json_document(b"[1, 2]"))
        text = '{"a": "caf\u00e9 \u2028 \U0001f600"}'
        self.assertEqual({"a": "caf\u00e9 \u2028 \U0001f600"}, checker.json_document(text.encode()))
        self.assertEqual({"a": {"b": [1, {"c": None}]}}, checker.json_document(b'\n {"a": {"b": [1, {"c": null}]}} \n'))
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            checker.json_document(b'{"a": 1, "a": 2}')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            checker.json_document(b'{"a": [{"b": 1, "b": 2}]}')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            checker.json_document(b'{"\\u0069f": 1, "if": 2}')
        for repo in generator.PROFILES["repositories"]:
            output = generator.artifacts(repo)
            for name in (".github/agent-policy.json", CI, SETUP, ".github/github-app.yml"):
                self.assertIsInstance(checker.json_document(output[name].encode()), dict)


if __name__ == "__main__":
    unittest.main()
