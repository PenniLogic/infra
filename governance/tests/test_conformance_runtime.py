"""Infra#24 runtime expansion: a single ephemeral token channel, isolated children and real gates.

All API responses and credentials here are synthetic. No hosted run or consumer main acceptance
is inferred from these tests.
"""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import conformance_support as support
from conformance import defects, github_api, registry, report, run


BASE = "e96eb757beeb02b0a802e7545ca781669e85deb8"
CONFORMANCE = ".github/workflows/conformance.yml"
TOKEN_EXPRESSION = "${{ github.token }}"
SYNTHETIC_TOKEN = "synthetic-short-lived-metadata-credential"
UV_INSTALL = (
    "printf 'uv==0.11.33 --hash=sha256:"
    "9542178978b0b6f16a7ae99e55aca039f493a1edb373a15d7993eab80a28615a\\n'"
    " | python -m pip install --quiet --only-binary :all: --require-hashes --no-deps -r /dev/stdin"
)


def document():
    return json.loads(support.generator.artifacts("infra")[CONFORMANCE])


def harness_step(value):
    return next(step for step in value["jobs"]["conformance"]["steps"] if step.get("name") == "Run conformance")


def authenticated_document():
    value = document()
    harness_step(value)["env"] = {"GH_TOKEN": TOKEN_EXPRESSION}
    return value


def rendered_checker(name):
    module = types.ModuleType("runtime_checker")
    module.__file__ = str(support.GOVERNANCE.parent / "scripts" / "check_repository.py")
    exec(compile(support.generator.checker(name), module.__file__, "exec"), module.__dict__)
    return module


def validate(value, profile="infra", path=CONFORMANCE):
    rendered_checker(profile).validate_workflow(path, json.dumps(value).encode())


def hostile_environment():
    return {
        **os.environ,
        "GITHUB_ACTIONS": "true", "GH_TOKEN": SYNTHETIC_TOKEN,
        "GITHUB_TOKEN": "synthetic-unapproved-fallback", "GH_HOST": "wrong.invalid",
        "GH_REPO": "wrong/repository", "GH_CONFIG_DIR": "wrong-config",
        "GH_ENTERPRISE_TOKEN": "synthetic-enterprise-credential", "GH_DEBUG": "api",
        "ACTIONS_RUNTIME_TOKEN": "synthetic-artifact-credential",
        "GITHUB_ENV": "wrong-env-file", "GITHUB_PATH": "wrong-path-file",
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "credential.helper",
        "GIT_CONFIG_VALUE_0": "wrong-helper", "GIT_CONFIG_PARAMETERS": "invalid injected config",
    }


class TokenChannelTests(unittest.TestCase):
    def test_exact_token_leaf_is_accepted_without_widening_the_global_allowlist(self):
        checker = rendered_checker("infra")
        self.assertNotIn(TOKEN_EXPRESSION, checker.WORKFLOW_EXPRESSIONS)
        validate(authenticated_document())

    def test_expression_cannot_move_to_another_path_or_profile(self):
        for profile in support.generator.PROFILES["repositories"]:
            for path in (".github/workflows/ci.yml", ".github/workflows/copilot-setup-steps.yml",
                         ".github/workflows/conformance.yaml", ".github/workflows/Conformance.yml",
                         ".github/workflows/sub/conformance.yml", CONFORMANCE):
                if profile == "infra" and path == CONFORMANCE:
                    continue
                with self.subTest(profile=profile, path=path), self.assertRaises(ValueError):
                    validate(authenticated_document(), profile, path)

    def test_all_nine_ci_and_setup_workflows_still_refuse_tokens_at_every_channel(self):
        for profile in support.generator.PROFILES["repositories"]:
            for setup in (False, True):
                path = ".github/workflows/copilot-setup-steps.yml" if setup else ".github/workflows/ci.yml"
                original = json.loads(support.generator.workflow(profile, setup=setup))
                for channel in ("top-env", "job-env", "step-env", "run", "input"):
                    value = copy.deepcopy(original)
                    job = next(iter(value["jobs"].values()))
                    if channel == "top-env":
                        value["env"] = {"GH_TOKEN": TOKEN_EXPRESSION}
                    elif channel == "job-env":
                        job["env"] = {"GH_TOKEN": TOKEN_EXPRESSION}
                    elif channel == "step-env":
                        job["steps"][-1]["env"] = {"GH_TOKEN": TOKEN_EXPRESSION}
                    elif channel == "run":
                        job["steps"][-1]["run"] += "\n" + TOKEN_EXPRESSION
                    else:
                        job["steps"][0]["with"]["token"] = TOKEN_EXPRESSION
                    with self.subTest(profile=profile, setup=setup, channel=channel), self.assertRaises(ValueError):
                        validate(value, profile, path)

    def test_wrong_env_name_value_or_extra_context_is_refused(self):
        for env in ({}, {"GITHUB_TOKEN": TOKEN_EXPRESSION}, {"gh_token": TOKEN_EXPRESSION},
                    {"GH_TOKEN": "synthetic-static-token"}, {"GH_TOKEN": None},
                    {"GH_TOKEN": TOKEN_EXPRESSION, "EXTRA": "context"},
                    {"GH_TOKEN": TOKEN_EXPRESSION + "suffix"},
                    {"GH_TOKEN": "prefix" + TOKEN_EXPRESSION},
                    {"GH_TOKEN": [TOKEN_EXPRESSION]}, {"GH_TOKEN": {"value": TOKEN_EXPRESSION}}):
            value = authenticated_document()
            harness_step(value)["env"] = env
            with self.subTest(env=env), self.assertRaises(ValueError):
                validate(value)

    def test_job_env_duplicate_harness_and_action_impostor_are_refused(self):
        for mutation in ("job-env", "extra-job", "duplicate", "other-env", "action", "no-run", "renamed"):
            value = authenticated_document()
            job = value["jobs"]["conformance"]
            step = harness_step(value)
            if mutation == "job-env":
                job["env"] = {"EXTRA": "context"}
            elif mutation == "extra-job":
                value["jobs"]["extra"] = copy.deepcopy(job)
            elif mutation == "duplicate":
                job["steps"].append(copy.deepcopy(step))
            elif mutation == "other-env":
                job["steps"][1]["env"] = {"EXTRA": "context"}
            elif mutation == "action":
                del step["run"]
                step["uses"] = job["steps"][0]["uses"]
                step["with"] = {"persist-credentials": False}
            elif mutation == "no-run":
                del step["run"]
            else:
                step["name"] = "Run conformance "
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate(value)

    def test_other_token_spellings_and_whole_contexts_stay_refused_in_the_allowed_leaf(self):
        for expression in ("${{github.token}}", "${{ github.token  }}", "${{ github\n.token }}",
                           "${{ github['token'] }}", "${{ github[format('to{0}', 'ken')] }}",
                           "${{ toJSON(github) }}", "${{ secrets.X }}", "${{ toJSON(secrets) }}",
                           "github.token", "secrets.X"):
            value = authenticated_document()
            harness_step(value)["env"] = {"GH_TOKEN": expression}
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                validate(value)

    def test_allowed_leaf_does_not_exempt_the_rest_of_the_workflow_from_secret_scanning(self):
        for location in ("run", "name", "cron", "key", "input"):
            value = authenticated_document()
            if location == "run":
                harness_step(value)["run"] += "\n" + TOKEN_EXPRESSION
            elif location == "name":
                harness_step(value)["name"] = TOKEN_EXPRESSION
            elif location == "cron":
                value["on"]["schedule"][0]["cron"] = TOKEN_EXPRESSION
            elif location == "key":
                harness_step(value)[TOKEN_EXPRESSION] = "context"
            else:
                value["jobs"]["conformance"]["steps"][0]["with"]["token"] = TOKEN_EXPRESSION
            with self.subTest(location=location), self.assertRaises(ValueError):
                validate(value)


class RuntimeRenderingTests(unittest.TestCase):
    def test_node_pin_and_nvmrc_are_canonical_and_infra_only(self):
        self.assertEqual("24.14.0", support.generator.PROFILES["repositories"]["infra"]["node"])
        self.assertEqual("24.14.0\n", support.generator.artifacts("infra")[".nvmrc"])
        for name in support.generator.PROFILES["repositories"]:
            with self.subTest(profile=name):
                self.assertEqual(name == "infra", ".nvmrc" in support.generator.artifacts(name))
                self.assertEqual(22 if name == "infra" else 20, len(support.generator.artifacts(name)))

    def test_node_and_verified_uv_install_precede_the_authenticated_three_toolchain_run(self):
        value = document()
        steps = value["jobs"]["conformance"]["steps"]
        self.assertEqual(["Checkout", "Python", "Node", "Install uv", "Run conformance", "Upload report",
                          "Fail on findings"], [step["name"] for step in steps])
        self.assertEqual({
            "name": "Node", "uses": "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
            "with": {"node-version-file": ".nvmrc"},
        }, steps[2])
        self.assertEqual({"name": "Install uv", "run": UV_INSTALL}, steps[3])
        self.assertEqual(UV_INSTALL, support.generator.PROFILES["repositories"]["ai-service"]["install"][0])
        self.assertIn("--github-client gh --exercise python,node,uv", harness_step(value)["run"])
        self.assertEqual({"GH_TOKEN": TOKEN_EXPRESSION}, harness_step(value)["env"])
        self.assertNotIn("env", value)
        self.assertNotIn("env", value["jobs"]["conformance"])
        self.assertEqual({"contents": "read"}, value["permissions"])
        self.assertNotIn("setup-java", json.dumps(value))
        self.assertNotIn("Android SDK", json.dumps(value))

    def test_infra_runtime_pin_cannot_be_omitted_or_replaced_with_an_expression(self):
        for node in (None, "${{ github.token }}", "24", "24.14.0\n"):
            profile = copy.deepcopy(support.generator.profile_for("infra"))
            profile["node"] = node
            with self.subTest(node=node), self.assertRaises(ValueError):
                support.generator.validate_profile("infra", profile)

    def test_all_sixteen_consumer_ci_and_setup_bytes_and_eight_profiles_are_unchanged(self):
        historical = registry.render_workflow_at(support.GOVERNANCE.parent, BASE, "infra")
        if historical is None:
            self.skipTest("accepted base not in shallow history; native workflow source binding not exercised")
        profiles = json.loads(support.git(support.GOVERNANCE.parent, "show",
                                         f"{BASE}:governance/repository-profiles.json"))
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            for relative in ("governance/generate.py", "governance/repository-profiles.json"):
                (root / Path(relative).name).write_text(
                    support.git(support.GOVERNANCE.parent, "show", f"{BASE}:{relative}"), encoding="utf-8",
                )
            old = run.generator_module.load(root / "generate.py", name="runtime_accepted_generator")
            for name in support.generator.PROFILES["repositories"]:
                if name == "infra":
                    continue
                with self.subTest(profile=name):
                    for setup in (False, True):
                        self.assertEqual(old.workflow(name, setup=setup), support.generator.workflow(name, setup=setup))
                    self.assertEqual(profiles["repositories"][name], support.generator.PROFILES["repositories"][name])
        self.assertEqual("python", registry.expected_language("infra", support.generator.profile_for("infra")))


class AuthenticatedMetadataTests(unittest.TestCase):
    def test_hosted_gh_client_propagates_only_its_ephemeral_token_to_bounded_explicit_gets(self):
        calls = []

        def spy(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, b'{"id": 1394135059}', SYNTHETIC_TOKEN.encode())

        client = github_api.choose_client("gh", run=spy, which=lambda name: "gh", environ=hostile_environment())
        self.assertEqual({"id": 1394135059}, client.get("/repos/PenniLogic/infra"))
        self.assertEqual(1, len(calls), "a workflow token must not probe the user endpoint or stored authentication")
        command, kwargs = calls[0]
        self.assertEqual(["gh", "api", "--hostname", "github.com", "-X", "GET", "/repos/PenniLogic/infra"], command)
        self.assertEqual(60, kwargs["timeout"])
        self.assertTrue(kwargs["capture_output"])
        self.assertFalse(kwargs["check"])
        self.assertNotIn(SYNTHETIC_TOKEN, " ".join(command))
        env = kwargs["env"]
        self.assertEqual(SYNTHETIC_TOKEN, env["GH_TOKEN"])
        self.assertEqual({"GH_TOKEN", "GH_CONFIG_DIR"},
                         {key for key in env if key.upper().startswith(("GH_", "GITHUB_", "ACTIONS_"))})
        self.assertEqual([], list(Path(env["GH_CONFIG_DIR"]).iterdir()))

    def test_missing_hosted_token_or_wrong_client_never_falls_back_to_stored_or_anonymous_auth(self):
        for mode in ("gh", "auto", "anonymous"):
            env = hostile_environment()
            del env["GH_TOKEN"]
            with self.subTest(mode=mode), self.assertRaises(github_api.ApiError):
                github_api.choose_client(mode, run=mock.Mock(side_effect=AssertionError("must not probe credentials")),
                                         which=lambda name: "gh", environ=env)
        for token in ("", " ", None):
            env = {**hostile_environment(), "GH_TOKEN": token}
            with self.subTest(token=token), self.assertRaises(github_api.ApiError):
                github_api.choose_client("gh", which=lambda name: "gh", environ=env)
        with self.assertRaises(github_api.ApiError):
            github_api.choose_client("gh", which=lambda name: None, environ=hostile_environment())

    def test_http_denial_timeout_startup_error_and_body_error_never_echo_a_token(self):
        for error in (subprocess.TimeoutExpired(["gh"], 60, output=SYNTHETIC_TOKEN.encode()),
                      OSError(SYNTHETIC_TOKEN), None, "garbage"):
            def failed(command, **kwargs):
                if isinstance(error, Exception):
                    raise error
                return subprocess.CompletedProcess(command, 1 if error is None else 0,
                                                   SYNTHETIC_TOKEN.encode(), SYNTHETIC_TOKEN.encode())

            client = github_api.choose_client("gh", run=failed, which=lambda name: "gh", environ=hostile_environment())
            with self.subTest(error=type(error).__name__), self.assertRaises(github_api.ApiError) as caught:
                client.get("/repos/PenniLogic/infra")
            self.assertNotIn(SYNTHETIC_TOKEN, str(caught.exception))
            self.assertEqual(1, client.requests)

    def test_absolute_url_or_option_cannot_redirect_the_metadata_credential(self):
        for path in ("https://wrong.invalid/repos/x", "//wrong.invalid/repos/x", "--hostname=wrong.invalid"):
            client = github_api.choose_client("gh", run=mock.Mock(side_effect=AssertionError("must not execute")),
                                             which=lambda name: "gh", environ=hostile_environment())
            with self.subTest(path=path), self.assertRaises(github_api.ApiError):
                client.get(path)

    def test_authenticated_identity_mismatch_or_denial_prevents_any_clone_or_consumer_execution(self):
        name = "web"
        profile = support.generator.profile_for(name)
        for denied in (False, True):
            payloads = support.fake_client_for(name, profile["id"], "a" * 40,
                                               identity={"id": 42, "full_name": "wrong", "default_branch": "main"})

            def read(command, **kwargs):
                if denied:
                    return subprocess.CompletedProcess(command, 1, b"", SYNTHETIC_TOKEN.encode())
                return subprocess.CompletedProcess(command, 0, json.dumps(payloads.get(command[-1])).encode(), b"")

            client = github_api.choose_client("gh", run=read, which=lambda name: "gh", environ=hostile_environment())
            with tempfile.TemporaryDirectory() as scratch, mock.patch.object(run, "prepare_checkout") as clone:
                consumer = mock.Mock(side_effect=AssertionError("unverified consumer must not execute"))
                record = run.inspect_repository(name, profile, support.generator, client, registry.load_registry(),
                                                Path(scratch), support.GOVERNANCE.parent, consumer,
                                                ("python", "node", "uv"))
            with self.subTest(denied=denied):
                clone.assert_not_called()
                consumer.assert_not_called()
                self.assertIsNone(record["main_sha"])
                self.assertEqual([], record["planted_defects"])
                self.assertIn("nothing from the repository was executed", record["clone_error"])
                self.assertEqual("fail", report.evaluate_repository(record)["result"])
                self.assertNotIn(SYNTHETIC_TOKEN, json.dumps(record))

    def test_missing_step_token_stops_the_controller_before_git_or_consumer_execution(self):
        env = hostile_environment()
        del env["GH_TOKEN"]
        stderr = io.StringIO()
        choose_client = run.github_api.choose_client
        with mock.patch.object(defects.os, "environ", env), \
                mock.patch.object(run.github_api, "choose_client",
                                  side_effect=lambda mode: choose_client(mode, which=lambda name: "/synthetic/gh")), \
                mock.patch.object(run, "git") as git, \
                mock.patch.object(run, "inspect_repository") as inspect, \
                contextlib.redirect_stderr(stderr):
            code = run.main(["--scratch", "unused-scratch", "--output", "unused-output", "--github-client", "gh"])
        self.assertEqual(2, code)
        git.assert_not_called()
        inspect.assert_not_called()
        self.assertIn("non-empty step-scoped GH_TOKEN", stderr.getvalue())


class RuntimeIsolationTests(unittest.TestCase):
    def test_every_scratch_git_entry_point_scrubs_hostile_selectors_before_execution(self):
        seen = []

        def spy(command, **kwargs):
            seen.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with mock.patch.object(defects.os, "environ", hostile_environment()):
            with mock.patch.object(run.subprocess, "run", spy):
                run.git(Path("."), "rev-parse", "HEAD")
                defects.git_status(Path("."), run=spy)
                registry.render_workflow_at(support.GOVERNANCE.parent, "0" * 40, "infra",
                                            run=lambda command, **kwargs: (
                                                spy(command, **kwargs),
                                                subprocess.CompletedProcess(command, 128, b"", b""),
                                            )[1])
                support.git(Path("."), "rev-parse", "HEAD")
                with tempfile.TemporaryDirectory() as scratch:
                    support.make_consumer(Path(scratch) / "synthetic", ".github")
        self.assertGreaterEqual(len(seen), 5)
        for command, kwargs in seen:
            with self.subTest(command=command):
                self.assertIsNotNone(kwargs.get("env"))
                self.assertEqual({"GH_CONFIG_DIR"},
                                 {key for key in kwargs["env"] if key.upper().startswith(("GH_", "GITHUB_", "ACTIONS_"))})
                self.assertNotIn("GIT_CONFIG_PARAMETERS", kwargs["env"])
                self.assertNotIn("GIT_CONFIG_COUNT", kwargs["env"])
                self.assertGreater(kwargs["timeout"], 0)

    def test_a_real_consumer_and_its_child_cannot_read_the_metadata_token_or_actions_selectors(self):
        code = (
            "import json,os,subprocess,sys; "
            "names=lambda: sorted(k for k in os.environ if k.upper().startswith(('GH_','GITHUB_','ACTIONS_'))); "
            "print(json.dumps(names())); "
            "subprocess.run([sys.executable,'-c',"
            "\"import os,json; print(json.dumps(sorted(k for k in os.environ "
            "if k.upper().startswith(('GH_','GITHUB_','ACTIONS_')))))\"],check=True)"
        )
        with tempfile.TemporaryDirectory() as scratch, mock.patch.object(defects.os, "environ", hostile_environment()):
            result = defects.subprocess_runner([sys.executable, "-c", code], scratch, timeout=60)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertNotIn(SYNTHETIC_TOKEN, result.output)
        self.assertEqual([["GH_CONFIG_DIR"], ["GH_CONFIG_DIR"]],
                         [json.loads(line) for line in result.output.splitlines() if line.startswith("[")])

    def test_raw_ephemeral_token_is_redacted_from_output_reports_and_the_public_summary(self):
        with tempfile.TemporaryDirectory() as scratch:
            output = Path(scratch) / "published"
            client = support.FakeClient({})
            contaminated = {
                "repository": "PenniLogic/infra", "profile": "infra", "repository_id": 1394135059,
                "language": "python", "job_error": "synthetic failure " + SYNTHETIC_TOKEN,
                "planted_defects": [], "language_coverage": {},
            }
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(defects.os, "environ", hostile_environment()), \
                    mock.patch.object(run.github_api, "choose_client", return_value=client), \
                    mock.patch.object(run, "inspect_repository", return_value=contaminated), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = run.main(["--scratch", str(Path(scratch) / "clones"), "--output", str(output),
                                 "--repository", "infra", "--github-client", "gh"])
            self.assertEqual(1, code)
            for text in (stdout.getvalue(), stderr.getvalue(),
                         (output / "conformance-report.json").read_text(),
                         (output / "conformance-summary.md").read_text()):
                self.assertNotIn(SYNTHETIC_TOKEN, text)
            self.assertIn("[redacted]", stdout.getvalue())

    def test_failed_credential_redaction_is_not_published_or_echoed(self):
        with tempfile.TemporaryDirectory() as scratch:
            output = Path(scratch) / "not-published"
            stderr = io.StringIO()
            record = {"repository": "PenniLogic/infra", "profile": "infra",
                      "job_error": SYNTHETIC_TOKEN, "planted_defects": [], "language_coverage": {}}
            with mock.patch.object(defects.os, "environ", hostile_environment()), \
                    mock.patch.object(run.github_api, "choose_client", return_value=support.FakeClient({})), \
                    mock.patch.object(run, "inspect_repository", return_value=record), \
                    mock.patch.object(run.report_module, "redact", side_effect=lambda value, *args: value), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                code = run.main(["--scratch", str(Path(scratch) / "clones"), "--output", str(output),
                                 "--repository", "infra", "--github-client", "gh"])
            self.assertEqual(2, code)
            self.assertEqual([], list(output.iterdir()))
            self.assertIn("Redaction incomplete (credential); nothing written", stderr.getvalue())
            self.assertNotIn(SYNTHETIC_TOKEN, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
