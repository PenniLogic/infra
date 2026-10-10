"""Explicit native acquisition controls with synthetic credentials and offline HTTP responses."""

import contextlib
import copy
from email.message import Message
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.request

import conformance_support as support
import test_database_admission_installation as installation
import test_money_source_materialization as money


TOKEN_NAME = "PENNILOGIC_NATIVE_SOURCE_TOKEN"
TOKEN = "synthetic-native-source-credential"
STEP_NAMES = ("Prepare pinned Money sources", "Prepare pinned database and interop sources")
PROVIDER_STEP = "Prepare verified Money provider"
COMMANDS = (
    "python -I -S -B scripts/materialize_money_sources.py --native-fetch",
    "python -I -S -B scripts/prepare_database_admission.py prepare --fetch --native-fetch",
    "python -I -S -B scripts/money_client_interop.py prepare --native-fetch",
)


def native_environment():
    return {
        "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "PenniLogic/api",
        "GITHUB_REPOSITORY_ID": "1394134582", "GITHUB_REPOSITORY_OWNER_ID": "335295566",
        "GITHUB_EVENT_NAME": "pull_request", TOKEN_NAME: TOKEN,
        "GH_TOKEN": "ambient-personal-credential", "GITHUB_TOKEN": "ambient-other-credential",
    }


def script(commands, windows=False):
    commands = [command.replace("/", "\\") for command in commands] if windows else list(commands)
    run = ("\n".join(command + "\nif ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }" for command in commands)
           if windows else "\n".join(commands))
    return run


def native_step(windows=False, phase=0):
    return {"name": STEP_NAMES[phase], "env": {TOKEN_NAME: "${{ github.token }}"},
            "run": script(COMMANDS[:1] if phase == 0 else COMMANDS[1:], windows)}


def native_owning_script(workflow, windows=False):
    steps = json.loads(workflow)["jobs"]["windows" if windows else "ci"]["steps"]
    return "\n".join(steps[index]["run"] for index in (-5, -3, -1))


def remove_native_steps(case, workflow, jobs=("ci", "windows")):
    value = json.loads(workflow)
    for job in jobs:
        steps = value["jobs"][job]["steps"]
        windows = job == "windows"
        case.assertEqual([native_step(windows), native_step(windows, phase=1)],
                         [step for step in steps if step.get("name") in STEP_NAMES])
        case.assertEqual(native_step(windows), steps[-4])
        case.assertEqual(native_step(windows, phase=1), steps[-2])
        case.assertEqual({"name": "Check repository", "run": script(["python scripts/check_repository.py"], windows)},
                         steps[-5])
        provider_commands = list(support.generator.profile_for("api")["commands"][1:5])
        case.assertEqual("python scripts/materialize_money_sources.py", provider_commands[0])
        provider_commands[0] += " --verify-inputs"
        case.assertEqual({"name": PROVIDER_STEP, "run": script(provider_commands, windows)}, steps[-3])
        combined = "\n".join(steps[index]["run"] for index in (-5, -3, -1))
        case.assertEqual(1, combined.count(" --verify-inputs"))
        case.assertEqual(2 if windows else 1, combined.count(" --require-prepared"))
        combined = combined.replace(" --verify-inputs", "").replace(" --require-prepared", "")
        preparation = "python -I -S -B scripts/prepare_database_admission.py prepare"
        if windows:
            preparation = preparation.replace("/", "\\")
        case.assertEqual(1, combined.count(preparation))
        case.assertNotIn(preparation + " --fetch", combined)
        steps[-1]["run"] = combined.replace(preparation, preparation + " --fetch")
        del steps[-5:-1]
    return support.generator.encoded(value)


class NativeWorkflowTests(unittest.TestCase):
    def test_only_exact_api_ci_acquisition_steps_receive_the_ephemeral_token(self):
        current = support.generator.workflow("api")
        without = json.loads(remove_native_steps(self, current))
        for job in ("ci", "windows"):
            self.assertNotIn("env", without["jobs"][job])
            for step in without["jobs"][job]["steps"]:
                self.assertNotIn(TOKEN_NAME, json.dumps(step))
                self.assertNotIn("${{ github.token }}", json.dumps(step))
        self.assertEqual({"contents": "read"}, without["permissions"])
        self.assertEqual(["ci", "windows"], without["jobs"]["ci-result"]["needs"])
        self.assertEqual("always()", without["jobs"]["ci-result"]["if"])
        for repo in support.generator.PROFILES["repositories"]:
            for setup in (False, True):
                if repo != "api" or setup:
                    self.assertNotIn(TOKEN_NAME, support.generator.workflow(repo, setup=setup))
            self.assertNotIn("--native-fetch", "\n".join(support.generator.profile_for(repo)["commands"]))
        self.assertNotIn(TOKEN_NAME, support.generator.conformance_workflow())
        self.assertNotIn("--native-fetch", support.generator.conformance_workflow())
        commands = json.loads(current)["jobs"]["ci"]["steps"][-1]["run"]
        self.assertIn('python scripts/quality.py build --base "$BASE_SHA" --require-prepared ', commands)
        self.assertNotIn("--fetch", commands)
        windows = json.loads(current)["jobs"]["windows"]["steps"][-1]["run"]
        self.assertIn("money_client_interop.py prepare --require-prepared", windows)
        self.assertIn("qualify_windows.py --require-prepared", windows)
        self.assertNotIn("--fetch", windows)

    def test_native_step_drift_is_refused_without_widening_the_expression_allowlist(self):
        checker = {"__name__": "native_source_checker", "__file__": str(support.GOVERNANCE.parent / "scripts/check_repository.py")}
        exec(compile(support.generator.checker("api"), "current API checker", "exec"), checker)
        original = json.loads(support.generator.workflow("api"))
        checker["validate_workflow"](".github/workflows/ci.yml", support.generator.encoded(original).encode())
        for job in ("ci", "windows"):
            for index in (-4, -2):
                for label, mutation in (
                    ("missing", lambda steps: steps.pop(index)),
                    ("duplicate", lambda steps: steps.insert(index, copy.deepcopy(steps[index]))),
                    ("changed-command", lambda steps: steps[index].update(run="echo accepted")),
                    ("ambient-name", lambda steps: steps[index].update(env={"GH_TOKEN": "${{ github.token }}"})),
                    ("extra-command", lambda steps: steps[index].update(run=steps[index]["run"] + "\npython scripts/quality.py build")),
                    ("test-token", lambda steps: steps[-1].setdefault("env", {}).update({TOKEN_NAME: "${{ github.token }}"})),
                    ("provider-token", lambda steps: steps[-3].update(env={TOKEN_NAME: "${{ github.token }}"})),
                    ("offline-flag-removed", lambda steps: steps[-1].update(run=steps[-1]["run"].replace(" --require-prepared", ""))),
                ):
                    value = copy.deepcopy(original)
                    mutation(value["jobs"][job]["steps"])
                    with self.subTest(job=job, phase=index, mutation=label), self.assertRaisesRegex(ValueError, "API CI must match"):
                        checker["validate_workflow"](".github/workflows/ci.yml", support.generator.encoded(value).encode())
        self.assertNotIn("${{ github.token }}", checker["WORKFLOW_EXPRESSIONS"])
        with self.assertRaisesRegex(ValueError, "unreviewed workflow expression"):
            checker["validate_expressions"]({"env": {TOKEN_NAME: "${{ github.token }}"}})

    def test_windows_native_acquisition_stops_at_each_failed_command(self):
        for phase, count in ((0, 1), (1, 2)):
            support.assert_powershell_failure_boundaries(self, native_step(windows=True, phase=phase)["run"], count)

    def test_complete_windows_native_order_retains_all_twelve_fail_fast_boundaries(self):
        steps = json.loads(support.generator.workflow("api"))["jobs"]["windows"]["steps"][-5:]
        combined = "\n".join(step["run"] for step in steps)
        profile = support.generator.profile_for("api")["commands"]
        expected = [
            profile[0], COMMANDS[0], profile[1] + " --verify-inputs", *profile[2:5],
            *COMMANDS[1:], profile[5].removesuffix(" --fetch"), profile[6],
            "python -I -S -B scripts/money_client_interop.py prepare --require-prepared",
            "python scripts/qualify_windows.py --require-prepared",
        ]
        self.assertEqual([command.replace("/", "\\") for command in expected], combined.splitlines()[::2])
        self.assertEqual(["if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"] * 12, combined.splitlines()[1::2])
        support.assert_powershell_failure_boundaries(self, combined, 12)


class NativeTransportTests(unittest.TestCase):
    def test_consumed_native_credential_is_absent_from_a_real_descendant_environment(self):
        transport = money.Transport()
        with mock.patch.dict(os.environ, native_environment()):
            client = transport.client(native_fetch=True)
            self.assertNotIn(TOKEN_NAME, os.environ)
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c",
                 "import os,sys;sys.exit(int('PENNILOGIC_NATIVE_SOURCE_TOKEN' in os.environ))"],
                capture_output=True, check=False, timeout=10,
            )
            self.assertEqual((0, b"", b""), (result.returncode, result.stdout, result.stderr))
            self.assertEqual("Bearer " + TOKEN, client.headers["Authorization"])
        self.assertEqual([], transport.calls)

    def test_explicit_native_mode_consumes_only_the_scoped_token_for_exact_pinned_gets(self):
        transport = money.Transport()
        environment = native_environment()
        with tempfile.TemporaryDirectory(prefix="native-money-sources-") as temporary, \
                mock.patch.object(money.materializer, "CATALOG", transport.catalog):
            root = Path(temporary)
            client = transport.client(native_fetch=True, environ=environment)
            self.assertNotIn(TOKEN_NAME, environment)
            self.assertEqual("ambient-personal-credential", environment["GH_TOKEN"])
            result = money.materializer.materialize(root, client=client, native_fetch=True)
            self.assertEqual(("materialized", 17, 11), (result["status"], result["requests"], result["inputs"]))
            money.materializer.verify_inputs(root)
            for request, timeout in transport.calls:
                self.assertEqual("GET", request.get_method())
                self.assertTrue(request.full_url.startswith("https://api.github.com/repos/PenniLogic/"))
                self.assertNotIn("?", request.full_url.split("/git/trees/")[0])
                self.assertNotIn(TOKEN, request.full_url)
                self.assertEqual("Bearer " + TOKEN, request.get_header("Authorization"))
                self.assertLessEqual(timeout, 10)
            self.assertFalse(any(request.full_url.endswith("/user") for request, _ in transport.calls))
            self.assertNotIn(TOKEN, json.dumps(result))
            for path in root.rglob("*"):
                if path.is_file():
                    self.assertNotIn(TOKEN.encode(), path.read_bytes())
            before = len(transport.calls)
            with mock.patch.object(transport, "open") as opener:
                self.assertEqual("verified_existing", money.materializer.materialize(root, transport.client())["status"])
                opener.assert_not_called()
                receipt = root / money.materializer.INPUTS / "materialization.json"
                original = receipt.read_bytes()
                for content in (b"{}", original + b"\n"):
                    receipt.write_bytes(content)
                    with self.assertRaises(money.materializer.MaterializationError):
                        money.materializer.materialize(root, transport.client())
                    self.assertEqual(content, receipt.read_bytes())
                    opener.assert_not_called()
                receipt.write_bytes(original)
            self.assertEqual(before, len(transport.calls))

    def test_native_context_and_token_fail_closed_even_for_cached_inputs(self):
        mutations = [
            {key: value} for key, value in (
                ("GITHUB_ACTIONS", ""), ("GITHUB_ACTIONS", "false"), ("GITHUB_ACTIONS", "True"),
                ("GITHUB_REPOSITORY", "PenniLogic/contracts"), ("GITHUB_REPOSITORY_ID", "1"),
                ("GITHUB_REPOSITORY_OWNER_ID", "1"), ("GITHUB_EVENT_NAME", "pull_request_target"),
                (TOKEN_NAME, ""), (TOKEN_NAME, "short"), (TOKEN_NAME, "x" * 4097),
                (TOKEN_NAME, "x" * 20 + "\n"), (TOKEN_NAME, "x" * 20 + "\u00e9"),
            )
        ]
        for key in ("GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID",
                    "GITHUB_REPOSITORY_OWNER_ID", "GITHUB_EVENT_NAME", TOKEN_NAME):
            mutations.append({key: None})
        with tempfile.TemporaryDirectory(prefix="native-source-mode-refusal-") as temporary:
            root = Path(temporary)
            transport = money.Transport()
            with mock.patch.object(money.materializer, "CATALOG", transport.catalog):
                money.materializer.materialize(root, transport.client())
                before = {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}
                for changes in mutations:
                    environment = native_environment()
                    for key, value in changes.items():
                        if value is None:
                            environment.pop(key)
                        else:
                            environment[key] = value
                    with self.subTest(changes=list(changes)), \
                            mock.patch.dict(os.environ, environment, clear=True), \
                            mock.patch.object(money.materializer.urllib.request, "build_opener") as opener:
                        with self.assertRaisesRegex(money.materializer.MaterializationError, "^native-source-(context|authentication)$"):
                            money.materializer.materialize(root, native_fetch=True)
                        opener.assert_not_called()
                        self.assertNotIn(TOKEN_NAME, os.environ)
                self.assertEqual(before, {
                    str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
                })

    def test_anonymous_default_ignores_every_ambient_credential_and_native_mode_has_no_user_endpoint(self):
        environment = native_environment()
        transport = money.Transport()
        anonymous = transport.client(environ=environment)
        anonymous.get("/repos/PenniLogic/contracts")
        self.assertNotIn("Authorization", transport.calls[-1][0].headers)
        self.assertIn(TOKEN_NAME, environment)
        native = transport.client(native_fetch=True, environ=environment)
        for path in ("/user", "https://api.github.com/repos/PenniLogic/contracts",
                     "/repos/PenniLogic/contracts/releases/latest", "/repos/other/contracts",
                     "/repos/PenniLogic/contracts/git/commits/" + "0" * 40):
            with self.subTest(path=path), self.assertRaisesRegex(money.materializer.MaterializationError, "^source-api-path$"):
                native.get(path)
        self.assertEqual(1, len(transport.calls))
        for event in ("push", "workflow_dispatch"):
            environment = native_environment()
            environment["GITHUB_EVENT_NAME"] = event
            self.assertTrue(transport.client(native_fetch=True, environ=environment).native_fetch)

    def test_native_http_failures_close_unread_bodies_and_never_retry_or_fall_back(self):
        for status, remaining, code in (
            (401, (), "source-unauthorized"), (403, ("0",), "source-rate-exhausted"),
            (403, ("1",), "source-forbidden"), (403, (), "source-forbidden"),
            (403, ("0", "0"), "source-forbidden"), (403, ("0 ",), "source-forbidden"),
            (404, (), "source-not-found"), (429, (), "source-rate-limited"), (503, (), "source-http-unavailable"),
        ):
            transport = money.Transport()
            headers = Message()
            for value in remaining:
                headers["X-RateLimit-Remaining"] = value
            body = mock.Mock(wraps=io.BytesIO(b"private upstream response"))
            transport.data["/repos/PenniLogic/contracts"] = urllib.error.HTTPError(
                "https://api.github.com/repos/PenniLogic/contracts", status, "private upstream reason", headers, body,
            )
            with self.subTest(status=status, remaining=remaining), tempfile.TemporaryDirectory(prefix="native-http-refusal-") as temporary, \
                    mock.patch.object(money.materializer, "CATALOG", transport.catalog):
                root = Path(temporary)
                client = transport.client(native_fetch=True, environ=native_environment())
                with self.assertRaisesRegex(money.materializer.MaterializationError, "^" + code + "$"):
                    money.materializer.materialize(root, client=client, native_fetch=True)
                self.assertEqual(1, len(transport.calls))
                self.assertEqual("Bearer " + TOKEN, transport.calls[0][0].get_header("Authorization"))
                body.read.assert_not_called()
                body.close.assert_called_once()
                self.assertEqual([], list(root.iterdir()))

    def test_native_redirect_and_expired_deadline_keep_existing_static_refusals(self):
        for status in (301, 302, 303, 307, 308):
            for target in ("https://foreign.invalid/path", "https://api.github.com/repos/other/source", "/redirect"):
                calls = []
                response = money.Response(b"unread private redirect", "https://api.github.com/repos/PenniLogic/contracts")
                response.status = response.code = status
                response.msg = "synthetic redirect"
                response.headers["Location"] = target
                response.info = lambda: response.headers

                class RedirectFixture(urllib.request.HTTPSHandler):
                    def https_open(self, request):
                        calls.append(request)
                        return response

                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}), money.materializer.NoRedirect(), RedirectFixture(),
                )
                self.assertFalse(any(name.lower() == "authorization" for name, _ in opener.addheaders))
                client = money.Transport().client(native_fetch=True, environ=native_environment(), opener=opener)
                with self.subTest(status=status, target=target), \
                        self.assertRaisesRegex(money.materializer.MaterializationError, "^source-redirect$"):
                    client.get("/repos/PenniLogic/contracts")
                self.assertTrue(response.closed)
                self.assertEqual(1, len(calls))
                self.assertEqual("https://api.github.com/repos/PenniLogic/contracts", calls[0].full_url)
                self.assertEqual("Bearer " + TOKEN, calls[0].get_header("Authorization"))
        transport = money.Transport()
        now = [0.0]
        budget = money.materializer.Budget(clock=lambda: now[0])
        client = transport.client(native_fetch=True, environ=native_environment(), budget=budget)
        now[0] = 181
        with self.assertRaisesRegex(money.materializer.MaterializationError, "^source-deadline$"):
            client.get("/repos/PenniLogic/contracts")
        self.assertEqual([], transport.calls)

    def test_local_authenticated_mode_still_refuses_every_present_actions_marker(self):
        for marker in ("true", "", "false", "True", "0", "malformed"):
            environment = {"GITHUB_ACTIONS": marker, "GH_TOKEN": "synthetic-local-source-credential"}
            with self.subTest(marker=marker), self.assertRaises(money.materializer.MaterializationError):
                money.Transport().client(authenticated_local=True, environ=environment)

    def test_native_cli_failures_publish_only_static_codes_before_any_fetch_or_verification(self):
        for args, environment, code in (
            (["--native-fetch"], {key: value for key, value in native_environment().items() if key != TOKEN_NAME},
             "native-source-authentication"),
            (["--native-fetch"], {**native_environment(), "GITHUB_ACTIONS": "false"}, "native-source-context"),
            (["--verify", "--native-fetch"], native_environment(), "verification-mode"),
            (["--verify-inputs", "--native-fetch"], native_environment(), "verification-mode"),
        ):
            output, error = io.StringIO(), io.StringIO()
            with self.subTest(mode=args), mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(money.materializer.sys, "argv", ["materialize_money_sources.py", *args]), \
                    mock.patch.object(money.materializer, "CATALOG", money.Transport().catalog), \
                    mock.patch.object(money.materializer.urllib.request, "build_opener") as opener, \
                    mock.patch.object(money.materializer, "verify_inputs") as inputs, \
                    mock.patch.object(money.materializer, "verify_provider") as provider, \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                self.assertEqual(1, money.materializer.main())
                opener.assert_not_called()
                inputs.assert_not_called()
                provider.assert_not_called()
            self.assertEqual("", output.getvalue())
            self.assertEqual({"event": "money_sources", "status": "refused", "code": code}, json.loads(error.getvalue()))
            self.assertNotIn(TOKEN, error.getvalue())
            self.assertNotIn("ambient", error.getvalue())

    def test_generated_input_only_cli_never_fetches_missing_partial_or_changed_prepared_inputs(self):
        with tempfile.TemporaryDirectory(prefix="native-source-offline-verification-") as temporary:
            root = Path(temporary)
            script = root / "scripts/materialize_money_sources.py"
            script.parent.mkdir()
            script.write_text(money.generator.money_materializer(), encoding="utf-8", newline="\n")
            module = money.load("native_offline_input_verifier", script)
            transport = money.Transport()
            module.CATALOG = transport.catalog

            def verify(expected_exit, flag="--verify-inputs"):
                output, error = io.StringIO(), io.StringIO()
                with mock.patch.object(module.sys, "argv", [str(script), flag]), \
                        mock.patch.object(module.urllib.request, "build_opener") as opener, \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                    self.assertEqual(expected_exit, module.main())
                    opener.assert_not_called()
                if expected_exit:
                    self.assertEqual("", output.getvalue())
                    self.assertEqual("refused", json.loads(error.getvalue())["status"])
                else:
                    self.assertEqual("", error.getvalue())
                    self.assertEqual({"event": "money_sources", "status": "verified_inputs", "inputs": 11},
                                     json.loads(output.getvalue()))

            verify(1)
            module.materialize(root, module.ReadOnlyClient(transport.catalog, opener=transport))
            self.assertEqual(17, len(transport.calls))
            verify(0)
            self.assertFalse((root / module.PROVIDER).exists())
            verify(1, "--verify")
            directory = root / module.INPUTS
            receipt = directory / "materialization.json"
            original = receipt.read_bytes()
            receipt.write_bytes(b"{}")
            verify(1)
            self.assertEqual(b"{}", receipt.read_bytes())
            receipt.unlink()
            verify(1)
            receipt.write_bytes(original)
            verify(0)
            moved = directory.with_name("owned-complete-input-backup")
            directory.rename(moved)
            verify(1)
            self.assertFalse(directory.exists())
            self.assertEqual(17, len(transport.calls))


class NativeInstallationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = installation.InstallationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_current_generated_database_preparation_authenticates_only_acquisition_and_then_verifies_offline(self):
        case = self.fixture.case
        case.evidence = {
            entry["path"]: ("synthetic pinned evidence " + entry["path"]).encode("ascii")
            for entry in installation.CANONICAL["binding"]["sources"]["evidence"]["files"]
        }
        case.source_pin, source = installation.gate_tests.source_pair(
            1394134582, installation.gate_tests.API_COMMIT, case.evidence,
        )
        case.request["inventory"]["source"] = source
        for node in case.data["nodes"]:
            node["evidence"] = list(case.evidence)
        case.seal_inventory()
        data, transport, contents = self.fixture.fixture()
        self.fixture.render(data)
        root = self.fixture.root
        preparation = money.load("native_generated_preparation", root / "scripts/prepare_database_admission.py")
        with mock.patch.dict(os.environ, native_environment(), clear=True):
            helper = preparation.load_helper(root)
            authority = preparation.read_installation(root, helper)
            with mock.patch.object(helper.urllib.request, "build_opener", return_value=transport), \
                    mock.patch.object(preparation.subprocess, "run") as child:
                result = preparation.prepare(root, authority, helper, fetch=True, native_fetch=True)
                child.assert_not_called()
            self.assertNotIn(TOKEN_NAME, os.environ)
        self.assertEqual("prepared", result["status"])
        self.assertEqual(28, result["requests"])
        self.assertEqual(sum(len(source["files"]) + 3 for source in data["binding"]["sources"].values()), result["requests"])
        self.assertEqual(contents, preparation.verify(root, authority, helper))
        self.assertTrue(all(request.get_header("Authorization") == "Bearer " + TOKEN for request in transport.calls))
        for payload in contents.values():
            self.assertNotIn(TOKEN.encode(), payload)
        before = len(transport.calls)
        with mock.patch.object(helper.urllib.request, "build_opener") as opener, \
                mock.patch.object(preparation.subprocess, "run") as child:
            self.assertEqual("verified_existing", preparation.prepare(root, authority, helper)["status"])
            opener.assert_not_called()
            child.assert_not_called()
            payload = root / preparation.OUTPUT / "inputs.json"
            original = payload.read_bytes()
            payload.write_bytes(b"{}")
            with self.assertRaises(helper.MaterializationError):
                preparation.prepare(root, authority, helper)
            self.assertEqual(b"{}", payload.read_bytes())
            opener.assert_not_called()
            payload.write_bytes(original)
            self.assertEqual(contents, preparation.verify(root, authority, helper))
            with mock.patch.dict(os.environ, {key: value for key, value in native_environment().items() if key != TOKEN_NAME}, clear=True):
                with self.assertRaisesRegex(helper.MaterializationError, "^native-source-authentication$"):
                    preparation.prepare(root, authority, helper, fetch=True, native_fetch=True)
            with self.assertRaisesRegex(preparation.InstallationError, "^installation-native-fetch-mode$"):
                preparation.prepare(root, authority, helper, native_fetch=True)
            bundle = root / preparation.OUTPUT
            saved = bundle.with_name("owned-prepared-backup")
            bundle.rename(saved)
            with self.assertRaisesRegex(preparation.InstallationError, "^explicit-fetch-required$"):
                preparation.prepare(root, authority, helper)
            opener.assert_not_called()
            child.assert_not_called()
            self.assertFalse(bundle.exists())
        self.assertEqual(before, len(transport.calls))


if __name__ == "__main__":
    unittest.main()
