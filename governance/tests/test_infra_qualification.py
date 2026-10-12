"""Infra routing and synthetic qualification controls, not held workstation experiments."""

import ast
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock
import zipfile

import conformance_support as support
from conformance import generator as generator_module
import qualify as qualification
from test_api_node_runtime import shell_path


generator = support.generator
MARKER = "PRIVATE-FIXTURE-PAYLOAD-DO-NOT-PRINT"
SOURCE = ("a" * 40, "b" * 40, [{"path_sha256": "c" * 64, "mode": "100644", "git_blob": "d" * 40}])
LINUX_PROCESS_IDS = frozenset({
    "test_conformance_processes.LinuxProcessTests."
    "test_timeout_stops_shell_and_argv_group_members_but_keeps_restoration_fail_closed",
    "test_conformance_processes.LinuxProcessTests."
    "test_an_escaped_descendant_is_not_mistaken_for_a_terminated_owned_tree",
})
LINUX_PROCESS_SKIP = "skipped 'native Linux owned-group/escaped-descendant evidence'"
WINDOWS_SECURITY_IDS = frozenset({
    "test_security_controls.ScannerBoundaryTests.test_interrupted_teardown_never_claims_confirmed_cleanup",
    "test_security_controls.ScannerBoundaryTests.test_timeout_terminates_actual_descendants_holding_pipes_and_files",
    "test_security_controls.GitleaksIntegrationTests."
    "test_confirmed_interruption_keeps_public_cleanup_unconfirmed_and_incidents",
})


class InfraQualificationWorkflowTests(unittest.TestCase):
    def test_both_ordinary_suites_preserve_the_linux_graph_and_windows_preparation(self):
        document = json.loads(generator.workflow("infra"))
        jobs = document["jobs"]
        self.assertEqual({"ci", "windows", "ci-result"}, set(jobs))
        profile = generator.profile_for("infra")
        expected = [generator.infra_ci_command(command) for command in profile["commands"]]
        self.assertEqual(expected, jobs["ci"]["steps"][-1]["run"].splitlines())
        self.assertEqual([
            "python scripts/check_repository.py",
            "python governance/generate.py --repository infra --check",
            "python governance/qualify.py -- python -m unittest discover -s governance/tests",
            "docker compose -f docker-compose.yml config --quiet",
            "python governance/qualify.py -- python -m unittest discover -s scripts/tests",
        ], expected)
        self.assertEqual("windows-2025", jobs["windows"]["runs-on"])
        self.assertEqual(generator.tool_steps(profile), jobs["windows"]["steps"][:3])
        windows = jobs["windows"]["steps"][-1]["run"]
        self.assertEqual([line.replace("/", "\\") for line in expected if not line.startswith("docker ")],
                         windows.splitlines()[::2])
        self.assertNotIn("PENNILOGIC_SKIP_DOCKER_TESTS", json.dumps(document))
        self.assertEqual("always()", jobs["ci-result"]["if"])
        self.assertEqual(["ci", "windows"], jobs["ci-result"]["needs"])
        self.assertEqual("CI", jobs["ci-result"]["name"])
        self.assertEqual(1, sum(job["name"] == "CI" for job in jobs.values()))
        for name in ("ci", "windows"):
            self.assertNotIn("needs", jobs[name])
            self.assertEqual(10, jobs[name]["timeout-minutes"])
        self.assertEqual({"contents": "read"}, document["permissions"])
        installer = jobs["windows"]["steps"][4]["run"]
        self.assertIn("uv-0.11.33-py3-none-win_amd64.whl", installer)
        self.assertIn("#sha256=521229afa69ad5f57127de800120cb2bea1ac729a05a0851aaf920124f8edf66", installer)
        self.assertIn("--only-binary :all: --require-hashes --no-deps", installer)
        support.assert_powershell_failure_boundaries(self, installer, 1)
        support.assert_powershell_failure_boundaries(self, windows, 4)
        for name, windows_os in (("ci", False), ("windows", True)):
            preparation = jobs[name]["steps"][3]
            self.assertEqual(generator.infra_security_step(windows_os), preparation)
            self.assertEqual({"name", "run"}, set(preparation))
            self.assertIn(generator.infra_security_program(windows_os), preparation["run"])
            self.assertIn("pythonLocation", preparation["run"])
            self.assertIn("-I -S", preparation["run"])
        for document in (generator.workflow("infra", setup=True), generator.conformance_workflow()):
            self.assertNotIn("Prepare security tools", document)

    def test_api_caller_checker_and_qualifier_match_their_exact_source_bindings(self):
        historical = {
            ".github/workflows/ci.yml": "f6738c070157b5fdb59b84bfe854b22a6371e8be711bf308667ecf555f1bc3da",
            "scripts/check_repository.py": "5654613c86d17b070c06c7492dbf187302e7c6b3fb6bf02d38286726415a4cbf",
            "scripts/qualify_windows.py": "a98c825995da19e8e0499bc51b5a272b17da2bb065fb5d3593671467901e31b2",
        }
        current = {
            ".github/workflows/ci.yml": "51bf74f97dbb427e68c4db320ebd69bf9daadcc116c9ca628fcbd33f2349fceb",
            "scripts/check_repository.py": "cecfa08f274f4705ee08939d31b1b15808b25cfac83df827befaec2459e60f7f",
            "scripts/qualify_windows.py": "0a073083148e670081eee72612fd9853a1a78100c2a50129ce89a2da9adfe1b3",
            "scripts/materialize_money_sources.py": "e9f83c57079c6cadc42c751da4db8c0524012ee3f2629cd9b1f010d6413656b5",
            "scripts/prepare_database_admission.py": "fdcab20a76569fc4b03991003e06918f9d03d4f845e2562b844ee76dcc50ab49",
            "src/main/resources/database-admission-installation.json": "6d9821ac08ffba68865793d2998cba2aad21bbb8acd6a237d7aceec0a40b0195",
        }
        with tempfile.TemporaryDirectory(prefix="exact-api-source-bindings-") as temporary:
            root = Path(temporary)
            accepted = root / "historical"
            for relative in ("generate.py", "repository-profiles.json", "templates/check_repository.py",
                             "templates/api_ci_checker.py", "templates/qualify_windows.py"):
                content = subprocess.run(
                    ["git", "--no-pager", "show", "a40b9018a4b04fa78a5643905ebedc3a1a107db3:governance/" + relative],
                    cwd=support.GOVERNANCE.parent, capture_output=True, check=True, timeout=30,
                ).stdout
                path = accepted / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            previous = generator_module.load(accepted / "generate.py", name="historical_api_exact_bindings")
            previous_bytes = {
                ".github/workflows/ci.yml": previous.workflow("api").encode("utf-8"),
                "scripts/check_repository.py": previous.checker("api").encode("utf-8"),
                "scripts/qualify_windows.py": (accepted / "templates/qualify_windows.py").read_bytes(),
            }
            for path, digest in historical.items():
                with self.subTest(historical=path):
                    self.assertEqual(digest, hashlib.sha256(previous_bytes[path]).hexdigest())
            candidate = root / "current"
            generator.generate("api", candidate)
            generator.generate("api", candidate, check=True)
            for path, digest in current.items():
                with self.subTest(current=path):
                    self.assertEqual(digest, hashlib.sha256((candidate / path).read_bytes()).hexdigest())

    def test_only_the_two_exact_profiles_admit_their_qualification_workflows(self):
        for repo in generator.PROFILES["repositories"]:
            namespace = {"__file__": str(support.GOVERNANCE.parent / "scripts/check_repository.py")}
            exec(compile(generator.checker(repo), "rendered qualification checker", "exec"), namespace)
            validate = namespace["validate_workflow"]
            if repo not in ("api", "infra"):
                with self.subTest(repo=repo), self.assertRaises(ValueError):
                    validate(".github/workflows/ci.yml", generator.workflow("infra").encode())
                continue
            original = json.loads(generator.workflow(repo))
            validate(".github/workflows/ci.yml", generator.encoded(original).encode())
            for mutate in (
                lambda value: value["jobs"].pop("windows"),
                lambda value: value["jobs"]["ci-result"].pop("if"),
                lambda value: value["jobs"]["ci-result"].update(needs=["ci"]),
                lambda value: value["jobs"]["windows"].update({"continue-on-error": True}),
                lambda value: value["jobs"]["windows"]["steps"][-1].update(run="echo skipped"),
            ):
                changed = copy.deepcopy(original)
                mutate(changed)
                with self.subTest(repo=repo, mutate=mutate), self.assertRaisesRegex(ValueError, "CI must match"):
                    validate(".github/workflows/ci.yml", generator.encoded(changed).encode())

    def test_security_preparation_shells_require_bound_python_and_propagate_the_native_exit(self):
        for windows, tool in ((False, "bash"), (True, "pwsh")):
            runner = support.shutil.which(tool)
            self.assertIsNotNone(runner, "The existing emitted-shell test prerequisite is missing")
            for code in (0, 37, None, "relative"):
                with self.subTest(windows=windows, code=code), \
                        tempfile.TemporaryDirectory(prefix="infra-security-shell-") as temporary:
                    root = Path(temporary)
                    program = generator.infra_security_program(windows)
                    script = generator.infra_security_step(windows)["run"]
                    self.assertEqual(1, script.count(program))
                    exit_code = code if isinstance(code, int) else 0
                    environment = support.defects.probe_environment()
                    after, captured = root / "after", root / "captured-program"
                    environment["PENNILOGIC_FIXTURE_AFTER"] = str(after)
                    environment["PENNILOGIC_FIXTURE_PROGRAM"] = str(captured)
                    environment["PENNILOGIC_FIXTURE_EXIT"] = str(exit_code)
                    if windows:
                        invocation = '& "$env:pythonLocation\\python.exe"'
                        self.assertEqual(1, script.count(invocation))
                        fixture = """function Invoke-PreparedPython {
  if ($args.Count -ne 4 -or $args[0] -cne "-I" -or $args[1] -cne "-S" -or $args[2] -cne "-c") {
    throw "Unexpected prepared Python arguments"
  }
  [System.IO.File]::WriteAllText($env:PENNILOGIC_FIXTURE_PROGRAM, $args[3])
  $global:LASTEXITCODE = [int]$env:PENNILOGIC_FIXTURE_EXIT
}
"""
                        script = fixture + script.replace(invocation, "Invoke-PreparedPython")
                        environment["pythonLocation"] = r"C:\fixture-python"
                        script += '\n[System.IO.File]::WriteAllText($env:PENNILOGIC_FIXTURE_AFTER, "continued")'
                        path = root / "step.ps1"
                        command = [runner, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(path)]
                    else:
                        sdk = root / "sdk" / "bin"
                        sdk.mkdir(parents=True)
                        python = sdk / "python"
                        python.write_text("""#!/bin/bash
if [ "$#" -ne 3 ] || [ "$1" != "-I" ] || [ "$2" != "-S" ] || [ "$3" != "-" ]; then exit 91; fi
status=0
IFS= read -r -d '' program || status=$?
if [ "$status" -ne 1 ]; then exit 92; fi
printf '%s' "$program" > "$PENNILOGIC_FIXTURE_PROGRAM"
exit "$PENNILOGIC_FIXTURE_EXIT"
""", encoding="utf-8", newline="\n")
                        python.chmod(0o700)
                        environment["pythonLocation"] = shell_path(sdk.parent)
                        environment["PENNILOGIC_FIXTURE_AFTER"] = shell_path(after)
                        environment["PENNILOGIC_FIXTURE_PROGRAM"] = shell_path(captured)
                        script += '\nprintf continued > "$PENNILOGIC_FIXTURE_AFTER"'
                        path = root / "step.sh"
                        command = [runner, "--noprofile", "--norc", str(path)]
                    if code is None:
                        environment.pop("pythonLocation")
                    elif code == "relative":
                        environment["pythonLocation"] = "sdk"
                    path.write_text(script, encoding="utf-8", newline="\n")
                    result = subprocess.run(command, cwd=root, env=environment,
                                            capture_output=True, check=False, timeout=15)
                    if not isinstance(code, int):
                        self.assertNotEqual(0, result.returncode)
                    else:
                        self.assertEqual(code, result.returncode, result.stderr)
                    self.assertEqual(code == 0, after.exists())
                    if isinstance(code, int):
                        self.assertEqual(program + ("\n" if not windows else ""),
                                         captured.read_text(encoding="utf-8"))
                    else:
                        self.assertFalse(captured.exists(), "invalid interpreter binding must start nothing")


class InfraSecurityPreparationTests(unittest.TestCase):
    payload = b"nonfunctional synthetic scanner executable"

    def archive(self, windows, entries=None):
        executable = "gitleaks.exe" if windows else "gitleaks"
        entries = entries if entries is not None else [
            ("LICENSE", b"fixture", "file"), ("README.md", b"fixture", "file"),
            (executable, self.payload, "file"),
        ]
        stream = io.BytesIO()
        if windows:
            with zipfile.ZipFile(stream, "w") as archive:
                for name, data, kind in entries:
                    entry = zipfile.ZipInfo(name)
                    entry.create_system = 3
                    mode = {"file": stat.S_IFREG | 0o755, "link": stat.S_IFLNK | 0o777,
                            "directory": stat.S_IFDIR | 0o755, "special": stat.S_IFIFO | 0o600,
                            "setuid": stat.S_IFREG | 0o4755, "dos": 0}[kind]
                    entry.external_attr = mode << 16
                    archive.writestr(entry, data)
        else:
            with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                for name, data, kind in entries:
                    entry = tarfile.TarInfo(name)
                    entry.type = {"file": tarfile.REGTYPE, "link": tarfile.SYMTYPE,
                                  "directory": tarfile.DIRTYPE, "special": tarfile.FIFOTYPE,
                                  "setuid": tarfile.REGTYPE, "dos": tarfile.REGTYPE}[kind]
                    entry.mode = 0o4755 if kind == "setuid" else 0o755
                    entry.size = len(data) if entry.isreg() else 0
                    if kind == "link":
                        entry.linkname = "../outside"
                    archive.addfile(entry, io.BytesIO(data))
        return stream.getvalue()

    @contextlib.contextmanager
    def fixture(self, windows):
        module = types.ModuleType("infra_security_preparation_fixture")
        exec(compile(generator.infra_security_program(windows), "<emitted security preparation>", "exec"),
             module.__dict__)
        with tempfile.TemporaryDirectory(prefix="infra-security-preparation-") as temporary:
            root = Path(temporary).resolve()
            workspace, runner, host = root / "candidate", root / "runner", root / "host"
            for path in (workspace, runner, host):
                path.mkdir()
            git = host / ("git.exe" if windows else "git")
            git.write_bytes(b"synthetic runner image Git")
            env_file = runner / "github-env"
            env_file.write_bytes(b"")
            raw = self.archive(windows)
            module.SETTINGS.update(git=str(git), archive_sha256=hashlib.sha256(raw).hexdigest())
            response = io.BytesIO(raw)
            response.status = 200
            response.headers = {"Content-Length": str(len(raw))}
            opener = mock.Mock()
            opener.open.return_value = response
            state = {"module": module, "root": root, "workspace": workspace, "runner": runner, "git": git,
                     "env_file": env_file, "directory": runner / "pennilogic-gitleaks-8.30.1",
                     "response": response, "opener": opener, "calls": [], "on_version": None}

            def run(command, **options):
                state["calls"].append(command)
                self.assertEqual(state["directory"], options["cwd"])
                self.assertTrue(Path(command[0]).is_absolute())
                self.assertNotIn(MARKER, json.dumps(options["env"]))
                self.assertNotIn("GH_TOKEN", options["env"])
                self.assertEqual(str(git.parent), options["env"]["PATH"])
                self.assertEqual("1", options["env"]["NoDefaultCurrentDirectoryInExePath"])
                self.assertEqual(".EXE", options["env"]["PATHEXT"])
                self.assertGreater(options["timeout"], 0)
                self.assertLessEqual(options["timeout"], 15)
                if state["on_version"] is not None:
                    return state["on_version"](command, options)
                value = b"git version 2.53.0.windows.1\n" if command[0] == str(git) else b"8.30.1\n"
                options["stdout"].write(value)
                return subprocess.CompletedProcess(command, 0)

            environment = {
                "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": module.SETTINGS["runner_os"], "RUNNER_ARCH": "X64",
                "GITHUB_REPOSITORY": "PenniLogic/infra", "GITHUB_REPOSITORY_ID": "1394135059",
                "GITHUB_REPOSITORY_OWNER_ID": "335295566", "GITHUB_WORKSPACE": str(workspace),
                "RUNNER_TEMP": str(runner), "GITHUB_ENV": str(env_file),
                "GH_TOKEN": MARKER, "GITLEAKS_CONFIG": MARKER, "GIT_CONFIG_PARAMETERS": MARKER,
            }
            with mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(sys, "platform", module.SETTINGS["platform"]), \
                    mock.patch.object(module.urllib.request, "build_opener", return_value=opener) as network, \
                    mock.patch.object(module.subprocess, "run", side_effect=run):
                state["network"] = network
                yield state

    def invoke(self, state):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = state["module"].main()
        self.assertEqual("", stderr.getvalue())
        for private in (MARKER, str(state["root"]), str(state["workspace"]), "Traceback"):
            self.assertNotIn(private, stdout.getvalue())
        return code, json.loads(stdout.getvalue())

    def replace_download(self, state, raw, *, bind=True):
        response = io.BytesIO(raw)
        response.status = 200
        response.headers = {"Content-Length": str(len(raw))}
        state["response"] = response
        state["opener"].open.return_value = response
        if bind:
            state["module"].SETTINGS["archive_sha256"] = hashlib.sha256(raw).hexdigest()

    def bindings(self, state):
        return dict(line.split("=", 1) for line in state["env_file"].read_text(encoding="utf-8").splitlines())

    def test_both_emitted_programs_verify_then_publish_only_the_exact_tool_bindings(self):
        for windows in (False, True):
            with self.subTest(windows=windows), self.fixture(windows) as state:
                code, result = self.invoke(state)
                self.assertEqual(0, code)
                self.assertEqual("infra_security_tools_prepared", result["event"])
                executable = state["directory"] / state["module"].SETTINGS["executable"]
                self.assertEqual(self.payload, executable.read_bytes())
                self.assertEqual([executable], list(state["directory"].iterdir()))
                bindings = self.bindings(state)
                self.assertEqual(set(state["module"].BINDINGS), set(bindings))
                self.assertEqual(str(state["git"]), bindings["PENNILOGIC_TEST_GIT"])
                self.assertEqual(str(executable), bindings["PENNILOGIC_TEST_GITLEAKS"])
                self.assertEqual(hashlib.sha256(self.payload).hexdigest(),
                                 bindings["PENNILOGIC_TEST_GITLEAKS_SHA256"])
                self.assertEqual(hashlib.sha256(state["git"].read_bytes()).hexdigest(),
                                 bindings["PENNILOGIC_TEST_GIT_SHA256"])
                self.assertEqual([[str(state["git"]), "--version"], [str(executable), "version"]], state["calls"])
                request = state["opener"].open.call_args.args[0]
                self.assertEqual("GET", request.get_method())
                self.assertEqual("https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/"
                                 + state["module"].SETTINGS["archive"], request.full_url)
                self.assertEqual({}, state["network"].call_args.args[0].proxies)
                self.assertFalse(request.has_header("Authorization"))
                self.assertEqual(1, state["opener"].open.call_count)

    def test_fixed_archive_and_image_git_pins_match_qualification_without_candidate_lookup(self):
        for windows, platform in ((False, "linux"), (True, "win32")):
            module = types.ModuleType("infra_fixed_tool_pins")
            exec(generator.infra_security_program(windows), module.__dict__)
            self.assertEqual(qualification.GITLEAKS_ARCHIVE_PINS[platform], module.SETTINGS["archive_sha256"])
            self.assertEqual(qualification.HOST_GIT[platform], module.SETTINGS["git"])
            for text in ("shutil.which", "extractall", "pip install", "GITHUB_PATH"):
                self.assertNotIn(text, generator.infra_security_program(windows))

    def test_wrong_whole_archive_digest_prevents_parsing_extraction_and_every_child(self):
        for windows in (False, True):
            with self.subTest(windows=windows), self.fixture(windows) as state:
                state["module"].SETTINGS["archive_sha256"] = "0" * 64
                with mock.patch.object(state["module"], "executable_bytes") as extract:
                    code, result = self.invoke(state)
                self.assertEqual((1, "archive-digest-mismatch"), (code, result["code"]))
                extract.assert_not_called()
                self.assertEqual([], state["calls"])
                self.assertFalse(state["directory"].exists())
                self.assertEqual(b"", state["env_file"].read_bytes())

    def test_failed_truncated_oversized_and_malformed_downloads_never_extract_or_publish(self):
        for windows in (False, True):
            for case in ("status", "missing-length", "length-text", "length-large", "truncated", "overlong",
                         "denied", "read-error", "deadline"):
                with self.subTest(windows=windows, case=case), self.fixture(windows) as state:
                    response = state["response"]
                    if case == "status":
                        response.status = 403
                    elif case.startswith("length-") or case == "missing-length":
                        response.headers["Content-Length"] = {
                            "missing-length": None, "length-text": MARKER,
                            "length-large": str(state["module"].ARCHIVE_LIMIT + 1),
                        }[case]
                    elif case in ("truncated", "overlong"):
                        response.headers["Content-Length"] = str(
                            int(response.headers["Content-Length"]) + (1 if case == "truncated" else -1)
                        )
                    elif case == "denied":
                        state["opener"].open.side_effect = state["module"].urllib.error.URLError(MARKER)
                    elif case == "read-error":
                        response.read1 = mock.Mock(side_effect=OSError(MARKER))
                    with contextlib.ExitStack() as stack:
                        if case == "deadline":
                            stack.enter_context(mock.patch.object(state["module"].time, "monotonic",
                                                                  side_effect=[0, 181]))
                        code, result = self.invoke(state)
                    self.assertEqual((1, "infra_security_preparation_refused"), (code, result["event"]))
                    self.assertEqual([], state["calls"])
                    self.assertFalse(state["directory"].exists())
                    self.assertEqual(b"", state["env_file"].read_bytes())

    def test_archive_members_must_be_exact_unique_regular_bounded_files(self):
        for windows in (False, True):
            for case in ("missing", "extra", "traversal", "absolute", "backslash", "link", "directory",
                         "special", "setuid", "empty", "size", "malformed", "truncated"):
                with self.subTest(windows=windows, case=case), self.fixture(windows) as state:
                    executable = state["module"].SETTINGS["executable"]
                    entries = [("LICENSE", b"fixture", "file"), ("README.md", b"fixture", "file"),
                               (executable, self.payload, "file")]
                    if case == "missing":
                        entries.pop()
                    elif case == "extra":
                        entries.append(("extra.exe", self.payload, "file"))
                    elif case in ("traversal", "absolute", "backslash"):
                        entries[-1] = ({"traversal": "../" + executable, "absolute": "/" + executable,
                                        "backslash": "folder\\" + executable}[case], self.payload, "file")
                    elif case in ("link", "directory", "special", "setuid"):
                        entries[-1] = (executable, self.payload, case)
                    elif case == "empty":
                        entries[-1] = (executable, b"", "file")
                    elif case == "size":
                        state["module"].EXECUTABLE_LIMIT = len(self.payload) - 1
                    raw = self.archive(windows, entries)
                    if case == "malformed":
                        raw = b"not a release archive"
                    elif case == "truncated":
                        raw = raw[:-12]
                    self.replace_download(state, raw)
                    code, _ = self.invoke(state)
                    self.assertEqual(1, code)
                    self.assertEqual([], state["calls"])
                    self.assertFalse(state["directory"].exists())
                    self.assertEqual(b"", state["env_file"].read_bytes())

    def test_duplicate_archive_member_is_not_last_entry_wins(self):
        for windows in (False, True):
            with self.subTest(windows=windows), self.fixture(windows) as state:
                entries = [("LICENSE", b"a", "file"), ("README.md", b"a", "file"),
                           (state["module"].SETTINGS["executable"], self.payload, "file"),
                           ("LICENSE", b"b", "file")]
                with contextlib.redirect_stderr(io.StringIO()):
                    raw = self.archive(windows, entries)
                self.replace_download(state, raw)
                code, result = self.invoke(state)
                self.assertEqual((1, "archive-member-inventory"), (code, result["code"]))
                self.assertEqual([], state["calls"])

    def test_metadata_paths_links_and_existing_bindings_fail_before_download(self):
        for windows in (False, True):
            for case in ("identity", "owner", "runner", "relative", "inside", "env-outside", "git-inside",
                         "exists", "binding", "symlink", "junction"):
                with self.subTest(windows=windows, case=case), self.fixture(windows) as state:
                    if case in ("identity", "owner", "runner"):
                        os.environ[{"identity": "GITHUB_REPOSITORY_ID", "owner": "GITHUB_REPOSITORY_OWNER_ID",
                                    "runner": "RUNNER_ENVIRONMENT"}[case]] = "wrong"
                    elif case == "relative":
                        os.environ["RUNNER_TEMP"] = "relative"
                    elif case == "inside":
                        os.environ["RUNNER_TEMP"] = str(state["workspace"])
                    elif case == "env-outside":
                        os.environ["GITHUB_ENV"] = str(state["git"])
                    elif case == "git-inside":
                        candidate = state["workspace"] / "git"
                        candidate.write_bytes(b"untrusted")
                        state["module"].SETTINGS["git"] = str(candidate)
                    elif case == "exists":
                        state["directory"].mkdir()
                    elif case == "binding":
                        os.environ["PENNILOGIC_TEST_GIT"] = MARKER
                    with contextlib.ExitStack() as stack:
                        if case in ("symlink", "junction"):
                            stack.enter_context(mock.patch.object(
                                Path, "is_symlink" if case == "symlink" else "is_junction",
                                autospec=True, side_effect=lambda path: path == state["git"].parent,
                            ))
                        code, _ = self.invoke(state)
                    self.assertEqual(1, code)
                    state["network"].assert_not_called()
                    self.assertEqual([], state["calls"])
                    self.assertEqual(b"", state["env_file"].read_bytes())

    def test_redirects_cannot_select_another_scheme_host_or_authenticated_endpoint(self):
        for windows in (False, True):
            with self.fixture(windows) as state:
                module = state["module"]
                request = module.urllib.request.Request("https://github.com/gitleaks/gitleaks")
                handler = module.ReleaseRedirect()
                for url in ("http://github.com/file", "file:///file", "https://example.invalid/file",
                            "https://github.com.evil.invalid/file", "https://user:password@github.com/file",
                            "https://github.com:8443/file", "https://github.com/file#fragment"):
                    with self.subTest(windows=windows, url=url), self.assertRaises(module.Refused):
                        handler.redirect_request(request, None, 302, "redirect", {}, url)
                redirected = handler.redirect_request(
                    request, None, 302, "redirect", {}, "https://release-assets.githubusercontent.com/file?synthetic=1",
                )
                self.assertEqual("GET", redirected.get_method())
                state["network"].assert_not_called()

    def test_versions_exits_timeouts_interrupts_and_changed_bytes_never_publish_bindings(self):
        for windows in (False, True):
            for which in ("git", "gitleaks"):
                for case in ("exit", "stderr", "version", "timeout", "os-error", "interrupted", "changed"):
                    with self.subTest(windows=windows, tool=which, case=case), self.fixture(windows) as state:
                        def run(command, options):
                            git_command = command[0] == str(state["git"])
                            target = git_command == (which == "git")
                            value = b"git version 2.53.0\n" if git_command else b"8.30.1\n"
                            if target:
                                if case == "timeout":
                                    raise subprocess.TimeoutExpired(MARKER, 15)
                                if case == "os-error":
                                    raise OSError(MARKER)
                                if case == "interrupted":
                                    raise KeyboardInterrupt(MARKER)
                                if case == "stderr":
                                    options["stderr"].write(MARKER.encode())
                                elif case == "version":
                                    value = MARKER.encode()
                                elif case == "changed":
                                    Path(command[0]).write_bytes(b"changed after verification")
                            options["stdout"].write(value)
                            return subprocess.CompletedProcess(command, 23 if target and case == "exit" else 0)

                        state["on_version"] = run
                        code, result = self.invoke(state)
                        self.assertEqual((1, "infra_security_preparation_refused"), (code, result["event"]))
                        self.assertEqual(b"", state["env_file"].read_bytes())
                        self.assertTrue(state["directory"].exists(), "no false cleanup claim or automatic retry")

    def test_environment_publication_error_is_a_failure_not_prepared_success(self):
        with self.fixture(True) as state:
            original = Path.open

            def open_file(path, mode="r", *args, **kwargs):
                if path == state["env_file"] and mode == "a":
                    raise PermissionError(MARKER)
                return original(path, mode, *args, **kwargs)

            with mock.patch.object(Path, "open", open_file):
                code, result = self.invoke(state)
            self.assertEqual((1, "infra_security_preparation_refused"), (code, result["event"]))
            self.assertEqual(b"", state["env_file"].read_bytes())

    def test_changed_scanner_after_git_probe_is_refused_before_scanner_execution(self):
        for windows in (False, True):
            with self.subTest(windows=windows), self.fixture(windows) as state:
                def run(command, options):
                    if command[0] == str(state["git"]):
                        (state["directory"] / state["module"].SETTINGS["executable"]).write_bytes(b"replaced")
                        options["stdout"].write(b"git version 2.53.0\n")
                    else:
                        options["stdout"].write(b"8.30.1\n")
                    return subprocess.CompletedProcess(command, 0)

                state["on_version"] = run
                self.assertEqual(1, self.invoke(state)[0])
                self.assertEqual([[str(state["git"]), "--version"]], state["calls"])
                self.assertEqual(b"", state["env_file"].read_bytes())

    def test_qualifier_consumes_prepared_paths_and_digests_without_git_lookup(self):
        for windows, platform in ((False, "linux"), (True, "win32")):
            with self.subTest(windows=windows), self.fixture(windows) as state:
                self.assertEqual(0, self.invoke(state)[0])
                with mock.patch.dict(os.environ, self.bindings(state)), \
                        mock.patch.dict(qualification.HOST_GIT, {platform: str(state["git"])}), \
                        mock.patch.object(qualification.shutil, "which") as lookup:
                    values = qualification.security_tools(state["workspace"])
                self.assertEqual(str(state["git"]), values["git"])
                self.assertEqual(self.bindings(state)["PENNILOGIC_TEST_GITLEAKS_SHA256"], values["gitleaks_sha256"])
                lookup.assert_not_called()

    def test_qualifier_refuses_missing_forged_moved_linked_and_changed_tool_bindings(self):
        for windows, platform in ((False, "linux"), (True, "win32")):
            for case in ("missing-git", "missing-scanner", "missing-digest", "missing-git-digest", "digest",
                         "uppercase", "inside", "moved-git", "moved-scanner", "changed-git", "changed-scanner",
                         "symlink", "junction"):
                with self.subTest(windows=windows, case=case), self.fixture(windows) as state:
                    self.assertEqual(0, self.invoke(state)[0])
                    bindings = self.bindings(state)
                    if case.startswith("missing-"):
                        key = {"missing-git": "PENNILOGIC_TEST_GIT", "missing-scanner": "PENNILOGIC_TEST_GITLEAKS",
                               "missing-digest": "PENNILOGIC_TEST_GITLEAKS_SHA256",
                               "missing-git-digest": "PENNILOGIC_TEST_GIT_SHA256"}[case]
                        bindings.pop(key)
                    elif case in ("digest", "uppercase"):
                        bindings["PENNILOGIC_TEST_GITLEAKS_SHA256"] = ("a" if case == "digest" else "A") * 64
                    elif case in ("inside", "moved-git", "moved-scanner"):
                        key = "PENNILOGIC_TEST_GIT" if case == "moved-git" else "PENNILOGIC_TEST_GITLEAKS"
                        path = (state["workspace"] if case == "inside" else state["runner"]) / "shadow"
                        path.write_bytes(Path(bindings[key]).read_bytes())
                        bindings[key] = str(path)
                    elif case.startswith("changed-"):
                        key = "PENNILOGIC_TEST_GIT" if case == "changed-git" else "PENNILOGIC_TEST_GITLEAKS"
                        Path(bindings[key]).write_bytes(b"changed")
                    with contextlib.ExitStack() as stack:
                        stack.enter_context(mock.patch.dict(os.environ, bindings))
                        stack.enter_context(mock.patch.dict(qualification.HOST_GIT, {platform: str(state["git"])}))
                        probe = stack.enter_context(mock.patch.object(qualification, "checked"))
                        if case in ("symlink", "junction"):
                            stack.enter_context(mock.patch.object(
                                Path, "is_symlink" if case == "symlink" else "is_junction", autospec=True,
                                side_effect=lambda path: path == state["directory"],
                            ))
                        with self.assertRaises(qualification.Refused):
                            qualification.source_inventory(state["workspace"])
                        probe.assert_not_called()

    @contextlib.contextmanager
    def qualifier_fixture(self, windows):
        with self.fixture(windows) as state:
            self.assertEqual(0, self.invoke(state)[0])
            state["calls"].clear()
            scanner = state["directory"] / state["module"].SETTINGS["executable"]
            node = state["root"] / "node" / "bin" / ("node.exe" if windows else "node")
            npm = (node.parent / "node_modules/npm/bin/npm-cli.js" if windows
                   else node.parent.parent / "lib/node_modules/npm/bin/npm-cli.js")
            npm.parent.mkdir(parents=True)
            npm.write_bytes(b"synthetic npm")
            tools = {"node": str(node), "uv": str(state["root"] / "uv"),
                     "bash": str(state["root"] / "bash")}
            listing = b"".join(b"100644 blob " + b"c" * 40 + b"\t" + name.encode() + b"\0"
                               for name in sorted(qualification.SECURITY_SOURCE_FILES))
            replies = {
                (str(node), "--version"): b"v24.14.0\n",
                (str(node), str(npm), "--version"): b"11.9.0\n",
                (tools["uv"], "--version"): b"uv 0.11.33 (fixture)\n",
                (str(state["git"]), "--version"): b"git version 2.53.0\n",
                (tools["bash"], "--noprofile", "--norc", "--version"): b"GNU bash, version 5.2.37\n",
                (str(scanner), "version"): b"8.30.1\n",
                (str(state["git"]), "--no-pager", "rev-parse", "HEAD"): b"a" * 40 + b"\n",
                (str(state["git"]), "--no-pager", "rev-parse", "--is-shallow-repository"): b"false\n",
                (str(state["git"]), "--no-pager", "status", "--porcelain", "--untracked-files=normal"): b"",
                (str(state["git"]), "--no-pager", "rev-parse", "HEAD^{tree}"): b"b" * 40 + b"\n",
                (str(state["git"]), "--no-pager", "ls-tree", "-r", "-z", "HEAD"): listing,
            }
            state.update(scanner=scanner, node=node, tools=tools, replies=replies,
                         on_qualifier_probe=None, on_discovery=None)

            def run(command, **options):
                if command[1:3] == ["-c", qualification.UNITTEST_DISCOVERY]:
                    self.assertEqual({"cwd", "stdout", "stderr", "check"}, set(options))
                    self.assertEqual(state["workspace"], options["cwd"])
                    self.assertFalse(options["check"])
                    state["calls"].append(command)
                    Path(command[3]).write_text(
                        "test_pass (test_binding_inventory.ControlTests.test_pass) ... ok\n\n"
                        "----------------------------------------------------------------------\n"
                        "Ran 1 test in 0.001s\n\nOK\n", encoding="utf-8",
                    )
                    if state["on_discovery"] is not None:
                        state["on_discovery"]()
                    return subprocess.CompletedProcess(command, 0)
                self.assertEqual({"cwd": state["workspace"], "capture_output": True, "check": False}, options)
                self.assertIn(tuple(command), replies)
                state["calls"].append(command)
                if state["on_qualifier_probe"] is not None:
                    result = state["on_qualifier_probe"](command)
                    if result is not None:
                        return result
                return subprocess.CompletedProcess(command, 0, replies[tuple(command)], b"")

            environment = {**self.bindings(state), "ImageOS": "win25" if windows else "ubuntu24",
                           "ImageVersion": "20261001.3.2", "GITHUB_SHA": "a" * 40}
            platform = "win32" if windows else "linux"
            with mock.patch.dict(os.environ, environment), \
                    mock.patch.dict(qualification.HOST_GIT, {platform: str(state["git"])}), \
                    mock.patch.object(qualification.shutil, "which", side_effect=tools.get), \
                    mock.patch.object(qualification.subprocess, "run", side_effect=run):
                yield state

    def test_qualifier_rejects_scanner_replacement_during_an_earlier_probe_before_dispatch(self):
        for windows in (False, True):
            for earlier in ("node", "git", "bash"):
                with self.subTest(windows=windows, earlier=earlier), self.qualifier_fixture(windows) as state:
                    def replace(command):
                        path = str(state["git"]) if earlier == "git" else state["tools"][earlier]
                        if command[0] == path:
                            state["scanner"].write_bytes(b"replaced after original admission")

                    state["on_qualifier_probe"] = replace
                    refusal = None
                    try:
                        qualification.versions(state["workspace"])
                    except qualification.Refused as error:
                        refusal = str(error)
                    self.assertEqual(0, sum(command[0] == str(state["scanner"]) for command in state["calls"]))
                    self.assertIsNotNone(refusal)

    def test_qualifier_rejects_git_replacement_between_inventory_queries_before_next_dispatch(self):
        for windows in (False, True):
            with self.subTest(windows=windows), self.qualifier_fixture(windows) as state:
                class ReplaceAfterRead(bytes):
                    def decode(self, *args, **kwargs):
                        state["git"].write_bytes(b"replaced between inventory queries")
                        return super().decode(*args, **kwargs)

                def replace(command):
                    if command[-2:] == ["rev-parse", "HEAD"]:
                        return subprocess.CompletedProcess(command, 0, ReplaceAfterRead(b"a" * 40 + b"\n"), b"")

                state["on_qualifier_probe"] = replace
                refusal = None
                try:
                    qualification.source_inventory(state["workspace"])
                except qualification.Refused as error:
                    refusal = str(error)
                self.assertEqual(1, len(state["calls"]))
                self.assertIsNotNone(refusal)

    def change_qualifier_binding(self, state, tool, case):
        path = state[tool]
        key = "PENNILOGIC_TEST_" + ("GIT" if tool == "git" else "GITLEAKS")
        if case in ("bytes", "bytes-and-digest"):
            path.write_bytes(b"changed synthetic tool")
            if case == "bytes-and-digest":
                os.environ[key + "_SHA256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif case in ("missing", "directory"):
            path.unlink()
            if case == "directory":
                path.mkdir()
        elif case == "missing-digest":
            del os.environ[key + "_SHA256"]
        elif case == "path":
            moved = state["root"] / "tool-shadow"
            moved.write_bytes(path.read_bytes())
            os.environ[key] = str(moved)
        elif case == "noncanonical":
            os.environ[key] = str(path.parent / ".." / path.parent.name / path.name)
        elif case == "prepared-relocation":
            runner = state["root"] / "other-runner"
            scanner = runner / state["directory"].name / state["scanner"].name
            scanner.parent.mkdir(parents=True)
            scanner.write_bytes(state["scanner"].read_bytes())
            os.environ.update(RUNNER_TEMP=str(runner), PENNILOGIC_TEST_GITLEAKS=str(scanner))
        elif case == "linked-parent":
            parent = path.parent
            target = parent.with_name(parent.name + "-target")
            parent.rename(target)
            if os.name == "nt":
                import _winapi
                _winapi.CreateJunction(str(target), str(parent))
            else:
                parent.symlink_to(target, target_is_directory=True)
            self.assertTrue(parent.is_junction() or parent.is_symlink())
        else:
            self.fail("unknown synthetic binding mutation")

    def qualifier_main(self, state):
        output, errors = io.StringIO(), io.StringIO()
        arguments = ["qualify.py", "--", "python", "-m", "unittest", "discover", "-s", "governance/tests"]
        with mock.patch.object(qualification, "ROOT", state["workspace"]), \
                mock.patch.object(sys, "argv", arguments), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = qualification.main()
        self.assertEqual("", errors.getvalue())
        for private in (MARKER, str(state["root"]), "Traceback"):
            self.assertNotIn(private, output.getvalue())
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_qualifier_unchanged_bound_tools_preserve_versions_and_complete_inventory(self):
        for windows in (False, True):
            with self.subTest(windows=windows), self.qualifier_fixture(windows) as state:
                values = qualification.versions(state["workspace"])
                source = qualification.source_inventory(state["workspace"])
                bindings = self.bindings(state)
                self.assertEqual(("a" * 40, "b" * 40), source[:2])
                self.assertEqual({qualification.identifier(name) for name in qualification.SECURITY_SOURCE_FILES},
                                 {row["path_sha256"] for row in source[2]})
                self.assertEqual((bindings["PENNILOGIC_TEST_GIT_SHA256"],
                                  bindings["PENNILOGIC_TEST_GITLEAKS_SHA256"], "8.30.1"),
                                 (values["git_sha256"], values["gitleaks_sha256"], values["gitleaks"]))
                self.assertEqual(list(state["replies"]), [tuple(command) for command in state["calls"]])

    def test_qualifier_rechecks_after_every_bound_version_and_inventory_command(self):
        for windows in (False, True):
            for index in range(7):
                with self.subTest(windows=windows, index=index), self.qualifier_fixture(windows) as state:
                    targets = [command for command in state["replies"]
                               if command[0] in (str(state["git"]), str(state["scanner"]))]
                    target = targets[index]

                    def replace(command):
                        if tuple(command) == target:
                            tool = "git" if command[0] == str(state["git"]) else "scanner"
                            self.change_qualifier_binding(state, tool, "bytes")

                    state["on_qualifier_probe"] = replace
                    operation = qualification.versions if index < 2 else qualification.source_inventory
                    with self.assertRaisesRegex(qualification.Refused, "security-tool-digest-changed"):
                        operation(state["workspace"])
                    self.assertEqual(target, tuple(state["calls"][-1]))

    def test_qualifier_post_use_path_link_digest_and_binding_failures_are_sanitized(self):
        for windows in (False, True):
            for tool in ("git", "scanner"):
                for case in ("bytes-and-digest", "missing", "directory", "missing-digest", "path",
                             "noncanonical", "prepared-relocation", "linked-parent"):
                    with self.subTest(windows=windows, tool=tool, case=case), \
                            self.qualifier_fixture(windows) as state:
                        def replace(command):
                            if command[0] == str(state[tool]):
                                self.change_qualifier_binding(state, tool, case)
                                return subprocess.CompletedProcess(
                                    command, 0, state["replies"][tuple(command)], MARKER.encode(),
                                )

                        state["on_qualifier_probe"] = replace
                        code, records = self.qualifier_main(state)
                        self.assertEqual(1, code)
                        self.assertEqual("infra_qualification_refused", records[-1]["event"])
                        self.assertEqual(str(state[tool]), state["calls"][-1][0])
                        self.assertEqual(1, sum(command[0] == str(state[tool]) for command in state["calls"]))

    def test_qualifier_primary_command_failures_survive_failed_post_use_rechecks(self):
        for windows in (False, True):
            for tool in ("git", "scanner"):
                for failure in ("exit", "os-error", "subprocess-error", "value-error", "interrupt"):
                    for changed in (False, True):
                        with self.subTest(windows=windows, tool=tool, failure=failure, changed=changed), \
                                self.qualifier_fixture(windows) as state:
                            def fail(command):
                                if command[0] != str(state[tool]):
                                    return None
                                if changed:
                                    self.change_qualifier_binding(state, tool, "missing")
                                if failure == "exit":
                                    return subprocess.CompletedProcess(command, 37, MARKER.encode(), MARKER.encode())
                                raise {"os-error": OSError, "subprocess-error": subprocess.SubprocessError,
                                       "value-error": ValueError, "interrupt": KeyboardInterrupt}[failure](MARKER)

                            state["on_qualifier_probe"] = fail
                            code, records = self.qualifier_main(state)
                            self.assertEqual(130 if failure == "interrupt" else 1, code)
                            expected = "qualification-prerequisite-command-failed" if failure == "exit" else (
                                "qualification-interrupted" if failure == "interrupt" else "process-or-evidence-error"
                            )
                            events = ([{"event": "qualification_tool_recheck_refused",
                                        "code": "post-use-security-tool-binding-invalid"}] if changed else [])
                            self.assertEqual([*events, {"event": "infra_qualification_refused", "code": expected}],
                                             records)
                            self.assertEqual(str(state[tool]), state["calls"][-1][0])

    def test_qualifier_retains_original_bindings_across_versions_and_both_inventories(self):
        identity = "test_binding_inventory.ControlTests.test_pass"
        for windows in (False, True):
            for phase in ("unchanged", "after-versions", "during-discovery"):
                for case in ("bytes-and-digest", "prepared-relocation"):
                    with self.subTest(windows=windows, phase=phase, case=case), \
                            self.qualifier_fixture(windows) as state:
                        def change():
                            self.change_qualifier_binding(state, "scanner", case)
                            qualification.security_tools(state["workspace"])

                        class ChangeAfterRead(bytes):
                            def strip(self, *args, **kwargs):
                                change()
                                return super().strip(*args, **kwargs)

                        if phase == "after-versions":
                            def reply(command):
                                if command[0] == str(state["scanner"]):
                                    return subprocess.CompletedProcess(command, 0, ChangeAfterRead(b"8.30.1\n"), b"")

                            state["on_qualifier_probe"] = reply
                        elif phase == "during-discovery":
                            state["on_discovery"] = change
                        with mock.patch.object(qualification, "discovery_inventory", return_value={
                                qualification.identifier(identity): identity,
                        }), mock.patch.object(qualification, "SKIPS", {
                            "win32": {"governance": set()}, "linux": {"governance": set()},
                        }):
                            code, records = self.qualifier_main(state)
                        if phase == "unchanged":
                            self.assertEqual(0, code)
                            self.assertEqual({"event": "infra_qualification", "suite": "governance", "ok": True,
                                              "tests": 1, "skipped": 0}, records[-1])
                            git_count = 11
                        else:
                            self.assertEqual(1, code)
                            self.assertEqual({"event": "infra_qualification_refused",
                                              "code": "security-tool-original-binding-changed"}, records[-1])
                            git_count = 1 if phase == "after-versions" else 6
                        self.assertEqual(git_count, sum(command[0] == str(state["git"]) for command in state["calls"]))


class PowerShellFixtureDiagnosticTests(unittest.TestCase):
    name = ("test_api_windows_qualification.ApiWindowsWorkflowTests."
            "test_windows_powershell_stops_at_each_failed_native_command")
    prefix = b"PENNILOGIC_POWERSHELL_FIXTURE_V1 "
    private_bytes = (MARKER + "\x1b[31m").encode() + b"\xff"

    def project(self, data, *, name=None, suite="governance"):
        name = name or self.name
        output = io.StringIO()
        with contextlib.redirect_stdout(output), mock.patch.object(qualification, "python_outcomes") as parser:
            qualification.discovery_diagnostics(
                support.GOVERNANCE.parent, suite, data, {qualification.identifier(name): name}, [],
            )
            parser.assert_not_called()
        for private in (MARKER, "\x1b", str(support.GOVERNANCE), self.name):
            self.assertNotIn(private, output.getvalue())
        return json.loads(output.getvalue())

    def helper_run(self, mode, fail_at=2):
        import test_api_windows_qualification as api_tests

        attempts, scripts = [], []

        def run(command, **options):
            current = int(options["env"]["FAIL_AT"])
            attempts.append(current)
            script = Path(command[-1])
            scripts.append(script)
            self.assertTrue(script.is_file())
            self.assertEqual(["pwsh-fixture", "-NoLogo", "-NoProfile", "-NonInteractive", "-File"],
                             command[:-1])
            self.assertEqual({"env", "capture_output", "check", "timeout"}, set(options))
            self.assertEqual((True, False, 15), tuple(options[key] for key in ("capture_output", "check", "timeout")))
            if current == fail_at:
                if mode == "timeout":
                    raise subprocess.TimeoutExpired(MARKER, 15, output=self.private_bytes, stderr=b"")
                if mode == "os-error":
                    raise OSError(13, MARKER, MARKER)
                if mode == "other":
                    raise ValueError(MARKER)
                if mode == "subprocess":
                    raise subprocess.CalledProcessError(47, MARKER, output=self.private_bytes)
                if mode == "malformed-capture":
                    raise subprocess.TimeoutExpired(MARKER, 15, output=MARKER)
            stdout = "".join(f"{number}\n" for number in range(1, (current or 9) + 1)).encode()
            code = 37 if current else 0
            if current == fail_at and mode == "assertion":
                code = 123
            if current == fail_at and mode == "decode":
                stdout = self.private_bytes
            return subprocess.CompletedProcess(command, code, stdout, self.private_bytes)

        private = io.StringIO()
        case = api_tests.ApiWindowsWorkflowTests(self.name.rsplit(".", 1)[-1])
        with mock.patch.object(support.shutil, "which", return_value="pwsh-fixture"), \
                mock.patch.object(support.subprocess, "run", side_effect=run):
            result = unittest.TextTestRunner(stream=private, verbosity=2).run(unittest.TestSuite([case]))
        self.assertTrue(scripts)
        self.assertTrue(all(not script.parent.exists() for script in scripts))
        return result, attempts, self.project(private.getvalue().encode())

    def test_invocation_errors_keep_actual_metadata_and_abort_the_remaining_cases(self):
        for mode, fail_at, category, number in (
            ("timeout", 2, "timeout", None), ("os-error", 7, "os-error", 13),
            ("other", 0, "other-exception", None),
        ):
            with self.subTest(mode=mode):
                result, attempts, row = self.helper_run(mode, fail_at)
                self.assertEqual((1, 0, 1), (result.testsRun, len(result.failures), len(result.errors)))
                self.assertEqual(list(range(fail_at + 1)), attempts)
                observation = row["reports"][0]["powershell_fixture"]
                self.assertEqual("available", observation.pop("state"))
                self.assertEqual(qualification.identifier(self.name), observation["test_id_sha256"])
                self.assertEqual((fail_at, 9, list(range(fail_at))),
                                 tuple(observation[key] for key in ("fail_at", "count", "completed_cases")))
                self.assertEqual(("invoke", category, number, None, 15),
                                 tuple(observation[key] for key in
                                       ("boundary", "exception_category", "errno", "exit_code", "timeout_seconds")))
                self.assertGreaterEqual(observation["elapsed_seconds"], 0)
                if mode == "timeout":
                    self.assertEqual({"state": "partial", "bytes": len(self.private_bytes),
                                      "sha256": hashlib.sha256(self.private_bytes).hexdigest()}, observation["stdout"])
                    self.assertEqual({"state": "partial", "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
                                     observation["stderr"])
                else:
                    for stream in ("stdout", "stderr"):
                        self.assertEqual({"state": "unavailable", "bytes": None, "sha256": None}, observation[stream])

    def test_returned_failures_keep_actual_exit_and_full_captures_and_continue_subtests(self):
        for mode, failures, errors, category, code in (
            ("assertion", 1, 0, "assertion", 123), ("decode", 0, 1, "unicode-error", 37),
        ):
            with self.subTest(mode=mode):
                result, attempts, row = self.helper_run(mode)
                self.assertEqual((1, failures, errors), (result.testsRun, len(result.failures), len(result.errors)))
                self.assertEqual(list(range(10)), attempts)
                observation = row["reports"][0]["powershell_fixture"]
                self.assertEqual(("available", "assertions", category, code, None),
                                 tuple(observation[key] for key in
                                       ("state", "boundary", "exception_category", "exit_code", "errno")))
                self.assertEqual([0, 1], observation["completed_cases"])
                stdout = self.private_bytes if mode == "decode" else b"1\n2\n"
                for stream, value in (("stdout", stdout), ("stderr", self.private_bytes)):
                    self.assertEqual({"state": "complete", "bytes": len(value),
                                      "sha256": hashlib.sha256(value).hexdigest()}, observation[stream])

    def test_successful_helper_cases_have_no_failure_diagnostic_or_relaxed_assertion(self):
        result, attempts, row = self.helper_run("success")
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(list(range(10)), attempts)
        self.assertEqual([], row["reports"])

    def test_exception_exit_partial_and_malformed_captures_are_not_coerced_or_printed(self):
        for mode, category, code, state in (
            ("subprocess", "subprocess-error", 47, "partial"),
            ("malformed-capture", "timeout", None, "malformed"),
        ):
            with self.subTest(mode=mode):
                result, attempts, row = self.helper_run(mode)
                self.assertEqual((1, 0, 1), (result.testsRun, len(result.failures), len(result.errors)))
                self.assertEqual([0, 1, 2], attempts)
                value = row["reports"][0]["powershell_fixture"]
                self.assertEqual(("available", category, code),
                                 tuple(value[key] for key in ("state", "exception_category", "exit_code")))
                self.assertEqual(state, value["stdout"]["state"])
                self.assertEqual({"state": "unavailable", "bytes": None, "sha256": None}, value["stderr"])
                if state == "malformed":
                    self.assertEqual({"state": "malformed", "bytes": None, "sha256": None}, value["stdout"])
                else:
                    self.assertEqual(len(self.private_bytes), value["stdout"]["bytes"])
                    self.assertEqual(hashlib.sha256(self.private_bytes).hexdigest(), value["stdout"]["sha256"])

    def test_timing_stops_at_invocation_return_or_raise_not_assertion_or_cleanup(self):
        for mode, calls in (("assertion", 10), ("timeout", 3)):
            clock = [value for index in range(calls) for value in (10 + index, 10.125 + index)]
            with self.subTest(mode=mode), \
                    mock.patch.object(support.time, "monotonic", side_effect=clock) as monotonic:
                _, _, row = self.helper_run(mode)
                self.assertEqual(calls * 2, monotonic.call_count)
                self.assertEqual(0.125, row["reports"][0]["powershell_fixture"]["elapsed_seconds"])
                self.assertEqual(15, row["reports"][0]["powershell_fixture"]["timeout_seconds"])

    def test_each_infra_owner_count_and_integer_exit_range_is_diagnostic_only(self):
        name = ("test_infra_qualification.InfraQualificationWorkflowTests."
                "test_both_ordinary_suites_preserve_the_linux_graph_and_windows_preparation")
        header = f"FAIL: {name.rsplit('.', 1)[-1]} ({name})\n".encode()
        for count in (1, 4):
            for code in (-(2 ** 31), 2 ** 32 - 1):
                value = {
                    "test_id_sha256": qualification.identifier(name), "count": count, "fail_at": count,
                    "completed_cases": list(range(count)), "elapsed_seconds": 0.25, "timeout_seconds": 15,
                    "boundary": "assertions", "exception_category": "assertion", "errno": None, "exit_code": code,
                    "stdout": {"state": "complete", "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
                    "stderr": {"state": "unavailable", "bytes": None, "sha256": None},
                }
                with self.subTest(count=count, code=code):
                    row = self.project(header + self.prefix + json.dumps(value).encode(), name=name)
                    self.assertEqual({"state": "available", **value}, row["reports"][0]["powershell_fixture"])
                    self.assertTrue(row["diagnostic_only"])
                    self.assertEqual("FAIL", row["reports"][0]["reported_status"])
        value["count"] = 9
        row = self.project(header + self.prefix + json.dumps(value).encode(), name=name)
        self.assertEqual({"state": "malformed"}, row["reports"][0]["powershell_fixture"])

    def test_missing_malformed_duplicate_and_wrong_owner_notes_are_explicit_not_admission(self):
        header = f"ERROR: {self.name.rsplit('.', 1)[-1]} ({self.name})\n".encode()
        value = {
            "test_id_sha256": qualification.identifier(self.name), "count": 9, "fail_at": 2,
            "completed_cases": [0, 1], "elapsed_seconds": 15.25, "timeout_seconds": 15,
            "boundary": "invoke", "exception_category": "timeout", "errno": None, "exit_code": None,
            "stdout": {"state": "partial", "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
            "stderr": {"state": "unavailable", "bytes": None, "sha256": None},
        }
        valid = self.prefix + json.dumps(value).encode() + b"\n"
        self.assertEqual({"state": "unavailable"}, self.project(header)["reports"][0]["powershell_fixture"])
        self.assertEqual({"state": "available", **value},
                         self.project(header + valid)["reports"][0]["powershell_fixture"])
        mutations = (
            {"test_id_sha256": "a" * 64}, {"test_id_sha256": MARKER}, {"count": 1}, {"count": True},
            {"fail_at": True}, {"fail_at": -1}, {"fail_at": 10}, {"completed_cases": [0]},
            {"completed_cases": [1, 0]}, {"completed_cases": [False, 1]}, {"completed_cases": list(range(20))},
            {"elapsed_seconds": -1}, {"elapsed_seconds": float("nan")}, {"elapsed_seconds": float("inf")},
            {"elapsed_seconds": True}, {"timeout_seconds": 16}, {"timeout_seconds": True},
            {"boundary": MARKER}, {"exception_category": MARKER}, {"errno": True}, {"errno": 2 ** 40},
            {"exit_code": True}, {"exit_code": -(2 ** 40)}, {"exit_code": MARKER}, {"extra": MARKER},
            {"stdout": {"state": "partial", "bytes": True, "sha256": "a" * 64}},
            {"stdout": {"state": "partial", "bytes": -1, "sha256": "a" * 64}},
            {"stdout": {"state": "partial", "bytes": 2 ** 64, "sha256": "a" * 64}},
            {"stdout": {"state": "partial", "bytes": 1, "sha256": MARKER}},
            {"stdout": {"state": "partial", "bytes": 0, "sha256": "a" * 64}},
            {"stdout": {"state": "unavailable", "bytes": 0, "sha256": None}},
            {"stdout": {"state": "complete", "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}},
            {"stdout": {"state": "partial", "bytes": 1, "sha256": "a" * 64, "raw": MARKER}},
            {"stdout": MARKER}, {"stderr": None},
        )
        invalid = [self.prefix + json.dumps({**value, **mutation}).encode() + b"\n" for mutation in mutations]
        invalid.extend((
            self.prefix + b"{\n", self.prefix + b"[]\n", valid + valid,
            self.prefix + b"{\n" + valid, valid + self.prefix + b"{\n",
            self.prefix + b"\xff\n", self.prefix + b"[" * 1000 + b"]" * 1000 + b"\n",
            valid.replace(b"FIXTURE_V1", b"FIXTURE_V2"),
            self.prefix + b" " * 2049 + b"\n",
            self.prefix + json.dumps(value).replace('"count": 9', '"count": 9, "count": 9').encode() + b"\n",
        ))
        for index, note in enumerate(invalid):
            with self.subTest(index=index):
                row = self.project(header + note)
                self.assertEqual({"state": "malformed"}, row["reports"][0]["powershell_fixture"])
                self.assertTrue(row["diagnostic_only"])
                self.assertEqual("ERROR", row["reports"][0]["reported_status"])
        wrong = "test_unrelated.Example.test_other"
        wrong_header = f"ERROR: test_other ({wrong})\n".encode()
        self.assertNotIn("powershell_fixture", self.project(wrong_header + valid, name=wrong)["reports"][0])
        self.assertNotIn("powershell_fixture", self.project(header + valid, suite="scripts")["reports"][0])

    def test_real_private_discovery_transports_helper_errors_before_cleanup_without_outcome_admission(self):
        for mode, fail_at, category in (("timeout", 2, "timeout"), ("os-error", 7, "os-error")):
            code = (
                "import subprocess\nimport sys\nimport unittest\nfrom unittest import mock\n"
                f"sys.path.insert(0, {str(support.GOVERNANCE / 'tests')!r})\n"
                "import conformance_support as support\n\n"
                "class ApiWindowsWorkflowTests(unittest.TestCase):\n"
                f"    def {self.name.rsplit('.', 1)[-1]}(self):\n"
                "        def run(command, **options):\n"
                "            current = int(options['env']['FAIL_AT'])\n"
                f"            if current == {fail_at}:\n"
                + (f"                raise subprocess.TimeoutExpired({MARKER!r}, 15, output={self.private_bytes!r})\n"
                   if mode == "timeout" else f"                raise OSError(13, {MARKER!r}, {MARKER!r})\n") +
                "            output = ''.join(f'{number}\\n' for number in range(1, (current or 9) + 1)).encode()\n"
                "            return subprocess.CompletedProcess(command, 37 if current else 0, output, b'')\n"
                "        with mock.patch.object(support.shutil, 'which', return_value='pwsh-fixture'), "
                "mock.patch.object(support.subprocess, 'run', side_effect=run):\n"
                "            support.assert_powershell_failure_boundaries(self, 'synthetic source', 9)\n"
            )
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="infra-private-helper-") as temporary:
                root = Path(temporary)
                path = root / "governance" / "tests" / "test_api_windows_qualification.py"
                path.parent.mkdir(parents=True)
                path.write_text(code, encoding="utf-8")
                reports, rows = [], []
                original_run = subprocess.run

                def run(command, **options):
                    reports.append(Path(command[3]))
                    return original_run(command, **options)

                def emit(event, **values):
                    if event == "ordinary_discovery_diagnostics":
                        self.assertTrue(reports[0].is_file(), "diagnostic projection must precede capture cleanup")
                        self.assertIn(self.prefix, reports[0].read_bytes())
                    rows.append({"event": event, **values})

                with mock.patch.dict(os.environ, support.defects.probe_environment(), clear=True), \
                        mock.patch.object(qualification, "ROOT", root), \
                        mock.patch.object(sys, "argv", ["qualify.py", "--", "python", "-m", "unittest",
                                                       "discover", "-s", "governance/tests"]), \
                        mock.patch.object(qualification, "versions", return_value={"image_version": "synthetic"}), \
                        mock.patch.object(qualification, "source_inventory", return_value=SOURCE), \
                        mock.patch.object(qualification, "discovery_inventory",
                                          return_value={qualification.identifier(self.name): self.name}), \
                        mock.patch.object(qualification.subprocess, "run", side_effect=run), \
                        mock.patch.object(qualification, "python_outcomes") as admission, \
                        mock.patch.object(qualification, "emit", side_effect=emit):
                    self.assertEqual(1, qualification.main())
                    admission.assert_not_called()
                self.assertEqual(1, len(reports))
                self.assertFalse(reports[0].parent.exists())
                self.assertEqual([1], [row["exit_code"] for row in rows if row["event"] == "ordinary_discovery"])
                diagnostic = next(row for row in rows if row["event"] == "ordinary_discovery_diagnostics")
                observation = diagnostic["reports"][0]["powershell_fixture"]
                self.assertEqual(("available", category, fail_at),
                                 tuple(observation[key] for key in ("state", "exception_category", "fail_at")))
                self.assertEqual("ordinary-discovery-or-setup-teardown-failed", rows[-1]["code"])
                self.assertFalse(any(row["event"] in ("test_outcome", "infra_qualification") for row in rows))
                for private in (MARKER, str(root), self.name, "\x1b"):
                    self.assertNotIn(private, json.dumps(rows))


class InfraDiscoveryTests(unittest.TestCase):
    def exercise(self, system, suite, *, statuses=None, missing=False, exit_code=0, cleanup=True,
                 changed_source=False, report=True, summary=None, extra_names=(), omitted=()):
        names = sorted(qualification.REQUIRED[suite] | {"test_fixture.Example.test_extra"} | set(extra_names))
        inventory = {qualification.identifier(name): name for name in names}
        allowed = qualification.SKIPS[system][suite]
        statuses = statuses or {}
        observed = [name for name in (names[:-1] if missing else names) if name not in omitted]
        lines = []
        for name in observed:
            status = statuses.get(name, "skipped 'platform'" if name in allowed else "ok")
            lines.append(f"{name.rsplit('.', 1)[-1]} ({name}) ... {status}")
        skipped = sum(line.rsplit(" ... ", 1)[-1].startswith("skipped ") for line in lines)
        if summary is None:
            summary = f"OK (skipped={skipped})" if skipped else "OK"
        lines.append(f"\nRan {len(observed)} tests in 0.001s\n\n{summary}\n")
        output = io.StringIO()

        def run(command, **options):
            self.assertEqual([sys.executable, "-c", qualification.UNITTEST_DISCOVERY,
                              command[3], str(Path(suite) / "tests")], command)
            self.assertEqual("1" if system == "win32" and suite == "scripts" else None,
                             os.environ.get("PENNILOGIC_SKIP_DOCKER_TESTS"))
            if report:
                Path(command[3]).write_bytes("\n".join(lines).encode())
            else:
                options["stderr"].write("\n".join(lines).encode())
            options["stderr"].write(MARKER.encode() + b"\xff\n")
            if cleanup and system == "linux" and suite == "scripts":
                for suffix in ("", "-conflict", "-bind", "-race"):
                    value = {"project": "pennilogic-test-01234567" + suffix, "containers": 0, "volumes": 0, "networks": 0}
                    options["stdout"].write(b"INFRA_STACK_CLEANUP " + json.dumps(value).encode() + b"\n")
                options["stdout"].write(b'INFRA_STACK_CLEANUP_TEMP {"project":"pennilogic-test-01234567","removed":true}\n')
            options["stdout"].write(MARKER.encode() + b"\xff\n")
            return subprocess.CompletedProcess(command, exit_code)

        with tempfile.TemporaryDirectory(prefix="infra-discovery-control-") as temporary, \
                mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(qualification.sys, "platform", system), \
                mock.patch.object(qualification, "versions", return_value={"image_version": "fixture-not-native"}), \
                mock.patch.object(qualification, "source_inventory", side_effect=[SOURCE, SOURCE if not changed_source else None]), \
                mock.patch.object(qualification, "discovery_inventory", return_value=inventory), \
                mock.patch.object(qualification.subprocess, "run", side_effect=run) as child, \
                contextlib.redirect_stdout(output):
            try:
                qualification.qualify(Path(temporary), suite)
            finally:
                self.assertEqual(1, child.call_count)
                self.assertNotIn(MARKER, output.getvalue())
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_full_ordinary_commands_and_exact_inventory_are_checked_on_both_platforms(self):
        for system in ("win32", "linux"):
            for suite in ("governance", "scripts"):
                with self.subTest(system=system, suite=suite):
                    records = self.exercise(system, suite)
                    inventory = {row["id_sha256"] for row in records if row["event"] == "test_inventory"}
                    outcomes = {row["id_sha256"] for row in records if row["event"] == "test_outcome"}
                    self.assertEqual(inventory, outcomes)
                    self.assertTrue(records[-1]["ok"])
                    self.assertEqual(len(qualification.SKIPS[system][suite]), records[-1]["skipped"])

    def test_windows_security_ids_have_only_their_exact_linux_skips_and_windows_passes(self):
        self.assertEqual(WINDOWS_SECURITY_IDS, qualification.WINDOWS_SECURITY)
        for system, status, expected in (("win32", "ok", "passed"), ("linux", "skipped 'Windows only'", "skipped")):
            with self.subTest(system=system):
                records = self.exercise(system, "scripts", statuses=dict.fromkeys(WINDOWS_SECURITY_IDS, status))
                outcomes = {row["id_sha256"]: row["outcome"] for row in records if row["event"] == "test_outcome"}
                for name in WINDOWS_SECURITY_IDS:
                    self.assertEqual(expected, outcomes[qualification.identifier(name)])
                self.assertTrue(records[-1]["ok"])
        self.assertTrue(WINDOWS_SECURITY_IDS.isdisjoint(qualification.SKIPS["win32"]["scripts"]))
        self.assertEqual(qualification.WINDOWS_SCRIPTS | WINDOWS_SECURITY_IDS,
                         qualification.SKIPS["linux"]["scripts"])

    def test_missing_security_ids_cannot_be_hidden_from_discovery_or_its_result(self):
        class InventoryCase(unittest.TestCase):
            def __init__(self, name):
                super().__init__()
                self.name = name

            def id(self):
                return self.name

            def runTest(self):
                self.fail("inventory must not execute test bodies")

        for system in ("win32", "linux"):
            for missing in sorted(WINDOWS_SECURITY_IDS):
                loader = mock.Mock(errors=[])
                loader.discover.return_value = unittest.TestSuite(
                    InventoryCase(name) for name in sorted(qualification.REQUIRED["scripts"] - {missing})
                )
                with self.subTest(system=system, missing=missing), \
                        mock.patch.object(qualification.sys, "platform", system), \
                        mock.patch.object(qualification.unittest, "TestLoader", return_value=loader):
                    with self.assertRaisesRegex(qualification.Refused, "full-discovery-inventory-is-incomplete"):
                        qualification.discovery_inventory(Path.cwd(), "scripts")
                with self.subTest(system=system, omitted=missing), \
                        self.assertRaisesRegex(qualification.Refused, "executed-test-ids-differ-from-full-discovery"):
                    self.exercise(system, "scripts", omitted={missing})

    def test_wrong_platform_extra_skip_and_false_green_security_outcomes_are_refused(self):
        for system, wrong in (("win32", "skipped 'not admitted'"), ("linux", "ok")):
            for name in sorted(WINDOWS_SECURITY_IDS):
                for status in (wrong, "FAIL", "ERROR", "expected failure", "unexpected success"):
                    with self.subTest(system=system, name=name, status=status), \
                            self.assertRaises(qualification.Refused):
                        self.exercise(system, "scripts", statuses={name: status})
            for name in ("test_security_controls.ScannerBoundaryTests.test_unknown",
                         "test_unrelated.Example.test_other"):
                with self.subTest(system=system, unknown=name), \
                        self.assertRaisesRegex(qualification.Refused, "test-outcome-differs-from-exact-platform"):
                    self.exercise(system, "scripts", extra_names={name}, statuses={name: "skipped 'unknown'"})

    def test_required_security_platform_ids_match_the_actual_three_decorated_methods(self):
        source = ast.parse((support.GOVERNANCE.parent / "scripts/tests/test_security_controls.py").read_text(
            encoding="utf-8",
        ))
        actual = set()
        for cls in source.body:
            if isinstance(cls, ast.ClassDef):
                for method in cls.body:
                    if isinstance(method, ast.FunctionDef) and any(
                        "skipUnless" in ast.unparse(decorator) for decorator in method.decorator_list
                    ):
                        self.assertEqual(["unittest.skipUnless(os.name == 'nt', "],
                                         [ast.unparse(decorator).split(", ", 1)[0] + ", "
                                          for decorator in method.decorator_list])
                        actual.add("test_security_controls." + cls.name + "." + method.name)
        self.assertEqual(WINDOWS_SECURITY_IDS, actual)

    def test_linux_process_ids_have_exact_platform_outcomes(self):
        for system, status, expected in (("win32", LINUX_PROCESS_SKIP, "skipped"), ("linux", "ok", "passed")):
            with self.subTest(system=system):
                records = self.exercise(
                    system, "governance", extra_names=LINUX_PROCESS_IDS,
                    statuses=dict.fromkeys(LINUX_PROCESS_IDS, status),
                )
                outcomes = {row["id_sha256"]: row["outcome"] for row in records if row["event"] == "test_outcome"}
                for name in LINUX_PROCESS_IDS:
                    self.assertEqual(expected, outcomes[qualification.identifier(name)])
                self.assertTrue(records[-1]["ok"])
                if system == "win32":
                    self.assertEqual(LINUX_PROCESS_IDS, qualification.SKIPS[system]["governance"])
                    self.assertEqual(2, records[-1]["skipped"])
                else:
                    self.assertTrue(LINUX_PROCESS_IDS.isdisjoint(qualification.SKIPS[system]["governance"]))

    def test_full_inventory_requires_each_linux_process_id_on_both_platforms(self):
        class InventoryCase(unittest.TestCase):
            def __init__(self, name):
                super().__init__()
                self.name = name

            def id(self):
                return self.name

            def runTest(self):
                self.fail("inventory must not execute test bodies")

        names = qualification.REQUIRED["governance"] | LINUX_PROCESS_IDS
        omissions = [set(), set(LINUX_PROCESS_IDS)] + [{name} for name in sorted(LINUX_PROCESS_IDS)]
        for system in ("win32", "linux"):
            for omitted in omissions:
                loader = mock.Mock(errors=[])
                loader.discover.return_value = unittest.TestSuite(InventoryCase(name) for name in sorted(names - omitted))
                with self.subTest(system=system, omitted=sorted(omitted)), \
                        mock.patch.object(qualification.sys, "platform", system), \
                        mock.patch.object(qualification.unittest, "TestLoader", return_value=loader):
                    if omitted:
                        with self.assertRaisesRegex(qualification.Refused, "full-discovery-inventory-is-incomplete"):
                            qualification.discovery_inventory(Path.cwd(), "governance")
                    else:
                        inventory = qualification.discovery_inventory(Path.cwd(), "governance")
                        self.assertEqual(names, set(inventory.values()))

    def test_linux_process_outcomes_cannot_be_omitted_on_either_platform(self):
        for system, status in (("win32", LINUX_PROCESS_SKIP), ("linux", "ok")):
            for name in sorted(LINUX_PROCESS_IDS):
                with self.subTest(system=system, name=name), \
                        self.assertRaisesRegex(qualification.Refused, "executed-test-ids-differ-from-full-discovery"):
                    self.exercise(system, "governance", extra_names=LINUX_PROCESS_IDS, omitted={name},
                                  statuses=dict.fromkeys(LINUX_PROCESS_IDS, status))

    def test_linux_process_wrong_platform_outcomes_refuse_even_with_zero_exit(self):
        for system, status, wrong in (("win32", LINUX_PROCESS_SKIP, "ok"), ("linux", "ok", LINUX_PROCESS_SKIP)):
            for name in sorted(LINUX_PROCESS_IDS):
                for invalid in (wrong, "FAIL", "ERROR", "expected failure", "unexpected success"):
                    statuses = {**dict.fromkeys(LINUX_PROCESS_IDS, status), name: invalid}
                    with self.subTest(system=system, name=name, invalid=invalid), \
                            self.assertRaisesRegex(qualification.Refused, "test-outcome-differs-from-exact-platform-applicability"):
                        self.exercise(system, "governance", extra_names=LINUX_PROCESS_IDS, statuses=statuses)

    def test_unknown_linux_class_and_unrelated_skips_remain_refused(self):
        for system, status in (("win32", LINUX_PROCESS_SKIP), ("linux", "ok")):
            for name in ("test_conformance_processes.LinuxProcessTests.test_unknown", "test_fixture.Example.test_extra"):
                with self.subTest(system=system, name=name), \
                        self.assertRaisesRegex(qualification.Refused, "test-outcome-differs-from-exact-platform-applicability"):
                    self.exercise(system, "governance", extra_names=LINUX_PROCESS_IDS | {name},
                                  statuses={**dict.fromkeys(LINUX_PROCESS_IDS, status), name: LINUX_PROCESS_SKIP})

    def test_linux_process_nonzero_failures_remain_primary_on_both_platforms(self):
        for system, status in (("win32", LINUX_PROCESS_SKIP), ("linux", "ok")):
            for name in sorted(LINUX_PROCESS_IDS):
                for invalid, kind in (("FAIL", "failures"), ("ERROR", "errors")):
                    with self.subTest(system=system, name=name, invalid=invalid), \
                            mock.patch.object(qualification, "python_outcomes") as parser:
                        with self.assertRaisesRegex(qualification.Refused, "ordinary-discovery-or-setup-teardown-failed"):
                            self.exercise(
                                system, "governance", extra_names=LINUX_PROCESS_IDS, exit_code=1,
                                statuses={**dict.fromkeys(LINUX_PROCESS_IDS, status), name: invalid},
                                summary=f"FAILED ({kind}=1)",
                            )
                        parser.assert_not_called()

    def test_missing_failed_skipped_cleanup_and_setup_teardown_results_refuse(self):
        cases = [
            ("win32", "governance", {"statuses": {next(iter(qualification.NATIVE_LINKS)): "skipped 'privilege'"}}),
            ("win32", "scripts", {"statuses": {next(iter(qualification.WINDOWS_SCRIPTS)): "skipped 'fixture'"}}),
            ("linux", "scripts", {"statuses": {next(iter(qualification.STACK_TESTS)): "skipped 'Docker unavailable'"}}),
            ("linux", "scripts", {"cleanup": False}),
            ("linux", "governance", {"statuses": {"test_fixture.Example.test_extra": "FAIL"}}),
            ("linux", "governance", {"missing": True}),
            ("linux", "governance", {"exit_code": 1}),
            ("linux", "governance", {"changed_source": True}),
            ("linux", "governance", {"report": False}),
            ("linux", "governance", {"summary": "FAILED (failures=1)"}),
            ("linux", "governance", {"summary": "OK"}),
            ("linux", "governance", {"summary": "OK (skipped=0)"}),
            ("linux", "governance", {"summary": "OK (expected failures=1)"}),
            ("linux", "governance", {"summary": ""}),
        ]
        for system, suite, options in cases:
            with self.subTest(system=system, suite=suite, options=options), self.assertRaises(qualification.Refused):
                self.exercise(system, suite, **options)

    def test_ambient_docker_skip_and_command_selectors_never_start_tests(self):
        with mock.patch.dict(os.environ, {"PENNILOGIC_SKIP_DOCKER_TESTS": "1"}), \
                mock.patch.object(qualification, "versions") as versions:
            with self.assertRaisesRegex(qualification.Refused, "ambient-docker"):
                qualification.qualify(Path.cwd(), "governance")
            versions.assert_not_called()
        for suffix in ([], ["-k", "test_only"], [MARKER]):
            arguments = ["qualify.py", "--", "python", "-m", "unittest", "discover", "-s", "unknown/tests", *suffix]
            output = io.StringIO()
            with mock.patch.object(sys, "argv", arguments), mock.patch.object(qualification, "qualify") as child, \
                    contextlib.redirect_stdout(output):
                self.assertEqual(1, qualification.main())
                child.assert_not_called()
            self.assertNotIn(MARKER, output.getvalue())

    def test_source_inventory_requires_clean_full_history_and_the_native_sha(self):
        listing = b"".join(b"100644 blob " + b"c" * 40 + b"\t" + name.encode() + b"\0"
                           for name in sorted(qualification.SECURITY_SOURCE_FILES | {"unrelated/file.txt"}))
        replies = [b"a" * 40 + b"\n", b"false\n", b"", b"b" * 40 + b"\n",
                   listing]
        with mock.patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}), \
                mock.patch.object(qualification, "security_tools", return_value={"git": "bound-git"}), \
                mock.patch.object(qualification, "checked", side_effect=replies) as probe:
            head, tree, files = qualification.source_inventory(Path.cwd())
        self.assertEqual(("a" * 40, "b" * 40), (head, tree))
        self.assertEqual(len(qualification.SECURITY_SOURCE_FILES) + 1, len(files))
        self.assertTrue(all(call.args[0][0] == "bound-git" for call in probe.call_args_list))
        for index, value in ((0, b"d" * 40), (1, b"true\n"), (2, b" M private-file"), (4, b"")):
            changed = list(replies)
            changed[index] = value
            with mock.patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}), \
                    mock.patch.object(qualification, "security_tools", return_value={"git": "bound-git"}), \
                    mock.patch.object(qualification, "checked", side_effect=changed), \
                    self.subTest(index=index), self.assertRaises(qualification.Refused):
                qualification.source_inventory(Path.cwd())

    def test_source_inventory_requires_the_whole_security_closure_not_changed_files_only(self):
        for missing in sorted(qualification.SECURITY_SOURCE_FILES):
            listing = b"".join(b"100644 blob " + b"c" * 40 + b"\t" + name.encode() + b"\0"
                               for name in sorted(qualification.SECURITY_SOURCE_FILES - {missing}))
            with self.subTest(missing=missing), mock.patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}), \
                    mock.patch.object(qualification, "security_tools", return_value={"git": "bound-git"}), \
                    mock.patch.object(qualification, "checked", side_effect=[
                        b"a" * 40, b"false", b"", b"b" * 40, listing,
                    ]), self.assertRaisesRegex(qualification.Refused, "security-source-closure-is-incomplete"):
                qualification.source_inventory(Path.cwd())

    def test_security_closure_contains_static_local_imports_and_the_dynamic_windows_helpers(self):
        root = support.GOVERNANCE.parent
        self.assertTrue({
            "scripts/bootstrap.py", "scripts/smoke_infra.py", "governance/repository-profiles.json",
            "security/gitleaks.toml", "security/exceptions.json", "security/exceptions.schema.json",
        } <= qualification.SECURITY_SOURCE_FILES)
        for relative in sorted(qualification.SECURITY_SOURCE_FILES):
            path = root / relative
            self.assertTrue(path.is_file(), relative)
            if path.suffix != ".py" or "tests" in path.parts:
                continue
            candidates = set()
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    candidates.update(name.name for name in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    candidates.add(node.module)
                    candidates.update(node.module + "." + name.name for name in node.names)
            for name in candidates:
                for prefix in (root / "scripts", root / "governance"):
                    module = prefix.joinpath(*name.split("."))
                    for dependency in (module.with_suffix(".py"), module / "__init__.py"):
                        if dependency.is_file():
                            self.assertIn(dependency.relative_to(root).as_posix(), qualification.SECURITY_SOURCE_FILES)

    def test_real_synthetic_full_discovery_and_class_teardown_failure_are_not_counts_only(self):
        module = "test_qualification_owned_fixture"
        names = {f"{module}.Example.test_first", f"{module}.Example.test_second"}
        code = (
            "import unittest\nfrom pathlib import Path\n\nclass Example(unittest.TestCase):\n"
            f"    def test_first(self):\n        '''{MARKER}'''\n"
            "        Path(__file__).with_suffix('.executed').write_text('executed')\n"
            "        self.assertTrue(True)\n"
            "    def test_second(self):\n        self.assertEqual(1, 1)\n"
        )
        with tempfile.TemporaryDirectory(prefix="infra-real-discovery-") as temporary:
            root = Path(temporary)
            directory = root / "governance" / "tests"
            directory.mkdir(parents=True)
            path = directory / (module + ".py")
            try:
                for teardown_failure in (False, True):
                    path.write_text(code + (
                        f"    @classmethod\n    def tearDownClass(cls):\n        raise RuntimeError('{MARKER}')\n"
                        if teardown_failure else ""
                    ), encoding="utf-8")
                    executed = path.with_suffix(".executed")
                    executed.unlink(missing_ok=True)
                    output = io.StringIO()
                    with mock.patch.dict(os.environ, {}, clear=True), \
                            mock.patch.object(qualification, "versions", return_value={"image_version": "synthetic"}), \
                            mock.patch.object(qualification, "source_inventory", return_value=SOURCE), \
                            mock.patch.object(qualification, "REQUIRED", {"governance": names}), \
                            mock.patch.object(qualification, "SKIPS", {sys.platform: {"governance": set()}}), \
                            contextlib.redirect_stdout(output):
                        inventory = qualification.discovery_inventory(root, "governance")
                        self.assertEqual(names, set(inventory.values()))
                        self.assertFalse(executed.exists(), "inventory must not run a test body")
                        if teardown_failure:
                            with self.assertRaisesRegex(qualification.Refused, "setup-teardown"):
                                qualification.qualify(root, "governance")
                        else:
                            qualification.qualify(root, "governance")
                    self.assertTrue(executed.is_file(), "ordinary discovery must execute its test bodies")
                    rows = [json.loads(line) for line in output.getvalue().splitlines()]
                    self.assertEqual(0 if teardown_failure else 2, sum(row["event"] == "test_outcome" for row in rows))
                    self.assertNotIn(MARKER, output.getvalue())
                    if teardown_failure:
                        self.assertNotIn('"ok": true', output.getvalue())
            finally:
                sys.modules.pop(module, None)

    def test_real_failed_discovery_reports_only_known_diagnostic_ids_and_source_locations(self):
        module = "test_qualification_failure_fixture"
        names = {f"{module}.Example.test_first", f"{module}.Example.test_second"}
        relative = f"governance/tests/{module}.py"
        path_digest = qualification.identifier(relative)
        source = (SOURCE[0], SOURCE[1], [
            {"path_sha256": path_digest, "mode": "100644", "git_blob": "d" * 40},
        ])
        for phase in ("test", "setUpClass", "tearDownClass", "setUpModule", "tearDownModule"):
            code = "import sys\nimport unittest\n\n"
            if phase.endswith("Module"):
                code += f"def {phase}():\n    raise RuntimeError('{MARKER}')\n\n"
            code += "class Example(unittest.TestCase):\n"
            if phase.endswith("Class"):
                code += f"    @classmethod\n    def {phase}(cls):\n        raise RuntimeError('{MARKER}')\n"
            code += "    def test_first(self):\n"
            code += (f"        sys.stderr.write('{MARKER}\\nok\\n')\n"
                     f"        self.fail('{MARKER}')\n" if phase == "test" else "        self.assertTrue(True)\n")
            code += "    def test_second(self):\n        self.assertTrue(True)\n"
            line = next(index for index, text in enumerate(code.splitlines(), 1)
                        if "raise RuntimeError" in text or "self.fail(" in text)
            identity = f"{module}.Example.test_first" if phase == "test" else (
                f"{module}.Example" if phase.endswith("Class") else module
            )
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(prefix="infra-failure-diagnostic-") as temporary:
                root = Path(temporary)
                fixture = root / relative
                fixture.parent.mkdir(parents=True)
                fixture.write_text(code, encoding="utf-8")
                output = io.StringIO()
                with mock.patch.dict(os.environ, {}, clear=True), mock.patch.dict(sys.modules), \
                        mock.patch.object(sys, "path", sys.path[:]), \
                        mock.patch.object(qualification, "ROOT", root), \
                        mock.patch.object(sys, "argv", ["qualify.py", "--", "python", "-m", "unittest",
                                                       "discover", "-s", "governance/tests"]), \
                        mock.patch.object(qualification, "versions", return_value={"image_version": "synthetic"}), \
                        mock.patch.object(qualification, "source_inventory", return_value=source), \
                        mock.patch.object(qualification, "REQUIRED", {"governance": names}), \
                        contextlib.redirect_stdout(output):
                    self.assertEqual(1, qualification.main())
                rows = [json.loads(text) for text in output.getvalue().splitlines()]
                self.assertEqual([1], [row["exit_code"] for row in rows if row["event"] == "ordinary_discovery"])
                diagnostics = [row for row in rows if row["event"] == "ordinary_discovery_diagnostics"]
                self.assertEqual(1, len(diagnostics))
                self.assertEqual({
                    "event": "ordinary_discovery_diagnostics", "suite": "governance", "diagnostic_only": True,
                    "unrecognized_headers": 0, "truncated": False,
                    "reports": [{
                        "reported_status": "FAIL" if phase == "test" else "ERROR", "scope": phase,
                        "reported_id_sha256": qualification.identifier(identity),
                        "source_frames": [{"path_sha256": path_digest, "line": line}],
                    }],
                }, diagnostics[0])
                self.assertEqual("ordinary-discovery-or-setup-teardown-failed", rows[-1]["code"])
                self.assertFalse(any(row["event"] in ("test_outcome", "infra_qualification") for row in rows))
                self.assertNotIn(MARKER, output.getvalue())
                self.assertNotIn(str(root), output.getvalue())
                self.assertNotIn(module, output.getvalue())

    def test_failure_diagnostic_hints_are_bounded_source_scoped_and_never_outcomes(self):
        name = "test_fixture.Example.test_case"
        relative = "governance/tests/test_fixture.py"
        inventory = {qualification.identifier(name): name, qualification.identifier("opaque"): "opaque"}
        files = [{"path_sha256": qualification.identifier(relative)}]
        with tempfile.TemporaryDirectory(prefix="infra-diagnostic-scope-") as temporary:
            root = Path(temporary)
            header = f"FAIL: test_case ({name}) (payload='{MARKER}')\n"
            frames = "".join(f'  File "{root / relative}", line {line}, in test_case\n' for line in range(1, 10))
            data = (
                header +
                f'  File "{root.parent / "outside.py"}", line 1, in {MARKER}\n' +
                f'  File "{root / "untracked.py"}", line 1, in {MARKER}\n' +
                frames + f"AssertionError: {MARKER}\n" +
                (header + frames) * 20 +
                f"ERROR: test_unknown (test_unknown.Example.test_unknown)\n" +
                f"FAIL: test_wrong ({name})\nFAIL: {MARKER}\n"
            ).encode() + b"\xff\n"
            output = io.StringIO()
            with contextlib.redirect_stdout(output), mock.patch.object(qualification, "python_outcomes") as parser:
                qualification.discovery_diagnostics(root, "governance", data, inventory, files)
                parser.assert_not_called()
            row = json.loads(output.getvalue())
            self.assertTrue(row["diagnostic_only"])
            self.assertTrue(row["truncated"])
            self.assertEqual(3, row["unrecognized_headers"])
            self.assertEqual(20, len(row["reports"]))
            for report in row["reports"]:
                self.assertEqual("FAIL", report["reported_status"])
                self.assertEqual(qualification.identifier(name), report["reported_id_sha256"])
                self.assertEqual([
                    {"path_sha256": qualification.identifier(relative), "line": number} for number in range(1, 9)
                ], report["source_frames"])
            for value in (MARKER, str(root), "test_fixture", "outside.py", "untracked.py", '"ok"', '"outcome"'):
                self.assertNotIn(value, output.getvalue())

    def test_nonzero_discovery_is_primary_and_does_not_consult_outcome_admission(self):
        with mock.patch.object(qualification, "python_outcomes") as parser:
            with self.assertRaisesRegex(qualification.Refused, "ordinary-discovery-or-setup-teardown-failed"):
                self.exercise("linux", "governance", exit_code=9)
            parser.assert_not_called()

    def reporting_fixture(self, source, *, suite="governance", system=None, allowed=(),
                          warning_policy=None, ordinary_expected=None):
        system = system or sys.platform
        module = "test_reporting_fixture"
        names = {f"{module}.Example.test_first", f"{module}.Example.test_second"}
        with tempfile.TemporaryDirectory(prefix="infra-reporting-") as temporary:
            root = Path(temporary)
            path = root / suite / "tests" / (module + ".py")
            path.parent.mkdir(parents=True)
            path.write_text(source, encoding="utf-8")
            output = io.StringIO()
            environment = {} if warning_policy is None else {"PYTHONWARNINGS": warning_policy}
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.dict(sys.modules), \
                    mock.patch.object(sys, "path", sys.path[:]), mock.patch.object(sys, "platform", system), \
                    mock.patch.object(qualification, "ROOT", root), \
                    mock.patch.object(sys, "argv", ["qualify.py", "--", "python", "-m", "unittest",
                                                   "discover", "-s", f"{suite}/tests"]), \
                    mock.patch.object(qualification, "versions", return_value={"image_version": "synthetic"}), \
                    mock.patch.object(qualification, "source_inventory", return_value=SOURCE), \
                    mock.patch.object(qualification, "REQUIRED", {suite: names}), \
                    mock.patch.object(qualification, "SKIPS", {system: {suite: set(allowed)}}), \
                    contextlib.redirect_stdout(output):
                if ordinary_expected is not None:
                    ordinary = subprocess.run(
                        [sys.executable, "-m", "unittest", "discover", "-s", str(path.parent), "-v"],
                        cwd=root, capture_output=True, check=False, timeout=15,
                    )
                    self.assertEqual(ordinary_expected, (ordinary.returncode, ordinary.stderr.splitlines()[-1]))
                code = qualification.main()
            self.assertNotIn(MARKER, output.getvalue())
            self.assertNotIn(str(root), output.getvalue())
            return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_real_warning_policies_match_ordinary_unittest_discovery(self):
        cases = []
        for policy, observed in ((None, 1), ("default", 1), ("ignore", 0)):
            for expected in (0, 1):
                body = ("with warnings.catch_warnings(record=True) as caught:\n"
                        f"            warnings.warn('{MARKER}', ResourceWarning)\n"
                        f"        self.assertEqual({expected}, len(caught))")
                cases.append((policy, body, None if observed == expected else "failures"))
        cases.extend((
            ("error", f"warnings.warn('{MARKER}', ResourceWarning)", "errors"),
            ("error", "with self.assertRaises(ResourceWarning):\n"
             f"            warnings.warn('{MARKER}', ResourceWarning)", None),
        ))
        for policy, body, failure in cases:
            source = ("import unittest\nimport warnings\n\nclass Example(unittest.TestCase):\n"
                      f"    def test_first(self):\n        {body}\n"
                      "    def test_second(self):\n        self.assertTrue(True)\n")
            expected_exit = int(failure is not None)
            summary = f"FAILED ({failure}=1)".encode() if failure else b"OK"
            with self.subTest(policy=policy, body=body):
                code, rows = self.reporting_fixture(
                    source, warning_policy=policy, ordinary_expected=(expected_exit, summary),
                )
                self.assertEqual(expected_exit, code)
                self.assertEqual([expected_exit],
                                 [row["exit_code"] for row in rows if row["event"] == "ordinary_discovery"])
                if failure:
                    self.assertFalse(any(row["event"] in ("test_outcome", "infra_qualification") for row in rows))
                    hints = next(row for row in rows if row["event"] == "ordinary_discovery_diagnostics")
                    self.assertEqual(["ERROR" if failure == "errors" else "FAIL"],
                                     [report["reported_status"] for report in hints["reports"]])
                else:
                    self.assertEqual(["passed", "passed"],
                                     [row["outcome"] for row in rows if row["event"] == "test_outcome"])
                    self.assertEqual(
                        {row["id_sha256"] for row in rows if row["event"] == "test_inventory"},
                        {row["id_sha256"] for row in rows if row["event"] == "test_outcome"},
                    )
                    self.assertTrue(rows[-1]["ok"])

    def test_real_diagnostics_do_not_share_the_stdlib_result_stream(self):
        for phase in ("test", "setUpClass", "tearDownClass", "setUpModule", "tearDownModule"):
            for diagnostic in (f"{MARKER}\n", "ok\n", f"{MARKER}\nok\n"):
                write = f"sys.stderr.buffer.write({diagnostic.encode()!r}); os.write(2, {diagnostic.encode()!r})"
                source = "import os\nimport sys\nimport unittest\n\n"
                if phase.endswith("Module"):
                    source += f"def {phase}():\n    {write}\n\n"
                source += "class Example(unittest.TestCase):\n"
                if phase.endswith("Class"):
                    source += f"    @classmethod\n    def {phase}(cls):\n        {write}\n"
                source += (f"    def test_first(self):\n        '''{MARKER}'''\n"
                           f"        {write if phase == 'test' else 'pass'}\n"
                           "    def test_second(self):\n        self.assertTrue(True)\n")
                with self.subTest(phase=phase, diagnostic=diagnostic):
                    code, rows = self.reporting_fixture(source)
                    self.assertEqual(0, code)
                    self.assertEqual([0], [row["exit_code"] for row in rows if row["event"] == "ordinary_discovery"])
                    self.assertEqual(["passed", "passed"],
                                     [row["outcome"] for row in rows if row["event"] == "test_outcome"])
                    self.assertEqual(
                        {row["id_sha256"] for row in rows if row["event"] == "test_inventory"},
                        {row["id_sha256"] for row in rows if row["event"] == "test_outcome"},
                    )
                    self.assertTrue(rows[-1]["ok"])

    def test_real_separated_reports_preserve_adverse_outcomes_and_exact_allowed_skips(self):
        for body, decorator, expected_exit in (
            (f"self.skipTest('{MARKER}')", "", 0),
            (f"self.fail('{MARKER}')", "    @unittest.expectedFailure\n", 0),
            (f"self.fail('{MARKER}')", "", 1),
            (f"raise RuntimeError('{MARKER}')", "", 1),
        ):
            for diagnostic in ("", "ok\n", f"{MARKER}\nok\n"):
                source = ("import os\nimport sys\nimport unittest\n\nclass Example(unittest.TestCase):\n"
                          + decorator + "    def test_first(self):\n"
                          f"        sys.stderr.write({diagnostic!r}); os.write(2, {diagnostic.encode()!r})\n"
                          f"        {body}\n"
                          "    def test_second(self):\n        self.assertTrue(True)\n")
                with self.subTest(body=body, diagnostic=diagnostic):
                    code, rows = self.reporting_fixture(source)
                    self.assertEqual(1, code)
                    self.assertEqual([expected_exit],
                                     [row["exit_code"] for row in rows if row["event"] == "ordinary_discovery"])
                    self.assertNotIn("infra_qualification", [row["event"] for row in rows])
                    if body.startswith("self.skipTest"):
                        code, rows = self.reporting_fixture(
                            source, allowed={"test_reporting_fixture.Example.test_first"},
                        )
                        self.assertEqual(0, code)
                        self.assertEqual(["skipped", "passed"],
                                         [row["outcome"] for row in rows if row["event"] == "test_outcome"])

    def test_real_separate_report_keeps_cleanup_stdout_and_stderr_distinct(self):
        source = (
            "import sys\nimport unittest\n\nclass Example(unittest.TestCase):\n"
            "    def test_first(self):\n        self.assertTrue(True)\n"
            "    def test_second(self):\n        self.assertTrue(True)\n"
            "    @classmethod\n    def tearDownClass(cls):\n"
            f"        sys.stderr.write('INFRA_STACK_CLEANUP {MARKER}\\nok\\n')\n"
        )
        for suffix in ("", "-conflict", "-bind", "-race"):
            value = {"project": "pennilogic-test-01234567" + suffix, "containers": 0, "volumes": 0, "networks": 0}
            source += f"        print({'INFRA_STACK_CLEANUP ' + json.dumps(value)!r})\n"
        source += ("        print('INFRA_STACK_CLEANUP_TEMP "
                   "{\"project\":\"pennilogic-test-01234567\",\"removed\":true}')\n")
        code, rows = self.reporting_fixture(source, suite="scripts", system="linux")
        self.assertEqual(0, code)
        self.assertEqual(4, sum(row["event"] == "owned_stack_cleanup" for row in rows))
        self.assertEqual(1, sum(row["event"] == "owned_stack_temporary_cleanup" for row in rows))
        self.assertTrue(rows[-1]["ok"])

    def test_resource_receipts_cannot_hide_duplicates_nonzero_or_boolean_counts(self):
        for body in (
            '{"project":"pennilogic-test-01234567","containers":1,"volumes":0,"networks":0}',
            '{"project":"pennilogic-test-01234567","containers":false,"volumes":0,"networks":0}',
            '{"project":"pennilogic-test-01234567","containers":1,"containers":0,"volumes":0,"networks":0}',
            '{"project":"not-owned","containers":0,"volumes":0,"networks":0}',
        ):
            with self.subTest(body=body), self.assertRaises(qualification.Refused):
                qualification.cleanup_evidence(b"INFRA_STACK_CLEANUP " + body.encode(), required=True)

    def test_inventory_refuses_import_errors_missing_controls_and_duplicate_ids(self):
        case = unittest.FunctionTestCase(lambda: None)
        name = case.id()
        for errors, cases in ((["private import failure"], [case]), ([], []), ([], [case, case])):
            loader = mock.Mock(errors=errors)
            loader.discover.return_value = unittest.TestSuite(cases)
            with self.subTest(errors=bool(errors), count=len(cases)), \
                    mock.patch.object(qualification.unittest, "TestLoader", return_value=loader), \
                    mock.patch.object(qualification, "REQUIRED", {"governance": {name}}), \
                    self.assertRaises(qualification.Refused):
                qualification.discovery_inventory(Path.cwd(), "governance")
        loader = mock.Mock(errors=[])
        loader.discover.return_value = unittest.TestSuite([case])
        with mock.patch.object(qualification.unittest, "TestLoader", return_value=loader), \
                mock.patch.object(qualification, "REQUIRED", {"governance": {name, "missing.required.control"}}), \
                self.assertRaises(qualification.Refused):
            qualification.discovery_inventory(Path.cwd(), "governance")

    def test_main_accepts_only_the_two_complete_commands_and_suppresses_process_errors(self):
        for suite in ("governance", "scripts"):
            for separator in ("/", "\\"):
                arguments = ["qualify.py", "--", "python", "-m", "unittest", "discover", "-s",
                             suite + separator + "tests"]
                with mock.patch.object(sys, "argv", arguments), mock.patch.object(qualification, "qualify") as child:
                    self.assertEqual(0, qualification.main())
                    child.assert_called_once_with(qualification.ROOT, suite)
        for error in (OSError(MARKER), ValueError(MARKER), subprocess.TimeoutExpired(MARKER, 1), KeyboardInterrupt()):
            output = io.StringIO()
            with mock.patch.object(sys, "argv", ["qualify.py", "--", "python", "-m", "unittest",
                                                "discover", "-s", "scripts/tests"]), \
                    mock.patch.object(qualification, "qualify", side_effect=error), contextlib.redirect_stdout(output):
                self.assertEqual(130 if isinstance(error, KeyboardInterrupt) else 1, qualification.main())
            code = "qualification-interrupted" if isinstance(error, KeyboardInterrupt) else "process-or-evidence-error"
            self.assertEqual({"event": "infra_qualification_refused", "code": code},
                             json.loads(output.getvalue()))
            self.assertNotIn(MARKER, output.getvalue())


class InfraVersionTests(unittest.TestCase):
    bindings = {"git": "bound-git", "gitleaks": "bound-gitleaks",
                "git_sha256": "a" * 64, "gitleaks_sha256": "b" * 64}

    def environment(self):
        return {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64", "GITHUB_REPOSITORY": "PenniLogic/infra",
                "GITHUB_REPOSITORY_ID": "1394135059", "GITHUB_REPOSITORY_OWNER_ID": "335295566",
                "ImageOS": "win25", "ImageVersion": "20261001.3.2"}

    def test_actual_version_formats_and_image_build_identifier_are_required_not_an_image_byte_pin(self):
        for system, runner, image, image_version in (
            ("win32", "Windows", "win25", "20261001.3.2"),
            ("win32", "Windows", "win25-vs2026", "20260925.250.1"),
            ("linux", "Linux", "ubuntu24", "20261001.3.2"),
        ):
            with self.subTest(system=system), tempfile.TemporaryDirectory(prefix="infra-version-fixture-") as temporary:
                root = Path(temporary)
                node = root / ("node.exe" if system == "win32" else "bin/node")
                npm = root / ("node_modules/npm/bin/npm-cli.js" if system == "win32"
                              else "lib/node_modules/npm/bin/npm-cli.js")
                npm.parent.mkdir(parents=True)
                npm.write_text("", encoding="utf-8")
                environment = {**self.environment(), "RUNNER_OS": runner, "ImageOS": image,
                               "ImageVersion": image_version}
                tools = {"node": str(node), "uv": "uv", "git": "git", "bash": "bash"}
                replies = [b"v24.14.0\n", b"11.9.0\n", b"uv 0.11.33 (fixture)\n",
                           b"git version 2.53.0.windows.1\n", b"GNU bash, version 5.2.37(1)-release\n", b"8.30.1\n"]
                with mock.patch.dict(os.environ, environment, clear=True), \
                        mock.patch.object(sys, "platform", system), \
                        mock.patch.object(qualification, "security_tools", return_value=self.bindings), \
                        mock.patch.object(qualification.shutil, "which", side_effect=tools.get), \
                        mock.patch.object(qualification, "checked", side_effect=replies):
                    values = qualification.versions(root)
                self.assertEqual(image_version, values["image_version"])
                self.assertEqual(image, values["image_family"])
                self.assertEqual(("24.14.0", "11.9.0", "0.11.33", "5.2.37"),
                                 tuple(values[key] for key in ("node", "npm", "uv", "bash")))
                self.assertNotIn("image_sha256", values)
                self.assertEqual(("8.30.1", "a" * 64, "b" * 64),
                                 tuple(values[key] for key in ("gitleaks", "git_sha256", "gitleaks_sha256")))
                self.assertEqual(qualification.GITLEAKS_ARCHIVE_PINS[system], values["gitleaks_archive_pin"])
                for index in range(len(replies)):
                    invalid = list(replies)
                    invalid[index] = MARKER.encode()
                    with self.subTest(index=index), mock.patch.dict(os.environ, environment, clear=True), \
                            mock.patch.object(sys, "platform", system), \
                            mock.patch.object(qualification, "security_tools", return_value=self.bindings), \
                            mock.patch.object(qualification.shutil, "which", side_effect=tools.get), \
                            mock.patch.object(qualification, "checked", side_effect=invalid), \
                            self.assertRaises(qualification.Refused):
                        qualification.versions(root)

    def test_missing_wrong_platform_or_node_startup_metadata_stops_before_probes(self):
        for image in ("win25", "win25-vs2026"):
            for key, value in (("ImageVersion", ""), ("ImageVersion", "."), ("ImageVersion", "2026..1"),
                               ("ImageOS", ""), ("ImageOS", "win22"), ("ImageOS", "win25-vs2026-unreviewed"),
                               ("ImageOS", "win25-vs2027"), ("ImageOS", "ubuntu24"),
                               ("GITHUB_ACTIONS", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"),
                               ("RUNNER_OS", "Linux"), ("RUNNER_ARCH", "ARM64"),
                               ("GITHUB_REPOSITORY", "Other/infra"),
                               ("GITHUB_REPOSITORY_OWNER_ID", "1"),
                               ("GITHUB_REPOSITORY_ID", "1"), ("NODE_OPTIONS", MARKER)):
                environment = {**self.environment(), "ImageOS": image, key: value}
                with self.subTest(image=image, key=key), mock.patch.dict(os.environ, environment, clear=True), \
                        mock.patch.object(sys, "platform", "win32"), \
                        mock.patch.object(qualification, "checked") as probe:
                    with self.assertRaises(qualification.Refused):
                        qualification.versions(Path.cwd())
                    probe.assert_not_called()

    def test_missing_tools_and_unsupported_python_fail_before_any_version_child(self):
        for missing_tool in ("node", "npm", "uv", "git", "bash"):
            tools = {name: name for name in ("node", "uv", "git", "bash")}
            if missing_tool != "npm":
                tools[missing_tool] = None
            with tempfile.TemporaryDirectory(prefix="infra-missing-sdk-") as temporary:
                tools["node"] = None if missing_tool == "node" else str(Path(temporary) / "node.exe")
                with self.subTest(tool=missing_tool), mock.patch.dict(os.environ, self.environment(), clear=True), \
                        mock.patch.object(sys, "platform", "win32"), \
                        mock.patch.object(qualification, "security_tools", return_value=self.bindings,
                                          side_effect=qualification.Refused("missing-git")
                                          if missing_tool == "git" else None), \
                        mock.patch.object(qualification.shutil, "which", side_effect=tools.get), \
                        mock.patch.object(qualification, "checked") as probe:
                    with self.assertRaises(qualification.Refused):
                        qualification.versions(Path(temporary))
                    probe.assert_not_called()
        with mock.patch.dict(os.environ, self.environment(), clear=True), \
                mock.patch.object(sys, "platform", "win32"), mock.patch.object(sys, "version_info", (3, 13, 0)), \
                mock.patch.object(qualification, "checked") as probe:
            with self.assertRaisesRegex(qualification.Refused, "python-3-14"):
                qualification.versions(Path.cwd())
            probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
