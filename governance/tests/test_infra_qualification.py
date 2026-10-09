"""Infra routing and synthetic qualification controls, not held workstation experiments."""

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import conformance_support as support
import qualify as qualification


generator = support.generator
MARKER = "PRIVATE-FIXTURE-PAYLOAD-DO-NOT-PRINT"
SOURCE = ("a" * 40, "b" * 40, [{"path_sha256": "c" * 64, "mode": "100644", "git_blob": "d" * 40}])


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
        installer = jobs["windows"]["steps"][3]["run"]
        self.assertIn("uv-0.11.33-py3-none-win_amd64.whl", installer)
        self.assertIn("#sha256=521229afa69ad5f57127de800120cb2bea1ac729a05a0851aaf920124f8edf66", installer)
        self.assertIn("--only-binary :all: --require-hashes --no-deps", installer)
        support.assert_powershell_failure_boundaries(self, installer, 1)
        support.assert_powershell_failure_boundaries(self, windows, 4)

    def test_api_caller_checker_and_qualifier_match_their_exact_source_bindings(self):
        frozen = {
            ".github/workflows/ci.yml": "b402c17a8f475e69dae2e317a27d1df3530925d40592c1727a1948f1c6b47f29",
            "scripts/check_repository.py": "f8ef2c500e6c6991ae797b26f845b6d1f5093c97a2920d3c5b66c64b681ae049",
            "scripts/qualify_windows.py": "60fc0b4a28d598317c4324b22bfc89280bdc04aa1ccc7393f0932508ba3abb1f",
        }
        for path, digest in frozen.items():
            with self.subTest(path=path):
                self.assertEqual(digest, hashlib.sha256(generator.artifacts("api")[path].encode("utf-8")).hexdigest())

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


class InfraDiscoveryTests(unittest.TestCase):
    def exercise(self, system, suite, *, statuses=None, missing=False, exit_code=0, cleanup=True, changed_source=False):
        names = sorted(qualification.REQUIRED[suite] | {"test_fixture.Example.test_extra"})
        inventory = {qualification.identifier(name): name for name in names}
        allowed = qualification.SKIPS[system][suite]
        statuses = statuses or {}
        observed = names[:-1] if missing else names
        lines = []
        for name in observed:
            status = statuses.get(name, "skipped 'platform'" if name in allowed else "ok")
            lines.append(f"{name.rsplit('.', 1)[-1]} ({name}) ... {status}")
        lines.append(f"\nRan {len(observed)} tests in 0.001s\n\nOK\n")
        output = io.StringIO()

        def run(command, **options):
            self.assertEqual([sys.executable, "-m", "unittest", "discover", "-s", str(Path(suite) / "tests"), "-v"], command)
            self.assertEqual("1" if system == "win32" and suite == "scripts" else None,
                             os.environ.get("PENNILOGIC_SKIP_DOCKER_TESTS"))
            options["stderr"].write("\n".join(lines).encode() + MARKER.encode() + b"\xff\n")
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
        replies = [b"a" * 40 + b"\n", b"false\n", b"", b"b" * 40 + b"\n",
                   b"100644 blob " + b"c" * 40 + b"\tgovernance/qualify.py\0"]
        with mock.patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}), \
                mock.patch.object(qualification, "checked", side_effect=replies):
            head, tree, files = qualification.source_inventory(Path.cwd())
        self.assertEqual(("a" * 40, "b" * 40), (head, tree))
        self.assertEqual(1, len(files))
        for index, value in ((0, b"d" * 40), (1, b"true\n"), (2, b" M private-file"), (4, b"")):
            changed = list(replies)
            changed[index] = value
            with mock.patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}), \
                    mock.patch.object(qualification, "checked", side_effect=changed), \
                    self.subTest(index=index), self.assertRaises(qualification.Refused):
                qualification.source_inventory(Path.cwd())

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
    def environment(self):
        return {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64", "GITHUB_REPOSITORY": "PenniLogic/infra",
                "GITHUB_REPOSITORY_ID": "1394135059", "ImageOS": "win25", "ImageVersion": "20261001.3.2"}

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
                           b"git version 2.53.0.windows.1\n", b"GNU bash, version 5.2.37(1)-release\n"]
                with mock.patch.dict(os.environ, environment, clear=True), \
                        mock.patch.object(sys, "platform", system), \
                        mock.patch.object(qualification.shutil, "which", side_effect=tools.get), \
                        mock.patch.object(qualification, "checked", side_effect=replies):
                    values = qualification.versions(root)
                self.assertEqual(image_version, values["image_version"])
                self.assertEqual(image, values["image_family"])
                self.assertEqual(("24.14.0", "11.9.0", "0.11.33", "5.2.37"),
                                 tuple(values[key] for key in ("node", "npm", "uv", "bash")))
                self.assertNotIn("image_sha256", values)
                for index in range(len(replies)):
                    invalid = list(replies)
                    invalid[index] = MARKER.encode()
                    with self.subTest(index=index), mock.patch.dict(os.environ, environment, clear=True), \
                            mock.patch.object(sys, "platform", system), \
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
