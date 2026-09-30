"""Planted-defect harness (PenniLogic/infra#24 addendum item 1): against a fake generated consumer in
a temporary Git repository, the real python and workflow fixtures prove the profile's real
commands refuse the planted defects, the tree is restored byte for byte, a stubbed harness cannot
pass (a runner that always exits 0 is reported not_proved), an unrestored tree fails, excluded
toolchains are recorded as not exercised, and probe processes never inherit credential variables."""

import sys
import tempfile
import unittest
from pathlib import Path

import conformance_support as support
from conformance import defects


def context_for(case):
    return defects.Context(case.profile_name, case.profile, case.root, support.GOVERNANCE.parent)


def fixture(fixture_id):
    return next(item for item in defects.FIXTURES if item.id == fixture_id)


class FixtureCatalogueTests(unittest.TestCase):
    def test_every_language_has_a_fixture_and_every_fixture_names_a_known_toolchain(self):
        ids = [item.id for item in defects.FIXTURES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(defects.LANGUAGES), {item.language for item in defects.FIXTURES})
        for item in defects.FIXTURES:
            self.assertIn(item.toolchain, defects.TOOLCHAINS, item.id)
        # At least one fixture per language requires a probe to fail, so the language is provable.
        for language in defects.LANGUAGES:
            provable = [item for item in defects.FIXTURES if item.language == language and item.id != "kotlin-android-self-test"]
            self.assertTrue(provable, language)

    def test_fixtures_apply_by_profile_commands_not_by_name(self):
        for name, profile in support.generator.PROFILES["repositories"].items():
            context = defects.Context(name, profile, None, None)
            applicable = {item.id for item in defects.applicable_fixtures(context)}
            with self.subTest(profile=name):
                self.assertTrue({"workflow-test-step-removed", "workflow-unpinned-action"} <= applicable)
                self.assertEqual("check_docs.py" in " ".join(profile["commands"]), "documentation-index-link-broken" in applicable)
                self.assertEqual(any("unittest" in c for c in profile["commands"]), "python-test-failing" in applicable)
                self.assertEqual(any(c.startswith("npm test") for c in profile["commands"]), "typescript-test-failing" in applicable)
                self.assertEqual(any("pytest" in c for c in profile["commands"]), "python-pytest-failing" in applicable)
                self.assertEqual("quality.py build" in " ".join(profile["commands"]), "kotlin-test-failing" in applicable)
                self.assertEqual("self-test" in " ".join(profile["commands"]), "kotlin-android-self-test" in applicable)
        self.assertEqual("kotlin-android-self-test", [item.id for item in defects.FIXTURES if item.toolchain == "android"][0])


class PlanterTests(support.ConsumerCase):
    def test_write_create_edit_and_move_aside_are_restored_in_reverse_order(self):
        before = support.tree_digest(self.root)
        planter = defects.Planter(self.root)
        planter.write("README.md", b"changed")
        planter.create("new/deep/file.txt", "created")
        planter.edit_text("AGENTS.md", lambda text: text + "\nplanted\n")
        planter.edit_json(".github/workflows/ci.yml", lambda document: document.__setitem__("name", "Planted"))
        planter.move_aside("scripts/tests/test_baseline_ok.py")
        self.assertEqual(b"changed", (self.root / "README.md").read_bytes())
        self.assertTrue((self.root / "new/deep/file.txt").is_file())
        self.assertFalse((self.root / "scripts/tests/test_baseline_ok.py").exists())
        self.assertTrue(defects.git_status(self.root))
        planter.restore()
        self.assertEqual(before, support.tree_digest(self.root))
        self.assertFalse((self.root / "new").exists())
        self.assertEqual([], defects.git_status(self.root))

    def test_planter_refuses_overwrites_escapes_and_no_op_edits(self):
        planter = defects.Planter(self.root)
        with self.assertRaises(FileExistsError):
            planter.create("README.md", "x")
        with self.assertRaises(ValueError):
            planter.write("../outside.txt", "x")
        with self.assertRaises(ValueError):
            planter.edit_text("README.md", lambda text: text)
        with self.assertRaises(FileNotFoundError):
            planter.move_aside("does/not/exist")
        planter.restore()
        self.assertEqual([], defects.git_status(self.root))


class RealFixtureTests(unittest.TestCase):
    """The .github profile: python unittest plus the six workflow fixtures, run once with the real runner."""

    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory(prefix="pennilogic-conformance-test-")
        cls.root = support.make_consumer(Path(cls._temporary.name) / ".github", ".github")
        cls.profile = support.generator.PROFILES["repositories"][".github"]
        context = defects.Context(".github", cls.profile, cls.root, support.GOVERNANCE.parent)
        cls.before = support.tree_digest(cls.root)
        cls.records = {record["id"]: record for record in defects.run_fixtures(context, exercise=("python",))}

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def test_tree_is_restored_byte_for_byte_and_clean(self):
        self.assertEqual(self.before, support.tree_digest(self.root))
        self.assertEqual([], defects.git_status(self.root))

    def test_failing_and_removed_python_tests_are_refused_by_the_real_unittest_command(self):
        failing = self.records["python-test-failing"]
        self.assertEqual("proved", failing["outcome"], failing)
        self.assertEqual(1, failing["probes"][0]["exit_code"])
        self.assertIn("test_planted_defect_must_fail", failing["probes"][0]["output_tail"])
        removed = self.records["python-tests-removed"]
        self.assertEqual("proved", removed["outcome"], removed)
        self.assertEqual(5, removed["probes"][0]["exit_code"])
        self.assertIn("NO TESTS RAN", removed["probes"][0]["output_tail"])

    def test_removed_and_stubbed_test_steps_fail_the_drift_check(self):
        for fixture_id in ("workflow-test-step-removed", "workflow-test-step-stubbed"):
            with self.subTest(fixture=fixture_id):
                record = self.records[fixture_id]
                self.assertEqual("proved", record["outcome"], record)
                drift, checker = record["probes"]
                self.assertEqual(1, drift["exit_code"])
                self.assertIn(".github/workflows/ci.yml", drift["output_tail"])
                self.assertEqual("not_detected", checker["outcome"])  # the checker is not the tripwire for commands

    def test_condition_unpinned_action_reusable_workflow_and_continue_on_error_are_refused(self):
        rules = {
            "workflow-step-skipped-by-condition": "conditions are not part of the generated workflows",
            "workflow-unpinned-action": "action must be immutable",
            "workflow-reusable-workflow-job": "action must be immutable",
        }
        for fixture_id, rule in rules.items():
            with self.subTest(fixture=fixture_id):
                record = self.records[fixture_id]
                self.assertEqual("proved", record["outcome"], record)
                checker = record["probes"][1]
                self.assertEqual(1, checker["exit_code"])
                self.assertIn("Invalid or unsafe workflow", checker["output_tail"])
                self.assertTrue(checker["detail_surfaced"], "the current template surfaces its rule text")
                self.assertIn(rule, checker["output_tail"])
        record = self.records["workflow-step-continue-on-error"]
        self.assertEqual("proved", record["outcome"], record)
        self.assertIn("step-level key outside the generated step keys", record["probes"][1]["output_tail"])

    def test_the_python_fixture_set_on_a_clean_consumer_is_fully_proved(self):
        self.assertEqual({"proved"}, {record["outcome"] for record in self.records.values()}, self.records)
        self.assertEqual({"workflow": "proved", "python": "proved"}, defects.language_coverage(list(self.records.values())))
        self.assertEqual(8, len(self.records))


class FakeRunnerTests(support.ConsumerCase):
    def test_a_stubbed_command_that_always_succeeds_is_not_proved(self):
        always_green = lambda command, cwd: defects.Result(0, "everything is fine")  # noqa: E731
        record = defects.run_fixture(fixture("python-test-failing"), context_for(self), runner=always_green)
        self.assertEqual("not_proved", record["outcome"])
        self.assertEqual("unexpected", record["probes"][0]["outcome"])
        self.assertEqual([], defects.git_status(self.root))

    def test_a_failure_without_the_expected_rule_text_is_not_proved_and_a_timeout_is_an_error(self):
        wrong_reason = lambda command, cwd: defects.Result(1, "Traceback: SyntaxError")  # noqa: E731
        record = defects.run_fixture(fixture("python-tests-removed"), context_for(self), runner=wrong_reason)
        self.assertEqual("not_proved", record["outcome"])
        timeout = lambda command, cwd: defects.Result(None, "", timed_out=True)  # noqa: E731
        record = defects.run_fixture(fixture("python-test-failing"), context_for(self), runner=timeout)
        self.assertEqual("error", record["outcome"])
        self.assertEqual("a probe timed out or could not start", record["reason"])

    def test_excluded_toolchain_is_recorded_not_exercised_without_running_anything(self):
        calls = []
        record = defects.run_fixture(fixture("python-test-failing"), context_for(self),
                                     runner=lambda command, cwd: calls.append(command), exercise=("node",))
        self.assertEqual("not_exercised", record["outcome"])
        self.assertEqual("toolchain python not exercised in this run", record["reason"])
        self.assertEqual([], calls)

    def test_dirty_tree_before_planting_is_an_error(self):
        (self.root / "README.md").write_text("dirty", encoding="utf-8")
        record = defects.run_fixture(fixture("python-test-failing"), context_for(self),
                                     runner=lambda command, cwd: defects.Result(1, "x"))
        self.assertEqual("error", record["outcome"])
        self.assertEqual("scratch checkout is not clean before planting", record["reason"])

    def test_unrestored_tree_fails_and_stops_further_fixtures(self):
        statuses = iter([[], ["?? leftover.txt"]] + [["?? leftover.txt"]] * 20)
        record = defects.run_fixture(fixture("python-test-failing"), context_for(self),
                                     runner=lambda command, cwd: defects.Result(1, "test_planted_defect_must_fail"),
                                     status=lambda root: next(statuses))
        self.assertEqual("error", record["outcome"])
        self.assertEqual(["?? leftover.txt"], record["unrestored_paths"])
        statuses = iter([[], ["?? leftover.txt"]] + [["?? leftover.txt"]] * 20)
        records = defects.run_fixtures(context_for(self), runner=lambda command, cwd: defects.Result(1, "x"),
                                       status=lambda root: next(statuses))
        self.assertEqual(1, len(records))
        self.assertTrue(records[0].get("unrestored_paths"))

    def test_prepare_commands_run_before_planting_and_their_failure_is_an_error(self):
        web = support.generator.PROFILES["repositories"]["web"]
        context = defects.Context("web", web, self.root, support.GOVERNANCE.parent)
        calls = []

        def runner(command, cwd):
            calls.append(command)
            return defects.Result(1 if command == "npm ci" else 0, "")

        record = defects.run_fixture(fixture("typescript-test-failing"), context, runner=runner, exercise=("node",))
        self.assertEqual(["npm ci"], calls)
        self.assertEqual("error", record["outcome"])
        self.assertEqual("prepare command failed", record["reason"])
        self.assertEqual("unexpected", record["probes"][0]["outcome"])


class PlantShapeTests(support.ConsumerCase):
    """Fixtures whose toolchains are never exercised here still plant the right files and restore."""

    def spy(self, expected_path, expected_fragment, probe_command=None):
        def runner(command, cwd):
            if probe_command is not None and command != probe_command:
                return defects.Result(0, "prepared")  # install commands are not the probe
            path = self.root / expected_path
            content = path.read_text(encoding="utf-8") if path.exists() else None
            self.seen = (command, content)
            return defects.Result(1, f"{expected_fragment} refused")
        return runner

    def test_vitest_junit_pytest_and_docs_plants_land_where_the_consumer_test_runners_look(self):
        cases = [
            ("web", "typescript-test-failing", ("node",), "tests/planted-conformance-defect.test.ts", "planted defect must fail", "npm test"),
            ("admin", "typescript-test-failing", ("node",), "tests/unit/planted-conformance-defect.test.ts", "planted defect must fail", "npm test"),
            ("api", "kotlin-test-failing", ("java",), "src/test/kotlin/com/pennilogic/PlantedConformanceDefectTest.kt", "planted defect", "python scripts/quality.py test"),
            ("ai-service", "python-pytest-failing", ("uv",), "tests/test_planted_conformance_defect.py", "test_planted_defect_must_fail", "uv run --locked pytest"),
        ]
        for name, fixture_id, exercise, path, fragment, command in cases:
            with self.subTest(fixture=fixture_id, profile=name):
                if name == "admin":
                    (self.root / "tests" / "unit").mkdir(parents=True)
                    (self.root / "tests" / "unit" / ".keep").write_text("", encoding="utf-8")
                    support.git(self.root, "add", "-A")
                    support.git(self.root, "commit", "-q", "-m", "unit dir")
                profile = support.generator.PROFILES["repositories"][name]
                context = defects.Context(name, profile, self.root, support.GOVERNANCE.parent)
                before = support.tree_digest(self.root)
                record = defects.run_fixture(fixture(fixture_id), context, runner=self.spy(path, fragment, command), exercise=exercise)
                self.assertEqual("proved", record["outcome"], record)
                self.assertEqual(command, self.seen[0])
                self.assertIn(fragment, self.seen[1])
                self.assertEqual(before, support.tree_digest(self.root))

    def test_docs_plants_edit_the_index_the_adr_header_and_the_root_readme(self):
        (self.root / "adr").mkdir()
        (self.root / "adr" / "README.md").write_text("| Source | [ADR-001.md](ADR-001.md) |\n", encoding="utf-8")
        (self.root / "adr" / "ADR-015.md").write_text("---\nnumber: ADR-015\nsupersedes: null\n---\n", encoding="utf-8")
        support.git(self.root, "add", "-A")
        support.git(self.root, "commit", "-q", "-m", "adr")
        profile = support.generator.PROFILES["repositories"]["docs"]
        context = defects.Context("docs", profile, self.root, support.GOVERNANCE.parent)
        before = support.tree_digest(self.root)
        record = defects.run_fixture(fixture("documentation-index-link-broken"), context,
                                     runner=self.spy("adr/README.md", "generated slot ADR-001 differs"))
        self.assertEqual("proved", record["outcome"])
        self.assertIn("(ADR-001-missing.md)", self.seen[1])
        record = defects.run_fixture(fixture("documentation-dangling-supersedes"), context,
                                     runner=self.spy("adr/ADR-015.md", "supersedes ADR-099, which has no source record"))
        self.assertEqual("proved", record["outcome"])
        self.assertIn("supersedes: ADR-099", self.seen[1])
        record = defects.run_fixture(fixture("documentation-body-link-broken"), context,
                                     runner=lambda command, cwd: defects.Result(0, "Docs inventory valid"))
        self.assertEqual("recorded", record["outcome"])
        self.assertEqual("not_detected", record["probes"][0]["outcome"])
        self.assertEqual(before, support.tree_digest(self.root))
        self.assertEqual({"documentation": "proved"}, defects.language_coverage([record, {"language": "documentation", "outcome": "proved"}]))


class EnvironmentTests(unittest.TestCase):
    def test_probe_environment_drops_credential_looking_variables_and_keeps_the_path(self):
        environ = {"PATH": "/usr/bin", "GH_TOKEN": "x", "GITHUB_TOKEN": "x", "MY_SECRET": "x", "DB_PASSWORD": "x",
                   "AWS_ACCESS_KEY": "x", "NPM_CONFIG_PRIVATE_KEY": "x", "JAVA_HOME": "/jdk", "ANDROID_HOME": "/sdk",
                   "SOME_CREDENTIAL_FILE": "x", "PATHEXT": ".EXE"}
        cleaned = defects.probe_environment(environ)
        self.assertEqual({"PATH", "JAVA_HOME", "ANDROID_HOME", "PATHEXT", "PYTHONDONTWRITEBYTECODE", "PYTHONIOENCODING", "CI"},
                         set(cleaned))
        self.assertEqual("1", cleaned["PYTHONDONTWRITEBYTECODE"])

    def test_probe_outcomes(self):
        probe = defects.Probe("x", "cmd", expect="fail", expect_text="rule")
        self.assertEqual("as_expected", defects.probe_outcome(probe, defects.Result(1, "the rule fired")))
        self.assertEqual("unexpected", defects.probe_outcome(probe, defects.Result(1, "other")))
        self.assertEqual("unexpected", defects.probe_outcome(probe, defects.Result(0, "rule")))
        self.assertEqual("error", defects.probe_outcome(probe, defects.Result(None, "", timed_out=True)))
        passing = defects.Probe("x", "cmd", expect="pass")
        self.assertEqual("as_expected", defects.probe_outcome(passing, defects.Result(0, "")))
        self.assertEqual("unexpected", defects.probe_outcome(passing, defects.Result(2, "")))
        observe = defects.Probe("x", "cmd", expect="observe")
        self.assertEqual("detected", defects.probe_outcome(observe, defects.Result(1, "")))
        self.assertEqual("not_detected", defects.probe_outcome(observe, defects.Result(0, "")))

    def test_language_coverage_keeps_the_weakest_outcome_until_one_fixture_is_proved(self):
        records = [{"language": "kotlin", "outcome": "not_exercised"}, {"language": "kotlin", "outcome": "error"},
                   {"language": "python", "outcome": "not_proved"}, {"language": "python", "outcome": "proved"}]
        self.assertEqual({"kotlin": "error", "python": "proved"}, defects.language_coverage(records))

    def test_subprocess_runner_reports_exit_code_output_and_a_failure_to_start(self):
        result = defects.subprocess_runner([sys.executable, "-c", "import sys; print('hello'); sys.exit(3)"], ".")
        self.assertEqual(3, result.exit_code)
        self.assertIn("hello", result.output)
        self.assertEqual(None, defects.subprocess_runner(["definitely-not-a-command-8f3a"], ".").exit_code)
        self.assertTrue(defects.subprocess_runner([sys.executable, "-c", "import time; time.sleep(5)"], ".", timeout=0.5).timed_out)


if __name__ == "__main__":
    unittest.main()
