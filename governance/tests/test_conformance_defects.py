"""Planted-defect harness (PenniLogic/infra#24 addendum item 1): against a fake generated consumer in
a temporary Git repository, the real python and workflow fixtures prove the profile's real
commands refuse the planted defects, the tree is restored byte for byte, a stubbed harness cannot
pass (a runner that always exits 0 is reported not_proved), an unrestored tree fails, excluded
toolchains are recorded as not exercised, and probe processes never inherit credential variables."""

import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest import mock

import conformance_support as support
from conformance import defects, report


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

    def test_restore_continues_past_a_failing_undo_step_and_removes_the_aside_directory(self):
        """C2: one undo step that raises must not abandon the remaining steps or the moved-aside files."""
        before = support.tree_digest(self.root)
        planter = defects.Planter(self.root)
        planter.write("README.md", b"changed")
        planter.move_aside("scripts/tests/test_baseline_ok.py")
        planter.create("planted.txt", "planted")
        aside = planter._aside
        self.assertTrue(aside and Path(aside).is_dir())

        def failing_step():
            raise PermissionError("locked")

        planter._undo.insert(1, failing_step)  # runs after the planted.txt removal, before the move back and the write
        with self.assertRaises(PermissionError):
            planter.restore()
        self.assertEqual(before, support.tree_digest(self.root), "every other undo step still ran")
        self.assertFalse(Path(aside).exists(), "the aside directory is removed even when a step raised")
        self.assertIsNone(planter._aside)
        self.assertEqual([], planter._undo)
        self.assertEqual([], defects.git_status(self.root))

    def test_backup_cleanup_failure_retains_its_location_and_the_first_undo_error(self):
        before = support.tree_digest(self.root)
        planter = defects.Planter(self.root)
        planter.move_aside("README.md")
        aside = planter._aside
        first = PermissionError("first undo failure")
        planter._undo.append(mock.Mock(side_effect=first))
        original = shutil.rmtree

        def locked(path, *args, **kwargs):
            if str(path) == aside:
                if kwargs.get("ignore_errors"):
                    return None
                raise PermissionError("backup directory locked")
            return original(path, *args, **kwargs)

        try:
            with mock.patch.object(defects.shutil, "rmtree", locked):
                with self.assertRaises(PermissionError) as caught:
                    planter.restore()
            self.assertIs(first, caught.exception)
            self.assertEqual(before, support.tree_digest(self.root))
            self.assertEqual(aside, planter._aside)
            self.assertIsInstance(planter.cleanup_error, PermissionError)
            self.assertTrue(Path(aside).is_dir())
            self.assertEqual([], planter._undo)
            planter.restore()
            self.assertIsNone(planter._aside)
            self.assertIsNone(planter.cleanup_error)
        finally:
            if Path(aside).exists():
                original(aside)

    def test_a_failed_file_undo_never_deletes_its_only_backup_copy(self):
        planter = defects.Planter(self.root)
        original = (self.root / "README.md").read_bytes()
        planter.move_aside("README.md")
        aside = Path(planter._aside)
        try:
            with mock.patch.object(defects.shutil, "move", side_effect=PermissionError("restore locked")):
                with self.assertRaisesRegex(PermissionError, "restore locked"):
                    planter.restore()
            self.assertFalse((self.root / "README.md").exists())
            backup = next(aside.iterdir())
            self.assertEqual(original, backup.read_bytes())
            self.assertEqual([{"file": backup.name, "restore_to": "README.md"}],
                             planter.cleanup_state("restore failed")["backups"])
            self.assertIsNotNone(planter.cleanup_error)
            shutil.move(str(backup), str(self.root / "README.md"))
        finally:
            shutil.rmtree(aside)


class RealFixtureTests(unittest.TestCase):
    """The .github profile: python unittest plus the six workflow fixtures, run once with the real runner."""

    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory(prefix="pennilogic-conformance-test-")
        cls.addClassCleanup(cls._temporary.cleanup)
        cls.root = support.make_consumer(Path(cls._temporary.name) / ".github", ".github")
        cls.profile = support.generator.PROFILES["repositories"][".github"]
        context = defects.Context(".github", cls.profile, cls.root, support.GOVERNANCE.parent)
        cls.before = support.tree_digest(cls.root)
        cls.records = {record["id"]: record for record in defects.run_fixtures(context, exercise=("python",))}

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

    def test_a_restore_that_raises_is_an_error_not_a_crash(self):
        owned = {}
        item = fixture("python-test-failing")

        def plant(context, planter):
            owned["planter"] = planter
            item.plant(context, planter)

        try:
            with mock.patch.object(defects.Planter, "restore", side_effect=PermissionError("locked")):
                record = defects.run_fixture(dataclasses.replace(item, plant=plant), context_for(self),
                                             runner=lambda command, cwd: defects.Result(1, "test_planted_defect_must_fail"))
            self.assertEqual("error", record["outcome"])
            self.assertIn("restore failed: PermissionError", record["reason"])
            self.assertTrue(record.get("unrestored_paths"))
        finally:
            owned["planter"].restore()

    def test_backup_cleanup_failure_is_an_error_even_when_the_consumer_tree_is_restored(self):
        before = support.tree_digest(self.root)
        owned = {}
        original = shutil.rmtree

        def plant(context, planter):
            planter.move_aside("README.md")
            owned["aside"] = planter._aside

        def locked(path, *args, **kwargs):
            if str(path) == owned.get("aside"):
                if kwargs.get("ignore_errors"):
                    return None
                raise PermissionError("backup directory locked")
            return original(path, *args, **kwargs)

        item = defects.Fixture("cleanup-failure", "python", "python", "synthetic cleanup refusal",
                               lambda context: True, plant,
                               lambda context: [defects.Probe("refusal", "unused", expect_text="refused")])
        try:
            with mock.patch.object(defects.shutil, "rmtree", locked):
                records = defects.run_fixtures(context_for(self), fixtures=(item, fixture("python-test-failing")),
                                               runner=lambda command, cwd: defects.Result(1, "refused"))
            self.assertEqual(before, support.tree_digest(self.root))
            self.assertEqual([], defects.git_status(self.root))
            self.assertEqual(1, len(records), "cleanup failure stops further planting")
            record = records[0]
            self.assertEqual("error", record["outcome"])
            self.assertIn("backup cleanup failed: PermissionError", record["reason"])
            self.assertEqual({"directory": owned["aside"], "error": "PermissionError"}, record["cleanup"])
            self.assertTrue(Path(owned["aside"]).is_dir())
            replacements = report.path_replacements(self.scratch, support.GOVERNANCE.parent)
            redacted = report.redact(record, replacements)
            self.assertEqual([], report.redaction_survivors(redacted, replacements))
            self.assertIn("<tmp>", redacted["cleanup"]["directory"])
        finally:
            if owned.get("aside") and Path(owned["aside"]).exists():
                original(owned["aside"])

    @unittest.skipUnless(os.name == "nt", "Windows file sharing")
    def test_a_real_locked_backup_directory_cannot_be_reported_as_proved(self):
        before = support.tree_digest(self.root)
        owned = {}

        def plant(context, planter):
            planter.move_aside("README.md")
            owned["aside"] = Path(planter._aside)
            owned["lock"] = (owned["aside"] / "locked.tmp").open("w+b")

        item = defects.Fixture("real-locked-backup", "python", "python", "real Windows cleanup refusal",
                               lambda context: True, plant,
                               lambda context: [defects.Probe("refusal", "unused", expect_text="refused")])
        try:
            record = defects.run_fixture(item, context_for(self), runner=lambda command, cwd: defects.Result(1, "refused"))
            self.assertEqual(before, support.tree_digest(self.root))
            self.assertEqual([], defects.git_status(self.root))
            self.assertEqual("error", record["outcome"])
            self.assertIn("backup cleanup failed: PermissionError", record["reason"])
            self.assertEqual(str(owned["aside"]), record["cleanup"]["directory"])
            self.assertTrue(owned["aside"].exists())
        finally:
            if owned.get("lock") is not None:
                owned["lock"].close()
            if owned.get("aside") is not None:
                shutil.rmtree(owned["aside"])

    def test_unconfirmed_process_exit_defers_restore_and_stops_further_fixtures(self):
        owned = {}

        def plant(context, planter):
            owned["planter"] = planter
            planter.move_aside("README.md")

        def unsafe(command, cwd):
            raise defects.UnsafeProcessTreeError("synthetic teardown not confirmed")

        item = defects.Fixture("unsafe-lifetime", "python", "python", "synthetic unconfirmed process exit",
                               lambda context: True, plant, lambda context: [defects.Probe("refusal", "unused")])
        try:
            records = defects.run_fixtures(context_for(self), fixtures=(item, fixture("python-test-failing")), runner=unsafe)
            self.assertEqual(1, len(records))
            self.assertEqual("error", records[0]["outcome"])
            self.assertIn("synthetic teardown not confirmed", records[0]["reason"])
            self.assertTrue(records[0]["restoration_deferred"])
            self.assertFalse((self.root / "README.md").exists(), "never restore while an owned consumer may still run")
            self.assertEqual("README.md", records[0]["cleanup"]["backups"][0]["restore_to"])
            self.assertTrue(owned["planter"]._undo)
        finally:
            owned["planter"].restore()
        self.assertEqual([], defects.git_status(self.root))

    def test_consumer_self_test_is_recorded_as_consumer_evidence_never_as_proved(self):
        """Q7: the android self-test is a consumer-owned command; its exit 0 is the consumer's claim."""
        android = support.generator.PROFILES["repositories"]["android"]
        context = defects.Context("android", android, self.root, support.GOVERNANCE.parent)
        self_test = fixture("kotlin-android-self-test")
        self.assertEqual(["consumer"], [probe.expect for probe in self_test.probes(context)])
        command = "python scripts/quality_gates.py self-test"
        self.assertEqual([command], [probe.command for probe in self_test.probes(context)])
        green_runner = mock.Mock(return_value=defects.Result(0, "all gates bit"))
        green = defects.run_fixture(self_test, context, runner=green_runner, exercise=("android",))
        green_runner.assert_called_once_with(command, self.root)
        self.assertEqual("consumer_evidence", green["outcome"])
        self.assertNotEqual("proved", green["outcome"])
        red_runner = mock.Mock(return_value=defects.Result(1, "gate did not bite"))
        red = defects.run_fixture(self_test, context, runner=red_runner, exercise=("android",))
        red_runner.assert_called_once_with(command, self.root)
        self.assertEqual("not_proved", red["outcome"], "a consumer whose own self-test fails is still a finding")
        self.assertEqual({"kotlin": "consumer_evidence"}, defects.language_coverage([green]))
        self.assertEqual({"kotlin": "proved"}, defects.language_coverage([green, {"language": "kotlin", "outcome": "proved"}]))
        # No other fixture relies on a consumer-owned pass; every other required probe expects a failure.
        consumer_fixtures = set()
        for name, profile in support.generator.PROFILES["repositories"].items():
            probe_context = defects.Context(name, profile, self.root, support.GOVERNANCE.parent)
            for item in defects.applicable_fixtures(probe_context):
                if any(probe.expect == "consumer" for probe in item.probes(probe_context)):
                    consumer_fixtures.add(item.id)
        self.assertEqual({"kotlin-android-self-test"}, consumer_fixtures)

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


class UnittestWitnessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="conformance-unittest-witness-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.case_id = "test_planted_conformance_defect_0.PlantedConformanceDefect.test_planted_defect_must_fail"

    def witness(self, case_id=None):
        return defects._UnittestWitness(self.root, case_id or self.case_id)

    def write_record(self, witness, **overrides):
        document = {"nonce": witness.nonce, "test": witness.case_id, "failed": True}
        document.update(overrides)
        data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
        witness.path.write_bytes(data)
        return data

    def assert_refused(self, witness):
        result = witness.consume(defects.Result(1, witness.heading, failure_evidence=witness.heading), self.root)
        self.assertIn("unittest witness refused:", result.error)
        self.assertEqual("", result.failure_evidence)
        self.assertEqual(1, result.exit_code)
        return result

    def test_exact_true_and_false_records_are_single_use(self):
        for failed in (False, True):
            with self.subTest(failed=failed):
                witness = self.witness()
                witness.arm()
                self.write_record(witness, failed=failed)
                result = witness.consume(defects.Result(1, ""), self.root)
                self.assertIsNone(result.error)
                self.assertEqual(witness.heading if failed else "", result.failure_evidence)
                self.assertLessEqual(len(result.failure_evidence), defects.RECORDED_TAIL)
                self.assert_refused(witness)

    def test_absent_malformed_duplicate_and_mismatched_records_are_refused(self):
        for kind in ("empty", "missing", "malformed", "duplicate", "nonce", "case", "integer", "extra", "oversize"):
            with self.subTest(kind=kind):
                witness = self.witness()
                witness.arm()
                data = self.write_record(witness)
                if kind == "missing":
                    witness.path.unlink()
                elif kind in ("nonce", "case", "integer", "extra"):
                    changes = {"nonce": {"nonce": "0" * 32}, "case": {"test": self.case_id.replace("_0.", "_1.")},
                               "integer": {"failed": 1}, "extra": {"unrelated": True}}
                    self.write_record(witness, **changes[kind])
                else:
                    data = {"empty": b"", "malformed": b"{", "duplicate": data[:-1] + b',"failed":true}',
                            "oversize": b"x" * (witness.limit + 1)}[kind]
                    witness.path.write_bytes(data)
                self.assert_refused(witness)

    def test_replay_from_another_run_or_discovery_is_refused(self):
        previous = self.witness()
        previous.arm()
        data = self.write_record(previous)
        for case_id in (self.case_id, self.case_id.replace("_0.", "_1.")):
            with self.subTest(case_id=case_id):
                witness = self.witness(case_id)
                self.assertNotEqual(previous.nonce, witness.nonce)
                witness.arm()
                witness.path.write_bytes(data)
                self.assert_refused(witness)

    def test_stale_unarmed_and_repeated_arming_are_refused(self):
        witness = self.witness()
        self.write_record(witness)
        with self.assertRaisesRegex(ValueError, "stale"):
            witness.arm()
        self.assert_refused(witness)
        witness = self.witness()
        witness.arm()
        with self.assertRaisesRegex(ValueError, "stale"):
            witness.arm()

    def test_replaced_and_hardlinked_witness_files_are_refused(self):
        for kind in ("replaced", "hardlinked"):
            with self.subTest(kind=kind):
                witness = self.witness()
                witness.arm()
                data = self.write_record(witness)
                if kind == "replaced":
                    witness.path.unlink()
                    witness.path.write_bytes(data)
                    self.assertNotEqual(witness.file_id, witness._identity(witness.path.stat()))
                else:
                    os.link(witness.path, self.root / "alias.json")
                self.assert_refused(witness)
                self.assertEqual(data, witness.path.read_bytes(), "validation never repairs unsafe evidence")

    def test_links_junctions_special_files_and_changed_directories_are_refused_before_read(self):
        witness = self.witness()
        witness.arm()
        self.write_record(witness)
        original_lstat = Path.lstat
        for kind in ("symlink", "junction", "special", "directory"):
            with self.subTest(kind=kind):
                witness.consumed = False

                def lstat(path, *args, **kwargs):
                    info = original_lstat(path, *args, **kwargs)
                    if path == (witness.directory if kind == "directory" else witness.path):
                        values = {key: getattr(info, key) for key in
                                  ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size")}
                        values["st_file_attributes"] = getattr(info, "st_file_attributes", 0)
                        if kind == "symlink":
                            values["st_mode"] = defects.stat.S_IFLNK
                        elif kind == "special":
                            values["st_mode"] = defects.stat.S_IFIFO
                        elif kind == "junction":
                            values["st_file_attributes"] |= defects.stat.FILE_ATTRIBUTE_REPARSE_POINT
                        else:
                            values["st_ino"] += 1
                        return SimpleNamespace(**values)
                    return info

                with mock.patch.object(Path, "lstat", lstat), \
                        mock.patch.object(Path, "open", side_effect=AssertionError("unsafe path must not be read")):
                    self.assert_refused(witness)

    def test_wrong_exits_timeout_errors_and_unsafe_lifetimes_never_consume_evidence(self):
        for original in (
            defects.Result(0, ""), defects.Result(2, ""), defects.Result(5, ""),
            defects.Result(None, ""), defects.Result(None, "", timed_out=True),
            defects.Result(1, "", error="capture failed"), defects.Result(1, "", restoration_safe=False),
        ):
            with self.subTest(result=original):
                witness = self.witness()
                witness.arm()
                self.write_record(witness)
                original.failure_evidence = witness.heading
                with mock.patch.object(witness, "_read", side_effect=AssertionError("must not consume")):
                    result = witness.consume(original, self.root)
                self.assertEqual("", result.failure_evidence)
                self.assertEqual(original.exit_code, result.exit_code)
                self.assertEqual(original.error, result.error)
                self.assertEqual(original.restoration_safe, result.restoration_safe)

    def test_read_errors_are_explicit_and_do_not_publish_private_error_text(self):
        witness = self.witness()
        witness.arm()
        with mock.patch.object(witness, "_read", side_effect=PermissionError("private diagnostic")):
            result = self.assert_refused(witness)
        self.assertIn("PermissionError", result.error)
        self.assertNotIn("private diagnostic", result.error)

    def test_verified_heading_is_redacted_before_its_publication_bound(self):
        witness = self.witness()
        witness.arm()
        self.write_record(witness)
        with mock.patch.object(report, "credential_values", return_value=("PlantedConformanceDefect",)):
            result = witness.consume(defects.Result(1, ""), self.root)
        self.assertIsNone(result.error)
        self.assertEqual("", result.failure_evidence)


class RuntimeRepairTests(unittest.TestCase):
    def consumer(self, name, extra_files=None):
        temporary = tempfile.TemporaryDirectory(prefix="conformance-runtime-repair-")
        self.addCleanup(temporary.cleanup)
        root = support.make_consumer(Path(temporary.name) / name, name, extra_files)
        context = defects.Context(name, support.generator.profile_for(name), root, support.GOVERNANCE.parent)
        return root, context

    def test_each_unittest_start_directory_survives_cross_suite_import_paths(self):
        root, context = self.consumer("infra", {
            "governance/tests/test_cross_suite_import.py":
                "from pathlib import Path\nimport sys\n"
                "sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts' / 'tests'))\n",
        })
        before = support.tree_digest(root)
        record = defects.run_fixture(fixture("python-test-failing"), context)
        self.assertEqual("proved", record["outcome"], record)
        self.assertEqual(defects.unittest_commands(context.profile),
                         [probe["command"] for probe in record["probes"]])
        self.assertEqual(2, len(record["probes"]))
        for probe in record["probes"]:
            self.assertEqual(1, probe["exit_code"], probe)
            self.assertNotIn("incorrectly imported", probe["output_tail"])
            self.assertIn("test_planted_defect_must_fail", probe["failure_evidence"])
        self.assertEqual(before, support.tree_digest(root))
        self.assertEqual([], defects.git_status(root))

    def test_planted_failure_evidence_survives_later_unrelated_failure_output(self):
        root, context = self.consumer(".github", {
            "scripts/tests/test_zz_later_failure.py":
                "import unittest\n\nclass LaterFailure(unittest.TestCase):\n"
                "    def test_later_failure(self):\n"
                "        self.fail('unrelated later failure ' * 400)\n",
        })
        before = support.tree_digest(root)
        record = defects.run_fixture(fixture("python-test-failing"), context)
        self.assertEqual("proved", record["outcome"], record)
        probe = record["probes"][0]
        self.assertEqual(1, probe["exit_code"])
        self.assertIn("FAILED (failures=2)", probe["output_tail"])
        self.assertNotIn("test_planted_defect_must_fail", probe["output_tail"])
        self.assertRegex(probe["failure_evidence"], r"^FAIL: test_planted_defect_must_fail \(")
        self.assertLessEqual(len(probe["output_tail"]), defects.RECORDED_TAIL)
        self.assertLessEqual(len(probe["failure_evidence"]), defects.RECORDED_TAIL)
        self.assertEqual(before, support.tree_digest(root))

    def test_a_passing_plant_cannot_borrow_an_unrelated_failure(self):
        root, context = self.consumer(".github", {
            "scripts/tests/test_zz_later_failure.py":
                "import unittest\n\nclass LaterFailure(unittest.TestCase):\n"
                "    def test_later_failure(self):\n"
                "        self.fail('unrelated failure mentions test_planted_defect_must_fail')\n",
        })
        passing = defects.PLANTED_PYTHON_TEST.replace('self.fail("planted defect")', "self.assertTrue(True)")
        with mock.patch.object(defects, "PLANTED_PYTHON_TEST", passing):
            record = defects.run_fixture(fixture("python-test-failing"), context)
        self.assertEqual("not_proved", record["outcome"], record)
        self.assertEqual(1, record["probes"][0]["exit_code"])
        self.assertNotIn("failure_evidence", record["probes"][0])
        self.assertEqual([], defects.git_status(root))

    def test_only_a_recorded_failure_of_the_exact_case_supplies_a_witness(self):
        template = defects.PLANTED_PYTHON_TEST
        variants = {
            "caught assertion": template.replace('self.fail("planted defect")',
                                                 'with self.assertRaises(AssertionError): self.fail("planted defect")'),
            "skip": template.replace('self.fail("planted defect")', 'self.skipTest("synthetic skip")'),
            "error": template.replace('self.fail("planted defect")', 'raise RuntimeError("synthetic error")'),
            "expected failure": template.replace("    def test_planted_defect_must_fail",
                                                 "    @unittest.expectedFailure\n    def test_planted_defect_must_fail"),
        }
        variants["unexpected success"] = variants["expected failure"].replace(
            'self.fail("planted defect")', "self.assertTrue(True)",
        )
        for label, source in variants.items():
            with self.subTest(outcome=label):
                root, context = self.consumer(".github", {
                    "scripts/tests/test_zz_unrelated.py":
                        "import unittest\n\nclass Unrelated(unittest.TestCase):\n"
                        "    def test_unrelated(self): self.fail('unrelated failure')\n",
                })
                before = support.tree_digest(root)
                with mock.patch.object(defects, "PLANTED_PYTHON_TEST", source):
                    record = defects.run_fixture(fixture("python-test-failing"), context)
                self.assertEqual("not_proved", record["outcome"], record)
                self.assertEqual(1, record["probes"][0]["exit_code"])
                self.assertNotIn("failure_evidence", record["probes"][0])
                self.assertEqual(before, support.tree_digest(root))
                self.assertEqual([], defects.git_status(root))

    def test_an_unexecuted_plant_cannot_borrow_a_complete_printed_report(self):
        context = defects.Context(".github", support.generator.profile_for(".github"), None, None)
        heading = fixture("python-test-failing").probes(context)[0].expect_text
        message = ".F\n" + "=" * 70 + "\n" + heading + "\n" + "-" * 70 + "\nFAILED (failures=1)"
        root, context = self.consumer(".github", {
            "scripts/tests/test_zz_unrelated.py":
                f"import unittest\nMESSAGE = {message!r}\n\nclass Unrelated(unittest.TestCase):\n"
                "    def test_unrelated(self): self.fail(MESSAGE)\n",
        })
        before = support.tree_digest(root)
        source = defects.PLANTED_PYTHON_TEST + "\ndef load_tests(loader, tests, pattern):\n    return unittest.TestSuite()\n"
        with mock.patch.object(defects, "PLANTED_PYTHON_TEST", source):
            record = defects.run_fixture(fixture("python-test-failing"), context)
        self.assertEqual("error", record["outcome"], record)
        self.assertIn("unittest witness refused", record["reason"])
        self.assertNotIn("failure_evidence", record["probes"][0])
        self.assertEqual(before, support.tree_digest(root))

    def test_the_child_refuses_to_write_a_witness_that_has_gained_another_link(self):
        root, context = self.consumer(".github")
        before = support.tree_digest(root)
        alias = root.parent / "witness-alias.json"
        arm = defects._UnittestWitness.arm

        def linked(witness):
            arm(witness)
            os.link(witness.path, alias)

        with mock.patch.object(defects._UnittestWitness, "arm", linked):
            record = defects.run_fixture(fixture("python-test-failing"), context)
        self.assertEqual("error", record["outcome"], record)
        self.assertEqual(1, record["probes"][0]["exit_code"])
        self.assertIn("unittest witness ownership changed", record["probes"][0]["output_tail"])
        self.assertEqual(b"", alias.read_bytes(), "the child must not write through an unsafe witness")
        self.assertNotIn("failure_evidence", record["probes"][0])
        self.assertEqual(before, support.tree_digest(root))

    def test_timeout_unsafe_lifetime_and_cleanup_failure_cannot_prove_a_fixture(self):
        original_planter = defects.Planter
        original_rmtree = shutil.rmtree
        for boundary in ("timeout", "unsafe", "cleanup"):
            with self.subTest(boundary=boundary):
                extras = ({
                    "scripts/tests/test_zz_slow.py":
                        "import time\nimport unittest\n\nclass Slow(unittest.TestCase):\n"
                        "    def test_slow(self): time.sleep(6)\n",
                } if boundary == "timeout" else {})
                root, context = self.consumer(".github", extras)
                before = support.tree_digest(root)
                owned = []

                def planter(root):
                    value = original_planter(root)
                    owned.append(value)
                    return value

                def runner(command, cwd):
                    result = defects.subprocess_runner(command, cwd, timeout=2 if boundary == "timeout" else 20)
                    witness, = owned[0]._unittest_witnesses.values()
                    self.assertEqual(True, witness.responses[witness.path.read_bytes()])
                    if boundary == "unsafe":
                        return dataclasses.replace(result, restoration_safe=False, error="synthetic unconfirmed lifetime")
                    return result

                def cleanup(path, *args, **kwargs):
                    if boundary == "cleanup" and owned and str(path) == owned[0]._aside:
                        raise PermissionError("synthetic witness cleanup refusal")
                    return original_rmtree(path, *args, **kwargs)

                try:
                    with mock.patch.object(defects, "Planter", side_effect=planter), \
                            mock.patch.object(defects.shutil, "rmtree", cleanup):
                        record = defects.run_fixture(fixture("python-test-failing"), context, runner=runner)
                    self.assertEqual("error", record["outcome"], record)
                    if boundary == "cleanup":
                        self.assertIn("backup cleanup failed: PermissionError", record["reason"])
                        self.assertEqual("PermissionError", record["cleanup"]["error"])
                    else:
                        self.assertNotIn("failure_evidence", record["probes"][0])
                    if boundary == "unsafe":
                        self.assertTrue(record["restoration_deferred"])
                        self.assertTrue(Path(owned[0]._aside).is_dir())
                        self.assertNotEqual(before, support.tree_digest(root))
                    elif boundary == "timeout":
                        self.assertTrue(record["probes"][0]["timed_out"])
                        self.assertIsNone(owned[0]._aside)
                finally:
                    for value in owned:
                        value.restore()
                self.assertEqual(before, support.tree_digest(root))
                self.assertEqual([], defects.git_status(root))

    def test_a_passing_plant_cannot_borrow_quoted_failure_headings(self):
        context = defects.Context(".github", support.generator.profile_for(".github"), None, None)
        heading = fixture("python-test-failing").probes(context)[0].expect_text
        messages = (
            heading,
            repr(heading),
            heading + " (unrelated diagnostic)",
            "Quoted failure:\n" + heading + "\nEnd of quote",
            "Quoted failure:\n" + heading + " (unrelated diagnostic)\nEnd of quote",
            "Captured earlier unittest diagnostic:\n" + "=" * 70 + "\n" + heading
            + "\n" + "-" * 70 + "\nEnd of captured diagnostic",
            "Saved report:\n.F\n" + "=" * 70 + "\n" + heading + "\n" + "-" * 70
            + "\nTraceback (most recent call last):\nAssertionError: planted defect\n\n"
            + "-" * 70 + "\nRan 2 tests in 0.001s\n\nFAILED (failures=1)\n",
        )
        for message in messages:
            with self.subTest(message=message):
                root, context = self.consumer(".github", {
                    "scripts/tests/test_zz_unrelated.py":
                        f"import unittest\n\nMESSAGE = {message!r}\n\nclass Unrelated(unittest.TestCase):\n"
                        "    def test_unrelated(self):\n"
                        "        self.fail(MESSAGE)\n",
                })
                before = support.tree_digest(root)
                results = []

                def runner(command, cwd):
                    result = defects.subprocess_runner(command, cwd)
                    results.append(result)
                    return result

                passing = defects.PLANTED_PYTHON_TEST.replace('self.fail("planted defect")', "self.assertTrue(True)")
                with mock.patch.object(defects, "PLANTED_PYTHON_TEST", passing):
                    record = defects.run_fixture(fixture("python-test-failing"), context, runner=runner)
                result, = results
                self.assertLess(len(result.output), defects.OUTPUT_TAIL, "inspect the complete tiny diagnostic")
                self.assertIn("FAIL: test_unrelated (test_zz_unrelated.Unrelated.test_unrelated)", result.output)
                self.assertIn("FAILED (failures=1)", result.output)
                self.assertEqual("", result.failure_evidence)
                self.assertEqual("not_proved", record["outcome"], record)
                self.assertEqual(1, result.exit_code)
                self.assertFalse(result.timed_out)
                self.assertIsNone(result.error)
                self.assertTrue(result.restoration_safe)
                self.assertEqual(before, support.tree_digest(root))
                self.assertEqual([], defects.git_status(root))

    def test_capture_never_attributes_any_printed_section_or_report(self):
        context = defects.Context("infra", support.generator.profile_for("infra"), None, None)
        first, second = fixture("python-test-failing").probes(context)
        traceback = ("Traceback (most recent call last):\n"
                     "AssertionError: quoted failure\n" + first.expect_text + "\n")
        actual = "=" * 70 + "\n" + second.expect_text + "\n" + "-" * 70 + "\n"
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)):
                output = (traceback + actual + traceback + "x" * defects.OUTPUT_TAIL).replace("\n", newline)
                captured = defects._captured_output(output.encode("utf-8"), lambda text: text)
                self.assertEqual("", captured["failure_evidence"])
                self.assertEqual("x" * defects.OUTPUT_TAIL, captured["output"])
                result = defects.Result(1, **captured)
                self.assertEqual("unexpected", defects.probe_outcome(first, result))
                self.assertEqual("unexpected", defects.probe_outcome(second, result))

    def test_capture_never_attributes_complete_or_decorated_headings(self):
        context = defects.Context(".github", support.generator.profile_for(".github"), None, None)
        heading = fixture("python-test-failing").probes(context)[0].expect_text
        for altered in (heading, "AssertionError: " + heading, repr(heading), " " + heading,
                        heading + " suffix", heading + " ", heading[:-1]):
            for newline in ("\n", "\r\n"):
                with self.subTest(heading=altered, newline=repr(newline)):
                    output = ("=" * 70 + "\n" + altered + "\n" + "-" * 70 + "\n").replace("\n", newline)
                    captured = defects._captured_output(output.encode("utf-8"), lambda text: text)
                    self.assertEqual("", captured["failure_evidence"])

    def test_each_directory_requires_its_own_failure_and_the_unittest_failure_code(self):
        _, context = self.consumer("infra")
        first, second = fixture("python-test-failing").probes(context)
        for result in (
            defects.Result(1, "", failure_evidence=second.expect_text),
            defects.Result(1, first.expect_text),
            defects.Result(1, first.expect_text, failure_evidence=second.expect_text),
            defects.Result(1, "", failure_evidence=first.expect_text + " suffix"),
            defects.Result(1, "", failure_evidence="AssertionError: " + first.expect_text),
            defects.Result(2, "", failure_evidence=first.expect_text),
            defects.Result(5, "", failure_evidence=first.expect_text),
            defects.Result(0, "", failure_evidence=first.expect_text),
        ):
            with self.subTest(result=result):
                self.assertEqual("unexpected", defects.probe_outcome(first, result))
        for result in (
            defects.Result(None, "", timed_out=True, failure_evidence=first.expect_text),
            defects.Result(1, "", error="unconfirmed capture", failure_evidence=first.expect_text),
            defects.Result(1, "", restoration_safe=False, failure_evidence=first.expect_text),
        ):
            with self.subTest(result=result):
                self.assertEqual("error", defects.probe_outcome(first, result))
        self.assertEqual("as_expected", defects.probe_outcome(
            first, defects.Result(1, "", failure_evidence=first.expect_text),
        ))

    def test_contracts_uses_declared_locked_preparation_before_planting_and_fails_closed(self):
        for failure_at in (None, 0, 1):
            with self.subTest(failure_at=failure_at):
                root, context = self.consumer("contracts")
                installs = context.profile["install"]
                self.assertEqual(["npm ci --no-audit --no-fund", "python scripts/toolchain.py install"], installs)
                before = support.tree_digest(root)
                calls = []
                probe = fixture("python-test-failing").probes(context)[0]

                def runner(command, cwd):
                    calls.append(command)
                    planted = root / "scripts/tests/test_planted_conformance_defect_0.py"
                    if command in installs:
                        self.assertFalse(planted.exists())
                        code = 1 if installs.index(command) == failure_at else 0
                        return defects.Result(code, "synthetic dependency refusal" if code else "prepared")
                    self.assertTrue(planted.exists())
                    self.assertEqual(probe.command, command)
                    return defects.subprocess_runner(command, cwd)

                record = defects.run_fixture(fixture("python-test-failing"), context, runner=runner)
                if failure_at is None:
                    self.assertEqual(installs + [probe.command], calls)
                    self.assertEqual("proved", record["outcome"], record)
                else:
                    self.assertEqual(installs[:failure_at + 1], calls)
                    self.assertEqual("error", record["outcome"])
                    self.assertEqual("prepare command failed", record["reason"])
                    self.assertIn("synthetic dependency refusal", record["probes"][-1]["output_tail"])
                self.assertEqual(before, support.tree_digest(root))
                self.assertEqual([], defects.git_status(root))

    def test_unittest_preparation_does_not_expand_other_profiles_or_excluded_toolchains(self):
        for name in support.generator.PROFILES["repositories"]:
            context = defects.Context(name, support.generator.profile_for(name), None, None)
            if name != "contracts":
                self.assertEqual([], fixture("python-test-failing").prepare(context), name)
        root, context = self.consumer("contracts")
        runner = mock.Mock(side_effect=AssertionError("excluded fixtures must not install or execute"))
        record = defects.run_fixture(fixture("python-test-failing"), context, runner=runner, exercise=("node", "uv"))
        self.assertEqual("not_exercised", record["outcome"])
        runner.assert_not_called()
        self.assertEqual([], defects.git_status(root))

    def test_current_rendered_infra_checker_refuses_only_the_planted_ci_change(self):
        root, context = self.consumer("infra")
        before = support.tree_digest(root)
        baseline = defects.subprocess_runner([sys.executable, "scripts/check_repository.py"], root)
        self.assertEqual(0, baseline.exit_code, baseline.output)
        record = defects.run_fixture(fixture("workflow-step-continue-on-error"), context)
        self.assertEqual("proved", record["outcome"], record)
        drift, checker = record["probes"]
        self.assertIn(".github/workflows/ci.yml", drift["output_tail"])
        self.assertIn("Infra CI must match its generated qualification jobs and required result",
                      checker["output_tail"])
        self.assertNotIn("unreviewed workflow expression", checker["output_tail"])
        self.assertEqual(before, support.tree_digest(root))
        self.assertEqual([], defects.git_status(root))

    def test_rendered_checker_uses_the_existing_refusal_for_every_profile(self):
        for name in support.generator.PROFILES["repositories"]:
            if name == "infra":
                continue
            with self.subTest(profile=name):
                root, context = self.consumer(name)
                before = support.tree_digest(root)
                baseline = defects.subprocess_runner([sys.executable, "scripts/check_repository.py"], root)
                self.assertEqual(0, baseline.exit_code, baseline.output)
                record = defects.run_fixture(fixture("workflow-step-continue-on-error"), context)
                self.assertEqual("proved", record["outcome"], record)
                probe = record["probes"][-1]
                self.assertEqual(1, probe["exit_code"])
                self.assertIn(probe["expect_text"], probe["output_tail"])
                self.assertNotIn("unreviewed workflow expression", probe["output_tail"])
                self.assertEqual(before, support.tree_digest(root))
                self.assertEqual([], defects.git_status(root))

    def test_stale_api_binding_refusal_cannot_be_claimed_as_planted_step_evidence(self):
        document = json.loads(support.generator.workflow("api"))
        step = document["jobs"]["windows"]["steps"][-1]
        commands = step["run"].splitlines()[::2]
        self.assertEqual("python -I -S -B scripts\\money_client_interop.py prepare", commands[-2])
        step["run"] = support.generator.powershell_commands(commands[:-2] + commands[-1:])
        root, context = self.consumer("api", {".github/workflows/ci.yml": support.generator.encoded(document)})
        before = support.tree_digest(root)
        baseline = defects.subprocess_runner([sys.executable, "scripts/check_repository.py"], root)
        self.assertEqual(1, baseline.exit_code)
        self.assertIn("API CI must match", baseline.output)
        record = defects.run_fixture(fixture("workflow-step-continue-on-error"), context)
        self.assertEqual("error", record["outcome"], record)
        self.assertIn("unmodified workflow", record["reason"])
        self.assertEqual([], record["probes"])
        self.assertEqual(before, support.tree_digest(root))
        self.assertEqual([], defects.git_status(root))

    def test_existing_step_key_refusal_cannot_be_claimed_as_planted_step_evidence(self):
        document = json.loads(support.generator.workflow(".github"))
        defects.run_checks_step(document)["continue-on-error"] = False
        root, context = self.consumer(".github", {".github/workflows/ci.yml": support.generator.encoded(document)})
        before = support.tree_digest(root)
        record = defects.run_fixture(fixture("workflow-step-continue-on-error"), context)
        self.assertEqual("error", record["outcome"], record)
        self.assertIn("unmodified workflow", record["reason"])
        self.assertEqual([], record["probes"])
        self.assertEqual(before, support.tree_digest(root))
        self.assertEqual([], defects.git_status(root))


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
    ISOLATION_KEYS = {"PYTHONDONTWRITEBYTECODE", "PYTHONIOENCODING", "CI", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM",
                      "GIT_TERMINAL_PROMPT", "GH_CONFIG_DIR", "NoDefaultCurrentDirectoryInExePath"}

    def test_probe_environment_drops_credential_looking_variables_and_keeps_the_path(self):
        environ = {"PATH": "/usr/bin", "GH_TOKEN": "x", "GITHUB_TOKEN": "x", "MY_SECRET": "x", "DB_PASSWORD": "x",
                   "AWS_ACCESS_KEY": "x", "NPM_CONFIG_PRIVATE_KEY": "x", "JAVA_HOME": "/jdk", "ANDROID_HOME": "/sdk",
                   "SOME_CREDENTIAL_FILE": "x", "PATHEXT": ".EXE"}
        cleaned = defects.probe_environment(environ)
        self.assertEqual({"PATH", "JAVA_HOME", "ANDROID_HOME", "PATHEXT"} | self.ISOLATION_KEYS, set(cleaned))
        self.assertEqual("1", cleaned["PYTHONDONTWRITEBYTECODE"])

    def test_probe_environment_removes_the_explicit_deny_list_and_isolates_git_and_gh(self):
        """S1 of the security review: names that carry or point at credentials, or that the Actions
        runner reads back from a step, never reach a child; git and gh see empty configuration."""
        denied = {
            "GIT_CONFIG_PARAMETERS": "'credential.https://github.com.helper=copilot'", "GH_TOKEN": "x",
            "GITHUB_TOKEN": "x", "SSH_AUTH_SOCK": "/run/agent", "SSH_AGENT_PID": "1", "GIT_ASKPASS": "/bin/askpass",
            "SSH_ASKPASS": "/bin/askpass", "GIT_SSH_COMMAND": "ssh -i key", "GIT_SSH": "/bin/ssh",
            "GH_CONFIG_DIR": "/home/op/.config/gh", "GH_HOST": "github.example", "GH_ENTERPRISE_TOKEN": "x",
            "GIT_TERMINAL_PROMPT": "1", "GIT_CONFIG_GLOBAL": "/home/op/.gitconfig", "GIT_CONFIG_SYSTEM": "/etc/gitconfig",
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "credential.helper", "GIT_CONFIG_VALUE_0": "store",
            "GIT_PROXY_COMMAND": "/bin/proxy", "ACTIONS_RUNTIME_TOKEN": "x", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "x",
            "ACTIONS_RESULTS_URL": "https://results", "GITHUB_ENV": "/runner/env", "GITHUB_PATH": "/runner/path",
            "GITHUB_STEP_SUMMARY": "/runner/summary", "GITHUB_ACTIONS": "true", "DOCKER_AUTH_CONFIG": "{}",
            "DOCKER_CONFIG": "/home/op/.docker", "NUGET_APIKEY": "x", "NPM_CONFIG__AUTH": "x", "NODE_AUTH_TOKEN": "x",
            "NPM_TOKEN": "x", "PIP_INDEX_URL": "https://u:p@pypi", "UV_INDEX_URL": "https://u:p@pypi",
            "AWS_SECRET_ACCESS_KEY": "x", "AWS_SESSION_TOKEN": "x", "AZURE_CLIENT_SECRET": "x",
            "GOOGLE_APPLICATION_CREDENTIALS": "/k.json", "TWINE_PASSWORD": "x", "ORG_GRADLE_PROJECT_signingKey": "x",
            "KUBECONFIG": "/k", "VAULT_TOKEN": "x", "gh_token": "lower-case spelling", "Git_Config_Parameters": "mixed",
        }
        kept = {"PATH": "/usr/bin", "PATHEXT": ".EXE", "HOME": "/home/op", "USERPROFILE": "C:\\Users\\op",
                "JAVA_HOME": "/jdk", "ANDROID_HOME": "/sdk", "TEMP": "/tmp", "SystemRoot": "C:\\Windows",
                "RUNNER_TEMP": "/runner/temp", "NEXT_TELEMETRY_DISABLED": "1", "LANG": "C.UTF-8"}
        cleaned = defects.probe_environment({**denied, **kept})
        self.assertEqual(set(kept) | self.ISOLATION_KEYS, set(cleaned))
        for name, value in kept.items():
            self.assertEqual(value, cleaned[name])
        self.assertEqual("1", cleaned["GIT_CONFIG_NOSYSTEM"])
        self.assertEqual("0", cleaned["GIT_TERMINAL_PROMPT"])
        self.assertEqual("1", cleaned["NoDefaultCurrentDirectoryInExePath"])
        global_config = Path(cleaned["GIT_CONFIG_GLOBAL"])
        self.assertTrue(global_config.is_file())
        self.assertEqual(b"", global_config.read_bytes())
        gh_config = Path(cleaned["GH_CONFIG_DIR"])
        self.assertTrue(gh_config.is_dir())
        self.assertEqual([], list(gh_config.iterdir()))
        self.assertNotEqual("/home/op/.gitconfig", cleaned["GIT_CONFIG_GLOBAL"])
        self.assertNotEqual("/home/op/.config/gh", cleaned["GH_CONFIG_DIR"])

    def test_a_real_child_process_sees_the_isolated_environment(self):
        """The environment handed to a real child carries none of the denied variables. (The parent's
        os.environ is never patched: restoring an empty-valued variable through putenv deletes it from
        the real process block on Windows and would break git for the rest of the test process.)"""
        script = ("import os, json; print(json.dumps({k: v for k, v in os.environ.items() "
                  "if k.upper().startswith(('GH_', 'GIT_CONFIG', 'GITHUB_', 'ACTIONS_', 'SSH_')) or k == 'PLAIN'}))")
        environ = {**os.environ, "GH_TOKEN": "x", "GITHUB_TOKEN": "x", "GIT_CONFIG_PARAMETERS": "x",
                   "SSH_AUTH_SOCK": "x", "ACTIONS_RUNTIME_TOKEN": "x", "PLAIN": "kept"}
        completed = subprocess.run([sys.executable, "-c", script], capture_output=True, check=False,
                                   env=defects.probe_environment(environ), timeout=60)
        self.assertEqual(0, completed.returncode, completed.stderr)
        child = json.loads(completed.stdout.decode("utf-8").strip().splitlines()[-1])
        self.assertEqual({"GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GH_CONFIG_DIR", "PLAIN"}, set(child))
        self.assertEqual("kept", child["PLAIN"])

    def test_git_in_the_isolated_environment_reads_no_operator_configuration(self):
        with tempfile.TemporaryDirectory() as scratch:
            home = Path(scratch) / "home"
            home.mkdir()
            (home / ".gitconfig").write_text("[credential]\n\thelper = store\n[user]\n\tname = operator\n", encoding="utf-8")
            environ = {**os.environ, "HOME": str(home), "USERPROFILE": str(home), "GIT_CONFIG_GLOBAL": str(home / ".gitconfig")}
            visible = subprocess.run(["git", "config", "--global", "--list"], capture_output=True, check=False, env=environ)
            self.assertIn(b"credential.helper=store", visible.stdout, "precondition: the operator config is readable")
            hidden = subprocess.run(["git", "config", "--global", "--list"], capture_output=True, check=False,
                                    env=defects.probe_environment(environ))
            self.assertEqual(b"", hidden.stdout.strip())

    @unittest.skipUnless(os.name == "nt", "cmd.exe resolves bare command names from the working directory")
    def test_shell_probes_do_not_resolve_commands_from_the_consumer_working_directory(self):
        """S5: a consumer-committed python.cmd in the scratch root must not shadow the real interpreter."""
        with tempfile.TemporaryDirectory() as cwd:
            (Path(cwd) / "python.cmd").write_text("@echo HIJACKED\n", encoding="utf-8")
            result = defects.subprocess_runner('python -c "print(7 * 6)"', cwd)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("42", result.output)
        self.assertNotIn("HIJACKED", result.output)

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
        consumer = defects.Probe("x", "cmd", expect="consumer")
        self.assertEqual("as_expected", defects.probe_outcome(consumer, defects.Result(0, "")))
        self.assertEqual("unexpected", defects.probe_outcome(consumer, defects.Result(1, "")))

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
