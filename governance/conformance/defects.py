"""Planted-defect harness: plant one defect in a scratch checkout, run the profile's real command,
restore the tree byte for byte, and record whether the command refused the defect.

The acceptance this proves is "a repository whose test step is removed or stubbed fails the
conformance job": every fixture states which language it covers, which toolchain it needs and
which probes must exit non-zero. A fixture whose toolchain is not exercised in this run is
recorded as ``not_exercised`` with the reason; nothing is inferred. Precedents: the android
``quality_gates.py self-test`` and the contracts planted lint probes.

Safety: the harness refuses to plant into a tree that ``git status`` does not report clean,
restores every changed path in reverse order, and reports ``error`` (which fails the job) when
the tree is not clean again afterwards. Probe processes receive an environment without any
variable whose name looks like a credential. Nothing here writes to a remote.
"""

import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

from conformance import steps


LANGUAGES = ("workflow", "python", "documentation", "typescript", "kotlin")
TOOLCHAINS = ("python", "node", "uv", "java", "android")
DEFAULT_EXERCISE = ("python",)
COMMAND_TIMEOUT_SECONDS = 900
OUTPUT_TAIL = 3000
RECORDED_TAIL = 400
UNITTEST_COMMAND = re.compile(r"python -m unittest discover -s (\S+)")
CREDENTIAL_VARIABLE = re.compile(r"TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|PRIVATE_KEY|_KEY$", re.IGNORECASE)
PLANTED_PYTHON_TEST = '''"""Planted by the PenniLogic conformance job; never committed."""

import unittest


class PlantedConformanceDefect(unittest.TestCase):
    def test_planted_defect_must_fail(self):
        self.fail("planted defect")
'''
PLANTED_PYTEST = '''"""Planted by the PenniLogic conformance job; never committed."""


def test_planted_defect_must_fail() -> None:
    raise AssertionError("planted defect")
'''
PLANTED_VITEST = """// Planted by the PenniLogic conformance job; never committed.
import { expect, test } from 'vitest';

test('planted defect must fail', () => {
  expect('planted defect').toBe('refused');
});
"""
PLANTED_JUNIT = """// Planted by the PenniLogic conformance job; never committed.
package com.pennilogic

import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test

class PlantedConformanceDefectTest {
    @Test
    fun `planted defect must fail`() {
        fail<Unit>("planted defect")
    }
}
"""


@dataclasses.dataclass
class Result:
    exit_code: object
    output: str
    timed_out: bool = False


@dataclasses.dataclass
class Probe:
    """One command run against the planted tree.

    ``expect`` is ``fail`` (the command must exit non-zero, with ``expect_text`` in its output when
    given), ``pass`` (it must exit 0) or ``observe`` (recorded, never required). ``detail_text`` is
    recorded when present in the output but never required: the checker template surfaces its rule
    text only since PR E (#50), and a consumer that has not regenerated still refuses correctly.
    """
    label: str
    command: object          # argv list (run directly) or one shell line (the profile's own wording)
    expect: str = "fail"
    expect_text: str = None
    detail_text: str = None
    note: str = None


@dataclasses.dataclass
class Fixture:
    id: str
    language: str
    toolchain: str
    description: str
    applies: object          # callable(context) -> bool
    plant: object            # callable(context, planter) -> None
    probes: object           # callable(context) -> list[Probe]
    prepare: object = None   # callable(context) -> list[command] run before planting (installs)


@dataclasses.dataclass
class Context:
    name: str
    profile: dict
    root: object             # Path of the scratch checkout
    infra_root: object       # Path of the PenniLogic/infra checkout running the job


def probe_environment(environ=None):
    """The inherited environment without credential-looking variables, plus the Python hygiene flags."""
    environ = os.environ if environ is None else environ
    cleaned = {key: value for key, value in environ.items() if CREDENTIAL_VARIABLE.search(key) is None}
    cleaned.update(PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8", CI="1")
    return cleaned


def subprocess_runner(command, cwd, timeout=COMMAND_TIMEOUT_SECONDS):
    """Run one probe command in ``cwd`` with merged output; a shell line uses the platform shell."""
    try:
        completed = subprocess.run(
            command, cwd=str(cwd), shell=isinstance(command, str), env=probe_environment(), check=False,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
        )
    except subprocess.TimeoutExpired as expired:
        output = (expired.output or b"").decode("utf-8", errors="replace")
        return Result(None, output[-OUTPUT_TAIL:], timed_out=True)
    except OSError as error:
        return Result(None, f"{error.__class__.__name__}: command could not start")
    return Result(completed.returncode, completed.stdout.decode("utf-8", errors="replace")[-OUTPUT_TAIL:])


def git_status(root, run=subprocess.run):
    result = run(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
                 capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError("git status failed in the scratch checkout")
    return sorted(line for line in result.stdout.decode("utf-8", errors="replace").splitlines() if line)


class Planter:
    """Records every change made while planting so ``restore`` can undo it in reverse order."""

    def __init__(self, root):
        self.root = root
        self._undo = []
        self._aside = None

    def _path(self, relative):
        path = self.root / relative
        if self.root.resolve() not in path.resolve().parents:
            raise ValueError("planted path escapes the scratch checkout")
        return path

    def write(self, relative, content):
        path = self._path(relative)
        if path.exists():
            original = path.read_bytes()
            self._undo.append(lambda: path.write_bytes(original))
        else:
            self._undo.append(lambda: path.unlink(missing_ok=True))
            created = []
            parent = path.parent
            while not parent.exists():
                created.append(parent)
                parent = parent.parent
            for directory in reversed(created):
                directory.mkdir()
                self._undo.append(lambda d=directory: shutil.rmtree(d, ignore_errors=True))
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))

    def create(self, relative, content):
        if self._path(relative).exists():
            raise FileExistsError("refusing to overwrite an existing file for a planted defect")
        self.write(relative, content)

    def edit_text(self, relative, transform):
        path = self._path(relative)
        text = path.read_text(encoding="utf-8")
        changed = transform(text)
        if changed == text:
            raise ValueError("planted edit changed nothing")
        self.write(relative, changed)

    def edit_json(self, relative, transform):
        path = self._path(relative)
        document = json.loads(path.read_text(encoding="utf-8"))
        transform(document)
        self.write(relative, json.dumps(document, indent=2) + "\n")

    def move_aside(self, relative):
        path = self._path(relative)
        if not path.exists():
            raise FileNotFoundError("planted removal of a path that does not exist")
        if self._aside is None:
            self._aside = tempfile.mkdtemp(prefix="pennilogic-conformance-aside-")
        target = os.path.join(self._aside, uuid.uuid4().hex)
        shutil.move(str(path), target)
        self._undo.append(lambda: shutil.move(target, str(path)))

    def restore(self):
        while self._undo:
            self._undo.pop()()
        if self._aside is not None:
            shutil.rmtree(self._aside, ignore_errors=True)
            self._aside = None


def unittest_directories(profile):
    return [match.group(1) for command in profile["commands"]
            for match in [UNITTEST_COMMAND.search(command)] if match]


def unittest_commands(profile):
    return [command for command in profile["commands"] if UNITTEST_COMMAND.search(command)]


def has_command(profile, pattern):
    return any(re.search(pattern, command) for command in profile["commands"])


def run_checks_step(document):
    for job in document["jobs"].values():
        for step in job["steps"]:
            if step.get("name") == "Run checks":
                return step
    raise ValueError("the workflow has no Run checks step")


def drift_probe(context):
    command = [sys.executable, str(context.infra_root / "governance" / "generate.py"),
               "--repository", context.name, "--root", str(context.root), "--check"]
    return Probe("generator drift check: generate.py --repository <profile> --root <scratch> --check",
                 command, expect="fail", expect_text=".github/workflows/ci.yml")


def checker_probe(label="consumer scripts/check_repository.py", expect="fail", rule=None, note=None):
    """The consumer's own checker must refuse (exit 1 with its refusal line); the rule text is recorded."""
    return Probe(label, [sys.executable, "scripts/check_repository.py"], expect=expect,
                 expect_text="Invalid or unsafe workflow" if expect == "fail" else None, detail_text=rule, note=note)


def workflow_fixture(fixture_id, description, transform, extra_probes):
    def plant(context, planter):
        planter.edit_json(".github/workflows/ci.yml", lambda document: transform(context, document))

    def probes(context):
        return [drift_probe(context), *extra_probes(context)]

    return Fixture(fixture_id, "workflow", "python", description, lambda context: True, plant, probes)


def _remove_test_lines(context, document):
    step = run_checks_step(document)
    lines = step["run"].split("\n")
    kept = [line for line in lines if "test" not in steps.classify(line)]
    if kept == lines:
        raise ValueError("the profile has no test command to remove")
    step["run"] = "\n".join(kept)


def _stub_run_checks(context, document):
    run_checks_step(document)["run"] = "echo tests skipped"


def _condition_on_run_checks(context, document):
    run_checks_step(document)["if"] = "false"


def _unpin_checkout(context, document):
    for job in document["jobs"].values():
        for step in job["steps"]:
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                step["uses"] = "actions/checkout@v4"
                return
    raise ValueError("the workflow has no checkout step")


def _reusable_workflow_job(context, document):
    document["jobs"]["reuse"] = {"uses": "PenniLogic/infra/.github/workflows/ci.yml@" + "0" * 40}


def _continue_on_error(context, document):
    run_checks_step(document)["continue-on-error"] = True


def _plant_continue_on_error(context, planter):
    planter.edit_json(".github/workflows/ci.yml", lambda document: _continue_on_error(context, document))
    template = (context.infra_root / "governance" / "templates" / "check_repository.py").read_bytes()
    planter.write("scripts/check_repository.py", template)


def _plant_python_removed(context, planter):
    for directory in unittest_directories(context.profile):
        files = sorted((context.root / directory).glob("test*.py"))
        if not files:
            raise ValueError("no test modules to remove")
        for path in files:
            planter.move_aside(path.relative_to(context.root).as_posix())


def _plant_python_failing(context, planter):
    for directory in unittest_directories(context.profile):
        planter.create(f"{directory}/test_planted_conformance_defect.py", PLANTED_PYTHON_TEST)


def _unittest_probes(expect_text):
    def probes(context):
        return [Probe(f"profile command: {command}", command, expect="fail", expect_text=expect_text)
                for command in unittest_commands(context.profile)]
    return probes


def _pytest_command(profile):
    return next(command for command in profile["commands"] if re.search(r"\bpytest\b", command))


def _pytest_prepare(context):
    return [command for command in context.profile.get("install", []) if "uv sync" in command]


def _pytest_probe(context, expect_text):
    command = _pytest_command(context.profile)
    return [Probe(f"profile command: {command}", command, expect="fail", expect_text=expect_text)]


def _plant_pytest_failing(context, planter):
    planter.create("tests/test_planted_conformance_defect.py", PLANTED_PYTEST)


def _plant_pytest_removed(context, planter):
    files = sorted((context.root / "tests").rglob("test_*.py"))
    if not files:
        raise ValueError("no pytest modules to remove")
    for path in files:
        planter.move_aside(path.relative_to(context.root).as_posix())


def _vitest_directory(context):
    return "tests/unit" if (context.root / "tests" / "unit").is_dir() else "tests"


def _plant_vitest_failing(context, planter):
    planter.create(f"{_vitest_directory(context)}/planted-conformance-defect.test.ts", PLANTED_VITEST)


def _plant_vitest_removed(context, planter):
    files = sorted(path for suffix in ("*.test.ts", "*.test.tsx") for path in (context.root / "tests").rglob(suffix))
    if not files:
        raise ValueError("no vitest modules to remove")
    for path in files:
        planter.move_aside(path.relative_to(context.root).as_posix())


def _npm_prepare(context):
    return [command for command in context.profile.get("install", []) if command.startswith("npm ci")]


def _plant_junit_failing(context, planter):
    planter.create("src/test/kotlin/com/pennilogic/PlantedConformanceDefectTest.kt", PLANTED_JUNIT)


def _plant_docs_index_link(context, planter):
    planter.edit_text("adr/README.md",
                      lambda text: text.replace("[ADR-001.md](ADR-001.md)", "[ADR-001.md](ADR-001-missing.md)", 1))


def _plant_docs_dangling_supersedes(context, planter):
    planter.edit_text("adr/ADR-015.md", lambda text: text.replace("supersedes: null", "supersedes: ADR-099", 1))


def _plant_docs_body_link(context, planter):
    planter.edit_text("README.md", lambda text: text + "\n[planted broken link](planted-missing-target.md)\n")


def _docs_probe(expect="fail", expect_text="Documentation check failed", note=None):
    return Probe("profile command: python scripts/check_docs.py", "python scripts/check_docs.py",
                 expect=expect, expect_text=expect_text, note=note)


FIXTURES = (
    workflow_fixture(
        "workflow-test-step-removed",
        "every test command is deleted from the Run checks step of the rendered ci.yml",
        _remove_test_lines,
        lambda context: [checker_probe(expect="observe", note="the checker validates shape and token boundaries, not which commands run; the drift check is the tripwire for a removed command")],
    ),
    workflow_fixture(
        "workflow-test-step-stubbed",
        "the Run checks step is replaced by an echo that always succeeds",
        _stub_run_checks,
        lambda context: [checker_probe(expect="observe", note="a stubbed command is caught by the drift check, not by the checker")],
    ),
    workflow_fixture(
        "workflow-step-skipped-by-condition",
        "an `if: false` condition is added to the Run checks step",
        _condition_on_run_checks,
        lambda context: [checker_probe(rule="conditions are not part of the generated workflows")],
    ),
    workflow_fixture(
        "workflow-unpinned-action",
        "actions/checkout is referenced by the moving tag v4 instead of a commit",
        _unpin_checkout,
        lambda context: [checker_probe(rule="action must be immutable")],
    ),
    workflow_fixture(
        "workflow-reusable-workflow-job",
        "a job consumes a reusable workflow through jobs.<id>.uses (the adoption model PR D refused)",
        _reusable_workflow_job,
        lambda context: [checker_probe(rule="action must be immutable")],
    ),
    Fixture(
        "workflow-step-continue-on-error", "workflow", "python",
        "continue-on-error: true is added to the Run checks step; refused by the current template (the step-key rule from PR E) and by the drift check",
        lambda context: True, _plant_continue_on_error,
        lambda context: [drift_probe(context), Probe(
            "current infra template check_repository.py over the scratch tree",
            [sys.executable, "scripts/check_repository.py"], expect="fail",
            expect_text="step-level key outside the generated step keys",
            note="the template of the generator running this job is copied over scripts/check_repository.py for this probe",
        )],
    ),
    Fixture(
        "python-tests-removed", "python", "python",
        "every test module of each unittest start directory is removed; unittest exits 5 (NO TESTS RAN)",
        lambda context: bool(unittest_directories(context.profile)), _plant_python_removed,
        _unittest_probes("NO TESTS RAN"),
    ),
    Fixture(
        "python-test-failing", "python", "python",
        "a failing unittest module is planted in each unittest start directory and must be counted as a failure",
        lambda context: bool(unittest_directories(context.profile)), _plant_python_failing,
        _unittest_probes("test_planted_defect_must_fail"),
    ),
    Fixture(
        "python-pytest-failing", "python", "uv",
        "a failing pytest module is planted under tests/ and the locked uv pytest command must fail",
        lambda context: has_command(context.profile, r"\bpytest\b"), _plant_pytest_failing,
        lambda context: _pytest_probe(context, "test_planted_defect_must_fail"),
        prepare=_pytest_prepare,
    ),
    Fixture(
        "python-pytest-removed", "python", "uv",
        "every pytest module under tests/ is removed; pytest exits 5 (no tests collected)",
        lambda context: has_command(context.profile, r"\bpytest\b"), _plant_pytest_removed,
        lambda context: _pytest_probe(context, "no tests ran"),
        prepare=_pytest_prepare,
    ),
    Fixture(
        "documentation-index-link-broken", "documentation", "python",
        "an ADR index link in adr/README.md points at a file that does not exist",
        lambda context: has_command(context.profile, r"\bcheck_docs\.py\b"), _plant_docs_index_link,
        lambda context: [_docs_probe(expect_text="generated slot ADR-001 differs")],
    ),
    Fixture(
        "documentation-dangling-supersedes", "documentation", "python",
        "ADR-015 claims to supersede ADR-099, a record that does not exist",
        lambda context: has_command(context.profile, r"\bcheck_docs\.py\b"), _plant_docs_dangling_supersedes,
        lambda context: [_docs_probe(expect_text="supersedes ADR-099, which has no source record")],
    ),
    Fixture(
        "documentation-body-link-broken", "documentation", "python",
        "a relative Markdown link outside the ADR graph points at a missing file; recorded to show what check_docs.py does not cover",
        lambda context: has_command(context.profile, r"\bcheck_docs\.py\b"), _plant_docs_body_link,
        lambda context: [_docs_probe(expect="observe", expect_text=None,
                                     note="check_docs.py validates the ADR graph, index and inventories, not arbitrary Markdown links; a general link checker is a separate docs decision")],
    ),
    Fixture(
        "typescript-test-failing", "typescript", "node",
        "a failing vitest module is planted under the tests directory and npm test must fail",
        lambda context: has_command(context.profile, r"^npm test\b"), _plant_vitest_failing,
        lambda context: [Probe("profile command: npm test", "npm test", expect="fail", expect_text="planted defect")],
        prepare=_npm_prepare,
    ),
    Fixture(
        "typescript-tests-removed", "typescript", "node",
        "every vitest module under tests/ is removed; vitest exits non-zero with no test files",
        lambda context: has_command(context.profile, r"^npm test\b"), _plant_vitest_removed,
        lambda context: [Probe("profile command: npm test", "npm test", expect="fail", expect_text="No test files found")],
        prepare=_npm_prepare,
    ),
    Fixture(
        "kotlin-test-failing", "kotlin", "java",
        "a failing JUnit 5 test is planted under src/test/kotlin and the Gradle test gate must fail",
        lambda context: has_command(context.profile, r"\bquality\.py build\b"), _plant_junit_failing,
        lambda context: [Probe("profile gate: python scripts/quality.py test", "python scripts/quality.py test",
                               expect="fail", expect_text="planted defect")],
    ),
    Fixture(
        "kotlin-android-self-test", "kotlin", "android",
        "the consumer-owned quality_gates.py self-test plants a failing test, spotless and lint defects and reused results on every CI run",
        lambda context: has_command(context.profile, r"\bquality_gates\.py self-test\b"),
        lambda context, planter: None,
        lambda context: [Probe("profile command: python scripts/quality_gates.py self-test",
                               "python scripts/quality_gates.py self-test", expect="pass",
                               note="exit 0 means every planted defect was refused; needs the Android SDK")],
    ),
)


def applicable_fixtures(context, fixtures=FIXTURES):
    return [fixture for fixture in fixtures if fixture.applies(context)]


def probe_outcome(probe, result):
    """``as_expected``/``unexpected`` for a required probe, ``detected``/``not_detected`` for an observation."""
    if result.timed_out or result.exit_code is None:
        return "error"
    failed = result.exit_code != 0
    matched = probe.expect_text is None or probe.expect_text in result.output
    if probe.expect == "fail":
        return "as_expected" if failed and matched else "unexpected"
    if probe.expect == "pass":
        return "as_expected" if not failed else "unexpected"
    return "detected" if failed else "not_detected"


def _probe_record(probe, result):
    return {
        "label": probe.label, "command": probe.command, "expect": probe.expect,
        "expect_text": probe.expect_text, "detail_text": probe.detail_text, "note": probe.note,
        "exit_code": result.exit_code, "timed_out": result.timed_out, "outcome": probe_outcome(probe, result),
        "detail_surfaced": None if probe.detail_text is None else probe.detail_text in result.output,
        "output_tail": result.output[-RECORDED_TAIL:],
    }


def run_fixture(fixture, context, runner=subprocess_runner, exercise=DEFAULT_EXERCISE, status=git_status):
    """Plant, probe and restore one fixture; the returned record is what the report publishes.

    Outcomes: ``proved`` (every required probe behaved as required), ``not_proved``, ``recorded``
    (only observations), ``not_exercised`` (toolchain excluded from this run) or ``error``.
    """
    record = {
        "id": fixture.id, "language": fixture.language, "toolchain": fixture.toolchain,
        "description": fixture.description, "outcome": None, "reason": None, "probes": [],
    }
    if fixture.toolchain not in exercise:
        record["outcome"] = "not_exercised"
        record["reason"] = f"toolchain {fixture.toolchain} not exercised in this run"
        return record
    try:
        before = status(context.root)
    except RuntimeError as error:
        record["outcome"], record["reason"] = "error", str(error)
        return record
    if before:
        record["outcome"], record["reason"] = "error", "scratch checkout is not clean before planting"
        return record
    for command in (fixture.prepare(context) if fixture.prepare else []):
        result = runner(command, context.root)
        record["probes"].append(_probe_record(Probe(f"prepare: {command}", command, expect="pass"), result))
        if result.exit_code != 0:
            record["outcome"], record["reason"] = "error", "prepare command failed"
            return record
    planter = Planter(context.root)
    try:
        fixture.plant(context, planter)
        for probe in fixture.probes(context):
            record["probes"].append(_probe_record(probe, runner(probe.command, context.root)))
    except (OSError, ValueError, KeyError, TypeError) as error:
        record["outcome"], record["reason"] = "error", f"planting failed: {error.__class__.__name__}: {error}"
    finally:
        try:
            planter.restore()
        except OSError as error:
            # The status check below then reports the paths that are still wrong.
            record["outcome"], record["reason"] = "error", f"restore failed: {error.__class__.__name__}"
    try:
        after = status(context.root)
    except RuntimeError as error:
        record["outcome"], record["reason"] = "error", str(error)
        return record
    if after:
        detail = "scratch checkout was not restored after planting"
        record["reason"] = f"{record['reason']}; {detail}" if record["outcome"] == "error" and record["reason"] else detail
        record["outcome"] = "error"
        record["unrestored_paths"] = after
        return record
    if record["outcome"] == "error":
        return record
    required = [probe for probe in record["probes"] if probe["expect"] in ("fail", "pass")]
    if any(probe["outcome"] == "error" for probe in record["probes"]):
        record["outcome"], record["reason"] = "error", "a probe timed out or could not start"
    elif required and all(probe["outcome"] == "as_expected" for probe in required):
        record["outcome"] = "proved"
    elif required:
        record["outcome"] = "not_proved"
        record["reason"] = "a required probe did not behave as the fixture requires"
    else:
        record["outcome"] = "recorded"
    return record


def run_fixtures(context, runner=subprocess_runner, exercise=DEFAULT_EXERCISE, fixtures=FIXTURES, status=git_status):
    records = []
    for fixture in applicable_fixtures(context, fixtures):
        record = run_fixture(fixture, context, runner, exercise, status)
        records.append(record)
        if record.get("unrestored_paths"):
            break  # the tree is no longer trustworthy; later fixtures would plant on top of the damage
    return records


def language_coverage(records):
    """Per language: ``proved`` when at least one fixture was proved, else the weakest outcome seen."""
    rank = {"proved": 0, "recorded": 1, "not_exercised": 2, "not_proved": 3, "error": 4}
    coverage = {}
    for record in records:
        language, outcome = record["language"], record["outcome"]
        current = coverage.get(language)
        if current == "proved":
            continue
        if outcome == "proved" or current is None or rank[outcome] > rank[current]:
            coverage[language] = outcome
    return coverage
