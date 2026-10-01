"""Detect the build, test and lint steps a profile runs and the check names its workflow produces.

Classification is a reviewed table of command patterns, evaluated against the exact command lines
of ``repository-profiles.json`` (the same lines the generator renders into the ``Run checks`` step).
A command may carry several categories: ``python scripts/quality.py build`` runs Gradle ``build``,
which executes the test and spotless tasks, so it is build, test and lint at once. Anything the
table does not know is ``other`` and never counts as a test.
"""

import json
import re


CATEGORIES = ("checker", "install", "build", "test", "lint", "other")
# (pattern, categories). Patterns are matched with re.search against one command line.
STEP_PATTERNS = (
    (r"\bscripts/check_repository\.py\b", {"checker"}),
    (r"\bgenerate\.py\b.*--check\b", {"checker"}),
    (r"^npm ci\b", {"install"}),
    (r"\buv sync\b", {"install"}),
    (r"\bpip install\b", {"install"}),
    (r"\btoolchain\.py install\b", {"install"}),
    (r"\bunittest\b", {"test"}),
    (r"\bpytest\b", {"test"}),
    (r"^npm test\b", {"test"}),
    (r"\bnpm run smoke\b", {"test"}),
    (r"\bscripts/smoke\.py\b", {"test"}),
    (r"\bquality_gates\.py test\b", {"test"}),
    (r"\bquality_gates\.py coverage\b", {"test"}),
    (r"\bquality_gates\.py self-test\b", {"test"}),
    (r"\bquality_gates\.py build\b", {"build"}),
    (r"\bquality_gates\.py lint\b", {"lint"}),
    (r"\bquality\.py build\b", {"build", "test", "lint"}),
    (r"\bquality\.py coverage\b", {"test"}),
    (r"\bnpm run build\b", {"build"}),
    (r"\bgenerate_clients\.py --verify\b", {"build"}),
    (r"\bnpm run check:bundle:planted\b", {"test"}),
    (r"\bnpm run check:bundle\b", {"lint"}),
    (r"\bnpm run report:build\b", {"other"}),
    (r"\bnpm run lint\b", {"lint"}),
    (r"\bnpm run format:check\b", {"lint"}),
    (r"\bnpm run typecheck\b", {"lint"}),
    (r"\bnpm run check:imports\b", {"lint"}),
    (r"\bruff (check|format)\b", {"lint"}),
    (r"\bmypy\b", {"lint"}),
    (r"\blint_spec\.py\b", {"lint"}),
    (r"\bcheck_breaking_changes\.py\b", {"lint"}),
    (r"\bcheck_docs\.py\b", {"lint"}),
    (r"\bcheck_test_strategy\.py\b", {"lint"}),
    (r"\bcheck_agent_profiles\.py\b", {"lint"}),
    (r"\bdocker compose\b.*\bconfig\b", {"lint"}),
)
# Consumer-owned planted-defect commands: the repository proves its own gates bite on every CI run.
CONSUMER_SELF_TESTS = (
    r"\bquality_gates\.py self-test\b",
    r"\bnpm run check:bundle:planted\b",
)


def classify(command):
    """Return the sorted categories of one command line (``["other"]`` when unknown)."""
    categories = set()
    for pattern, names in STEP_PATTERNS:
        if re.search(pattern, command):
            categories |= names
    return sorted(categories) or ["other"]


def detect_steps(commands):
    """Group a profile's command lines by category, preserving command order inside each group."""
    detected = {name: [] for name in CATEGORIES}
    for command in commands:
        for category in classify(command):
            detected[category].append(command)
    detected["consumer_self_tests"] = [
        command for command in commands if any(re.search(pattern, command) for pattern in CONSUMER_SELF_TESTS)
    ]
    return detected


def missing_categories(detected, required=("test",)):
    return [category for category in required if not detected.get(category)]


def produced_check_names(workflow_bytes):
    """The status-check contexts a JSON-syntax workflow produces: one per job, its name or its id."""
    document = json.loads(workflow_bytes.decode("utf-8"))
    jobs = document.get("jobs") if isinstance(document, dict) else None
    if not isinstance(jobs, dict):
        return set()
    names = set()
    for job_id, job in jobs.items():
        name = job.get("name") if isinstance(job, dict) else None
        names.add(name if isinstance(name, str) and name else job_id)
    return names


def produced_pr_check_names(workflows):
    """Only the CI and opted-in target-event file produce eligible native PR checks."""
    produced = set()
    for path, event in ((".github/workflows/ci.yml", "pull_request"),
                        (".github/workflows/pr-workflow-integrity.yml", "pull_request_target")):
        content = workflows.get(path)
        if content is None:
            continue
        document = json.loads(content.decode("utf-8"))
        events = document.get("on") if isinstance(document, dict) else None
        if isinstance(events, dict) and event in events:
            produced |= produced_check_names(content)
    return produced


def workflow_run_commands(workflow_bytes, step_name="Run checks"):
    """The command lines of the named run step (the generator joins profile commands with newlines)."""
    document = json.loads(workflow_bytes.decode("utf-8"))
    for job in document.get("jobs", {}).values():
        for step in job.get("steps", []):
            if step.get("name") == step_name and isinstance(step.get("run"), str):
                return step["run"].split("\n")
    return []
