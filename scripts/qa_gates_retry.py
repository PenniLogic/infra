"""Retry-limit configuration check for PenniLogic/infra#28 (T-QA-04; E25-F01).

    python scripts/qa_gates_retry.py [--root DIR] [--workflow .github/workflows/NAME.yml ...]
        [--runner-config RELATIVE/PATH.json ...] [--manifest PATH]

Docs test-strategy 1.1.1 section 8, "Automatic retry limit": a pipeline step configured to retry beyond the limit
fails the pipeline configuration check. The limits come only from the vendored, pinned docs flake policy
(`retry_limit`, `money_path_retry_limit`); a job is money-path only when the committed protected-tag manifest maps
it (workflow file and job key) to a money-path package.

Inputs are JSON-syntax workflow files and JSON runner configurations (for example package.json), named relative to
`--root`. The check reads object keys, `uses` action names and command-line flag tokens of string values; it never
matches free-text substrings. Known constructs (`--reruns`, `--retry`, `--retries`, `--max-attempts`,
`rerunFailingTestsCount`, `retry`/`retries`/`max_attempts` keys, retry actions such as nick-fields/retry) are counted
as re-executions. Only a known wrapper multiplies what it wraps (a retry action and the rest of its step); every
other combination is an alternative and the largest applies (independent steps, package.json scripts, commands of
one shell string, several flags of one command, workflow or job `env` against the step commands). Flags inside
`NAME=value` values (PYTEST_ADDOPTS, MAVEN_ARGS, `-o addopts=`) are read. A retry-shaped key, flag or action whose
count cannot be read, a workflow or job re-run request (`gh run rerun`, the rerun REST endpoints) and a retry-shaped
command word of a command line fail closed (RETRY-UNKNOWN). Every workflow file the manifest maps must be among the
inputs (INPUT-WORKFLOWS-MISSING otherwise). A job the manifest does not map takes the manifest's
strictest limit (RETRY-JOB-UNMAPPED, report). Every counted construct of at least one re-execution is reported as
RETRY-ATTEMPT-HIDDEN: it re-runs inside the reported attempt, so the quarantine gate cannot record the flake. A
retry-shaped name in a top-level dependency map of a runner configuration is reported without failing.

Exit 0 pass, 1 fail, 2 refused input or usage. stdout carries one ASCII JSON report with static rule codes, the
validated input paths and job keys only (no key names, values or other file content).
"""

import argparse
import json
from pathlib import Path
import re
import sys

import qa_gates_policy as policies
import qa_gates_tags as tags
from qa_gates_common import Refused, json_document, read_bounded


REPORT_SCHEMA = "pennilogic.qa-gates.retry-report/1"
CONFIG_LIMIT = 1024 * 1024
MAX_INPUTS = 64
MAX_DEPTH = 64
# Compounded re-executions are capped so a report stays printable; any value near the cap is far above every limit.
EXECUTION_CAP = 1000000
ROOT = Path(__file__).resolve().parent.parent
RELATIVE = re.compile(r"(?!\.{1,2}(?:/|\Z))[A-Za-z0-9_.-]+(?:/(?!\.{1,2}(?:/|\Z))[A-Za-z0-9_.-]+)*")
NUMBER = re.compile(r"[0-9]{1,6}")
# Normalized (lower case, alphanumerics only) names whose value is a number of re-executions or of attempts.
RE_EXECUTIONS = frozenset({
    "retry", "retries", "reruns", "maxretries", "retrycount", "retrytimes", "numretries", "rerunfailingtestscount",
    "flakyretries", "testretrycount",
})
ATTEMPTS = frozenset({"maxattempts", "attempts", "maxruns"})
# Normalized names that contain a retry-shaped word but do not set a count: Gradle forced task rerun, and the
# non-count modifiers of the named mechanisms (pytest-rerunfailures, nick-fields/retry).
NOT_RETRY = frozenset({
    "reruntasks", "rerun", "rerunsdelay", "onlyrerun", "retryon", "retrywaitseconds", "retryonexitcode",
    "onretrycommand", "warningonretry", "newcommandonretry",
})
SHAPES = ("retry", "retries", "rerun", "attempt", "flaky")
DEPENDENCY_MAPS = frozenset({
    "dependencies", "devdependencies", "peerdependencies", "optionaldependencies", "bundleddependencies",
    "bundledependencies", "overrides", "resolutions",
})
# Maps whose keys are labels (package.json script names): only their values are read.
LABEL_MAPS = frozenset({"scripts"})
SEPARATORS = re.compile(r"[\s'\"`;|&()<>]+")
# Commands of one shell string run one after another; their retries do not wrap each other.
COMMANDS = re.compile(r"(?:\n|;|&&|\|\||\|)+")
# An empty quote pair inside a word (`--re''runs`) is removed by the shell; join the fragments before tokenising.
EMPTY_QUOTES = re.compile(r"(?<=[A-Za-z0-9_.=-])(?:''|\"\")+(?=[A-Za-z0-9_.=-])")
# Re-running a failed workflow run from a workflow (gh CLI or the REST endpoint) is a retry with no readable count.
RERUN_ENDPOINT = re.compile(
    r"/actions/(?:runs/[^/\s]+/(?:rerun|rerun-failed-jobs)|jobs/[^/\s]+/rerun)\Z|\Arerun-failed-jobs\Z")
# A GitHub expression (`${{ github.event.workflow_run.id }}`) is one opaque word: it may contain spaces, which must not
# split the path or flag it is part of. Its value is unknown, so a count it supplies still fails closed.
EXPRESSION = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)


def normalize(name):
    return "".join(character for character in name.lower() if character.isalnum())


def shaped(normalized):
    return any(shape in normalized for shape in SHAPES)


def count(normalized, value):
    """Re-executions a known name with ``value`` configures; None when the name or value cannot be read."""
    if value is False:
        number = 0
    elif type(value) is int:
        number = value
    elif isinstance(value, str) and NUMBER.fullmatch(value):
        number = int(value)
    else:
        return None
    if number < 0:
        return None
    if normalized in RE_EXECUTIONS:
        return number
    if normalized in ATTEMPTS:
        return max(number - 1, 0)
    return None


def _named(name, value):
    """Classify one name (key, flag or property) with its value: None, ("count", n) or ("unknown", None)."""
    normalized = normalize(name.rsplit(".", 1)[-1])
    known = normalized in RE_EXECUTIONS or normalized in ATTEMPTS
    if normalized in NOT_RETRY or not (known or shaped(normalized)):
        return None
    number = count(normalized, value)
    return ("unknown", None) if number is None else ("count", number)


def _alternatives(groups):
    """Constructs of independent steps, scripts or commands: only the largest applies, nothing multiplies."""
    groups = [group for group in groups if group]
    if len(groups) <= 1:
        return groups[0] if groups else []
    return [("alternatives", tuple(groups))]


def _token_constructs(tokens, depth=0):
    # NAME=value values nest (A=B=--reruns=1); bound the walk so a deep chain is a refusal, not a RecursionError.
    if depth > MAX_DEPTH:
        raise Refused("CONFIG-DEPTH")
    found = []
    for index, token in enumerate(tokens):
        # `gh [global flags such as --repo o/r] run rerun`: `run rerun` after a `gh` word of the same command.
        rerun = token == "rerun" and index >= 2 and tokens[index - 1] == "run" and any(
            word == "gh" or word.endswith("/gh") for word in tokens[:index - 1])
        if rerun or RERUN_ENDPOINT.search(token):
            found.append(("unknown", None))
            continue
        dashed = token.startswith("-")
        if dashed:
            # -Dname=value (Java system property) and -Pname=value (Gradle project property).
            body = token[2:] if token.startswith(("-D", "-P")) else token.lstrip("-")
        elif "=" in token:
            body = token
        else:
            continue
        name, equals, inline = body.partition("=")
        if not name:
            continue
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if equals:
            argument = inline
        elif dashed and following is not None and not following.startswith("-"):
            argument = following
        else:
            argument = None
        construct = _named(name, argument)
        if construct is not None:
            found.append(construct)
        elif inline:
            # The value of NAME=value can carry flags itself (PYTEST_ADDOPTS=--reruns=5, -o addopts=--reruns=5,
            # MAVEN_ARGS=-D...=3); a following plain word can be the argument of such a flag.
            plain = following is not None and not following.startswith("-") and "=" not in following
            found.extend(_token_constructs([inline, following] if plain else [inline], depth + 1))
    return found


def _command_word(tokens):
    """The command word of one command: the first token that is not a `NAME=value` assignment, or None."""
    for token in tokens:
        if token.startswith("-") or "=" not in token:
            return token
    return None


def command_constructs(value, command=False):
    """Retry constructs among the flag and ``name=value`` tokens of one string; plain words are never matched.

    Commands separated by newlines, `;`, `&&`, `||` or `|` are independent: the largest of them applies. When the
    string is a command line (``command``: a workflow `run` or `shell`, a `scripts` entry), a retry-shaped command
    word (`retry --times 3 -- pytest`, `./retry.sh`) is a wrapper whose count cannot be read: it fails closed.
    """
    groups = []
    for line in COMMANDS.split(EMPTY_QUOTES.sub("", EXPRESSION.sub("${{expression}}", value))):
        tokens = [token for token in SEPARATORS.split(line) if token]
        found = _token_constructs(tokens)
        word = _command_word(tokens) if command else None
        if word is not None and shaped(normalize(word.rsplit("/", 1)[-1])):
            found.append(("unknown", None))
        groups.append(found)
    return _alternatives(groups)


def _counted(key):
    return normalize(key) in RE_EXECUTIONS or normalize(key) in ATTEMPTS


def _retry_action(node, depth):
    """A step whose `uses` names a retry-shaped action: None for any other node, else its constructs.

    The action is the one known wrapper: it re-runs everything else in the step, so its count multiplies what the
    rest of the step configures (("wrap", count or None, inner constructs)). Without a readable attempt or retry
    input it fails closed.
    """
    uses = node.get("uses")
    if not isinstance(uses, str) or not shaped(normalize(uses.split("@", 1)[0].rsplit("/", 1)[-1])):
        return None
    inputs = node.get("with")
    if not (isinstance(inputs, dict) and any(_counted(key) for key in inputs)):
        return [("unknown", None), *constructs({key: value for key, value in node.items() if key != "uses"}, depth + 1)]
    own = [_named(key, value) for key, value in inputs.items() if _counted(key)]
    rest = {key: value for key, value in node.items() if key not in ("uses", "with")}
    rest["with"] = {key: value for key, value in inputs.items() if not _counted(key)}
    numbers = [number for kind, number in own if kind == "count"]
    return [*(construct for construct in own if construct[0] != "count"),
            ("wrap", max(numbers) if numbers else None, tuple(constructs(rest, depth + 1)))]


def constructs(node, depth=0, dependencies=False, dependency_maps=False):
    """Every retry construct in a JSON value: ("count", n), ("unknown", None), ("report", None) or
    ("alternatives", groups) for independent steps, scripts or commands.

    ``dependency_maps`` is true only at the top level of a runner configuration (package.json): there a dependency
    map's names are package names, reported only. Everywhere else, including workflows and `env`, every string is
    read.
    """
    if depth > MAX_DEPTH:
        raise Refused("CONFIG-DEPTH")
    found = []
    if isinstance(node, dict):
        action = None if dependencies else _retry_action(node, depth)
        if action is not None:
            return action
        for key, value in node.items():
            if dependencies:
                if shaped(normalize(key)):
                    found.append(("report", None))
                if isinstance(value, (dict, list)):
                    found.extend(constructs(value, depth + 1, True))
                continue
            if normalize(key) in LABEL_MAPS and isinstance(value, dict):
                found.extend(_alternatives([command_constructs(command, True) if isinstance(command, str)
                                            else constructs(command, depth + 2) for command in value.values()]))
                continue
            if key in ("run", "shell") and isinstance(value, str):
                found.extend(command_constructs(value, True))
                continue
            if key == "steps" and isinstance(value, list):
                found.extend(_alternatives([constructs(step, depth + 2) for step in value]))
                continue
            construct = _named(key, value)
            if construct is not None:
                found.append(construct)
            found.extend(constructs(value, depth + 1, dependency_maps and normalize(key) in DEPENDENCY_MAPS))
    elif isinstance(node, list):
        for item in node:
            found.extend(constructs(item, depth + 1, dependencies))
    elif isinstance(node, str) and not dependencies:
        found.extend(command_constructs(node))
    return found


def leaves(found):
    """The single constructs of a list, inside alternatives and wrappers too (a wrapper's own count included)."""
    for construct in found:
        kind = construct[0]
        if kind == "alternatives":
            for group in construct[1]:
                yield from leaves(group)
        elif kind == "wrap":
            if construct[1] is not None:
                yield "count", construct[1]
            yield from leaves(construct[2])
        else:
            yield construct


def re_executions(found):
    """Re-executions of one job. Only a known wrapper (a retry action around the rest of its step) multiplies the
    executions of what it wraps. Everything else is an alternative and the largest applies: independent steps,
    scripts and commands, several retry flags or keys of one command (the runner applies one of them), and
    workflow or job `env` against the step commands (review round 2, PS-4)."""
    largest = 0
    for construct in found:
        kind = construct[0]
        if kind == "count":
            value = min(construct[1], EXECUTION_CAP)
        elif kind == "alternatives":
            value = max(re_executions(group) for group in construct[1])
        elif kind == "wrap":
            attempts = min(construct[1] or 0, EXECUTION_CAP) + 1
            value = min(attempts * (re_executions(construct[2]) + 1), EXECUTION_CAP + 1) - 1
        else:
            continue
        largest = max(largest, value)
    return largest


def _limit(policy, money_path):
    return policy.money_path_retry_limit if money_path else policy.retry_limit


def _judge(findings, found, limit, money_path, path, job):
    """Append the findings of one job (or runner configuration) and return its summary."""
    executions = re_executions(found)
    single = list(leaves(found))
    unknown = sum(1 for kind, _number in single if kind == "unknown")
    reported = sum(1 for kind, _number in single if kind == "report")
    # An in-runner or whole-step retry re-executes inside the reported attempt, so the quarantine gate never sees
    # the failed attempt and cannot record the flake (proposed re-execution model; QA/Reliability decision).
    hidden = sum(1 for kind, number in single if kind == "count" and number >= 1)
    if unknown:
        findings.append({"rule": "RETRY-UNKNOWN", "effect": "fail", "input": path, "job": job, "count": unknown})
    if executions > limit:
        rule = "RETRY-MONEY-PATH" if money_path else "RETRY-LIMIT-EXCEEDED"
        findings.append({"rule": rule, "effect": "fail", "input": path, "job": job, "count": executions})
    if hidden:
        findings.append({"rule": "RETRY-ATTEMPT-HIDDEN", "effect": "report", "input": path, "job": job,
                         "count": hidden})
    if reported:
        findings.append({"rule": "RETRY-DEPENDENCY", "effect": "report", "input": path, "job": job, "count": reported})
    return {"input": path, "job": job, "money_path": money_path, "limit": limit, "re_executions": executions,
            "constructs": sum(1 for kind, _number in single if kind == "count"), "unknown": unknown}


def evaluate(*, policy, manifest, workflows=(), runner_configs=()):
    """Judge (path, document) pairs; workflow paths are repository-relative `.github/workflows/...` names."""
    findings, checked = [], []
    strictest = any(mapped.money_path for mapped in manifest.jobs.values())
    # Every workflow file the manifest maps must be checked: an absent workflow is never a passing one
    # (review round 2, ADVSEC-R2-04), as the rate step refuses an absent job.
    if {mapped.workflow for mapped in manifest.jobs.values()} - {path for path, _document in workflows}:
        raise Refused("INPUT-WORKFLOWS-MISSING")
    for path, document in workflows:
        if tags.WORKFLOW.fullmatch(path) is None:
            raise Refused("INPUT-PATH")
        jobs = document.get("jobs") if isinstance(document, dict) else None
        if not isinstance(jobs, dict) or not jobs:
            raise Refused("CONFIG-SHAPE")
        shared = constructs({key: value for key, value in document.items() if key != "jobs"})
        for key, job in jobs.items():
            if tags.WORKFLOW_JOB.fullmatch(key) is None:
                raise Refused("CONFIG-JOB-KEY")
            if not isinstance(job, dict):
                raise Refused("CONFIG-SHAPE")
            mapped = [job for job in manifest.jobs.values() if job.workflow == path and job.job == key]
            # A job the manifest does not map gets the strictest limit of the manifest, never a silent relaxation.
            money_path = any(job.money_path for job in mapped) if mapped else strictest
            if not mapped and strictest:
                findings.append({"rule": "RETRY-JOB-UNMAPPED", "effect": "report", "input": path, "job": key,
                                 "count": 1})
            checked.append(_judge(findings, shared + constructs(job, 1), _limit(policy, money_path), money_path,
                                  path, key))
        for job in manifest.jobs.values():
            if job.workflow == path and job.job not in jobs:
                findings.append({"rule": "RETRY-MANIFEST-JOB-UNCHECKED", "effect": "report", "input": path,
                                 "job": job.job, "count": 1})
    for path, document in runner_configs:
        if RELATIVE.fullmatch(path) is None or not path.endswith(".json"):
            raise Refused("INPUT-PATH")
        checked.append(_judge(findings, constructs(document, dependency_maps=True), _limit(policy, strictest),
                              strictest, path, None))
    failing = [finding for finding in findings if finding["effect"] == "fail"]
    return {
        "schema": REPORT_SCHEMA,
        "decision": "fail" if failing else "pass",
        "policy": policy.summary(),
        "manifest": {"status": manifest.status, "sha256": manifest.sha256},
        "counts": {"inputs": len(workflows) + len(runner_configs), "jobs": len(checked) - len(runner_configs),
                   "failing": len(failing), "reported": len(findings) - len(failing)},
        "checked": checked,
        "findings": sorted(findings, key=lambda item: (item["rule"], item["input"], item["job"] or "")),
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused("USAGE")


def _arguments(argv):
    # Help only alone: a help token inside a check command must not turn it into exit 0 without evaluation.
    if any(argument in ("-h", "--help") for argument in argv) and len(argv) > 1:
        raise Refused("USAGE")
    parser = _Parser(prog="qa_gates_retry.py", description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--workflow", action="append", default=[])
    parser.add_argument("--runner-config", action="append", default=[])
    parser.add_argument("--manifest", default=str(tags.MANIFEST_FILE))
    return parser.parse_args(argv)


def _load(root, path):
    if RELATIVE.fullmatch(path) is None:
        raise Refused("INPUT-PATH")
    return json_document(read_bounded(root / path, CONFIG_LIMIT, "INPUT-UNREADABLE"), CONFIG_LIMIT, "CONFIG")


def main(argv=None):
    try:
        arguments = _arguments(sys.argv[1:] if argv is None else argv)
        inputs = arguments.workflow + arguments.runner_config
        if not inputs:
            raise Refused("INPUT-NONE")
        if len(inputs) > MAX_INPUTS or len(set(inputs)) != len(inputs):
            raise Refused("INPUT-PATHS")
        for path in arguments.workflow:
            if tags.WORKFLOW.fullmatch(path) is None:
                raise Refused("INPUT-PATH")
        root = Path(arguments.root)
        policy = policies.load_policy()
        manifest = tags.load_manifest(arguments.manifest)
        report = evaluate(policy=policy, manifest=manifest,
                          workflows=[(path, _load(root, path)) for path in arguments.workflow],
                          runner_configs=[(path, _load(root, path)) for path in arguments.runner_config])
    except Refused as error:
        report = {"schema": REPORT_SCHEMA, "decision": "refused", "reason": error.code}
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return {"pass": 0, "fail": 1}.get(report["decision"], 2)


if __name__ == "__main__":
    sys.exit(main())
