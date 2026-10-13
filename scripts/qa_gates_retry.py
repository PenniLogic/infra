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
as re-executions; several constructs in one job compound. A retry-shaped key, flag or action whose count cannot be
read fails closed (RETRY-UNKNOWN). A retry-shaped dependency name is reported without failing.

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
ROOT = Path(__file__).resolve().parent.parent
RELATIVE = re.compile(r"(?!\.{1,2}(?:/|\Z))[A-Za-z0-9_.-]+(?:/(?!\.{1,2}(?:/|\Z))[A-Za-z0-9_.-]+)*")
NUMBER = re.compile(r"[0-9]{1,6}")
# Normalized (lower case, alphanumerics only) names whose value is a number of re-executions or of attempts.
RE_EXECUTIONS = frozenset({
    "retry", "retries", "reruns", "maxretries", "retrycount", "retrytimes", "numretries", "rerunfailingtestscount",
    "flakyretries", "testretrycount",
})
ATTEMPTS = frozenset({"maxattempts", "attempts", "maxruns"})
# Normalized flag names that contain a retry-shaped word but do not retry a failure (Gradle forced task rerun).
NOT_RETRY = frozenset({"reruntasks", "rerun"})
SHAPES = ("retry", "retries", "rerun", "attempt", "flaky")
DEPENDENCY_MAPS = frozenset({
    "dependencies", "devdependencies", "peerdependencies", "optionaldependencies", "bundleddependencies",
    "bundledependencies", "overrides", "resolutions",
})
# Maps whose keys are labels (package.json script names): only their values are read.
LABEL_MAPS = frozenset({"scripts"})
SEPARATORS = re.compile(r"[\s'\"`;|&()<>]+")


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


def command_constructs(value):
    """Retry constructs among the flag and ``name=value`` tokens of one string; plain words are never matched."""
    tokens = [token for token in SEPARATORS.split(value) if token]
    found = []
    for index, token in enumerate(tokens):
        dashed = token.startswith("-")
        if dashed:
            body = token[2:] if token.startswith("-D") else token.lstrip("-")
        elif "=" in token:
            body = token
        else:
            continue
        name, equals, inline = body.partition("=")
        if not name:
            continue
        if equals:
            argument = inline
        elif dashed and index + 1 < len(tokens) and not tokens[index + 1].startswith("-"):
            argument = tokens[index + 1]
        else:
            argument = None
        construct = _named(name, argument)
        if construct is not None:
            found.append(construct)
    return found


def _retry_action(node):
    """True for a step whose `uses` names a retry-shaped action without a readable attempt or retry count."""
    uses = node.get("uses")
    if not isinstance(uses, str) or not shaped(normalize(uses.split("@", 1)[0].rsplit("/", 1)[-1])):
        return False
    inputs = node.get("with")
    return not (isinstance(inputs, dict)
                and any(normalize(key) in RE_EXECUTIONS or normalize(key) in ATTEMPTS for key in inputs))


def constructs(node, depth=0, dependencies=False):
    """Every retry construct in a JSON value: ("count", n), ("unknown", None) or ("report", None)."""
    if depth > MAX_DEPTH:
        raise Refused("CONFIG-DEPTH")
    found = []
    if isinstance(node, dict):
        if not dependencies and _retry_action(node):
            found.append(("unknown", None))
        for key, value in node.items():
            if dependencies:
                if shaped(normalize(key)):
                    found.append(("report", None))
                if isinstance(value, (dict, list)):
                    found.extend(constructs(value, depth + 1, True))
                continue
            if normalize(key) in LABEL_MAPS and isinstance(value, dict):
                for command in value.values():
                    found.extend(constructs(command, depth + 2))
                continue
            construct = _named(key, value)
            if construct is not None:
                found.append(construct)
            found.extend(constructs(value, depth + 1, normalize(key) in DEPENDENCY_MAPS))
    elif isinstance(node, list):
        for item in node:
            found.extend(constructs(item, depth + 1, dependencies))
    elif isinstance(node, str) and not dependencies:
        found.extend(command_constructs(node))
    return found


def re_executions(found):
    """Compounded re-executions of one job: every construct multiplies the executions of the ones it wraps."""
    executions = 1
    for kind, number in found:
        if kind == "count":
            executions *= number + 1
    return executions - 1


def _limit(policy, money_path):
    return policy.money_path_retry_limit if money_path else policy.retry_limit


def _judge(findings, found, limit, money_path, path, job):
    """Append the findings of one job (or runner configuration) and return its summary."""
    executions = re_executions(found)
    unknown = sum(1 for kind, _number in found if kind == "unknown")
    reported = sum(1 for kind, _number in found if kind == "report")
    if unknown:
        findings.append({"rule": "RETRY-UNKNOWN", "effect": "fail", "input": path, "job": job, "count": unknown})
    if executions > limit:
        rule = "RETRY-MONEY-PATH" if money_path else "RETRY-LIMIT-EXCEEDED"
        findings.append({"rule": rule, "effect": "fail", "input": path, "job": job, "count": executions})
    if reported:
        findings.append({"rule": "RETRY-DEPENDENCY", "effect": "report", "input": path, "job": job, "count": reported})
    return {"input": path, "job": job, "money_path": money_path, "limit": limit, "re_executions": executions,
            "constructs": sum(1 for kind, _number in found if kind == "count"), "unknown": unknown}


def evaluate(*, policy, manifest, workflows=(), runner_configs=()):
    """Judge (path, document) pairs; workflow paths are repository-relative `.github/workflows/...` names."""
    findings, checked = [], []
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
            money_path = any(mapped.money_path for mapped in manifest.jobs.values()
                             if mapped.workflow == path and mapped.job == key)
            checked.append(_judge(findings, shared + constructs(job, 1), _limit(policy, money_path), money_path,
                                  path, key))
    strictest = any(mapped.money_path for mapped in manifest.jobs.values())
    for path, document in runner_configs:
        if RELATIVE.fullmatch(path) is None or not path.endswith(".json"):
            raise Refused("INPUT-PATH")
        checked.append(_judge(findings, constructs(document), _limit(policy, strictest), strictest, path, None))
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
