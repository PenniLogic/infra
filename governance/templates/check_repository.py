"""Validate repository metadata, public CI boundaries and obvious secret exposure."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md",
    "CONSTITUTION.md", "COPILOT_FILES.md",
    ".github/copilot-instructions.md", ".github/agent-policy.json",
    ".github/workflows/ci.yml", ".github/workflows/copilot-setup-steps.yml",
    "migration-source.json", "scripts/setup.py",
)
SECRET_PATTERNS = (
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
# Generated workflows contain exactly these reviewed expressions. Every other
# `${{` is refused wherever it appears, so whole-context forms such as
# toJSON(github) or github[format('to{0}', 'ken')] cannot reach the token without
# naming it, and the key `if` is refused at any nesting level because a condition
# evaluates expressions without `${{`.
WORKFLOW_EXPRESSIONS = {
    "${{ github.workflow }}",
    "${{ github.event.pull_request.number || github.ref }}",
    "${{ github.event.pull_request.base.sha || github.sha }}",
}
# Tripwire behind the allowlist: any form of the secrets context or the workflow
# token stays refused even if the allowlist above is ever widened by mistake. It
# runs over the decoded strings because GitHub's expression lexer skips any
# Unicode whitespace, so `github\n.token` or `toJSON(\tgithub)` reads the token.
WORKFLOW_SECRET_ACCESS = re.compile(
    r"\bsecrets\b|\bgithub\b\s*(?:\.\s*token\b|\[)|\btojson\s*\(\s*github\b", re.IGNORECASE
)
# Generated workflows use exactly these GitHub-owned actions with exactly these
# inputs, each action pinned to exactly the generated commit. Every other `uses`
# or input is refused wherever it appears: an unlisted action such as
# actions/github-script receives `github.token` through a default input without
# any visible expression, an unlisted input such as checkout's github-server-url
# would send that default token to another host, and a job-level `uses` would
# hand the token to a reusable workflow this check never sees.
WORKFLOW_ACTIONS = {
    "actions/checkout": {"persist-credentials", "fetch-depth"},
    "actions/setup-python": {"python-version"},
    "actions/setup-node": {"node-version-file"},
    "actions/setup-java": {"distribution", "java-version"},
}
ACTION_COMMIT = re.compile(r"[0-9a-f]{40}")
# The commit each listed action is pinned to. generate.py renders this mapping
# from the `actions` pins of repository-profiles.json whenever it copies this
# template into a consumer, so one pin bump changes ci.yml and this checker in
# the same regeneration; the template carries the current pins too so that it can
# be imported and tested unrendered, and a governance test fails when the two
# differ. A listed action at any other commit, including a fork's commit that is
# reachable by SHA through the upstream repository, is refused before its inputs
# are read, because it would run foreign code holding the default input token.
WORKFLOW_ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-java": "de7274f081f381c8f8158605e0321c36c376e2e6",
    "actions/setup-node": "820762786026740c76f36085b0efc47a31fe5020",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
}
# Generated workflows use exactly these keys at the top level, in a job and in a
# step; every other key at these placements is refused, so nothing is accepted by
# omission. A job-level `container` would run the generated JavaScript actions,
# and their default `INPUT_TOKEN`, inside an attacker image; `services`,
# `snapshot`, `environment`, `strategy`, `outputs`, `defaults`, `needs`,
# `continue-on-error`, `if` and a reusable-workflow `uses`/`with`/`secrets` fall
# under the same rule. A job-level `permissions` is not emitted (the exact
# workflow-level `permissions` is the rule) and neither are step `id`, `shell`,
# `working-directory` or `timeout-minutes`; extend by generator change only.
WORKFLOW_KEYS = {"name", "on", "permissions", "concurrency", "jobs"}
JOB_KEYS = {"name", "runs-on", "timeout-minutes", "env", "steps"}
STEP_KEYS = {"name", "uses", "with", "run", "env"}
SENSITIVE_NAMES = {".env", "id_rsa", "id_ed25519"}
SENSITIVE_SUFFIXES = (".p12", ".pfx", ".keystore", ".jks", ".bks", ".pem")
TEXT_EXTENSIONS = {".md", ".json", ".yaml", ".yml", ".py", ".kt", ".kts", ".xml", ".toml", ".properties"}


class Refused(ValueError):
    """One rule of this checker refused a document.

    The message is static rule text: it never carries a key, value or other
    content of the refused file, so check() can print it as is.
    """


def git(*args):
    result = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, check=False,
    )
    if result.returncode:
        raise ValueError("Git inventory or staged-content read failed")
    return result.stdout


def inventory(staged=False):
    args = ["ls-files", "-z", "--cached"]
    if not staged:
        args += ["--others", "--exclude-standard"]
    names = {entry.decode("utf-8") for entry in git(*args).split(b"\0") if entry}
    for name in sorted(names):
        path = ROOT / name
        if path.is_symlink():
            raise ValueError(f"Repository symlink requires explicit review: {name}")
        if staged:
            content = git("show", f":{name}")
        else:
            if not path.is_file():
                raise ValueError(f"Tracked file is absent: {name}")
            content = path.read_bytes()
        yield name, content


def json_document(content):
    """Parse one strictly UTF-8 JSON document without a byte order mark or duplicate keys.

    json.loads(bytes) would skip a UTF-8 BOM and accept UTF-16/32 through its
    encoding detection, so the document this checker validates could differ
    from the bytes GitHub reads; decoding here keeps both views identical.
    """
    text = content.decode("utf-8")
    if text.startswith("\ufeff"):
        raise Refused("UTF-8 byte order mark before the JSON document")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Refused("Duplicate JSON key")
            value[key] = item
        return value
    return json.loads(text, object_pairs_hook=unique)


def workflow_strings(value):
    """Yield every key and string of a parsed workflow document at any nesting level."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from workflow_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from workflow_strings(item)
    elif isinstance(value, str):
        yield value


def workflow_mappings(value):
    """Yield every mapping of a parsed workflow document at any nesting level."""
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from workflow_mappings(item)
    elif isinstance(value, list):
        for item in value:
            yield from workflow_mappings(item)


def validate_expressions(value):
    for text in workflow_strings(value):
        start = text.find("${{")
        while start != -1:
            end = text.find("}}", start)
            if end == -1 or text[start:end + 2] not in WORKFLOW_EXPRESSIONS:
                raise Refused("unreviewed workflow expression; public jobs must not receive secrets")
            start = text.find("${{", end + 2)


def validate_mappings(value):
    for mapping in workflow_mappings(value):
        if "if" in mapping:
            # jobs.<id>.if, steps[].if, jobs.<id>.snapshot.if or any future condition field.
            raise Refused("conditions are not part of the generated workflows")
        if "uses" in mapping:
            action, _, commit = str(mapping["uses"]).partition("@")
            if action not in WORKFLOW_ACTIONS or ACTION_COMMIT.fullmatch(commit) is None:
                raise Refused("action must be immutable and one of the generated GitHub-owned actions")
            # Exact, case-sensitive comparison with the rendered pin: a differently cased
            # or otherwise foreign 40-hex commit is drift from the generated file.
            if commit != WORKFLOW_ACTION_PINS.get(action):
                raise Refused("action commit differs from the generated pin; regenerate instead of editing it")
            inputs = mapping.get("with", {})
            if not isinstance(inputs, dict) or set(inputs) - WORKFLOW_ACTIONS[action]:
                raise Refused("unreviewed action input; only the generated inputs are accepted")
            if action == "actions/checkout" and inputs.get("persist-credentials") is not False:
                raise Refused("checkout must not retain credentials")


def validate_shape(value):
    """Refuse every top-level, job-level and step-level key the generator does not emit."""
    if set(value) - WORKFLOW_KEYS:
        raise Refused("top-level key outside the generated workflow keys name, on, permissions, concurrency, jobs")
    jobs = value.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise Refused("jobs must be a mapping of job ids with at least one job")
    for job in jobs.values():
        if not isinstance(job, dict):
            raise Refused("job must be a mapping")
        if set(job) - JOB_KEYS:
            raise Refused("job-level key outside the generated job keys name, runs-on, timeout-minutes, env, steps")
        steps = job.get("steps")
        if not isinstance(steps, list) or not steps or not all(isinstance(step, dict) for step in steps):
            raise Refused("steps must be a list of step mappings with at least one step")
        for step in steps:
            if set(step) - STEP_KEYS:
                raise Refused("step-level key outside the generated step keys name, uses, with, run, env")


def validate_workflow(name, data):
    # Generated workflow files use JSON syntax, which is valid YAML.
    value = json_document(data)
    if not isinstance(value, dict):
        raise Refused("workflow document must be one JSON object")
    if value.get("permissions") != {"contents": "read"}:
        raise Refused("expected read-only workflow token")
    validate_expressions(value)
    if any(WORKFLOW_SECRET_ACCESS.search(text) for text in workflow_strings(value)):
        raise Refused("public candidate jobs must not receive secrets")
    validate_mappings(value)
    validate_shape(value)
    events = value.get("on", {})
    if not isinstance(events, dict) or set(events) - {"push", "pull_request", "workflow_dispatch"}:
        raise Refused("unreviewed workflow trigger")
    jobs = value["jobs"]
    for job in jobs.values():
        if job.get("runs-on") != "ubuntu-24.04":
            raise Refused("only the standard hosted Ubuntu runner is configured")
        # Behind the job-key allowlist, which already refuses a job-level `permissions`:
        # writable job credentials stay refused even if JOB_KEYS is ever widened by mistake.
        if job.get("permissions", {"contents": "read"}) != {"contents": "read"}:
            raise Refused("writable job credentials are not permitted")
    # The generator emits exactly two workflow files, each with exactly one job and its own
    # trigger set. A third file, an added plain job, a dropped manual dispatch or a setup
    # workflow that gained push/pull_request is drift the key allowlists above cannot see.
    if name == ".github/workflows/ci.yml":
        if set(events) != {"push", "pull_request", "workflow_dispatch"}:
            raise Refused("CI must run on exactly main pushes, pull requests and manual dispatch")
        if set(jobs) != {"ci"}:
            raise Refused("CI must contain its documented single job")
        if jobs["ci"].get("name") != "CI":
            raise Refused("Keep the required native CI job name stable")
    elif name == ".github/workflows/copilot-setup-steps.yml":
        if set(events) != {"workflow_dispatch"}:
            raise Refused("Copilot setup must run on manual dispatch only")
        if set(jobs) != {"copilot-setup-steps"}:
            raise Refused("Copilot setup must contain its documented single job")
    else:
        raise Refused("workflow file outside the generated pair ci.yml and copilot-setup-steps.yml")


def check(files):
    problems = []
    for name in REQUIRED:
        if name not in files:
            problems.append(f"Missing required repository file: {name}")
    for name, content in files.items():
        safe_name = name if name.isprintable() else "[non-printable path]"
        leaf = Path(name).name.lower()
        if leaf in SENSITIVE_NAMES or leaf.endswith(SENSITIVE_SUFFIXES):
            problems.append(f"Sensitive file must not be committed: {safe_name}")
        if any(pattern.search(content) for pattern in SECRET_PATTERNS):
            problems.append(f"Possible credential in {safe_name}; content withheld")
        if Path(name).suffix in TEXT_EXTENSIONS:
            try:
                content.decode("utf-8")
            except UnicodeDecodeError:
                problems.append(f"Invalid UTF-8 in {safe_name}")
        if name.endswith(".json"):
            try:
                json_document(content)
            except Refused as error:
                problems.append(f"Invalid JSON in {safe_name}: {error}")
            except (ValueError, UnicodeDecodeError, RecursionError):
                problems.append(f"Invalid JSON in {safe_name}")
        if name.startswith(".github/workflows/"):
            try:
                validate_workflow(name, content)
            except Refused as error:
                # The refusing rule is static text; no key, value or other file content is echoed.
                problems.append(f"Invalid or unsafe workflow: {safe_name}: {error}")
            except (ValueError, TypeError, KeyError, AttributeError, UnicodeDecodeError, RecursionError):
                # Malformed, non-UTF-8 or too deeply nested input, or a shape no rule anticipated,
                # fails closed with one static message instead of a traceback.
                problems.append(f"Invalid or unsafe workflow: {safe_name}: not a parseable UTF-8 JSON-syntax document")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true")
    args = parser.parse_args()
    try:
        files = dict(inventory(args.staged))
        problems = check(files)
    except (OSError, ValueError, UnicodeDecodeError) as error:
        print(f"Repository check failed: {error}", file=sys.stderr)
        return 1
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print(f"Repository checks passed ({len(files)} files); no application acceptance implied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
