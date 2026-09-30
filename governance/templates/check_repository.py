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
# inputs, each action pinned to a commit. Every other `uses` or input is refused
# wherever it appears: an unlisted action such as actions/github-script receives
# `github.token` through a default input without any visible expression, an
# unlisted input such as checkout's github-server-url would send that default
# token to another host, and a job-level `uses` would hand the token to a
# reusable workflow this check never sees.
WORKFLOW_ACTIONS = {
    "actions/checkout": {"persist-credentials", "fetch-depth"},
    "actions/setup-python": {"python-version"},
    "actions/setup-node": {"node-version-file"},
    "actions/setup-java": {"distribution", "java-version"},
}
ACTION_COMMIT = re.compile(r"[0-9a-f]{40}")
SENSITIVE_NAMES = {".env", "id_rsa", "id_ed25519"}
SENSITIVE_SUFFIXES = (".p12", ".pfx", ".keystore", ".jks", ".bks", ".pem")
TEXT_EXTENSIONS = {".md", ".json", ".yaml", ".yml", ".py", ".kt", ".kts", ".xml", ".toml", ".properties"}


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
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON key")
            value[key] = item
        return value
    return json.loads(content, object_pairs_hook=unique)


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


def validate_expressions(name, value):
    for text in workflow_strings(value):
        start = text.find("${{")
        while start != -1:
            end = text.find("}}", start)
            if end == -1 or text[start:end + 2] not in WORKFLOW_EXPRESSIONS:
                raise ValueError(f"{name}: unreviewed workflow expression; public jobs must not receive secrets")
            start = text.find("${{", end + 2)


def validate_mappings(name, value):
    for mapping in workflow_mappings(value):
        if "if" in mapping:
            # jobs.<id>.if, steps[].if, jobs.<id>.snapshot.if or any future condition field.
            raise ValueError(f"{name}: conditions are not part of the generated workflows")
        if "uses" in mapping:
            action, _, commit = str(mapping["uses"]).partition("@")
            if action not in WORKFLOW_ACTIONS or ACTION_COMMIT.fullmatch(commit) is None:
                raise ValueError(f"{name}: action must be immutable and one of the generated GitHub-owned actions")
            inputs = mapping.get("with", {})
            if not isinstance(inputs, dict) or set(inputs) - WORKFLOW_ACTIONS[action]:
                raise ValueError(f"{name}: unreviewed action input; only the generated inputs are accepted")
            if action == "actions/checkout" and inputs.get("persist-credentials") is not False:
                raise ValueError(f"{name}: checkout must not retain credentials")


def validate_workflow(name, data):
    # Generated workflow files use JSON syntax, which is valid YAML.
    value = json_document(data)
    if value.get("permissions") != {"contents": "read"}:
        raise ValueError(f"{name}: expected read-only workflow token")
    validate_expressions(name, value)
    if any(WORKFLOW_SECRET_ACCESS.search(text) for text in workflow_strings(value)):
        raise ValueError(f"{name}: public candidate jobs must not receive secrets")
    validate_mappings(name, value)
    events = value.get("on", {})
    if not isinstance(events, dict) or set(events) - {"push", "pull_request", "workflow_dispatch"}:
        raise ValueError(f"{name}: unreviewed workflow trigger")
    jobs = value.get("jobs", {})
    if not jobs:
        raise ValueError(f"{name}: workflow has no jobs")
    for job in jobs.values():
        if job.get("runs-on") != "ubuntu-24.04":
            raise ValueError(f"{name}: only the standard hosted Ubuntu runner is configured")
        if job.get("permissions", {"contents": "read"}) != {"contents": "read"}:
            raise ValueError(f"{name}: writable job credentials are not permitted")
    if name.endswith("/ci.yml"):
        if not {"push", "pull_request"} <= set(events):
            raise ValueError("CI must run on both main pushes and pull requests")
        if jobs.get("ci", {}).get("name") != "CI":
            raise ValueError("Keep the required native CI job name stable")
    else:
        if set(jobs) != {"copilot-setup-steps"}:
            raise ValueError("Copilot setup must contain its documented single job")


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
            except (ValueError, UnicodeDecodeError):
                problems.append(f"Invalid JSON in {safe_name}")
        if name.startswith(".github/workflows/"):
            try:
                validate_workflow(name, content)
            except (ValueError, TypeError, KeyError, UnicodeDecodeError):
                problems.append(f"Invalid or unsafe workflow: {safe_name}")
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
