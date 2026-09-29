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


def validate_workflow(name, data):
    # Generated workflow files use JSON syntax, which is valid YAML.
    value = json_document(data)
    if value.get("permissions") != {"contents": "read"}:
        raise ValueError(f"{name}: expected read-only workflow token")
    if "secrets." in json.dumps(value.get("env", {})):
        raise ValueError(f"{name}: public candidate jobs must not receive secrets")
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
        if "secrets." in json.dumps(job.get("env", {})):
            raise ValueError(f"{name}: public candidate jobs must not receive secrets")
        for step in job.get("steps", []):
            if "uses" in step and not re.fullmatch(r"actions/[a-z0-9-]+@[0-9a-f]{40}", step["uses"]):
                raise ValueError(f"{name}: action must be immutable and GitHub-owned")
            if "secrets." in json.dumps(step):
                raise ValueError(f"{name}: public candidate jobs must not receive secrets")
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                if step.get("with", {}).get("persist-credentials") is not False:
                    raise ValueError(f"{name}: checkout must not retain credentials")
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
        if leaf in {".env", "id_rsa", "id_ed25519"} or leaf.endswith((".p12", ".pfx", ".keystore")):
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
