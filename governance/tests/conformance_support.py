"""Shared fixtures for the conformance tests: load the package, build a fake generated consumer
checkout in a temporary Git repository, and provide fake GitHub API payloads. No network."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


GOVERNANCE = Path(__file__).resolve().parents[1]
if str(GOVERNANCE) not in sys.path:
    sys.path.insert(0, str(GOVERNANCE))

from conformance import defects, generator as generator_module  # noqa: E402

generator = generator_module.load()
ORGANIZATION = generator.PROFILES["organization"]
PASSING_TEST = '''import unittest


class BaselineTest(unittest.TestCase):
    def test_baseline_passes(self):
        self.assertEqual(2, 1 + 1)
'''


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False,
                            env=defects.probe_environment(), timeout=60)
    if result.returncode:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr.decode('utf-8', 'replace')}")
    return result.stdout.decode("utf-8", "replace")


def make_consumer(root, name, extra_files=None):
    """Render profile ``name`` into ``root``, add the files a consumer commits itself, and commit."""
    root = Path(root)
    generator.generate(name, root)
    (root / "migration-source.json").write_text("{}\n", encoding="utf-8")
    profile = generator.PROFILES["repositories"][name]
    for command in profile["commands"]:
        if command.startswith("python -m unittest discover -s "):
            directory = root / command.split("-s ", 1)[1].split()[0]
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "test_baseline_ok.py").write_text(PASSING_TEST, encoding="utf-8")
    for relative, content in (extra_files or {}).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True,
                   env=defects.probe_environment(), timeout=60)
    git(root, "config", "core.autocrlf", "false")
    git(root, "config", "user.name", "conformance-test")
    git(root, "config", "user.email", "conformance-test@example.invalid")
    git(root, "remote", "add", "origin", f"https://github.com/{ORGANIZATION}/{name}.git")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "fake consumer baseline")
    return root


def tree_digest(root):
    """Sorted (relative path, bytes) of every file outside .git, to prove byte-for-byte restoration."""
    root = Path(root)
    return sorted(
        (path.relative_to(root).as_posix(), path.read_bytes())
        for path in root.rglob("*") if path.is_file() and ".git" not in path.relative_to(root).parts
    )


class ConsumerCase(unittest.TestCase):
    """A test case with one fake consumer checkout per test, removed afterwards."""

    profile_name = ".github"

    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="pennilogic-conformance-test-")
        self.addCleanup(self._temporary.cleanup)
        self.scratch = Path(self._temporary.name)
        self.root = make_consumer(self.scratch / self.profile_name, self.profile_name)
        self.profile = generator.PROFILES["repositories"][self.profile_name]


def branch_rules_payload(contexts=(("CI", 15368),), strict=True, approvals=0):
    return [
        {"type": "deletion"},
        {"type": "non_fast_forward"},
        {"type": "required_linear_history"},
        {"type": "pull_request", "parameters": {
            "required_approving_review_count": approvals, "dismiss_stale_reviews_on_push": True,
            "required_review_thread_resolution": True, "allowed_merge_methods": ["squash"]}},
        {"type": "required_status_checks", "parameters": {
            "strict_required_status_checks_policy": strict, "do_not_enforce_on_create": False,
            "required_status_checks": [{"context": context, "integration_id": integration}
                                       for context, integration in contexts]}},
    ]


def ruleset_summary_payload(ruleset_id=24154862):
    return [{"id": ruleset_id, "name": "Protect main", "target": "branch", "enforcement": "active"}]


def ruleset_detail_payload(ruleset_id=24154862, bypass_actors=()):
    return {
        "id": ruleset_id, "name": "Protect main", "target": "branch", "enforcement": "active",
        "bypass_actors": list(bypass_actors),
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "required_linear_history"},
                  {"type": "pull_request"}, {"type": "required_status_checks"}],
    }


def runs_payload(head_sha, conclusion="success", seconds=47, name="CI"):
    return {"total_count": 1, "workflow_runs": [{
        "id": 36710661002, "name": name, "conclusion": conclusion, "head_sha": head_sha, "run_attempt": 1,
        "run_started_at": "2026-09-30T11:47:05Z",
        "updated_at": f"2026-09-30T11:{47 + seconds // 60:02d}:{5 + seconds % 60:02d}Z",
        "html_url": "https://github.com/PenniLogic/example/actions/runs/36710661002",
    }]}


class FakeClient:
    """Serves canned payloads by path prefix and records every path requested."""

    name = "fake"

    def __init__(self, payloads):
        self.payloads = payloads
        self.paths = []
        self.rate_limit_remaining = 55
        self.requests = 0

    def get(self, path):
        self.requests += 1
        self.paths.append(path)
        for prefix, payload in self.payloads.items():
            if path.startswith(prefix):
                if isinstance(payload, Exception):
                    raise payload
                return json.loads(json.dumps(payload))
        raise AssertionError(f"unexpected API path {path}")


def fake_client_for(name, repository_id, head_sha, **overrides):
    full = f"{ORGANIZATION}/{name}"
    payloads = {
        f"/repos/{full}/rulesets/": overrides.get("ruleset_detail", ruleset_detail_payload()),
        f"/repos/{full}/rulesets": overrides.get("rulesets", ruleset_summary_payload()),
        f"/repos/{full}/rules/branches/main": overrides.get("branch_rules", branch_rules_payload()),
        f"/repos/{full}/actions/runs": overrides.get("runs", runs_payload(head_sha)),
        f"/repos/{full}": overrides.get("identity", {"id": repository_id, "full_name": full, "default_branch": "main"}),
    }
    return FakeClient(payloads)
