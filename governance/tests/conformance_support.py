"""Shared fixtures for the conformance tests: load the package, build a fake generated consumer
checkout in a temporary Git repository, and provide fake GitHub API payloads. No network."""

import base64
import hashlib
import importlib.util
import io
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
    for start in defects.unittest_directories(profile):
        directory = root / start
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


def pr_gate_module():
    spec = importlib.util.spec_from_file_location(
        "trusted_pr_gate", GOVERNANCE / "templates" / "pr_workflow_integrity.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PRMetadata:
    """Real validator transport over finite Git-shaped metadata; never native check evidence."""

    source_sha = "1" * 40
    head_sha = "2" * 40
    token = "fixture-read-only-token-no-authority"

    def __init__(self, name="infra", changes=None, activated=False, fork=False):
        self.name = name
        self.contract = generator.pr_integrity_contract(name)
        self.prefix = "/repos/" + self.contract["repository"]
        self.payloads, self.calls = {}, []
        self.repository = {
            "id": self.contract["repository_id"], "full_name": self.contract["repository"],
            "default_branch": "main", "private": False,
            "owner": {"id": self.contract["organization_id"], "login": ORGANIZATION},
        }
        head_repo = json.loads(json.dumps(self.repository))
        if fork:
            head_repo.update(id=123456789, full_name="fixture-fork/" + name)
            head_repo["owner"] = {"id": 987654321, "login": "fixture-fork"}
        self.pull = {
            "number": 123, "state": "open", "merged": False,
            "base": {"ref": "main", "sha": self.source_sha, "repo": self.repository},
            "head": {"ref": "fixture-branch", "sha": self.head_sha, "repo": head_repo},
        }
        self.event = {"action": "synchronize", "number": 123,
                      "repository": self.repository, "pull_request": self.pull}
        self.environment = {
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request_target",
            "GITHUB_SERVER_URL": "https://github.com", "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_REPOSITORY": self.contract["repository"],
            "GITHUB_REPOSITORY_ID": str(self.contract["repository_id"]),
            "GITHUB_REPOSITORY_OWNER": ORGANIZATION,
            "GITHUB_REPOSITORY_OWNER_ID": str(self.contract["organization_id"]),
            "GITHUB_REF": "refs/heads/main", "GITHUB_REF_PROTECTED": "true",
            "GITHUB_SHA": self.source_sha, "GITHUB_WORKFLOW_SHA": self.source_sha,
            "GITHUB_WORKFLOW_REF": self.contract["repository"] +
                "/.github/workflows/pr-workflow-integrity.yml@refs/heads/main",
            "GH_TOKEN": self.token,
        }
        files = {path: generator.artifacts(name)[path].encode("utf-8") for path in self.contract["files"]}
        files["scripts/check_repository.py"] = generator.checker(name, integrity=True).encode("utf-8")
        files[".github/workflows/pr-workflow-integrity.yml"] = generator.pr_integrity_workflow(name).encode("utf-8")
        if name == "infra":
            files["governance/repository-profiles.json"] = generator.encoded(generator.PROFILES).encode("utf-8")
        self.base_files = files
        self.head_files = dict(files)
        for path, content in (changes or {}).items():
            if content is None:
                self.head_files.pop(path, None)
            else:
                self.head_files[path] = content.encode("utf-8") if isinstance(content, str) else content
        self.payloads[self.prefix] = self.repository
        self.payloads[self.prefix + "/pulls/123"] = self.pull
        self.payloads[self.prefix + "/branches/main"] = {
            "name": "main", "protected": True, "commit": {"sha": self.source_sha},
        }
        contexts = (("CI", 15368), ("PR workflow integrity", 15368)) if activated else (("CI", 15368),)
        self.payloads[self.prefix + "/rules/branches/main"] = branch_rules_payload(contexts=contexts)
        self.snapshot(self.base_files, self.source_sha)
        self.snapshot(self.head_files, self.head_sha)

    def snapshot(self, files, commit):
        tree = {}
        for path, content in files.items():
            node = tree
            parts = path.split("/")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = content

        def save(node):
            entries = []
            for name, content in sorted(node.items()):
                if isinstance(content, dict):
                    object_sha, kind, mode = save(content), "tree", "040000"
                else:
                    object_sha = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
                    self.payloads[self.prefix + "/git/blobs/" + object_sha] = {
                        "sha": object_sha, "encoding": "base64", "size": len(content),
                        "content": base64.b64encode(content).decode("ascii") + "\n",
                    }
                    kind, mode = "blob", "100644"
                entries.append({"path": name, "mode": mode, "type": kind, "sha": object_sha})
            raw = b"".join(entry["mode"].lstrip("0").encode() + b" " + entry["path"].encode() + b"\0"
                           + bytes.fromhex(entry["sha"]) for entry in entries)
            tree_sha = hashlib.sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            self.payloads[self.prefix + "/git/trees/" + tree_sha] = {
                "sha": tree_sha, "truncated": False, "tree": entries,
            }
            return tree_sha

        self.payloads[self.prefix + "/git/commits/" + commit] = {
            "sha": commit, "tree": {"sha": save(tree)},
        }

    def open(self, request, timeout):
        if request.get_method() != "GET" or not request.full_url.startswith("https://api.github.com/"):
            raise AssertionError("validator attempted a non-canonical read")
        self.calls.append(request.full_url)
        path = request.full_url[len("https://api.github.com"):]
        if path not in self.payloads:
            raise AssertionError("validator requested an unlisted fixture endpoint")
        value = self.payloads[path]
        if callable(value):
            value = value()
        if isinstance(value, Exception):
            raise value
        body = value if isinstance(value, bytes) else json.dumps(value).encode("utf-8")
        response = io.BytesIO(body)
        response.status = 200
        response.geturl = lambda: request.full_url
        return response

    def evaluate(self, module=None):
        module = module or pr_gate_module()
        contract = module.TrustedContract.from_data(self.contract)
        context = module.NativeContext.from_environment(contract, self.environment)
        budget = module.Budget()
        client = module.ReadOnlyClient(contract, self.token, budget, opener=self)
        return module.validate(contract, context, self.event, client, budget)
