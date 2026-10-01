"""Base-trusted PR metadata validation. No candidate code is checked out or executed."""

import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
import os
import re
import sys
import time
from typing import Any
import urllib.error
import urllib.request


CONTRACT = None
SCHEMA = "pennilogic.infra.pr-workflow-integrity/1"
CHECK_NAME = "PR workflow integrity"
WORKFLOW = ".github/workflows/pr-workflow-integrity.yml"
CHECKER = "scripts/check_repository.py"
PROFILES = "governance/repository-profiles.json"
ACTIVITIES = ("opened", "synchronize", "reopened", "ready_for_review", "edited")
MAX_BYTES = 1024 * 1024
MAX_REQUESTS = 32
DEADLINE_SECONDS = 180
REQUEST_SECONDS = 10
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*|\.github")
SECRET = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b|"
                    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")


class GateError(ValueError):
    """A static refusal code, never an API body, path, exception or candidate value."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str = "metadata-shape") -> None:
    if not condition:
        raise GateError(code)


def mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise GateError("metadata-shape")
    return value


def positive(value: object) -> int:
    if type(value) is not int or not 0 < value < 2**63:
        raise GateError("numeric-identity")
    return value


def sha(value: object) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise GateError("immutable-sha")
    return value


def json_document(data: bytes) -> Any:
    require(isinstance(data, bytes) and len(data) <= MAX_BYTES, "metadata-size")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate-json-key")
            result[key] = value
        return result

    def constant(_value):
        raise GateError("json-number")

    try:
        text = data.decode("utf-8")
        require(not text.startswith("\ufeff"), "json-bom")
        value = json.loads(text, object_pairs_hook=unique, parse_constant=constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        if isinstance(error, GateError):
            raise
        raise GateError("metadata-json") from None
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        require(depth <= 64, "metadata-depth")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


@dataclass(frozen=True)
class TrustedContract:
    repository: str
    repository_id: int
    organization: str
    organization_id: int
    files: dict[str, str]

    @classmethod
    def from_data(cls, value: object):
        data = mapping(value)
        require(set(data) == {"repository", "repository_id", "organization", "organization_id", "files"},
                "trusted-contract")
        organization = data["organization"]
        repository = data["repository"]
        require(isinstance(organization, str) and NAME.fullmatch(organization) is not None, "trusted-contract")
        require(isinstance(repository, str) and repository.startswith(organization + "/"), "trusted-contract")
        leaf = repository[len(organization) + 1:]
        require(NAME.fullmatch(leaf) is not None and leaf not in (".", ".."), "trusted-contract")
        files = mapping(data["files"])
        required = {".github/workflows/ci.yml", ".github/workflows/copilot-setup-steps.yml",
                    ".github/agent-policy.json"}
        allowed = required | ({".github/workflows/conformance.yml"} if leaf == "infra" else set())
        require(set(files) == allowed, "trusted-contract")
        require(all(isinstance(value, str) and DIGEST.fullmatch(value) for value in files.values()),
                "trusted-contract")
        return cls(repository, positive(data["repository_id"]), organization,
                   positive(data["organization_id"]), dict(files))


@dataclass(frozen=True)
class NativeContext:
    source_sha: str
    activity: str

    @classmethod
    def from_environment(cls, contract: TrustedContract, env):
        expected = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "pull_request_target",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_REPOSITORY": contract.repository,
            "GITHUB_REPOSITORY_ID": str(contract.repository_id),
            "GITHUB_REPOSITORY_OWNER": contract.organization,
            "GITHUB_REPOSITORY_OWNER_ID": str(contract.organization_id),
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_WORKFLOW_REF": f"{contract.repository}/{WORKFLOW}@refs/heads/main",
        }
        require(all(env.get(key) == value for key, value in expected.items()), "native-provenance")
        source = sha(env.get("GITHUB_SHA"))
        require(env.get("GITHUB_WORKFLOW_SHA") == source, "native-workflow-source")
        return cls(source, "pull_request_target")


class Budget:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.started = clock()
        self.requests = 0

    def remaining(self) -> float:
        remaining = DEADLINE_SECONDS - (self.clock() - self.started)
        require(remaining > 0, "metadata-deadline")
        return remaining

    def request(self) -> float:
        timeout = min(REQUEST_SECONDS, self.remaining())
        require(self.requests < MAX_REQUESTS, "metadata-request-limit")
        self.requests += 1
        return timeout


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise GateError("metadata-redirect")


class ReadOnlyClient:
    def __init__(self, contract: TrustedContract, token: str, budget: Budget, opener=None):
        require(isinstance(token, str) and 20 <= len(token) <= 4096
                and all(33 <= ord(char) <= 126 for char in token), "step-token")
        self.contract, self.token, self.budget = contract, token, budget
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        prefix = re.escape("/repos/" + contract.repository)
        self.paths = re.compile(prefix + r"(?:|/pulls/[1-9][0-9]{0,18}|/branches/main|/rules/branches/main|"
                                r"/git/(?:commits|trees|blobs)/[0-9a-f]{40})")

    def get(self, path: str) -> Any:
        require(isinstance(path, str) and self.paths.fullmatch(path) is not None, "metadata-path")
        timeout = self.budget.request()
        request = urllib.request.Request("https://api.github.com" + path, method="GET", headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "PenniLogic-PR-workflow-integrity",
        })
        try:
            with self.opener.open(request, timeout=timeout) as response:
                require(response.status == 200, "metadata-http")
                require(response.geturl() == request.full_url, "metadata-redirect")
                parts, size = [], 0
                while True:
                    self.budget.remaining()
                    part = response.read1(min(65536, MAX_BYTES + 1 - size))
                    if not part:
                        break
                    size += len(part)
                    require(size <= MAX_BYTES, "metadata-size")
                    parts.append(part)
                self.budget.remaining()
                return json_document(b"".join(parts))
        except urllib.error.HTTPError as error:
            error.close()
            raise GateError("metadata-denied" if error.code in (401, 403, 404) else "metadata-http") from None
        except (urllib.error.URLError, OSError, TimeoutError):
            raise GateError("metadata-unavailable") from None


def repository_identity(value: object, contract: TrustedContract) -> None:
    data = mapping(value)
    owner = mapping(data.get("owner"))
    require(positive(data.get("id")) == contract.repository_id
            and positive(owner.get("id")) == contract.organization_id
            and owner.get("login") == contract.organization
            and data.get("full_name") == contract.repository
            and data.get("default_branch") == "main"
            and data.get("private") is False, "repository-identity")


@dataclass(frozen=True)
class PullIdentity:
    number: int
    base_sha: str
    head_sha: str
    head_repository_id: int
    head_repository: str
    head_owner_id: int
    head_ref: str

    @classmethod
    def from_data(cls, value: object, contract: TrustedContract):
        data = mapping(value)
        base, head = mapping(data.get("base")), mapping(data.get("head"))
        repository_identity(base.get("repo"), contract)
        repo = mapping(head.get("repo"))
        owner = mapping(repo.get("owner"))
        full = repo.get("full_name")
        login = owner.get("login")
        require(isinstance(full, str) and isinstance(login, str)
                and NAME.fullmatch(login) is not None and full.startswith(login + "/")
                and NAME.fullmatch(full[len(login) + 1:]) is not None, "head-repository")
        ref = head.get("ref")
        require(isinstance(ref, str) and 1 <= len(ref) <= 255
                and all(32 <= ord(char) <= 126 for char in ref), "head-ref")
        require(data.get("state") == "open" and data.get("merged") is False
                and base.get("ref") == "main", "pull-request-state")
        return cls(positive(data.get("number")), sha(base.get("sha")), sha(head.get("sha")),
                   positive(repo.get("id")), full, positive(owner.get("id")), ref)


def branch_identity(value: object, source: str) -> None:
    data = mapping(value)
    commit = mapping(data.get("commit"))
    require(data.get("name") == "main" and data.get("protected") is True
            and sha(commit.get("sha")) == source, "current-protected-base")


class GitSnapshot:
    def __init__(self, client: ReadOnlyClient, commit: str):
        self.client, self.commit = client, sha(commit)
        self.prefix = "/repos/" + client.contract.repository + "/git/"
        data = mapping(client.get(self.prefix + "commits/" + commit))
        require(data.get("sha") == commit, "git-commit")
        self.root = sha(mapping(data.get("tree")).get("sha"))
        self.trees: dict[str, dict[str, Any]] = {}
        self.blobs: dict[str, bytes] = {}

    def tree(self, tree_sha: str):
        if tree_sha not in self.trees:
            data = mapping(self.client.get(self.prefix + "trees/" + sha(tree_sha)))
            require(data.get("sha") == tree_sha and data.get("truncated") is False, "git-tree")
            entries = data.get("tree")
            require(isinstance(entries, list) and len(entries) <= 4096, "git-tree")
            indexed = {}
            for raw in entries:
                entry = mapping(raw)
                path = entry.get("path")
                require(isinstance(path, str) and 1 <= len(path) <= 1024
                        and path not in (".", "..") and "/" not in path and "\\" not in path
                        and all(ord(char) >= 32 and char != "\x7f" for char in path)
                        and path not in indexed, "git-tree-path")
                sha(entry.get("sha"))
                require(entry.get("type") in ("tree", "blob", "commit")
                        and entry.get("mode") in ("040000", "100644", "100755", "120000", "160000"), "git-tree")
                indexed[path] = entry
            self.trees[tree_sha] = indexed
        return self.trees[tree_sha]

    def entry(self, path: str):
        parts = path.split("/")
        current = self.root
        for index, part in enumerate(parts):
            value = self.tree(current).get(part)
            if value is None:
                return None
            final = index == len(parts) - 1
            require(value["type"] == ("blob" if final else "tree")
                    and value["mode"] in (("100644", "100755") if final else ("040000",)), "git-entry-type")
            current = value["sha"]
        return value

    def directory(self, path: str):
        current = self.root
        for part in path.split("/"):
            value = self.tree(current).get(part)
            require(value is not None and value["type"] == "tree" and value["mode"] == "040000",
                    "git-workflow-directory")
            current = value["sha"]
        return self.tree(current)

    def blob(self, path: str):
        entry = self.entry(path)
        if entry is None:
            return None
        object_sha = entry["sha"]
        if object_sha not in self.blobs:
            data = mapping(self.client.get(self.prefix + "blobs/" + object_sha))
            size = data.get("size")
            content = data.get("content")
            require(data.get("sha") == object_sha and data.get("encoding") == "base64"
                    and type(size) is int and 0 <= size <= MAX_BYTES
                    and isinstance(content, str) and len(content) <= MAX_BYTES, "git-blob")
            try:
                raw = base64.b64decode(content.replace("\n", ""), validate=True)
            except (binascii.Error, ValueError):
                raise GateError("git-blob") from None
            require(len(raw) == size
                    and hashlib.sha1(b"blob " + str(size).encode("ascii") + b"\0" + raw).hexdigest() == object_sha,
                    "git-blob-identity")
            self.blobs[object_sha] = raw
        return self.blobs[object_sha]


def source_profile_contract(data: object) -> str:
    value = mapping(data)
    repositories = mapping(value.get("repositories"))
    fields = {"id", "commands", "install", "node", "java", "android_sdk", "gradle_wrapper_jar_sha256",
              "timeout_minutes", "env", "pr_workflow_integrity"}
    projected = {key: value.get(key) for key in ("schema_version", "organization", "organization_id",
                                               "runner", "python", "actions")}
    projected["repositories"] = {
        name: {key: item[key] for key in fields if key in item}
        for name, raw in repositories.items() for item in (mapping(raw),)
    }
    return json.dumps(projected, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def required_checks(value: object):
    require(isinstance(value, list) and len(value) <= 64, "branch-rules")
    checks = None
    types = []
    for raw in value:
        rule = mapping(raw)
        kind = rule.get("type")
        require(isinstance(kind, str) and kind not in types, "branch-rules")
        types.append(kind)
        if kind == "required_status_checks":
            parameters = mapping(rule.get("parameters"))
            require(parameters.get("strict_required_status_checks_policy") is True
                    and parameters.get("do_not_enforce_on_create") is False, "strict-required-checks")
            checks = parameters.get("required_status_checks")
        elif kind == "pull_request":
            parameters = mapping(rule.get("parameters"))
            require(parameters.get("required_review_thread_resolution") is True
                    and type(parameters.get("required_approving_review_count")) is int
                    and parameters["required_approving_review_count"] == 0, "pull-request-rules")
    require({"deletion", "non_fast_forward", "required_linear_history", "pull_request",
             "required_status_checks"} <= set(types), "branch-rules")
    require(isinstance(checks, list) and 1 <= len(checks) <= 2, "required-checks")
    names = set()
    for raw in checks:
        check = mapping(raw)
        name = check.get("context")
        require(name in ("CI", CHECK_NAME) and name not in names
                and type(check.get("integration_id")) is int and check["integration_id"] == 15368,
                "required-check-not-produced")
        names.add(name)
    require("CI" in names, "native-ci-required")
    return {"ci_required": True, "gate_required": CHECK_NAME in names}


def blank_report(contract: TrustedContract):
    return {
        "schema": SCHEMA, "check_name": CHECK_NAME, "repository": contract.repository,
        "identity": {"expected_repository_id": contract.repository_id,
                     "expected_organization_id": contract.organization_id, "verified": False},
        "pull_request_number": None, "base_sha": None, "head_sha": None, "workflow_source_sha": None,
        "bindings": [], "required_checks": None, "violations": [],
        "requests": 0, "elapsed_seconds": 0.0, "result": "error",
    }


def validate(contract: TrustedContract, context: NativeContext, event: object,
             client: ReadOnlyClient, budget: Budget):
    report = blank_report(contract)
    try:
        prefix = "/repos/" + contract.repository
        repository_identity(client.get(prefix), contract)
        report["identity"]["verified"] = True
        payload = mapping(event)
        require(payload.get("action") in ACTIVITIES, "native-activity")
        repository_identity(payload.get("repository"), contract)
        candidate = PullIdentity.from_data(payload.get("pull_request"), contract)
        require(positive(payload.get("number")) == candidate.number, "pull-request-number")
        require(candidate.base_sha == context.source_sha, "current-protected-base")
        current = PullIdentity.from_data(client.get(prefix + "/pulls/" + str(candidate.number)), contract)
        require(candidate == current, "current-pull-request")
        branch_identity(client.get(prefix + "/branches/main"), context.source_sha)
        report.update(pull_request_number=candidate.number, base_sha=candidate.base_sha,
                      head_sha=candidate.head_sha, workflow_source_sha=context.source_sha)
        report["required_checks"] = required_checks(client.get(prefix + "/rules/branches/main"))
        base = GitSnapshot(client, context.source_sha)
        head = GitSnapshot(client, candidate.head_sha)
        expected_workflows = {path.rsplit("/", 1)[1] for path in contract.files
                              if path.startswith(".github/workflows/")} | {WORKFLOW.rsplit("/", 1)[1]}
        base_files, head_files = base.directory(".github/workflows"), head.directory(".github/workflows")
        require(set(base_files) == expected_workflows, "trusted-workflow-inventory")
        if set(head_files) != expected_workflows:
            report["violations"].append("candidate-workflow-inventory")
        for path, digest in sorted(contract.files.items()):
            actual = head.blob(path)
            match = actual is not None and hashlib.sha256(actual).hexdigest() == digest
            report["bindings"].append({"path": path, "matches": match})
            if not match:
                report["violations"].append("required-generated-binding")
        for path in (CHECKER, WORKFLOW):
            trusted = base.blob(path)
            require(trusted is not None, "trusted-binding-missing")
            match = head.blob(path) == trusted
            report["bindings"].append({"path": path, "matches": match})
            if not match:
                report["violations"].append("protected-base-binding")
        if contract.repository == contract.organization + "/infra":
            trusted, actual = base.blob(PROFILES), head.blob(PROFILES)
            require(trusted is not None, "trusted-profile-missing")
            match = actual is not None and source_profile_contract(json_document(trusted)) == \
                source_profile_contract(json_document(actual))
            report["bindings"].append({"path": PROFILES, "matches": match})
            if not match:
                report["violations"].append("protected-profile-binding")
        final = PullIdentity.from_data(client.get(prefix + "/pulls/" + str(candidate.number)), contract)
        require(candidate == final, "stale-pull-request")
        branch_identity(client.get(prefix + "/branches/main"), context.source_sha)
        budget.remaining()
        report["result"] = "fail" if report["violations"] else "pass"
    except GateError as error:
        report["violations"].append(error.code)
        report["result"] = "error"
    report["requests"] = budget.requests
    report["elapsed_seconds"] = round(budget.clock() - budget.started, 3)
    return report


def event_input(env) -> Any:
    root, path = env.get("RUNNER_TEMP"), env.get("GITHUB_EVENT_PATH")
    require(isinstance(root, str) and os.path.isabs(root) and isinstance(path, str), "runner-event-path")
    expected = os.path.join(root, "_github_workflow", "event.json")
    require(os.path.abspath(path) == os.path.abspath(expected)
            and os.path.realpath(path) == os.path.abspath(path), "runner-event-path")
    try:
        with open(path, "rb") as stream:
            return json_document(stream.read(MAX_BYTES + 1))
    except OSError:
        raise GateError("runner-event-unavailable") from None


def exit_code(report) -> int:
    return {"pass": 0, "fail": 1, "error": 2}[report["result"]]


def main(contract_data=CONTRACT, environ=None, client_factory=ReadOnlyClient) -> int:
    env = os.environ if environ is None else environ
    report = {"schema": SCHEMA, "check_name": CHECK_NAME, "result": "error", "violations": []}
    try:
        contract = TrustedContract.from_data(contract_data)
        report = blank_report(contract)
        require(len(sys.argv) == 1, "unsupported-arguments")
        context = NativeContext.from_environment(contract, env)
        budget = Budget()
        client = client_factory(contract, env.get("GH_TOKEN"), budget)
        event = event_input(env)
        report = validate(contract, context, event, client, budget)
    except GateError as error:
        report["violations"].append(error.code)
    rendered = json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False)
    credentials = tuple(value for key in ("GH_TOKEN", "GITHUB_TOKEN")
                        if isinstance((value := env.get(key)), str) and value)
    if SECRET.search(rendered) or any(value in rendered for value in credentials):
        print(json.dumps({"schema": SCHEMA, "result": "error", "violations": ["output-refused"]}, sort_keys=True))
        return 2
    print(rendered)
    return exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
