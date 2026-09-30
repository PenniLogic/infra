"""Read-only GitHub REST access for the conformance job: repository identity, rulesets, the rules
that apply to ``main``, and the last completed ``main`` CI run.

Two interchangeable clients: ``AnonymousClient`` (plain ``urllib``, no credential, the public
rate limit of 60 requests per hour per address, the design the scheduled job uses because the
generated workflows never receive a token) and ``GhClient`` (the ``gh`` CLI's stored credential
for local runs). Both only ever issue GET requests; nothing here can write to a repository.
"""

import datetime
import json
import shutil
import subprocess
import urllib.error
import urllib.request


API = "https://api.github.com"
HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "PenniLogic-infra-conformance",
}
GITHUB_ACTIONS_APP_ID = 15368
BUDGET_MINUTES = 10
REQUEST_TIMEOUT_SECONDS = 30
GH_TIMEOUT_SECONDS = 60


class ApiError(RuntimeError):
    """A read failed (network, HTTP status or unparsable body); the message never carries a credential."""


class AnonymousClient:
    name = "anonymous"

    def __init__(self, opener=urllib.request.urlopen, base=API):
        self._opener = opener
        self._base = base
        self.rate_limit_remaining = None
        self.requests = 0

    def get(self, path):
        request = urllib.request.Request(self._base + path, headers=HEADERS, method="GET")
        try:
            with self._opener(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                remaining = response.headers.get("X-RateLimit-Remaining")
                body = response.read()
        except urllib.error.HTTPError as error:
            remaining = error.headers.get("X-RateLimit-Remaining") if error.headers else None
            error.close()  # the error carries the response body file object
            self._record(remaining)
            raise ApiError(f"GET {path} failed with HTTP {error.code}") from None
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            raise ApiError(f"GET {path} failed: {error.__class__.__name__}") from None
        self._record(remaining)
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ApiError(f"GET {path} returned an unparsable body") from None

    def _record(self, remaining):
        self.requests += 1
        if remaining is not None:
            try:
                self.rate_limit_remaining = int(remaining)
            except ValueError:
                pass


class GhClient:
    name = "gh"

    def __init__(self, run=subprocess.run):
        self._run = run
        self.rate_limit_remaining = None
        self.requests = 0

    def get(self, path):
        self.requests += 1
        try:
            result = self._run(["gh", "api", "-X", "GET", path], capture_output=True, check=False,
                               timeout=GH_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            raise ApiError(f"gh api GET {path} timed out") from None
        if result.returncode:
            raise ApiError(f"gh api GET {path} exited {result.returncode}")
        try:
            return json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ApiError(f"gh api GET {path} returned an unparsable body") from None


def _gh_authenticated(run):
    try:
        return run(["gh", "api", "user", "--jq", ".login"], capture_output=True, check=False,
                   timeout=GH_TIMEOUT_SECONDS).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def choose_client(mode="auto", run=subprocess.run, which=shutil.which, opener=urllib.request.urlopen):
    """``gh`` when requested (or, in ``auto`` mode, when it is installed and authenticated), else anonymous."""
    if mode == "anonymous":
        return AnonymousClient(opener)
    available = which("gh") is not None
    if mode == "gh":
        if not available:
            raise ApiError("gh is not installed")
        return GhClient(run)
    if available and _gh_authenticated(run):
        return GhClient(run)
    return AnonymousClient(opener)


def repository_identity(client, full_name):
    data = client.get(f"/repos/{full_name}")
    return {"id": data.get("id"), "full_name": data.get("full_name"), "default_branch": data.get("default_branch")}


def rulesets(client, full_name):
    """Every ruleset of the repository with its bypass actors and rule types (one detail read each)."""
    summaries = client.get(f"/repos/{full_name}/rulesets")
    details = []
    for summary in summaries if isinstance(summaries, list) else []:
        detail = client.get(f"/repos/{full_name}/rulesets/{summary['id']}")
        conditions = detail.get("conditions") or {}
        ref_name = conditions.get("ref_name") or {}
        details.append({
            "id": detail.get("id"),
            "name": detail.get("name"),
            "target": detail.get("target"),
            "enforcement": detail.get("enforcement"),
            "bypass_actors": [
                {"actor_type": actor.get("actor_type"), "bypass_mode": actor.get("bypass_mode")}
                for actor in detail.get("bypass_actors") or []
            ],
            "ref_include": list(ref_name.get("include") or []),
            "ref_exclude": list(ref_name.get("exclude") or []),
            "rule_types": sorted(rule.get("type", "") for rule in detail.get("rules") or []),
        })
    return details


def branch_rules(client, full_name, branch="main"):
    """The effective rules on one branch, reduced to the fields the conformance checks read."""
    rules = client.get(f"/repos/{full_name}/rules/branches/{branch}")
    return summarize_branch_rules(rules)


def summarize_branch_rules(rules):
    summary = {
        "rule_types": sorted({rule.get("type", "") for rule in rules}),
        "required_status_checks": [],
        "strict_required_status_checks_policy": None,
        "required_approving_review_count": None,
        "required_review_thread_resolution": None,
        "allowed_merge_methods": None,
        "required_linear_history": False,
        "non_fast_forward": False,
        "deletion": False,
        "pull_request": False,
    }
    for rule in rules:
        kind = rule.get("type")
        parameters = rule.get("parameters") or {}
        if kind == "required_status_checks":
            summary["required_status_checks"] = [
                {"context": check.get("context"), "integration_id": check.get("integration_id")}
                for check in parameters.get("required_status_checks") or []
            ]
            summary["strict_required_status_checks_policy"] = parameters.get("strict_required_status_checks_policy")
        elif kind == "pull_request":
            summary["pull_request"] = True
            summary["required_approving_review_count"] = parameters.get("required_approving_review_count")
            summary["required_review_thread_resolution"] = parameters.get("required_review_thread_resolution")
            summary["allowed_merge_methods"] = parameters.get("allowed_merge_methods")
        elif kind in ("required_linear_history", "non_fast_forward", "deletion"):
            summary[kind] = True
    return summary


def missing_required_checks(required, produced, actions_app_id=GITHUB_ACTIONS_APP_ID):
    """Required contexts no generated workflow produces: unknown context, or a context bound to an
    integration other than GitHub Actions (a check the workflow's job cannot satisfy)."""
    missing = []
    for check in required:
        context = check.get("context")
        integration = check.get("integration_id")
        if context not in produced or (integration is not None and integration != actions_app_id):
            missing.append({"context": context, "integration_id": integration})
    return missing


def last_main_run(client, full_name, workflow_name="CI", branch="main", budget_minutes=BUDGET_MINUTES):
    """The newest completed push run of the named workflow on ``branch`` (``None`` when there is none)."""
    data = client.get(f"/repos/{full_name}/actions/runs?branch={branch}&event=push&status=completed&per_page=10")
    for run in data.get("workflow_runs", []):
        if run.get("name") == workflow_name:
            return summarize_run(run, budget_minutes)
    return None


def _timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def wall_clock_seconds(run):
    """Seconds from the run's start to its last update (queue time excluded, all attempts included)."""
    started = _timestamp(run.get("run_started_at"))
    finished = _timestamp(run.get("updated_at"))
    if started is None or finished is None or finished < started:
        return None
    return int((finished - started).total_seconds())


def summarize_run(run, budget_minutes=BUDGET_MINUTES):
    seconds = wall_clock_seconds(run)
    return {
        "id": run.get("id"),
        "name": run.get("name"),
        "conclusion": run.get("conclusion"),
        "head_sha": run.get("head_sha"),
        "run_attempt": run.get("run_attempt"),
        "run_started_at": run.get("run_started_at"),
        "updated_at": run.get("updated_at"),
        "html_url": run.get("html_url"),
        "wall_clock_seconds": seconds,
        "budget_minutes": budget_minutes,
        "within_budget": None if seconds is None else seconds <= budget_minutes * 60,
    }
