"""Read-only GitHub access (PenniLogic/infra#24 addendum items 3 and 6): the anonymous client sends
no credential and only GET, both clients turn failures into ApiError without echoing anything
sensitive, branch rules and rulesets reduce to the recorded fields, the last completed main run of
the required workflow is selected, and the wall-clock figure is checked against the ten-minute
budget. No network: every response is a fake."""

import io
import json
import subprocess
import unittest
import urllib.error

import conformance_support as support
from conformance import github_api


class FakeResponse(io.BytesIO):
    def __init__(self, body, remaining="59"):
        super().__init__(json.dumps(body).encode("utf-8"))
        self.headers = {"X-RateLimit-Remaining": remaining} if remaining is not None else {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class AnonymousClientTests(unittest.TestCase):
    def test_get_sends_no_credential_records_the_rate_limit_and_parses_json(self):
        seen = []

        def opener(request, timeout):
            seen.append(request)
            return FakeResponse({"id": 1394135059}, remaining="58")

        client = github_api.AnonymousClient(opener)
        self.assertEqual({"id": 1394135059}, client.get("/repos/PenniLogic/infra"))
        request = seen[0]
        self.assertEqual("GET", request.get_method())
        self.assertEqual("https://api.github.com/repos/PenniLogic/infra", request.full_url)
        self.assertFalse(request.has_header("Authorization"))
        self.assertEqual("PenniLogic-infra-conformance", request.get_header("User-agent"))
        self.assertEqual(58, client.rate_limit_remaining)
        self.assertEqual(1, client.requests)

    def test_http_network_and_body_failures_become_api_errors(self):
        def http_error(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 403, "rate limited", {"X-RateLimit-Remaining": "0"}, None)

        client = github_api.AnonymousClient(http_error)
        with self.assertRaises(github_api.ApiError) as caught:
            client.get("/repos/PenniLogic/infra/rulesets")
        self.assertEqual("GET /repos/PenniLogic/infra/rulesets failed with HTTP 403", str(caught.exception))
        self.assertEqual(0, client.rate_limit_remaining)

        def network_error(request, timeout):
            raise urllib.error.URLError("unreachable")

        with self.assertRaises(github_api.ApiError):
            github_api.AnonymousClient(network_error).get("/x")

        def garbage(request, timeout):
            response = FakeResponse({})
            response.truncate(0)
            response.write(b"<html>")
            response.seek(0)
            return response

        with self.assertRaises(github_api.ApiError):
            github_api.AnonymousClient(garbage).get("/x")


class GhClientTests(unittest.TestCase):
    def test_gh_client_reads_through_gh_api_get_only(self):
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, json.dumps([{"id": 1}]).encode(), b"")

        client = github_api.GhClient(run)
        self.assertEqual([{"id": 1}], client.get("/repos/PenniLogic/infra/rulesets"))
        self.assertEqual(["gh", "api", "-X", "GET", "/repos/PenniLogic/infra/rulesets"], calls[0])

    def test_gh_failure_and_unparsable_output_become_api_errors(self):
        def failing(command, **kwargs):
            return subprocess.CompletedProcess(command, 1, b"", b"gh: Not Found")

        with self.assertRaises(github_api.ApiError):
            github_api.GhClient(failing).get("/x")

        def garbage(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, b"not json", b"")

        with self.assertRaises(github_api.ApiError):
            github_api.GhClient(garbage).get("/x")

    def test_choose_client_prefers_gh_only_when_installed_and_authenticated(self):
        ok = lambda command, **kwargs: subprocess.CompletedProcess(command, 0, b"basiltt\n", b"")  # noqa: E731
        denied = lambda command, **kwargs: subprocess.CompletedProcess(command, 1, b"", b"not logged in")  # noqa: E731
        self.assertEqual("anonymous", github_api.choose_client("anonymous", run=ok, which=lambda name: "/usr/bin/gh").name)
        self.assertEqual("gh", github_api.choose_client("auto", run=ok, which=lambda name: "/usr/bin/gh").name)
        self.assertEqual("anonymous", github_api.choose_client("auto", run=denied, which=lambda name: "/usr/bin/gh").name)
        self.assertEqual("anonymous", github_api.choose_client("auto", run=ok, which=lambda name: None).name)
        self.assertEqual("gh", github_api.choose_client("gh", run=denied, which=lambda name: "/usr/bin/gh").name)
        with self.assertRaises(github_api.ApiError):
            github_api.choose_client("gh", run=ok, which=lambda name: None)


class RulesTests(unittest.TestCase):
    def test_branch_rules_reduce_to_the_recorded_fields(self):
        summary = github_api.summarize_branch_rules(support.branch_rules_payload())
        self.assertEqual([{"context": "CI", "integration_id": 15368}], summary["required_status_checks"])
        self.assertTrue(summary["strict_required_status_checks_policy"])
        self.assertEqual(0, summary["required_approving_review_count"])
        self.assertTrue(summary["required_review_thread_resolution"])
        self.assertEqual(["squash"], summary["allowed_merge_methods"])
        self.assertTrue(summary["required_linear_history"] and summary["non_fast_forward"] and summary["deletion"])
        self.assertTrue(summary["pull_request"])
        empty = github_api.summarize_branch_rules([])
        self.assertEqual([], empty["required_status_checks"])
        self.assertFalse(empty["pull_request"])

    def test_rulesets_read_the_detail_of_each_ruleset(self):
        client = support.fake_client_for("infra", 1394135059, "a" * 40,
                                         ruleset_detail=support.ruleset_detail_payload(bypass_actors=[
                                             {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]))
        details = github_api.rulesets(client, "PenniLogic/infra")
        self.assertEqual(1, len(details))
        self.assertEqual("Protect main", details[0]["name"])
        self.assertEqual([{"actor_type": "RepositoryRole", "bypass_mode": "always"}], details[0]["bypass_actors"])
        self.assertEqual(["~DEFAULT_BRANCH"], details[0]["ref_include"])
        self.assertIn("required_status_checks", details[0]["rule_types"])
        self.assertEqual(["/repos/PenniLogic/infra/rulesets", "/repos/PenniLogic/infra/rulesets/24154862"], client.paths)

    def test_repository_identity_reads_the_numeric_id(self):
        client = support.fake_client_for("infra", 1394135059, "a" * 40)
        self.assertEqual({"id": 1394135059, "full_name": "PenniLogic/infra", "default_branch": "main"},
                         github_api.repository_identity(client, "PenniLogic/infra"))


class RunTests(unittest.TestCase):
    def test_last_main_run_selects_the_newest_completed_run_of_the_required_workflow(self):
        runs = support.runs_payload("b" * 40, seconds=47)
        runs["workflow_runs"].insert(0, {"id": 1, "name": "Other", "conclusion": "success",
                                         "run_started_at": "2026-09-30T11:00:00Z", "updated_at": "2026-09-30T11:00:10Z"})
        client = support.fake_client_for("infra", 1394135059, "b" * 40, runs=runs)
        run = github_api.last_main_run(client, "PenniLogic/infra")
        self.assertEqual(36710661002, run["id"])
        self.assertEqual(47, run["wall_clock_seconds"])
        self.assertTrue(run["within_budget"])
        self.assertEqual(10, run["budget_minutes"])
        self.assertIn("event=push", client.paths[-1])
        self.assertIn("status=completed", client.paths[-1])
        empty = support.fake_client_for("infra", 1394135059, "b" * 40, runs={"workflow_runs": []})
        self.assertIsNone(github_api.last_main_run(empty, "PenniLogic/infra"))

    def test_wall_clock_and_budget(self):
        run = {"run_started_at": "2026-09-30T11:47:05Z", "updated_at": "2026-09-30T11:58:05Z"}
        self.assertEqual(660, github_api.wall_clock_seconds(run))
        self.assertFalse(github_api.summarize_run(run)["within_budget"])
        self.assertTrue(github_api.summarize_run(run, budget_minutes=30)["within_budget"])
        self.assertEqual(600, github_api.wall_clock_seconds({"run_started_at": "2026-09-30T11:47:05Z", "updated_at": "2026-09-30T11:57:05Z"}))
        self.assertTrue(github_api.summarize_run({"run_started_at": "2026-09-30T11:47:05Z", "updated_at": "2026-09-30T11:57:05Z"})["within_budget"])
        self.assertIsNone(github_api.wall_clock_seconds({"run_started_at": None, "updated_at": "2026-09-30T11:58:05Z"}))
        self.assertIsNone(github_api.wall_clock_seconds({"run_started_at": "not a time", "updated_at": "2026-09-30T11:58:05Z"}))
        self.assertIsNone(github_api.wall_clock_seconds({"run_started_at": "2026-09-30T12:00:00Z", "updated_at": "2026-09-30T11:00:00Z"}))
        self.assertIsNone(github_api.summarize_run({})["within_budget"])


if __name__ == "__main__":
    unittest.main()
