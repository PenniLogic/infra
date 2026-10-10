"""Finite data-only validator, real CLI and emitted Bash-step regression harnesses."""

import contextlib
import copy
import http.client
import io
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error

import conformance_support as support
from conformance import steps
from test_api_node_runtime import BASE_ARGUMENT, BUILD_COMMAND, NODE_ARGUMENT, native_command


gate = support.pr_gate_module()
CI = ".github/workflows/ci.yml"
WORKFLOW = ".github/workflows/pr-workflow-integrity.yml"
MARKER = "candidate-marker-never-published-9f128a"
SECRET = "ghs_" + "synthetic-only-not-a-credential" * 2
PROFILE_NUMBER_PATHS = (
    ("schema_version",),
    ("actions", "checkout"),
    ("repositories", "infra", "timeout_minutes"),
    ("unprojected", "nested"),
    ("repositories", "infra", "unprojected", "nested"),
)
DRIVER = '''import io
import http.client
import json
import os
import runpy
import sys
import urllib.request

program, fixtures = sys.argv[1:3]
with open(fixtures, encoding="utf-8") as stream:
    data = json.load(stream)
if os.environ.get("EMITTED_STEP") == "true":
    with open(program, encoding="utf-8") as stream:
        expected = stream.read() + "\\n"
    if sys.stdin.read() != expected:
        raise RuntimeError("emitted step did not supply the trusted program")

def opened(_self, request, data_argument=None, timeout=None):
    if request.get_method() != "GET" or not request.full_url.startswith("https://api.github.com/"):
        raise RuntimeError("non-canonical fixture request")
    path = request.full_url[len("https://api.github.com"):]
    content = json.dumps(data[path]).encode("utf-8")
    protocol_case = data.get("__http_protocol_case__")
    if protocol_case is None:
        response = io.BytesIO(content)
        response.status = 200
    else:
        wire = b"HTTP/1.1 200 OK\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n"
        wire += (b"not-a-chunk-size" if protocol_case == "malformed-size"
                 else format(len(content), "x").encode("ascii")) + b"\\r\\n" + content
        if protocol_case != "missing-delimiter":
            wire += b"\\r\\n0\\r\\n\\r\\n"

        class MemorySocket:
            def makefile(self, _mode):
                return io.BytesIO(wire)

        response = http.client.HTTPResponse(MemorySocket())
        response.begin()
    response.geturl = lambda: request.full_url
    return response

urllib.request.OpenerDirector.open = opened
sys.argv = [program]
runpy.run_path(program, run_name="__main__")
'''


def encoded(value):
    return support.generator.encoded(value).encode("utf-8")


def edited_ci(name, update):
    value = json.loads(support.generator.workflow(name))
    update(value, value["jobs"]["ci"])
    return encoded(value)


def profile_number_payload(path, literal):
    value = copy.deepcopy(support.generator.PROFILES)
    node = value
    for part in path[:-1]:
        node = node.setdefault(part, {})
    node[path[-1]] = MARKER
    content = encoded(value)
    marker = json.dumps(MARKER).encode("utf-8")
    if content.count(marker) != 1:
        raise AssertionError("numeric fixture needs exactly one insertion point")
    return content.replace(marker, literal.encode("ascii"))


class ProtocolOpener:
    def __init__(self, case):
        header = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        size = b"not-a-chunk-size" if case == "malformed-size" else b"2"
        self.wire = header + size + b"\r\n{}"
        if case != "missing-delimiter":
            self.wire += b"\r\n0\r\n\r\n"
        self.response = None

    def open(self, request, timeout):
        wire = self.wire

        class MemorySocket:
            def makefile(self, _mode):
                return io.BytesIO(wire)

        self.response = http.client.HTTPResponse(MemorySocket())
        self.response.begin()
        self.response.geturl = lambda: request.full_url
        return self.response


class CommandBindingTests(unittest.TestCase):
    def assert_binding_failure(self, fixture):
        report = fixture.evaluate(gate)
        self.assertEqual("fail", report["result"], report)
        self.assertEqual(1, gate.exit_code(report))
        self.assertIn("required-generated-binding", report["violations"])
        self.assertNotIn(MARKER, json.dumps(report))
        return report

    def test_every_profile_clean_control_and_each_required_command_removed_or_stubbed(self):
        commands = 0
        api_build_cases = 0
        for name, profile in support.generator.PROFILES["repositories"].items():
            self.assertEqual(support.generator.workflow(name).encode("utf-8"),
                             edited_ci(name, lambda _document, _job: None))
            for activated in (False, True):
                with self.subTest(profile=name, activated=activated):
                    fixture = support.PRMetadata(name, activated=activated)
                    report = fixture.evaluate(gate)
                    self.assertEqual("pass", report["result"], report)
                    self.assertEqual(activated, report["required_checks"]["gate_required"])
                    self.assertLessEqual(report["requests"], 32)
            rendered_commands = steps.workflow_run_commands(support.generator.workflow(name).encode("utf-8"))
            self.assertEqual([
                native_command(command) if name == "api"
                else support.generator.infra_ci_command(command) if name == "infra"
                else command for command in profile["commands"]
            ], rendered_commands)
            for position, command in enumerate(rendered_commands):
                if not set(steps.classify(command)) & {"build", "test", "lint", "checker"}:
                    continue
                commands += 1
                for stub in (False, True):
                    def update(_document, job):
                        run = next(step for step in job["steps"]
                                   if step.get("name") in ("Check repository", "Prepare verified Money provider", "Run checks")
                                   and command in step["run"].split("\n"))
                        lines = run["run"].split("\n")
                        position = lines.index(command)
                        if stub:
                            lines[position] = "echo " + MARKER
                        else:
                            del lines[position]
                        run["run"] = "\n".join(lines)
                    with self.subTest(profile=name, command=command, stub=stub):
                        changed = edited_ci(name, update)
                        mutated = steps.workflow_run_commands(changed)
                        self.assertNotIn(command, mutated)
                        self.assertEqual(len(rendered_commands) if stub else len(rendered_commands) - 1,
                                         len(mutated))
                        report = self.assert_binding_failure(support.PRMetadata(name, {CI: changed}))
                        self.assertIn({"path": CI, "matches": False}, report["bindings"])
                        if name == "api" and command == BUILD_COMMAND:
                            api_build_cases += 1
        self.assertEqual(48, commands)
        self.assertEqual(2, api_build_cases)

    def test_api_combined_handoff_mutations_fail_exact_workflow_binding(self):
        command = BUILD_COMMAND
        mutations = {
            "missing-flag": command.removesuffix(NODE_ARGUMENT),
            "missing-value": command.removesuffix(NODE_ARGUMENT) + " --money-client-interop-node",
            "wrong-variable": command.replace("MONEY_CLIENT_INTEROP_NODE", "UNAPPROVED_NODE"),
            "missing-refusal": command.replace(
                "${MONEY_CLIENT_INTEROP_NODE:?API Node SDK was not prepared}", "$MONEY_CLIENT_INTEROP_NODE",
            ),
            "unquoted-path": command.replace(NODE_ARGUMENT, NODE_ARGUMENT.replace('"', "")),
            "split-command": command.replace(" --money-client-interop-node", "\n--money-client-interop-node", 1),
            "extra-sdk-flag": command + NODE_ARGUMENT,
            "missing-base": command.replace(BASE_ARGUMENT, ""),
            "head-base": command.replace(BASE_ARGUMENT, ' --base "$GITHUB_SHA"'),
            "empty-base": command.replace(BASE_ARGUMENT, ' --base ""'),
            "unquoted-base": command.replace(BASE_ARGUMENT, BASE_ARGUMENT.replace('"', "")),
            "unexpected-argument": command + " --unexpected",
            "unexpected-command": command + "\necho " + MARKER,
        }
        for mutation, replacement in mutations.items():
            def update(_document, job):
                step = next(step for step in job["steps"] if step["name"] == "Run checks")
                lines = step["run"].split("\n")
                self.assertEqual(1, lines.count(command))
                lines[lines.index(command)] = replacement
                step["run"] = "\n".join(lines)
            with self.subTest(mutation=mutation):
                changed = edited_ci("api", update)
                self.assertNotEqual(support.generator.workflow("api").encode("utf-8"), changed)
                report = self.assert_binding_failure(support.PRMetadata("api", {CI: changed}))
                self.assertIn({"path": CI, "matches": False}, report["bindings"])

    def test_api_node_profile_delta_is_not_a_protected_source_admission_waiver(self):
        accepted = support.git(
            support.GOVERNANCE.parent,
            "show", "dbdf2e27144e60b11aed54ed1e576d496a928ec3:governance/repository-profiles.json",
        ).encode("utf-8")
        expected = json.loads(accepted)
        android_commands = expected["repositories"]["android"]["commands"]
        self.assertEqual([
            "python scripts/check_repository.py",
            "python -m pip install -r scripts/privacy_traffic/requirements.txt",
            "python scripts/quality_gates.py ci",
            "python scripts/quality_gates.py self-test",
            "python scripts/privacy_traffic_harness.py self-test",
            "python scripts/check_privacy_components.py",
            'python -m unittest discover -s scripts/tests -p "test_*.py"',
        ], android_commands)
        android_commands[4] = "python scripts/privacy_traffic_harness.py self-test --all-scripts"
        android_commands.pop()
        self.assertNotIn("node", expected["repositories"]["api"])
        android_only = encoded(expected)
        expected["repositories"]["api"]["node"] = "24.14.0"
        self.assertEqual(expected, support.generator.PROFILES)
        for composed_android, source in ((False, accepted), (True, android_only)):
            with self.subTest(composed_android=composed_android):
                fixture = support.PRMetadata("infra")
                fixture.base_files[gate.PROFILES] = source
                fixture.snapshot(fixture.base_files, fixture.source_sha)
                report = fixture.evaluate(gate)
                self.assertEqual("fail", report["result"])
                self.assertEqual(["protected-profile-binding"], report["violations"])
                self.assertEqual(1, gate.exit_code(report))

    def test_whole_step_job_filters_skips_masking_and_wrong_names_all_fail(self):
        for name in support.generator.PROFILES["repositories"]:
            for mutation in ("step", "job", "check-name", "trigger", "paths", "types", "branches",
                             "job-if", "step-if", "job-continue", "step-continue", "mask", "order",
                             "extra-step", "pin", "env", "runner"):
                def update(document, job):
                    run = next(step for step in job["steps"] if step.get("name") == "Run checks")
                    if mutation == "step":
                        job["steps"].remove(run)
                    elif mutation == "job":
                        document["jobs"] = {}
                    elif mutation == "check-name":
                        job["name"] = "PR workflow integrity"
                    elif mutation == "trigger":
                        del document["on"]["pull_request"]
                    elif mutation in ("paths", "types", "branches"):
                        document["on"]["pull_request"][mutation] = ["never"]
                    elif mutation.startswith("job-"):
                        job["if" if mutation == "job-if" else "continue-on-error"] = False if mutation == "job-if" else True
                    elif mutation.startswith("step-"):
                        run["if" if mutation == "step-if" else "continue-on-error"] = False if mutation == "step-if" else True
                    elif mutation == "mask":
                        run["run"] = run["run"].replace("\n", " || true\n") + " || true"
                    elif mutation == "order":
                        run["run"] = "\n".join(reversed(run["run"].split("\n")))
                    elif mutation == "extra-step":
                        job["steps"].append({"name": MARKER, "run": "echo " + MARKER})
                    elif mutation == "pin":
                        job["steps"][0]["uses"] = "actions/checkout@" + "a" * 40
                    elif mutation == "env":
                        job["env"] = {"PATH": MARKER}
                    else:
                        job["runs-on"] = "self-hosted"
                with self.subTest(profile=name, mutation=mutation):
                    self.assert_binding_failure(support.PRMetadata(name, {CI: edited_ci(name, update)}))

    def test_checker_and_its_step_cannot_omit_base_validation(self):
        for name in support.generator.PROFILES["repositories"]:
            def update(_document, job):
                run = next(step for step in job["steps"] if step.get("name") == "Run checks")
                run["run"] = "echo " + MARKER
            changes = {CI: edited_ci(name, update), "scripts/check_repository.py": b"raise SystemExit(0)\n"}
            with self.subTest(profile=name):
                fixture = support.PRMetadata(name, changes)
                report = fixture.evaluate(gate)
                self.assertEqual("fail", report["result"])
                self.assertIn("protected-base-binding", report["violations"])
                self.assertIn("required-generated-binding", report["violations"])
                self.assertNotIn(MARKER, json.dumps(report))

    def test_validator_deleted_stubbed_skipped_and_an_extra_same_context_workflow_fail(self):
        for change in (None, b"echo skipped\n", encoded({"jobs": {"fake": {"name": gate.CHECK_NAME, "if": False}}})):
            fixture = support.PRMetadata(changes={WORKFLOW: change})
            report = fixture.evaluate(gate)
            self.assertEqual("fail", report["result"])
            self.assertIn("protected-base-binding", report["violations"])
        fixture = support.PRMetadata(changes={".github/workflows/fake.yml": encoded({
            "on": {"pull_request": {}}, "jobs": {"fake": {"name": gate.CHECK_NAME, "steps": [{"run": "true"}]}},
        })})
        report = fixture.evaluate(gate)
        self.assertEqual("fail", report["result"])
        self.assertIn("candidate-workflow-inventory", report["violations"])
        # Detecting the duplicate as data is not proof of GitHub's status aggregation.

    def test_sha_like_head_ref_does_not_prove_the_platform_invokes_the_validator(self):
        fixture = support.PRMetadata()
        fixture.pull["head"]["ref"] = "a" * 40
        self.assertEqual("pass", fixture.evaluate(gate)["result"])
        fixture = support.PRMetadata(changes={".github/workflows/forged-green.yml": encoded({
            "on": {"pull_request": {}},
            "jobs": {"fake": {"name": gate.CHECK_NAME, "steps": [{"run": "true"}]}},
        })})
        fixture.pull["head"]["ref"] = "a" * 40
        self.assertEqual("fail", fixture.evaluate(gate)["result"])
        # Only the invoked validator is exercised. A missing native run has no refusal to aggregate.

    def test_forged_policy_profile_and_required_context_fail_without_candidate_echo(self):
        fixture = support.PRMetadata(changes={".github/agent-policy.json": encoded({
            "repository_id": 1, "required_native_check": MARKER, "commands": ["echo " + MARKER],
        })})
        self.assert_binding_failure(fixture)
        for field in ("id", "commands", "node", "pr_workflow_integrity"):
            value = copy.deepcopy(support.generator.PROFILES)
            value["repositories"]["infra"][field] = MARKER
            fixture = support.PRMetadata(changes={gate.PROFILES: encoded(value)})
            report = fixture.evaluate(gate)
            self.assertEqual("fail", report["result"])
            self.assertIn("protected-profile-binding", report["violations"])
            self.assertNotIn(MARKER, json.dumps(report))
        value = copy.deepcopy(support.generator.PROFILES)
        value["repositories"]["infra"]["state"] = "Unrelated prose"
        self.assertEqual("pass", support.PRMetadata(changes={gate.PROFILES: encoded(value)}).evaluate(gate)["result"])
        fixture = support.PRMetadata()
        fixture.payloads[fixture.prefix + "/rules/branches/main"] = support.branch_rules_payload(
            contexts=((MARKER, 15368),),
        )
        report = fixture.evaluate(gate)
        self.assertEqual("error", report["result"])
        self.assertIn("required-check-not-produced", report["violations"])
        self.assertNotIn(MARKER, json.dumps(report))


class MetadataBoundaryTests(unittest.TestCase):
    def test_http_protocol_response_parser_returns_static_errors_and_valid_control(self):
        fixture = support.PRMetadata()
        contract = gate.TrustedContract.from_data(fixture.contract)
        for case in ("valid", "malformed-size", "missing-delimiter"):
            budget = gate.Budget()
            opener = ProtocolOpener(case)
            client = gate.ReadOnlyClient(contract, fixture.token, budget, opener=opener)
            with self.subTest(case=case):
                if case == "valid":
                    self.assertEqual({}, client.get(fixture.prefix))
                else:
                    with self.assertRaisesRegex(gate.GateError, "^metadata-protocol$"):
                        client.get(fixture.prefix)
                self.assertEqual(1, budget.requests)
                self.assertTrue(opener.response.isclosed())

    def test_all_nonfinite_json_numbers_are_refused_at_decode_at_every_depth(self):
        for literal in ("1e999", "-1e999", "1e+999", "-1e+999", "NaN", "Infinity", "-Infinity"):
            for document in (literal, "[" + literal + "]",
                             '{"unprojected":{"nested":[' + literal + "]}}"):
                with self.subTest(literal=literal, container=document[0]), \
                        self.assertRaisesRegex(gate.GateError, "^json-number$"):
                    gate.json_document(document.encode("ascii"))
        for literal in ("1e308", "-1e308", "1.25", "-1.25", "1e-999", "-1e-999"):
            with self.subTest(finite=literal):
                value = gate.json_document(literal.encode("ascii"))
                self.assertTrue(math.isfinite(value))
                nested = gate.json_document(('{"unprojected":[' + literal + "]}").encode("ascii"))
                self.assertTrue(math.isfinite(nested["unprojected"][0]))

    def test_nonfinite_candidate_profile_numbers_produce_static_metadata_errors(self):
        for path in PROFILE_NUMBER_PATHS:
            for literal in ("1e999", "-1e999", "NaN", "Infinity", "-Infinity"):
                fixture = support.PRMetadata(changes={
                    gate.PROFILES: profile_number_payload(path, literal),
                })
                with self.subTest(path=path, literal=literal):
                    report = fixture.evaluate(gate)
                    self.assertEqual("error", report["result"])
                    self.assertEqual(2, gate.exit_code(report))
                    self.assertEqual(["json-number"], report["violations"])
                    self.assertNotIn(MARKER, json.dumps(report))
                    self.assertNotIn(literal, json.dumps(report))

    def test_nonfinite_unprojected_api_numbers_stop_before_candidate_git_reads(self):
        for literal in ("1e999", "-1e999"):
            fixture = support.PRMetadata()
            value = copy.deepcopy(fixture.repository)
            value["unprojected"] = {"nested": [MARKER]}
            fixture.payloads[fixture.prefix] = encoded(value).replace(
                json.dumps(MARKER).encode("utf-8"), literal.encode("ascii"),
            )
            with self.subTest(literal=literal):
                report = fixture.evaluate(gate)
                self.assertEqual("error", report["result"])
                self.assertEqual(["json-number"], report["violations"])
                self.assertEqual(["https://api.github.com" + fixture.prefix], fixture.calls)

    def test_denied_mismatched_or_missing_identity_prevents_candidate_reads(self):
        for change in ("401", "403", "404", "id", "org", "name", "branch", "private", "bool", "missing"):
            fixture = support.PRMetadata()
            value = copy.deepcopy(fixture.repository)
            if change in ("401", "403", "404"):
                value = urllib.error.HTTPError("https://api.github.com" + fixture.prefix, int(change), SECRET, {}, None)
            elif change == "id":
                value["id"] += 1
            elif change == "org":
                value["owner"]["id"] += 1
            elif change == "name":
                value["full_name"] = MARKER
            elif change == "branch":
                value["default_branch"] = "other"
            elif change == "private":
                value["private"] = True
            elif change == "bool":
                value["id"] = True
            else:
                del value["id"]
            fixture.payloads[fixture.prefix] = value
            with self.subTest(change=change):
                report = fixture.evaluate(gate)
                self.assertEqual("error", report["result"])
                self.assertFalse(report["identity"]["verified"])
                self.assertEqual(["https://api.github.com" + fixture.prefix], fixture.calls)
                self.assertNotIn(SECRET, json.dumps(report))

    def test_head_fork_and_missing_metadata_are_verified_before_git_reads(self):
        self.assertEqual("pass", support.PRMetadata(fork=True).evaluate(gate)["result"])
        for change in ("head-sha", "head-id", "base-sha", "number", "closed", "missing-head", "encoded-sha"):
            fixture = support.PRMetadata(fork=True)
            live = copy.deepcopy(fixture.pull)
            if change == "head-sha":
                live["head"]["sha"] = "a" * 40
            elif change == "head-id":
                live["head"]["repo"]["id"] += 1
            elif change == "base-sha":
                live["base"]["sha"] = "b" * 40
            elif change == "number":
                live["number"] = True
            elif change == "closed":
                live["state"] = "closed"
            elif change == "missing-head":
                live["head"]["repo"] = None
            else:
                live["head"]["sha"] = "%2e%2e"
            fixture.payloads[fixture.prefix + "/pulls/123"] = live
            with self.subTest(change=change):
                report = fixture.evaluate(gate)
                self.assertEqual("error", report["result"])
                self.assertFalse(any("/git/" in call for call in fixture.calls))

    def test_runtime_host_source_ref_ids_event_and_token_are_fail_closed(self):
        fixture = support.PRMetadata()
        contract = gate.TrustedContract.from_data(fixture.contract)
        for key, bad in (
            ("GITHUB_ACTIONS", "false"), ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_SERVER_URL", "https://example.invalid"), ("GITHUB_API_URL", "https://example.invalid"),
            ("GITHUB_REPOSITORY", "PenniLogic-old/infra"), ("GITHUB_REPOSITORY_ID", "1"),
            ("GITHUB_REPOSITORY_OWNER_ID", "1"), ("GITHUB_REF", "refs/pull/123/merge"),
            ("GITHUB_REF_PROTECTED", "false"), ("GITHUB_WORKFLOW_REF", MARKER),
            ("GITHUB_SHA", "%2e%2e"), ("GITHUB_WORKFLOW_SHA", "a" * 40),
        ):
            env = dict(fixture.environment, **{key: bad})
            with self.subTest(key=key), self.assertRaises(gate.GateError):
                gate.NativeContext.from_environment(contract, env)
        for token in (None, "", " ", "short", "a" * 20 + "\n"):
            with self.subTest(token=token), self.assertRaises(gate.GateError):
                gate.ReadOnlyClient(contract, token, gate.Budget(), opener=fixture)
        for key in ("repository_id", "organization_id"):
            for bad in (True, "1", None, -1):
                value = dict(fixture.contract, **{key: bad})
                with self.subTest(key=key, bad=bad), self.assertRaises(gate.GateError):
                    gate.TrustedContract.from_data(value)

    def test_only_fixed_github_get_paths_are_allowed_and_redirects_are_denied(self):
        fixture = support.PRMetadata()
        client = gate.ReadOnlyClient(gate.TrustedContract.from_data(fixture.contract),
                                    fixture.token, gate.Budget(), opener=fixture)
        for path in ("https://example.invalid", "//example.invalid", fixture.prefix + "/../other",
                     fixture.prefix + "/pulls/%31", fixture.prefix + "/git/blobs/%2e%2e",
                     fixture.prefix + "/pulls/1?host=evil", fixture.prefix + "/pulls/0",
                     fixture.prefix + "/pulls/1\n", "/repos/Other/infra"):
            with self.subTest(path=path), self.assertRaises(gate.GateError):
                client.get(path)
        self.assertEqual([], fixture.calls)
        stream = io.BytesIO(b"ignored")
        with self.assertRaisesRegex(gate.GateError, "metadata-redirect"):
            gate.NoRedirect().redirect_request(None, stream, 302, SECRET, {}, "https://example.invalid")
        self.assertTrue(stream.closed)

    def test_request_deadline_body_json_and_process_errors_do_not_fall_back(self):
        fixture = support.PRMetadata()
        contract = gate.TrustedContract.from_data(fixture.contract)
        budget = gate.Budget(clock=lambda: 0)
        client = gate.ReadOnlyClient(contract, fixture.token, budget, opener=fixture)
        budget.requests = gate.MAX_REQUESTS
        with self.assertRaisesRegex(gate.GateError, "metadata-request-limit"):
            client.get(fixture.prefix)
        budget = gate.Budget(clock=lambda: 0)
        budget.clock = lambda: 181
        client = gate.ReadOnlyClient(contract, fixture.token, budget, opener=fixture)
        with self.assertRaisesRegex(gate.GateError, "metadata-deadline"):
            client.get(fixture.prefix)
        for body in (b"x" * (gate.MAX_BYTES + 1), b"\xff", b'{"id":1,"id":2}', b"\xef\xbb\xbf{}",
                     b'{"id":NaN}', b"[" * 66 + b"0" + b"]" * 66):
            with self.subTest(body_length=len(body)), self.assertRaises(gate.GateError):
                gate.json_document(body)
        for error in (TimeoutError(SECRET), OSError(SECRET), urllib.error.URLError(SECRET)):
            fixture.payloads[fixture.prefix] = error
            report = fixture.evaluate(gate)
            self.assertEqual("error", report["result"])
            self.assertEqual(["metadata-unavailable"], report["violations"])
            self.assertNotIn(SECRET, json.dumps(report))

    def test_malformed_git_inventory_blobs_and_late_revision_changes_fail(self):
        for mutation in ("truncated", "duplicate", "path", "symlink", "blob-id", "blob-size", "blob-encoding"):
            fixture = support.PRMetadata()
            head_tree = fixture.payloads[fixture.prefix + "/git/commits/" + fixture.head_sha]["tree"]["sha"]
            if mutation in ("truncated", "duplicate", "path"):
                tree = fixture.payloads[fixture.prefix + "/git/trees/" + head_tree]
                if mutation == "truncated":
                    tree["truncated"] = True
                elif mutation == "duplicate":
                    tree["tree"].append(dict(tree["tree"][0]))
                else:
                    tree["tree"][0]["path"] = "../" + MARKER
            else:
                blob_path = next(path for path in fixture.payloads if "/git/blobs/" in path)
                if mutation == "symlink":
                    for payload in fixture.payloads.values():
                        if isinstance(payload, dict) and isinstance(payload.get("tree"), list):
                            for entry in payload["tree"]:
                                if entry["type"] == "blob":
                                    entry["mode"] = "120000"
                elif mutation == "blob-id":
                    fixture.payloads[blob_path]["sha"] = "b" * 40
                elif mutation == "blob-size":
                    fixture.payloads[blob_path]["size"] = True
                else:
                    fixture.payloads[blob_path]["encoding"] = MARKER
            with self.subTest(mutation=mutation):
                report = fixture.evaluate(gate)
                self.assertEqual("error", report["result"], report)
                self.assertNotIn(MARKER, json.dumps(report))
        fixture = support.PRMetadata()
        first, changed = copy.deepcopy(fixture.pull), copy.deepcopy(fixture.pull)
        changed["head"]["sha"] = "f" * 40
        sequence = iter((first, changed))
        fixture.payloads[fixture.prefix + "/pulls/123"] = lambda: next(sequence)
        report = fixture.evaluate(gate)
        self.assertEqual("error", report["result"])
        self.assertIn("stale-pull-request", report["violations"])


class RealCLIAndStepTests(unittest.TestCase):
    def run_cli(self, fixture, bash_step=False, env_changes=None, http_case=None):
        with tempfile.TemporaryDirectory(prefix="pr-integrity-cli-") as directory:
            root = Path(directory).resolve(strict=True)
            program = root / "validator.py"
            program.write_text(support.generator.pr_integrity_program(fixture.name), encoding="utf-8")
            driver = root / "fixture_driver.py"
            driver.write_text(DRIVER, encoding="utf-8")
            payloads = root / "metadata.json"
            responses = dict(fixture.payloads)
            if http_case is not None:
                responses["__http_protocol_case__"] = http_case
            payloads.write_text(json.dumps(responses), encoding="utf-8")
            event = root / "_github_workflow" / "event.json"
            event.parent.mkdir()
            event.write_text(json.dumps(fixture.event), encoding="utf-8")
            env = support.defects.probe_environment()
            env.update(fixture.environment, RUNNER_TEMP=str(root), GITHUB_EVENT_PATH=str(event),
                       REAL_PYTHON=sys.executable, FIXTURE_DRIVER=str(driver),
                       TRUSTED_PROGRAM=str(program), FIXTURE_METADATA=str(payloads))
            env.update(env_changes or {})
            if bash_step:
                bash = shutil.which("bash")
                if bash is None:
                    self.fail("Bash is required for the finite emitted-step harness")
                step = json.loads(support.generator.pr_integrity_workflow(fixture.name))["jobs"]["pr-workflow-integrity"]["steps"][0]
                prefix = 'python3() { "$REAL_PYTHON" -I -S "$FIXTURE_DRIVER" "$TRUSTED_PROGRAM" "$FIXTURE_METADATA"; }\n'
                emitted = root / "emitted-step.sh"
                emitted.write_text(prefix + step["run"] + "\n", encoding="utf-8", newline="\n")
                env["EMITTED_STEP"] = "true"
                command = [bash, "--noprofile", "--norc", str(emitted)]
            else:
                command = [sys.executable, "-I", "-S", str(driver), str(program), str(payloads)]
            result = subprocess.run(command, cwd=root, capture_output=True, check=False, timeout=20, env=env)
            self.assertEqual(b"", result.stderr, result.stderr.decode("utf-8", "replace"))
            report = json.loads(result.stdout)
            self.assertNotIn(MARKER, result.stdout.decode())
            self.assertNotIn(fixture.token, result.stdout.decode())
            self.assertNotIn(str(root), result.stdout.decode())
            return result.returncode, report

    def test_real_cli_and_bash_use_canonical_owned_event_paths(self):
        for bash_step in (False, True):
            with self.subTest(bash_step=bash_step), tempfile.TemporaryDirectory(prefix="pr-event-alias-") as directory:
                root = Path(directory).resolve(strict=True)
                component = root / "alias component"
                component.mkdir()
                alias = str(component / "..")
                if sys.platform == "win32":
                    alias = alias.swapcase()
                self.assertTrue(os.path.samefile(root, alias))
                environments = []
                run = subprocess.run

                def observed(command, **kwargs):
                    environments.append(kwargs["env"])
                    return run(command, **kwargs)

                with mock.patch.object(tempfile, "TemporaryDirectory",
                                       return_value=contextlib.nullcontext(alias)), \
                        mock.patch.object(subprocess, "run", side_effect=observed):
                    code, report = self.run_cli(support.PRMetadata(), bash_step=bash_step)
                self.assertEqual(0, code)
                self.assertEqual("pass", report["result"])
                self.assertEqual(1, len(environments))
                self.assertEqual(str(root), environments[0]["RUNNER_TEMP"])
                self.assertEqual(str(root / "_github_workflow" / "event.json"),
                                 environments[0]["GITHUB_EVENT_PATH"])

    def test_all_nine_actual_cli_clean_controls_and_echo_omission_failures(self):
        for name in support.generator.PROFILES["repositories"]:
            with self.subTest(profile=name, baseline=True):
                code, report = self.run_cli(support.PRMetadata(name))
                self.assertEqual(0, code)
                self.assertEqual("pass", report["result"])
                self.assertEqual({
                    "schema", "check_name", "repository", "identity", "pull_request_number", "base_sha",
                    "head_sha", "workflow_source_sha", "bindings", "required_checks", "violations",
                    "requests", "elapsed_seconds", "result",
                }, set(report))
            def update(_document, job):
                run = next(step for step in job["steps"] if step.get("name") == "Run checks")
                run["run"] = "echo " + MARKER
            with self.subTest(profile=name, baseline=False):
                code, report = self.run_cli(support.PRMetadata(name, {
                    CI: edited_ci(name, update), "scripts/check_repository.py": b"raise SystemExit(0)\n",
                }))
                self.assertEqual(1, code)
                self.assertEqual("fail", report["result"])

    def test_nonfinite_profile_numbers_emit_static_json_in_actual_cli_and_bash_step(self):
        cases = [(path, literal) for path in PROFILE_NUMBER_PATHS for literal in ("1e999", "-1e999")]
        cases += [(("unprojected", "nested"), literal) for literal in (
            '[{"ignored":1e999}]', '[{"ignored":-1e999}]', "NaN", "Infinity", "-Infinity",
        )]
        for path, literal in cases:
            for bash_step in (False, True):
                fixture = support.PRMetadata(changes={
                    gate.PROFILES: profile_number_payload(path, literal),
                })
                with self.subTest(path=path, literal=literal, bash_step=bash_step):
                    code, report = self.run_cli(fixture, bash_step=bash_step)
                    self.assertEqual(2, code)
                    self.assertEqual("error", report["result"])
                    self.assertEqual(["json-number"], report["violations"])
                    self.assertNotIn(literal, json.dumps(report))

    def test_http_protocol_errors_emit_static_json_in_actual_cli_and_bash_step(self):
        for case in ("valid", "malformed-size", "missing-delimiter"):
            for bash_step in (False, True):
                with self.subTest(case=case, bash_step=bash_step):
                    code, report = self.run_cli(support.PRMetadata(), bash_step=bash_step, http_case=case)
                    self.assertEqual(0 if case == "valid" else 2, code)
                    self.assertEqual("pass" if case == "valid" else "error", report["result"])
                    self.assertEqual([] if case == "valid" else ["metadata-protocol"], report["violations"])

    def test_finite_profile_numbers_preserve_actual_cli_and_step_pass_or_binding_failure(self):
        for bash_step in (False, True):
            for path, literal, expected_code in (
                (("unprojected", "nested"), "[1e308,-1e308,1e-999,-1e-999]", 0),
                (("repositories", "infra", "timeout_minutes"), "2e1", 1),
            ):
                fixture = support.PRMetadata(changes={
                    gate.PROFILES: profile_number_payload(path, literal),
                })
                with self.subTest(path=path, bash_step=bash_step):
                    code, report = self.run_cli(fixture, bash_step=bash_step)
                    self.assertEqual(expected_code, code)
                    self.assertEqual("pass" if expected_code == 0 else "fail", report["result"])
                    self.assertEqual([] if expected_code == 0 else ["protected-profile-binding"],
                                     report["violations"])

    def test_emitted_bash_step_runs_real_validator_and_surfaces_guard_failures(self):
        code, report = self.run_cli(support.PRMetadata(), bash_step=True)
        self.assertEqual(0, code)
        self.assertEqual("pass", report["result"])
        code, report = self.run_cli(support.PRMetadata(changes={WORKFLOW: None}), bash_step=True)
        self.assertEqual(1, code)
        self.assertIn("protected-base-binding", report["violations"])
        for change in ({"GH_TOKEN": ""}, {"GITHUB_REF_PROTECTED": "false"},
                       {"GITHUB_API_URL": "https://example.invalid"}, {"GITHUB_SHA": "%2e%2e"}):
            with self.subTest(change=change):
                code, report = self.run_cli(support.PRMetadata(), bash_step=True, env_changes=change)
                self.assertEqual(2, code)
                self.assertEqual("error", report["result"])

    def test_missing_python_and_production_cli_arguments_are_explicit_failures(self):
        code = 'python3() { return 127; }\n' + json.loads(
            support.generator.pr_integrity_workflow("infra"),
        )["jobs"]["pr-workflow-integrity"]["steps"][0]["run"]
        bash = shutil.which("bash")
        if bash is None:
            self.fail("Bash is required; missing tooling is not a skipped success")
        with tempfile.TemporaryDirectory(prefix="pr-integrity-no-python-") as directory:
            emitted = Path(directory) / "emitted-step.sh"
            emitted.write_text(code + "\n", encoding="utf-8", newline="\n")
            result = subprocess.run([bash, "--noprofile", "--norc", str(emitted)],
                                    capture_output=True, check=False, timeout=20, env=support.defects.probe_environment())
            self.assertEqual(127, result.returncode)
        with tempfile.TemporaryDirectory(prefix="pr-integrity-args-") as directory:
            program = Path(directory) / "validator.py"
            program.write_text(support.generator.pr_integrity_program("infra"), encoding="utf-8")
            result = subprocess.run([sys.executable, "-I", "-S", str(program), "--candidate-command", SECRET],
                                    capture_output=True, check=False, timeout=20, env=support.defects.probe_environment())
            self.assertEqual(2, result.returncode)
            report = json.loads(result.stdout)
            self.assertEqual(["unsupported-arguments"], report["violations"])
            self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)

    def test_only_runner_event_is_opened_and_sensitive_output_is_refused(self):
        fixture = support.PRMetadata()
        env = dict(fixture.environment, RUNNER_TEMP=os.path.abspath("fixture"), GITHUB_EVENT_PATH=MARKER)
        with self.assertRaisesRegex(gate.GateError, "runner-event-path"), mock.patch("builtins.open") as opened:
            gate.event_input(env)
        opened.assert_not_called()
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["validator"]), mock.patch.object(gate, "event_input", return_value={}), \
                contextlib.redirect_stdout(out):
            self.assertEqual(2, gate.main(support.generator.pr_integrity_contract("infra"), {
                **fixture.environment, "GH_TOKEN": SECRET,
            }, client_factory=lambda *_args: (_ for _ in ()).throw(gate.GateError("step-token"))))
        self.assertNotIn(SECRET, out.getvalue())


if __name__ == "__main__":
    unittest.main()
