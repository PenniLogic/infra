"""Production parser, generated CLI and publication regressions; no hosted-CI claims."""

import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_money_source_materialization import HERE, Transport, generator, load, materializer


BODY = b'{"fixture":"body"}'
ACTIONS_MARKERS = ("true", "True", "TRUE", "false", "False", "0", "1", "", "malformed", " true ")


class WireSocket:
    def __init__(self, wire):
        self.wire = wire

    def makefile(self, _mode):
        return io.BytesIO(self.wire)


def wire_response(body, url, *, framing="length", missing=0):
    if framing == "length":
        headers = b"Content-Length: " + str(len(body) + missing).encode() + b"\r\n"
        payload = body
    elif framing == "chunked":
        headers = b"Transfer-Encoding: chunked\r\n"
        payload = format(len(body), "x").encode() + b"\r\n" + body + b"\r\n0\r\n\r\n"
    elif framing in ("truncated-chunked", "truncated-trailer"):
        headers = b"Transfer-Encoding: chunked\r\n"
        payload = format(len(body), "x").encode() + b"\r\n" + body + b"\r\n"
        if framing == "truncated-trailer":
            payload += b"0\r\n"
    else:
        headers = b"Connection: close\r\n"
        payload = body
    response = http.client.HTTPResponse(WireSocket(b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n" + payload))
    response.url = url
    response.begin()
    return response


class ParserTransport(Transport):
    def __init__(self, *, framing="length", truncated_path=None):
        super().__init__()
        self.framing, self.truncated_path = framing, truncated_path
        self.responses = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        path = request.full_url.removeprefix("https://api.github.com")
        value = self.data[path]
        body = value if isinstance(value, bytes) else json.dumps(value).encode()
        response = wire_response(body, request.full_url, framing=self.framing,
                                 missing=17 if path == self.truncated_path else 0)
        self.responses.append(response)
        return response


class RealHTTPFramingTests(unittest.TestCase):
    def client(self, body=BODY, *, framing="length", missing=0, budget=None):
        fixture = ParserTransport(framing=framing)
        fixture.data["/repos/PenniLogic/contracts"] = body
        fixture.truncated_path = "/repos/PenniLogic/contracts" if missing else None
        return fixture, fixture.client(budget=budget)

    def test_complete_content_length_is_parsed_by_the_real_stdlib(self):
        fixture, client = self.client()
        self.assertEqual({"fixture": "body"}, client.get("/repos/PenniLogic/contracts"))
        self.assertIsInstance(fixture.responses[0], http.client.HTTPResponse)
        self.assertEqual(0, fixture.responses[0].length)

    def test_parseable_premature_content_length_eof_is_not_complete(self):
        fixture, client = self.client(missing=17)
        with self.assertRaisesRegex(materializer.MaterializationError, "^source-protocol$"):
            client.get("/repos/PenniLogic/contracts")
        self.assertEqual(17, fixture.responses[0].length)

    def test_complete_and_truncated_chunked_use_the_real_stdlib_parser(self):
        fixture, client = self.client(framing="chunked")
        self.assertEqual({"fixture": "body"}, client.get("/repos/PenniLogic/contracts"))
        self.assertTrue(fixture.responses[0].chunked)
        fixture, client = self.client(framing="truncated-chunked")
        with self.assertRaisesRegex(materializer.MaterializationError, "^source-protocol$"):
            client.get("/repos/PenniLogic/contracts")

    def test_chunked_terminal_trailer_eof_is_not_complete(self):
        fixture, client = self.client(framing="truncated-trailer")
        with self.assertRaisesRegex(materializer.MaterializationError, "^source-protocol$"):
            client.get("/repos/PenniLogic/contracts")

    def test_close_delimited_eof_is_bounded_not_a_declared_length_fallback(self):
        fixture, client = self.client(framing="close")
        self.assertEqual({"fixture": "body"}, client.get("/repos/PenniLogic/contracts"))
        self.assertIsNone(fixture.responses[0].length)
        fixture, client = self.client(b"x" * (materializer.MAX_RESPONSE_BYTES + 1), framing="close")
        with self.assertRaisesRegex(materializer.MaterializationError, "^source-size$"):
            client.get("/repos/PenniLogic/contracts")

    def test_truncated_valid_repository_metadata_cannot_publish_all_eleven_inputs(self):
        fixture = ParserTransport(truncated_path="/repos/PenniLogic/contracts")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(materializer, "CATALOG", fixture.catalog):
            root = Path(directory)
            with self.assertRaisesRegex(materializer.MaterializationError, "^source-protocol$"):
                materializer.materialize(root, fixture.client())
            self.assertEqual(1, len(fixture.calls))
            self.assertFalse((root / materializer.INPUTS).exists())
            self.assertEqual([], list(root.iterdir()))

    def test_complete_parser_responses_materialize_the_full_catalog(self):
        for framing in ("length", "chunked", "close"):
            fixture = ParserTransport(framing=framing)
            with self.subTest(framing=framing), tempfile.TemporaryDirectory() as directory:
                with mock.patch.object(materializer, "CATALOG", fixture.catalog):
                    root = Path(directory)
                    result = materializer.materialize(root, fixture.client())
                    self.assertEqual(("materialized", 11, 31),
                                     (result["status"], result["inputs"], result["requests"]))
                    materializer.verify_inputs(root)

    def test_invalid_or_ambiguous_lengths_do_not_become_close_delimited_fallbacks(self):
        for headers in (
            b"Content-Length: invalid\r\n", b"Content-Length: -1\r\n",
            b"Content-Length: 2\r\nContent-Length: 2\r\n",
            b"Content-Length: 2\r\nContent-Length: 19\r\n",
            b"Transfer-Encoding: gzip\r\n",
            b"Transfer-Encoding: chunked\r\nContent-Length: 2\r\n",
        ):
            with self.subTest(headers=headers):
                response = http.client.HTTPResponse(WireSocket(b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n{}"))
                response.url = "https://api.github.com/repos/PenniLogic/contracts"
                response.begin()
                fixture = ParserTransport()
                with mock.patch.object(fixture, "open", return_value=response):
                    with self.assertRaisesRegex(materializer.MaterializationError, "^source-protocol$"):
                        fixture.client().get("/repos/PenniLogic/contracts")

    def test_exact_response_total_and_request_boundaries_use_real_parser_responses(self):
        body = b"{}" + b" " * (materializer.MAX_RESPONSE_BYTES - 2)
        fixture, client = self.client(body)
        for _ in range(2):
            self.assertEqual({}, client.get("/repos/PenniLogic/contracts"))
        self.assertEqual(materializer.MAX_TOTAL_BYTES, client.budget.bytes)
        with self.assertRaisesRegex(materializer.MaterializationError, "^source-size$"):
            client.get("/repos/PenniLogic/contracts")
        fixture, client = self.client(body + b" ")
        with self.assertRaisesRegex(materializer.MaterializationError, "^source-size$"):
            client.get("/repos/PenniLogic/contracts")
        fixture, client = self.client()
        client.budget.requests = 31
        self.assertEqual({"fixture": "body"}, client.get("/repos/PenniLogic/contracts"))
        self.assertEqual(32, client.budget.requests)
        with self.assertRaisesRegex(materializer.MaterializationError, "^source-request-limit$"):
            client.get("/repos/PenniLogic/contracts")
        self.assertEqual(1, len(fixture.calls))


class RequestDeadlineTests(unittest.TestCase):
    def read_at(self, elapsed, *, global_started=0, open_elapsed=0):
        now = [global_started]
        budget = materializer.Budget(clock=lambda: now[0])
        now[0] = 0
        fixture = ParserTransport()
        response = wire_response(BODY, "https://api.github.com/repos/PenniLogic/contracts")
        original_read = response.read1

        def read(size):
            part = original_read(size)
            now[0] = elapsed
            return part

        response.read1 = read

        def opened(request, timeout):
            now[0] = open_elapsed
            fixture.calls.append((request, timeout))
            return response

        with mock.patch.object(fixture, "open", side_effect=opened):
            return fixture.client(budget=budget).get("/repos/PenniLogic/contracts")

    def test_checked_request_boundary_refuses_exactly_ten_seconds_and_late_progress(self):
        self.assertEqual({"fixture": "body"}, self.read_at(9.999))
        for elapsed in (10, 10.001, 18):
            with self.subTest(elapsed=elapsed), self.assertRaisesRegex(
                materializer.MaterializationError, "^source-request-deadline$",
            ):
                self.read_at(elapsed)

    def test_open_and_json_completion_are_inside_the_checked_get_deadline(self):
        with self.assertRaisesRegex(materializer.MaterializationError, "^source-request-deadline$"):
            self.read_at(0, open_elapsed=10)
        fixture = ParserTransport()
        now = [0]
        budget = materializer.Budget(clock=lambda: now[0])
        original = materializer.json_document

        def decoded(content):
            value = original(content)
            now[0] = 10
            return value

        with mock.patch.object(materializer, "json_document", side_effect=decoded):
            with self.assertRaisesRegex(materializer.MaterializationError, "^source-request-deadline$"):
                fixture.client(budget=budget).get("/repos/PenniLogic/contracts")

    def test_global_boundary_remains_exact_even_when_request_budget_has_time(self):
        self.assertEqual({"fixture": "body"}, self.read_at(4.999, global_started=-175))
        for elapsed in (5, 5.001):
            with self.subTest(elapsed=elapsed), self.assertRaisesRegex(
                materializer.MaterializationError, "^source-deadline$",
            ):
                self.read_at(elapsed, global_started=-175)

    def test_six_second_progress_reads_cannot_accumulate_eighteen_seconds(self):
        fixture = ParserTransport()
        now = [0]
        budget = materializer.Budget(clock=lambda: now[0])
        response = wire_response(BODY, "https://api.github.com/repos/PenniLogic/contracts", framing="close")
        original = response.read1

        def progress(size):
            part = original(min(size, 9))
            now[0] += 6
            return part

        response.read1 = progress
        with mock.patch.object(fixture, "open", return_value=response):
            with self.assertRaisesRegex(materializer.MaterializationError, "^source-request-deadline$"):
                fixture.client(budget=budget).get("/repos/PenniLogic/contracts")
        self.assertEqual(12, now[0], "the late second read must refuse before an eighteen-second success")


CLI_DRIVER = r"""
import http.client,importlib.util,io,json,pathlib,sys,urllib.request
root=pathlib.Path(sys.argv[1])
fixture=json.loads((root/'fixture.json').read_bytes())
spec=importlib.util.spec_from_file_location('generated_money_cli',root/'scripts'/'materialize_money_sources.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.CATALOG=fixture['catalog']
events={'opener_created':0,'requests':0,'authorization_requests':0,'source_writes':0}
class Socket:
    def __init__(self,wire): self.wire=wire
    def makefile(self,mode): return io.BytesIO(self.wire)
class Opener:
    def open(self,request,timeout):
        events['requests']+=1
        events['authorization_requests']+=int('Authorization' in request.headers)
        path=request.full_url.removeprefix('https://api.github.com')
        body=json.dumps(fixture['responses'][path]).encode()
        wire=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        response=http.client.HTTPResponse(Socket(wire))
        response.url=request.full_url
        response.begin()
        return response
def opener(*args):
    events['opener_created']+=1
    return Opener()
urllib.request.build_opener=opener
original_open=pathlib.Path.open
def fault(path,*args,**kwargs):
    if args and args[0]=='xb':
        events['source_writes']+=1
        if events['source_writes']==2 and fixture.get('fail_second_write'):
            raise OSError('synthetic ordinary publication failure')
    return original_open(path,*args,**kwargs)
pathlib.Path.open=fault
sys.argv=[str(root/'scripts'/'materialize_money_sources.py')]
if fixture['authenticated_local']: sys.argv.append('--authenticated-local')
result=module.main()
(root/'observations.json').write_text(json.dumps(events),encoding='utf-8')
raise SystemExit(result)
"""


class GeneratedCLIModeTests(unittest.TestCase):
    def execute(self, root, marker, *, fail_second_write=False, authenticated_local=True):
        fixture = ParserTransport()
        scripts = root / "scripts"
        scripts.mkdir(exist_ok=True)
        script = scripts / "materialize_money_sources.py"
        source = generator.money_materializer().encode()
        script.write_bytes(source)
        (root / "fixture.json").write_text(json.dumps({
            "catalog": fixture.catalog, "responses": fixture.data, "fail_second_write": fail_second_write,
            "authenticated_local": authenticated_local,
        }), encoding="utf-8")
        env = {key: value for key, value in os.environ.items() if key.upper() not in {
            "GITHUB_ACTIONS", "GH_TOKEN", "GITHUB_TOKEN", "GH_CONFIG_DIR", "GIT_CONFIG_PARAMETERS",
            "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
        }}
        env["GH_TOKEN"] = "synthetic-process-local-token"
        if marker is not None:
            env["GITHUB_ACTIONS"] = marker
        result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", CLI_DRIVER, str(root)],
                                cwd=root, env=env, capture_output=True, check=False, timeout=30)
        self.assertEqual(hashlib.sha256(source).digest(), hashlib.sha256(script.read_bytes()).digest())
        self.assertNotIn(b"synthetic-process-local-token", result.stdout + result.stderr)
        self.assertNotIn(b"Authorization", result.stdout + result.stderr)
        observations = json.loads((root / "observations.json").read_bytes())
        return result, observations, fixture

    def test_any_present_actions_marker_refuses_real_generated_cli_fresh_and_cached(self):
        for cached in (False, True):
            for marker in ACTIONS_MARKERS:
                with self.subTest(cached=cached, marker=marker), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    fixture = ParserTransport()
                    with mock.patch.object(materializer, "CATALOG", fixture.catalog):
                        if cached:
                            materializer.materialize(root, fixture.client())
                            fixture.write_provider(root)
                    before = {path.relative_to(root): (path.read_bytes(), path.stat().st_mtime_ns)
                              for path in root.rglob("*") if path.is_file()}
                    result, observed, _ = self.execute(root, marker)
                    self.assertEqual(1, result.returncode)
                    self.assertEqual(b"", result.stdout)
                    self.assertEqual({"event": "money_sources", "status": "refused", "code": "local-authentication"},
                                     json.loads(result.stderr))
                    self.assertEqual({"opener_created": 0, "requests": 0, "authorization_requests": 0, "source_writes": 0},
                                     observed)
                    self.assertEqual(before, {path: ((root / path).read_bytes(), (root / path).stat().st_mtime_ns)
                                              for path in before})
                    if not cached:
                        self.assertFalse((root / materializer.INPUTS).exists())

    def test_absent_actions_marker_allows_valid_explicit_local_fresh_and_cached(self):
        for cached in (False, True):
            with self.subTest(cached=cached), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fixture = ParserTransport()
                if cached:
                    with mock.patch.object(materializer, "CATALOG", fixture.catalog):
                        materializer.materialize(root, fixture.client())
                    fixture.write_provider(root)
                result, observed, fixture = self.execute(root, None)
                self.assertEqual(0, result.returncode, result.stderr.decode())
                self.assertEqual("verified_existing" if cached else "materialized", json.loads(result.stdout)["status"])
                self.assertEqual(0 if cached else 32, observed["requests"])
                self.assertEqual(0 if cached else 32, observed["authorization_requests"])
                materializer.verify_inputs(root, fixture.catalog)
                if cached:
                    materializer.verify_provider(root, fixture.catalog)

    def test_generated_cli_write_failure_leaves_no_receipt_and_clean_retry_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, observed, fixture = self.execute(root, None, fail_second_write=True)
            self.assertEqual(1, result.returncode)
            self.assertEqual({"event": "money_sources", "status": "refused", "code": "materialization-io"},
                             json.loads(result.stderr))
            self.assertEqual(2, observed["source_writes"])
            self.assertFalse((root / materializer.INPUTS).exists())
            self.assertFalse((root / "build").exists())
            result, observed, fixture = self.execute(root, None)
            self.assertEqual(0, result.returncode)
            self.assertEqual(("materialized", 11), (json.loads(result.stdout)["status"], json.loads(result.stdout)["inputs"]))
            materializer.verify_inputs(root, fixture.catalog)

    def test_anonymous_generated_public_mode_never_sends_ambient_credential(self):
        for cached in (False, True):
            for marker in ("true", "", "malformed"):
                with self.subTest(cached=cached, marker=marker), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    fixture = ParserTransport()
                    if cached:
                        with mock.patch.object(materializer, "CATALOG", fixture.catalog):
                            materializer.materialize(root, fixture.client())
                        fixture.write_provider(root)
                    result, observed, fixture = self.execute(root, marker, authenticated_local=False)
                    self.assertEqual(0, result.returncode, result.stderr.decode())
                    self.assertEqual(0 if cached else 31, observed["requests"])
                    self.assertEqual(0, observed["authorization_requests"])
                    materializer.verify_inputs(root, fixture.catalog)


class PublicationFailureTests(unittest.TestCase):
    def test_partial_real_write_is_rolled_back_only_for_this_fresh_attempt(self):
        fixture = ParserTransport()
        original = Path.open
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(materializer, "CATALOG", fixture.catalog):
            root = Path(directory)
            preserved = root / "unrelated.bin"
            preserved.write_bytes(b"owned unrelated bytes")
            opened = []

            def fail(path, *args, **kwargs):
                stream = original(path, *args, **kwargs)
                if args and args[0] == "xb":
                    opened.append(path)
                    if len(opened) == 2:
                        class PartialWrite:
                            def __enter__(self):
                                return self

                            def __exit__(self, *arguments):
                                return stream.__exit__(*arguments)

                            def fileno(self):
                                return stream.fileno()

                            def write(self, _content):
                                stream.write(b"partial owned write")
                                raise OSError("synthetic disk write failure")

                        return PartialWrite()
                return stream

            with mock.patch.object(Path, "open", new=fail), self.assertRaises(OSError):
                materializer.materialize(root, fixture.client())
            self.assertEqual(2, len(opened))
            self.assertFalse((root / materializer.INPUTS).exists())
            self.assertEqual([preserved], list(root.iterdir()))
            self.assertEqual(b"owned unrelated bytes", preserved.read_bytes())
            self.assertEqual("materialized", materializer.materialize(root, fixture.client())["status"])
            materializer.verify_inputs(root)

    def test_cached_corruption_is_still_refused_without_cleanup_repair_or_fetch(self):
        fixture = ParserTransport()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(materializer, "CATALOG", fixture.catalog):
            root = Path(directory)
            materializer.materialize(root, fixture.client())
            path = root / materializer.INPUTS / "materialization.json"
            path.write_bytes(b"synthetic corrupt receipt")
            fixture.calls.clear()
            with self.assertRaisesRegex(materializer.MaterializationError, "^snapshot-receipt$"):
                materializer.materialize(root, fixture.client())
            self.assertEqual(b"synthetic corrupt receipt", path.read_bytes())
            self.assertEqual([], fixture.calls)

    def test_receipt_write_failure_rolls_back_fresh_files_but_not_an_existing_build(self):
        fixture = ParserTransport()
        original = Path.open
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(materializer, "CATALOG", fixture.catalog):
            root = Path(directory)
            build = root / "build"
            build.mkdir()
            sentinel = build / "unrelated.bin"
            sentinel.write_bytes(b"unchanged build artifact")

            def fail(path, *args, **kwargs):
                if args and args[0] == "xb" and path.name == "materialization.json":
                    raise OSError("synthetic receipt publication failure")
                return original(path, *args, **kwargs)

            with mock.patch.object(Path, "open", new=fail), self.assertRaises(OSError):
                materializer.materialize(root, fixture.client())
            self.assertEqual([sentinel], list(build.iterdir()))
            self.assertEqual(b"unchanged build artifact", sentinel.read_bytes())
            self.assertEqual("materialized", materializer.materialize(root, fixture.client())["status"])

    def test_unexpected_file_is_preserved_and_cleanup_failure_is_explicit(self):
        fixture = ParserTransport()
        original = Path.open
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(materializer, "CATALOG", fixture.catalog):
            root = Path(directory)
            unexpected = root / materializer.INPUTS / "unowned.bin"
            writes = []

            def fail(path, *args, **kwargs):
                if args and args[0] == "xb":
                    writes.append(path)
                    if len(writes) == 2:
                        with original(unexpected, "xb") as stream:
                            stream.write(b"preserve unexpected bytes")
                        raise OSError("synthetic publication failure")
                return original(path, *args, **kwargs)

            with mock.patch.object(Path, "open", new=fail):
                with self.assertRaisesRegex(materializer.MaterializationError, "^materialization-cleanup$"):
                    materializer.materialize(root, fixture.client())
            self.assertEqual(b"preserve unexpected bytes", unexpected.read_bytes())
            self.assertFalse((root / materializer.INPUTS / "materialization.json").exists())
            fixture.calls.clear()
            with self.assertRaisesRegex(materializer.MaterializationError, "^snapshot-inventory$"):
                materializer.materialize(root, fixture.client())
            self.assertEqual([], fixture.calls)
            self.assertEqual(b"preserve unexpected bytes", unexpected.read_bytes())

    def test_rollback_never_unlinks_a_replaced_or_hardlinked_attempt_file(self):
        for replacement in (True, False):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                relative = materializer.INPUTS / "attempt-input"
                path = root / relative
                path.parent.mkdir(parents=True)
                path.write_bytes(b"owned attempt bytes")
                expected = path.stat(follow_symlinks=False)
                alias = root / "preserved-alias"
                if replacement:
                    path.rename(alias)
                    path.write_bytes(b"preserve replacement bytes")
                else:
                    alias.hardlink_to(path)
                before = {path: path.read_bytes(), alias: alias.read_bytes()}
                with self.assertRaisesRegex(materializer.MaterializationError, "^materialization-cleanup$"):
                    materializer.rollback_attempt(root, [(relative, expected)])
                self.assertEqual(before, {name: name.read_bytes() for name in before})


class SourceHistoryTests(unittest.TestCase):
    def test_registry_source_commit_replays_the_current_materializer_not_only_command_text(self):
        registry = json.loads((HERE / "conformance/check-names.json").read_bytes())
        ref = next(entry["workflow_ref"] for entry in registry["entries"] if entry["repo"] == "PenniLogic/api")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in ("generate.py", "repository-profiles.json", "api-money-sources.json",
                             "templates/materialize_money_sources.py"):
                content = subprocess.run(
                    ["git", "--no-pager", "show", ref + ":governance/" + relative], cwd=HERE.parent,
                    capture_output=True, check=True, timeout=30,
                ).stdout
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            historical = load("money_source_history_regression", root / "generate.py")
            self.assertEqual(generator.money_materializer(), historical.money_materializer())
            self.assertEqual(generator.workflow("api"), historical.workflow("api"))


if __name__ == "__main__":
    unittest.main()
