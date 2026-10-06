"""Anonymous-fetch pressure and complete immutable tree/error boundaries; no hosted cause inference."""

import contextlib
import copy
from email.message import Message
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error

from test_money_source_materialization import Transport, materializer, tree_identity


class RecursiveTreeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = Transport()
        self.patch = mock.patch.object(materializer, "CATALOG", self.fixture.catalog)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.source = self.fixture.catalog["sources"][0]
        self.prefix = "/repos/" + self.source["repository"]
        self.commit_path = self.prefix + "/git/commits/" + self.source["commit"]
        self.tree_path = self.prefix + "/git/trees/" + self.fixture.data[self.commit_path]["tree"]["sha"] + "?recursive=1"

    def materialize(self, **kwargs):
        return materializer.materialize(self.root, self.fixture.client(**kwargs))

    def refuse_tree(self, mutation, code):
        original = copy.deepcopy(self.fixture.data[self.tree_path])
        mutation(self.fixture.data[self.tree_path])
        try:
            with self.assertRaisesRegex(materializer.MaterializationError, "^" + code + "$"):
                self.materialize()
            self.assertFalse((self.root / materializer.INPUTS).exists())
            self.assertEqual([], list(self.root.iterdir()))
            self.assertFalse(any("/git/blobs/" in request.full_url for request, _ in self.fixture.calls))
        finally:
            self.fixture.data[self.tree_path] = original
            self.fixture.calls.clear()

    def test_complete_recursive_trees_reduce_anonymous_reads_to_exactly_seventeen(self):
        result = self.materialize()
        self.assertEqual(("materialized", 11, 17), (result["status"], result["inputs"], result["requests"]))
        queries = [request.full_url for request, _ in self.fixture.calls]
        tree_queries = [url for url in queries if "/git/trees/" in url]
        self.assertEqual(2, len(tree_queries))
        self.assertTrue(all(url.endswith("?recursive=1") for url in tree_queries))
        self.assertEqual(11, sum("/git/blobs/" in url for url in queries))
        self.assertTrue(all(not request.has_header("Authorization") for request, _ in self.fixture.calls))
        materializer.verify_inputs(self.root)
        self.fixture.calls.clear()
        self.assertEqual(0, self.materialize()["requests"])
        self.assertEqual([], self.fixture.calls)

    def test_truncation_duplicates_malformed_identity_and_missing_ancestors_fail_before_blobs(self):
        source = self.fixture.data[self.tree_path]
        directory = next(entry["path"] for entry in source["tree"] if entry["type"] == "tree")
        cases = [
            (lambda data: data.update(truncated=True), "source-tree"),
            (lambda data: data.pop("truncated"), "source-tree"),
            (lambda data: data.update(sha="a" * 40), "source-tree"),
            (lambda data: data.update(tree={}), "source-tree"),
            (lambda data: data["tree"].append(copy.deepcopy(data["tree"][0])), "source-tree-path"),
            (lambda data: data.update(tree=[entry for entry in data["tree"] if entry["path"] != directory]),
             "source-tree-parent"),
            (lambda data: data["tree"][0].update(sha="short"), "immutable-sha"),
            (lambda data: data["tree"][0].update(mode="040000", type="blob"), "source-tree"),
            (lambda data: data["tree"][0].update(type="tree", mode="100644"), "source-tree"),
            (lambda data: data["tree"][0].update(type="commit", mode="100644"), "source-tree"),
            (lambda data: data["tree"].append({"path": "extra", "type": "blob", "mode": "100644",
                                             "sha": "b" * 40, "size": -1}), "source-tree"),
            (lambda data: data["tree"].append({"path": "extra", "type": "blob", "mode": "100644",
                                             "sha": "b" * 40, "size": True}), "source-tree"),
        ]
        for mutate, code in cases:
            with self.subTest(code=code, mutate=mutate):
                self.refuse_tree(mutate, code)

    def test_unsafe_flat_paths_and_oversized_inventory_are_refused(self):
        for path in ("../outside", "/absolute", "a//b", "a/./b", "a/../b", "a\\b", "a/\0b",
                     "a/\x1fb", "a/\x7fb", "a/", "", "a" * 1025, "a/\ud800"):
            with self.subTest(path=path):
                self.refuse_tree(lambda data: data["tree"][0].update(path=path), "source-tree-path")
        self.refuse_tree(lambda data: data.update(tree=[data["tree"][0]] * 4097), "source-tree")

    def test_changed_subtree_or_root_payload_cannot_hide_unrelated_missing_entries(self):
        self.refuse_tree(
            lambda data: next(entry for entry in data["tree"] if entry["type"] == "tree").update(sha="a" * 40),
            "source-tree-integrity",
        )
        self.refuse_tree(
            lambda data: next(entry for entry in data["tree"] if entry["type"] == "blob").update(sha="a" * 40),
            "source-tree-integrity",
        )
        self.refuse_tree(
            lambda data: data["tree"].remove(next(entry for entry in data["tree"] if entry["type"] == "blob")),
            "source-tree-integrity",
        )
        self.refuse_tree(
            lambda data: data["tree"].append({"path": "unbound", "type": "blob", "mode": "100644",
                                             "sha": "a" * 40, "size": 1}),
            "source-tree-integrity",
        )

    def test_pinned_blob_size_is_still_required_after_complete_tree_hash(self):
        selected = self.source["files"][0]["path"]
        self.refuse_tree(
            lambda data: next(entry for entry in data["tree"] if entry["path"] == selected).update(size=1),
            "source-blob-binding",
        )

    def test_commit_sha_and_root_binding_are_checked_before_immutable_reads(self):
        for field, value, code in (("sha", "a" * 40, "source-commit"), ("tree", {"sha": "a" * 40}, "source-tree")):
            old = copy.deepcopy(self.fixture.data[self.commit_path])
            self.fixture.data[self.commit_path][field] = value
            try:
                if field == "tree":
                    self.fixture.data[self.prefix + "/git/trees/" + "a" * 40 + "?recursive=1"] = {
                        **copy.deepcopy(self.fixture.data[self.tree_path]), "sha": self.fixture.data[self.tree_path]["sha"],
                    }
                with self.subTest(field=field), self.assertRaisesRegex(materializer.MaterializationError, "^" + code + "$"):
                    self.materialize()
                self.assertFalse((self.root / materializer.INPUTS).exists())
            finally:
                self.fixture.data[self.commit_path] = old

    def test_git_tree_hash_sorting_handles_directory_and_file_name_prefixes(self):
        names = [
            {"path": "folder", "type": "tree", "mode": "040000", "sha": "a" * 40},
            {"path": "folder.txt", "type": "blob", "mode": "100644", "sha": "b" * 40, "size": 1},
            {"path": "folder-old", "type": "blob", "mode": "100755", "sha": "c" * 40, "size": 1},
        ]
        expected = tree_identity(names)
        raw = b"100755 folder-old\0" + bytes.fromhex("c" * 40) \
            + b"100644 folder.txt\0" + bytes.fromhex("b" * 40) \
            + b"40000 folder\0" + bytes.fromhex("a" * 40)
        self.assertEqual(expected, hashlib.sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest())
        self.assertEqual(expected, materializer.git_tree_digest(names))
        nested = [{**entry, "path": "parent/" + entry["path"]} for entry in names]
        self.assertEqual(expected, materializer.git_tree_digest(nested))

    def test_flat_response_order_is_not_part_of_the_git_object_identity(self):
        self.fixture.data[self.tree_path]["tree"].reverse()
        self.assertEqual(17, self.materialize()["requests"])
        materializer.verify_inputs(self.root)

    def test_recursive_endpoint_does_not_admit_other_queries_or_nonrecursive_reads(self):
        client = self.fixture.client()
        bare = self.tree_path.removesuffix("?recursive=1")
        for path in (bare, bare + "?recursive=0", bare + "?recursive=true",
                     bare + "?recursive=1&host=other", bare + "?recursive=%31", bare + "#recursive=1"):
            with self.subTest(path=path), self.assertRaisesRegex(materializer.MaterializationError, "^source-api-path$"):
                client.get(path)
        self.assertEqual([], self.fixture.calls)

    def test_oversized_recursive_response_and_total_budget_refuse_without_blob_or_write(self):
        original = self.fixture.data[self.tree_path]
        self.fixture.data[self.tree_path] = b"x" * (materializer.MAX_RESPONSE_BYTES + 1)
        with self.assertRaisesRegex(materializer.MaterializationError, "^source-size$"):
            self.materialize()
        self.assertFalse((self.root / materializer.INPUTS).exists())
        self.fixture.data[self.tree_path] = original
        client = self.fixture.client()
        client.budget.bytes = materializer.MAX_TOTAL_BYTES
        with self.assertRaisesRegex(materializer.MaterializationError, "^source-size$"):
            materializer.materialize(self.root, client)
        self.assertFalse((self.root / materializer.INPUTS).exists())

    def test_leaf_cannot_replace_a_required_directory_or_hide_a_pinned_file(self):
        self.refuse_tree(
            lambda data: next(entry for entry in data["tree"] if entry["path"] == "scripts").update(
                type="blob", mode="100644", size=1,
            ),
            "source-tree-parent",
        )

    def test_required_file_mode_is_checked_even_when_the_recursive_tree_is_consistent(self):
        data = self.fixture.data[self.tree_path]
        selected = next(entry for entry in data["tree"] if entry["path"] == self.source["files"][0]["path"])
        selected["mode"] = "100755"
        children = {"": []}
        children.update({entry["path"]: [] for entry in data["tree"] if entry["type"] == "tree"})
        indexed = {entry["path"]: entry for entry in data["tree"]}
        for path, entry in indexed.items():
            children[path.rpartition("/")[0]].append(entry)
        for path in sorted(children, key=len, reverse=True):
            identity = tree_identity([
                {**entry, "path": entry["path"].rsplit("/", 1)[-1]} for entry in children[path]
            ])
            if path:
                indexed[path]["sha"] = identity
            else:
                data["sha"] = identity
        self.fixture.data[self.commit_path]["tree"]["sha"] = data["sha"]
        new_path = self.prefix + "/git/trees/" + data["sha"] + "?recursive=1"
        self.fixture.data[new_path] = data
        with self.assertRaisesRegex(materializer.MaterializationError, "^source-entry-mode$"):
            self.materialize()
        self.assertFalse((self.root / materializer.INPUTS).exists())


class DenialClassificationTests(unittest.TestCase):
    CASES = (
        (401, {}, "source-unauthorized"),
        (403, {}, "source-forbidden"),
        (404, {}, "source-not-found"),
        (403, {"X-RateLimit-Remaining": "0"}, "source-rate-exhausted"),
        (403, {"X-RateLimit-Remaining": "1"}, "source-forbidden"),
        (403, {"X-RateLimit-Remaining": "invalid"}, "source-forbidden"),
        (403, {"X-RateLimit-Remaining": "0", "Retry-After": "synthetic private header"}, "source-rate-exhausted"),
        (429, {}, "source-rate-limited"),
        (500, {}, "source-http-unavailable"),
        (502, {}, "source-http-unavailable"),
        (503, {}, "source-http-unavailable"),
        (504, {}, "source-http-unavailable"),
        (400, {}, "source-http"),
    )

    def test_static_http_classification_closes_unread_body_and_never_retries_or_falls_back(self):
        class UnreadableBody(io.BytesIO):
            def read(self, *args):
                raise AssertionError("HTTP denial body must not be read")

        for status, headers, code in self.CASES:
            with self.subTest(status=status, headers=headers):
                fixture = Transport()
                body = UnreadableBody(b"synthetic private response body")
                fixture.data["/repos/PenniLogic/contracts"] = urllib.error.HTTPError(
                    "https://api.github.com/repos/PenniLogic/contracts", status,
                    "synthetic credential/path/body must not be echoed", headers, body,
                )
                client = fixture.client()
                with self.assertRaisesRegex(materializer.MaterializationError, "^" + code + "$"):
                    client.get("/repos/PenniLogic/contracts")
                self.assertTrue(body.closed)
                self.assertEqual(1, client.budget.requests)
                self.assertEqual(1, len(fixture.calls))
                self.assertFalse(fixture.calls[0][0].has_header("Authorization"))

    def test_actual_cli_report_has_only_static_code_and_no_publication_on_http_error(self):
        for status, headers, code in self.CASES:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                fixture = Transport()
                fixture.data["/repos/PenniLogic/contracts"] = urllib.error.HTTPError(
                    "https://api.github.com/repos/PenniLogic/contracts", status, "untrusted diagnostic",
                    headers, io.BytesIO(b"untrusted body"),
                )
                original = materializer.materialize
                root = Path(directory)
                with mock.patch.object(materializer, "CATALOG", fixture.catalog), \
                     mock.patch.object(materializer, "materialize", side_effect=lambda **kwargs: original(root, fixture.client())), \
                     mock.patch.object(materializer.sys, "argv", ["materializer"]):
                    out, error = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(error):
                        self.assertEqual(1, materializer.main())
                self.assertEqual("", out.getvalue())
                self.assertEqual({"event": "money_sources", "status": "refused", "code": code}, json.loads(error.getvalue()))
                self.assertEqual([], list(root.iterdir()))

    def test_duplicate_rate_headers_are_not_asserted_to_prove_exhaustion(self):
        fixture = Transport()
        headers = Message()
        headers["X-RateLimit-Remaining"] = "0"
        headers["X-RateLimit-Remaining"] = "1"
        fixture.data["/repos/PenniLogic/contracts"] = urllib.error.HTTPError(
            "https://api.github.com/repos/PenniLogic/contracts", 403, "untrusted", headers, io.BytesIO(b"body"),
        )
        with self.assertRaisesRegex(materializer.MaterializationError, "^source-forbidden$"):
            fixture.client().get("/repos/PenniLogic/contracts")


if __name__ == "__main__":
    unittest.main()
