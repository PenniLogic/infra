"""Vendored docs flake policy: verbatim, pinned twice, fail closed (PenniLogic/infra#28; TS-m12).

Each negative has a passing control and exactly one mutation, and asserts the exact static refusal code.
"""

import copy
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock

import qa_gates_support as qs
import qa_gates_common
import qa_gates_policy as policies
from qa_gates_common import Refused, canonical_sha256


PINNED_DIGEST = "ed5626f8c95b2c1919c5ebbdd039a966fc7e4494077f2a786fd1ae29ecf6db2c"


def committed():
    return json.loads(policies.POLICY_FILE.read_bytes().decode("utf-8"))


class PolicyCase(unittest.TestCase):
    def assertRefused(self, code, data):
        with self.assertRaises(Refused) as caught:
            policies.parse_policy(data)
        self.assertEqual(caught.exception.code, code)
        self.assertIsNone(caught.exception.test)


class CommittedPolicyTests(PolicyCase):
    def test_committed_policy_loads_the_published_numbers(self):
        policy = policies.load_policy()
        self.assertEqual(
            (policy.quarantine_rate_ceiling_percent, policy.retry_limit, policy.money_path_retry_limit,
             policy.quarantine_after_flakes, policy.flake_window_days, policy.quarantine_max_age_days),
            (2, 1, 0, 2, 14, 14),
        )
        self.assertEqual((policy.commit, policy.strategy_version, policy.canonical_sha256),
                         ("1722fc79ab2abee15d3adc2ed2f3baaad4bd6ed4", "1.1.1", PINNED_DIGEST))

    def test_vendored_object_is_verbatim_and_canonically_formatted(self):
        document = committed()
        self.assertEqual(document["pin"], policies.PIN)
        self.assertEqual(tuple(document["flake_policy"]), policies.POLICY_KEYS)
        self.assertEqual(canonical_sha256(document["flake_policy"]), PINNED_DIGEST)
        self.assertEqual(policies.POLICY_FILE.read_bytes(), qs.encode(document))
        self.assertEqual(document["pin"]["canonicalization"], "sorted-keys-compact-ascii-json-sha256")
        self.assertEqual(set(document["re_pin"]), {"trigger", "offline_limitation"})


class FailClosedTests(PolicyCase):
    def test_policy_digest_mismatch_fails_closed(self):
        document = committed()
        policies.parse_policy(qs.encode(document))
        for key in policies.POLICY_KEYS:
            with self.subTest(key=key):
                mutated = copy.deepcopy(document)
                value = mutated["flake_policy"][key]
                mutated["flake_policy"][key] = value + 1 if type(value) is int else value + " (edited)"
                self.assertRefused("POLICY-DIGEST-MISMATCH", qs.encode(mutated))

    def test_missing_or_extra_key_fails_closed_at_every_level(self):
        document = committed()
        policies.parse_policy(qs.encode(document))
        for section in (None, "pin", "re_pin", "flake_policy"):
            for change in ("missing", "extra"):
                with self.subTest(section=section, change=change):
                    mutated = copy.deepcopy(document)
                    target = mutated if section is None else mutated[section]
                    if change == "missing":
                        del target[next(iter(target))]
                    else:
                        target["unexpected"] = 0
                    self.assertRefused("POLICY-KEYS", qs.encode(mutated))

    def test_repinning_the_data_without_the_code_pin_fails_closed(self):
        document = committed()
        policies.parse_policy(qs.encode(document))
        mutated = copy.deepcopy(document)
        mutated["flake_policy"]["retry_limit"] = 3
        mutated["pin"]["canonical_sha256"] = canonical_sha256(mutated["flake_policy"])
        self.assertRefused("POLICY-PIN-MISMATCH", qs.encode(mutated))
        for key, value in (("commit", "0" * 40), ("strategy_version", "1.1.2"), ("json_pointer", "/other")):
            with self.subTest(key=key):
                changed = copy.deepcopy(document)
                changed["pin"][key] = value
                self.assertRefused("POLICY-PIN-MISMATCH", qs.encode(changed))

    def test_schema_mismatch_refused(self):
        document = committed()
        policies.parse_policy(qs.encode(document))
        document["schema"] = "pennilogic.qa-gates.vendored-flake-policy/2"
        self.assertRefused("POLICY-SCHEMA", qs.encode(document))

    def test_values_are_rechecked_behind_a_matching_pin(self):
        # Defence in depth for a future re-pin: a pinned but unusable policy still fails closed.
        document = committed()
        mutations = {
            "money_path_retry_limit": 2, "retry_limit": True, "quarantine_rate_ceiling_percent": 101,
            "quarantine_after_flakes": 0, "flake_window_days": 0, "quarantine_max_age_days": -1,
            "on_quarantine_expired": " ",
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                for mutate in (False, True):
                    candidate = copy.deepcopy(document)
                    if mutate:
                        candidate["flake_policy"][key] = value
                    digest = canonical_sha256(candidate["flake_policy"])
                    candidate["pin"]["canonical_sha256"] = digest
                    with mock.patch.dict(policies.PIN, {"canonical_sha256": digest}):
                        if mutate:
                            self.assertRefused("POLICY-VALUE", qs.encode(candidate))
                        else:
                            self.assertEqual(policies.parse_policy(qs.encode(candidate)).retry_limit, 1)

    def test_strict_json_refusals(self):
        data = policies.POLICY_FILE.read_bytes()
        policies.parse_policy(data)
        duplicate = data.replace(b'"retry_limit": 1,', b'"retry_limit": 1,\n    "retry_limit": 1,', 1)
        self.assertNotEqual(duplicate, data)
        nonfinite = data.replace(b'"retry_limit": 1,', b'"retry_limit": 1e999,', 1)
        self.assertNotEqual(nonfinite, data)
        for label, mutated in (("bom", b"\xef\xbb\xbf" + data), ("duplicate", duplicate),
                               ("nonfinite", nonfinite), ("encoding", data.replace(b"Re-pin", b"\xffRe-pin", 1))):
            with self.subTest(label=label):
                self.assertRefused("POLICY-JSON", mutated)

    def test_size_bound_is_exact(self):
        data = policies.POLICY_FILE.read_bytes()
        padded = data + b" " * (policies.POLICY_LIMIT - len(data))
        self.assertEqual(len(padded), policies.POLICY_LIMIT)
        policies.parse_policy(padded)
        self.assertRefused("POLICY-SIZE", padded + b" ")
        self.assertRefused("POLICY-SIZE", b"")

    def test_unreadable_policy_file_refused(self):
        with tempfile.TemporaryDirectory(prefix="pennilogic-qa-policy-") as directory:
            copy_path = Path(directory) / "flake-policy.json"
            shutil.copyfile(policies.POLICY_FILE, copy_path)
            self.assertEqual(policies.load_policy(copy_path).retry_limit, 1)
            with self.assertRaises(Refused) as caught:
                policies.load_policy(Path(directory) / "missing.json")
            self.assertEqual(caught.exception.code, "POLICY-UNREADABLE")

    def test_non_regular_input_is_refused_before_opening(self):
        # A FIFO would block the open itself; simulated portably because os.mkfifo is POSIX-only.
        self.assertEqual(policies.load_policy().retry_limit, 1)
        fifo = os.stat_result((stat.S_IFIFO | 0o600, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        with mock.patch.object(qa_gates_common.os, "stat", return_value=fifo):
            with self.assertRaises(Refused) as caught:
                policies.load_policy()
        self.assertEqual(caught.exception.code, "POLICY-UNREADABLE")


if __name__ == "__main__":
    unittest.main()
