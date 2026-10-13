"""Repository quarantine-rate ceiling (PenniLogic/infra#28; review round 1, PS-1).

The docs policy sets the ceiling as a share of a repository's tests, so the denominator is the distinct tests of
every manifest job and the numerator the distinct actively quarantined tests. Each negative has a passing control
and exactly one mutation, and asserts the exact static rule or refusal code. All data is synthetic.
"""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import qa_gates_support as qs
import qa_gates_junit as junit
import qa_gates_rate as rate
from qa_gates_common import Refused


def plain(count, prefix="test_filler"):
    return qs.cases(*((f"{prefix}_{index:03d}", "passed") for index in range(count)))


def ledger(*quarantined):
    """``quarantined``: (job, name) pairs, each justified by two events."""
    events, records = [], []
    for job, name in quarantined:
        more, record = qs.justified(qs.identity(name=name), -3, job=job)
        events += more
        records.append(record)
    return qs.ledger_document(events, records)


def evaluate(attempts_by_job, ledger_doc=None, fix_only=None):
    policy, manifest, parsed = qs.parse_inputs(ledger_doc=ledger_doc)
    attempts = {job: [junit.parse_attempt(qs.junit_xml(items)) for items in chain]
                for job, chain in attempts_by_job.items()}
    return rate.evaluate(policy=policy, manifest=manifest, ledger=parsed, attempts=attempts, fix_only=fix_only)


def rules(report):
    return {(finding["rule"], finding["effect"]) for finding in report["findings"]}


class RepositoryRateTests(unittest.TestCase):
    def test_ceiling_counts_the_repository_not_one_job(self):
        # PS-1 reproduction (a): 1 quarantined of 10 tests in one job, but 1 of 1000 in the repository.
        attempts = {qs.JOB: [plain(9) + qs.cases(("test_a", "passed"))], qs.MONEY_JOB: [plain(990, "test_money")]}
        report = evaluate(attempts, ledger((qs.JOB, "test_a")))
        self.assertEqual((report["decision"], rules(report)), ("pass", set()))
        self.assertEqual(report["quarantine_rate"]["tests"], 1000)
        attempts[qs.MONEY_JOB] = [plain(39, "test_money")]
        report = evaluate(attempts, ledger((qs.JOB, "test_a")))
        self.assertEqual((report["decision"], rules(report)), ("fail", {("QG-QUARANTINE-RATE", "fail")}))

    def test_distinct_tests_across_jobs_are_counted_once(self):
        # PS-1 reproduction (b): two jobs run the same 100 tests; four distinct quarantined tests are 4 %.
        same = plain(100)
        control = evaluate({qs.JOB: [same], qs.MONEY_JOB: [same]},
                           ledger((qs.JOB, "test_filler_000"), (qs.JOB, "test_filler_001"),
                                  (qs.MONEY_JOB, "test_filler_000"), (qs.MONEY_JOB, "test_filler_001")))
        self.assertEqual((control["decision"], control["quarantine_rate"]["count"]), ("pass", 2))
        report = evaluate({qs.JOB: [same], qs.MONEY_JOB: [same]},
                          ledger((qs.JOB, "test_filler_000"), (qs.JOB, "test_filler_001"),
                                 (qs.MONEY_JOB, "test_filler_002"), (qs.MONEY_JOB, "test_filler_003")))
        self.assertEqual((report["decision"], rules(report)), ("fail", {("QG-QUARANTINE-RATE", "fail")}))
        self.assertEqual((report["quarantine_rate"]["count"], report["quarantine_rate"]["tests"]), (4, 100))

    def test_two_percent_boundary_and_rounded_down_basis_points(self):
        at_ceiling = evaluate({qs.JOB: [plain(50)], qs.MONEY_JOB: [plain(50)]}, ledger((qs.JOB, "test_filler_000")))
        self.assertEqual((at_ceiling["decision"], at_ceiling["quarantine_rate"]["basis_points"]), ("pass", 200))
        over = evaluate({qs.JOB: [plain(49)], qs.MONEY_JOB: [plain(49)]}, ledger((qs.JOB, "test_filler_000")))
        self.assertEqual((over["decision"], over["quarantine_rate"]["basis_points"]), ("fail", 204))
        self.assertTrue(over["quarantine_rate"]["exceeded"])

    def test_fix_only_exemption_requires_an_explicit_bound_input(self):
        attempts = {qs.JOB: [plain(49)], qs.MONEY_JOB: [plain(49)]}
        quarantined = ledger((qs.JOB, "test_filler_000"))
        self.assertEqual(rules(evaluate(attempts, quarantined)), {("QG-QUARANTINE-RATE", "fail")})
        exempt = evaluate(attempts, quarantined, fix_only=qs.TICKET)
        self.assertEqual((exempt["decision"], rules(exempt)), ("pass", {("QG-QUARANTINE-RATE", "report")}))
        unbound = evaluate(attempts, quarantined, fix_only=qs.OTHER_TICKET)
        self.assertEqual(rules(unbound), {("QG-QUARANTINE-RATE", "fail"), ("QG-FIX-ONLY-UNBOUND", "fail")})

    def test_repository_flake_rate_counts_a_test_flaking_in_two_jobs_once(self):
        first = plain(9) + qs.cases(("test_a", "failed"))
        retry = qs.cases(("test_a", "passed"))
        report = evaluate({qs.JOB: [first, retry], qs.MONEY_JOB: [first, retry]})
        self.assertEqual(report["flake_rate"], {"count": 1, "tests": 10, "basis_points": 1000})

    def test_every_manifest_job_is_required(self):
        attempts = {qs.JOB: [plain(10)], qs.MONEY_JOB: [plain(10)]}
        self.assertEqual(evaluate(attempts)["decision"], "pass")
        for code, mutated in (("INPUT-JOBS-MISSING", {qs.JOB: attempts[qs.JOB]}),
                              ("MANIFEST-UNKNOWN-JOB", {**attempts, "synthetic-other-job": [plain(1)]})):
            with self.subTest(code=code):
                with self.assertRaises(Refused) as caught:
                    evaluate(mutated)
                self.assertEqual(caught.exception.code, code)


class RateCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="pennilogic-qa-rate-cli-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def write(self, name, data):
        path = self.directory / name
        path.write_bytes(data)
        return str(path)

    def main(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = rate.main(argv, clock=lambda: qs.TODAY)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(stdout.getvalue().count("\n"), 1)
        return code, json.loads(stdout.getvalue())

    def argv(self, *extra, quarantined=()):
        manifest = self.write("manifest.json", qs.encode(qs.manifest_document()))
        ledger_path = self.write("ledger.json", qs.encode(ledger(*quarantined)))
        attempt = self.write("attempt.xml", qs.junit_xml(plain(49)))
        return ["--manifest", manifest, "--ledger", ledger_path, "--attempt", f"{qs.JOB}={attempt}",
                "--attempt", f"{qs.MONEY_JOB}={attempt}", *extra]

    def test_exit_codes(self):
        code, report = self.main(self.argv())
        self.assertEqual((code, report["decision"], report["scope"]), (0, "pass", "repository"))
        code, report = self.main(self.argv(quarantined=[(qs.JOB, "test_filler_000")]))
        self.assertEqual((code, [finding["rule"] for finding in report["findings"]]), (1, ["QG-QUARANTINE-RATE"]))

    def test_refusals_exit_two(self):
        self.assertEqual(self.main(self.argv())[0], 0)
        for code_name, argv in (
            ("USAGE", self.argv("--attempt", "no-separator.xml")),
            ("USAGE", self.argv("--help")),
            ("USAGE", self.argv("-h")),
            ("INPUT-FIX-ONLY", self.argv("--fix-only", "infra#28")),
            ("INPUT-JOBS-MISSING", self.argv()[:-2]),
            ("MANIFEST-UNKNOWN-JOB", self.argv("--attempt", "synthetic-other-job=x.xml")),
        ):
            with self.subTest(code=code_name):
                self.assertEqual(self.main(argv), (2, {"schema": rate.REPORT_SCHEMA, "decision": "refused",
                                                       "reason": code_name, "test": None}))
