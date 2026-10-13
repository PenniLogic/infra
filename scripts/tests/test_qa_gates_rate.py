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


def evaluate(attempts_by_job, ledger_doc=None, fix_only=None, base_doc=qs.SAME):
    """``base_doc``: SAME (default) uses the head ledger as the base ledger, None omits it."""
    policy, manifest, parsed = qs.parse_inputs(ledger_doc=ledger_doc)
    base = parsed if base_doc is qs.SAME else None if base_doc is None else qs.parse_inputs(ledger_doc=base_doc)[2]
    attempts = {job: [junit.parse_attempt(qs.junit_xml(items)) for items in chain]
                for job, chain in attempts_by_job.items()}
    return rate.evaluate(policy=policy, manifest=manifest, ledger=parsed, attempts=attempts, fix_only=fix_only,
                         base_ledger=base)


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

    def test_a_quarantined_test_no_job_reported_still_counts_as_a_repository_test(self):
        report = evaluate({qs.JOB: [plain(49)], qs.MONEY_JOB: [plain(49)]}, ledger((qs.JOB, "test_a")))
        self.assertEqual((report["decision"], report["quarantine_rate"]["tests"]), ("pass", 50))
        report = evaluate({qs.JOB: [plain(48)], qs.MONEY_JOB: [plain(48)]}, ledger((qs.JOB, "test_a")))
        self.assertEqual((report["decision"], report["quarantine_rate"]["tests"]), ("fail", 49))

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


TICKETS = [f"PenniLogic/infra#9002{index:02d}" for index in range(4)]


def four_quarantined(start=-3):
    """Four of 100 tests quarantined, each with its own ticket (4 % > the 2 % ceiling)."""
    events, records = [], []
    for index, ticket in enumerate(TICKETS):
        more, record = qs.justified(qs.identity(name=f"test_filler_{index:03d}"), start, ticket=ticket)
        events += more
        records.append(record)
    return qs.ledger_document(events, records)


class FixOnlyBaseTests(unittest.TestCase):
    # Review round 2, PS-1: --fix-only binds to a quarantine active in the base revision's ledger.
    attempts = {qs.JOB: [plain(100)], qs.MONEY_JOB: [plain(100)]}

    def released(self, start=-3):
        head = four_quarantined(start)
        head["releases"].append(qs.release(qs.identity(name="test_filler_000"), 0, ticket=TICKETS[0]))
        return head

    def test_fix_that_releases_its_own_quarantine_stays_exempt(self):
        for start in (-3, -15):  # -15: the fixed quarantine is past the maximum age.
            with self.subTest(start=start):
                base = four_quarantined(start)
                report = evaluate(self.attempts, self.released(start), fix_only=TICKETS[0], base_doc=base)
                self.assertEqual((report["decision"], rules(report)), ("pass", {("QG-QUARANTINE-RATE", "report")}))
                self.assertTrue(report["quarantine_rate"]["fix_only_bound"])
                unexempt = evaluate(self.attempts, self.released(start), base_doc=base)
                self.assertEqual(rules(unexempt), {("QG-QUARANTINE-RATE", "fail")})

    def test_ticket_not_active_in_the_base_is_unbound(self):
        base = four_quarantined()
        added = four_quarantined()
        more, record = qs.justified(qs.identity(name="test_filler_004"), -3, ticket=qs.OTHER_TICKET)
        added["flake_events"] += more
        added["quarantines"].append(record)
        report = evaluate(self.attempts, added, fix_only=qs.OTHER_TICKET, base_doc=base)
        self.assertEqual(rules(report), {("QG-QUARANTINE-RATE", "fail"), ("QG-FIX-ONLY-UNBOUND", "fail")})
        self.assertEqual(evaluate(self.attempts, added, fix_only=TICKETS[1], base_doc=base)["decision"], "pass")

    def test_missing_base_ledger_fails(self):
        self.assertEqual(evaluate(self.attempts)["decision"], "pass")
        report = evaluate(self.attempts, base_doc=None)
        self.assertEqual((report["decision"], rules(report)), ("fail", {("QG-LEDGER-BASE-MISSING", "fail")}))


class AllowanceTests(unittest.TestCase):
    # Review round 2, PS-6: the repository flake rate uses each job's re-execution allowance.
    def test_pass_on_a_non_permitted_re_execution_is_not_a_flake(self):
        first = plain(9) + qs.cases(("test_a", "failed"))
        retry = qs.cases(("test_a", "passed"))
        control = evaluate({qs.JOB: [first, retry], qs.MONEY_JOB: [plain(9)]})
        self.assertEqual(control["flake_rate"], {"count": 1, "tests": 10, "basis_points": 1000})
        report = evaluate({qs.MONEY_JOB: [first, retry], qs.JOB: [plain(9)]})
        self.assertEqual(report["flake_rate"], {"count": 0, "tests": 10, "basis_points": 0})


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
        return ["--manifest", manifest, "--ledger", ledger_path, "--base-ledger", ledger_path,
                "--attempt", f"{qs.JOB}={attempt}", "--attempt", f"{qs.MONEY_JOB}={attempt}", *extra]

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


class RateBaseCliTests(unittest.TestCase):
    setUp, write, main, argv = RateCliTests.setUp, RateCliTests.write, RateCliTests.main, RateCliTests.argv

    def test_cli_without_base_ledger_fails(self):
        # Review round 2, PS-1: the base ledger is a required input; without it the step fails.
        self.assertEqual(self.main(self.argv())[0], 0)
        argv = self.argv()
        index = argv.index("--base-ledger")
        code, report = self.main(argv[:index] + argv[index + 2:])
        self.assertEqual((code, [finding["rule"] for finding in report["findings"]]), (1, ["QG-LEDGER-BASE-MISSING"]))
