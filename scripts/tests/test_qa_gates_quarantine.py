"""Quarantine gate decisions, boundaries and CLI (PenniLogic/infra#28, T-QA-04; E25-F01).

Each rule test has a passing control and exactly one mutation, and asserts the exact rule ID, effect and test.
All identities, owners, tickets and run ids are synthetic (see qa_gates_support).
"""

import contextlib
import copy
import datetime
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import qa_gates_support as qs
import qa_gates_ledger as ledgers
import qa_gates_quarantine as gate
import qa_gates_tags as tags
from qa_gates_common import Refused, canonical_sha256


A = qs.identity(name="test_a")
B = qs.identity(name="test_b")
FILLER = qs.cases(*((f"test_filler_{index:02d}", "passed") for index in range(49)))


def run(*names_and_outcomes, filler=FILLER):
    """One attempt: (name, outcome) pairs in the plain class plus passing filler cases."""
    return qs.cases(*names_and_outcomes) + list(filler)


def quarantined_a(start=-3, **options):
    events, record = qs.justified(A, start, **options)
    return qs.ledger_document(events=events, quarantines=[record])


class GateCase(unittest.TestCase):
    def assertFindings(self, report, expected, decision):
        self.assertEqual(qs.findings(report), set(expected))
        self.assertEqual(report["decision"], decision)


class OutcomeTests(GateCase):
    def test_clean_run_passes(self):
        report = qs.run_gate(qs.cases(("test_a", "passed"), ("test_b", "passed")))
        self.assertFindings(report, [], "pass")
        self.assertEqual(report["counts"], {"tests": 2, "passed": 2, "failed": 0, "flaky": 0, "skipped": 0})
        self.assertEqual(report["retry"], {"money_path": False, "allowed_reexecutions": 1,
                                           "observed_reexecutions": 0, "reexecuted_tests": 0})
        self.assertEqual(report["ledger_delta"], {"flake_events": [], "quarantines": []})
        self.assertEqual(report["quarantine_rate"]["quarantined"], 0)
        self.assertEqual(report["policy"]["canonical_sha256"], "ed5626f8c95b2c1919c5ebbdd039a966fc7e4494077f2a786fd1ae29ecf6db2c")

    def test_real_failure_blocks(self):
        self.assertFindings(qs.run_gate(qs.cases(("test_a", "passed"), ("test_b", "passed"))), [], "pass")
        failing = qs.cases(("test_a", "failed"), ("test_b", "passed"))
        self.assertFindings(qs.run_gate(failing), [("QG-REAL-FAILURE", "fail", A)], "fail")
        self.assertFindings(qs.run_gate(failing, qs.cases(("test_a", "failed"))),
                            [("QG-REAL-FAILURE", "fail", A)], "fail")

    def test_flake_pass_on_retry_is_not_clean(self):
        port = qs.FakeTicketPort()
        clean = qs.run_gate(qs.cases(("test_a", "passed"), ("test_b", "passed")), port=port)
        self.assertFindings(clean, [], "pass")
        report = qs.run_gate(qs.cases(("test_a", "failed"), ("test_b", "passed")), qs.cases(("test_a", "passed")),
                             port=port)
        self.assertFindings(report, [("QG-FLAKE-EVENT", "fail", A)], "fail")
        self.assertEqual(report["counts"], {"tests": 2, "passed": 1, "failed": 0, "flaky": 1, "skipped": 0})
        self.assertEqual(report["flake_rate"], {"scope": "job", "flaky": 1, "tests": 2, "basis_points": 5000})
        self.assertEqual(report["ledger_delta"]["flake_events"],
                         [{"test": A, "job": qs.JOB, "run_id": qs.RUN, "observed_on": qs.day(0)}])
        self.assertEqual(report["ledger_delta"]["quarantines"], [])
        self.assertEqual(report["retry"]["reexecuted_tests"], 1)
        self.assertEqual(port.requests, [])


class QuarantineTriggerTests(GateCase):
    def flaky(self, classname=qs.PLAIN):
        return ([(classname, "test_a", "failed"), (qs.PLAIN, "test_b", "passed")], [(classname, "test_a", "passed")])

    def test_two_flakes_in_14d_quarantines_and_requests_ticket(self):
        control_port = qs.FakeTicketPort()
        control = qs.run_gate(*self.flaky(), port=control_port)
        self.assertFindings(control, [("QG-FLAKE-EVENT", "fail", A)], "fail")
        self.assertEqual(control_port.requests, [])
        port = qs.FakeTicketPort()
        report = qs.run_gate(*self.flaky(), ledger_doc=qs.ledger_document(events=[qs.event(A, -14)]), port=port)
        self.assertFindings(report, [("QG-FLAKE-EVENT", "fail", A), ("QG-QUARANTINE-PROPOSED", "fail", A)], "fail")
        self.assertEqual(port.requests, [gate.TicketRequest(
            repository="PenniLogic/infra", job=qs.JOB, test=A, owner=qs.OWNER, flake_dates=(qs.day(-14), qs.day(0)),
            idempotency_key=canonical_sha256(["PenniLogic/infra", qs.JOB, A, qs.RUN]),
        )])
        self.assertEqual(report["ledger_delta"]["quarantines"], [{
            "test": A, "job": qs.JOB, "owner": qs.OWNER, "ticket_ref": qs.TICKET,
            "quarantined_on": qs.day(0), "expires_on": qs.day(14),
        }])

    def test_recorded_proposal_takes_the_test_out_of_the_gating_set(self):
        history = qs.ledger_document(events=[qs.event(A, -14)])
        proposal = qs.run_gate(*self.flaky(), ledger_doc=history)
        recorded = copy.deepcopy(history)
        recorded["flake_events"] += proposal["ledger_delta"]["flake_events"]
        recorded["quarantines"] += proposal["ledger_delta"]["quarantines"]
        failing = run(("test_a", "failed"), ("test_b", "passed"))
        self.assertFindings(qs.run_gate(failing, ledger_doc=history, run_id="synthetic-run-next"),
                            [("QG-REAL-FAILURE", "fail", A)], "fail")
        report = qs.run_gate(failing, ledger_doc=recorded, run_id="synthetic-run-next")
        self.assertFindings(report, [("QG-QUARANTINED-FAILURE", "report", A)], "pass")

    def test_copied_proposal_always_parses_after_a_closure(self):
        # Review round 2, PS-2: the gate proposes with the ledger's own trigger (events after the last closure).
        closures = {"release": dict(releases=[qs.release(A, -2)]), "deletion": dict(deletions=[qs.deletion(A, -2)])}
        for name, closure in closures.items():
            events, record = qs.justified(A, -10)
            closed = qs.ledger_document(events=events, quarantines=[record], **closure)
            with self.subTest(closure=name):
                stale = qs.run_gate(*self.flaky(), ledger_doc=closed)
                self.assertFindings(stale, [("QG-FLAKE-EVENT", "fail", A)], "fail")
                fresh = copy.deepcopy(closed)
                fresh["flake_events"].append(qs.event(A, -1, run="synthetic-after-closure"))
                port = qs.FakeTicketPort()
                report = qs.run_gate(*self.flaky(), ledger_doc=fresh, port=port)
                self.assertFindings(report, [("QG-FLAKE-EVENT", "fail", A), ("QG-QUARANTINE-PROPOSED", "fail", A)],
                                    "fail")
                self.assertEqual(port.requests[0].flake_dates, (qs.day(-1), qs.day(0)))
                for proposal in (stale, report):
                    copied = copy.deepcopy(fresh if proposal is report else closed)
                    copied["flake_events"] += proposal["ledger_delta"]["flake_events"]
                    copied["quarantines"] += proposal["ledger_delta"]["quarantines"]
                    qs.parse_inputs(ledger_doc=copied)

    def test_flakes_outside_window_not_quarantined(self):
        inside = qs.run_gate(*self.flaky(), ledger_doc=qs.ledger_document(events=[qs.event(A, -14)]))
        self.assertFindings(inside, [("QG-FLAKE-EVENT", "fail", A), ("QG-QUARANTINE-PROPOSED", "fail", A)], "fail")
        port = qs.FakeTicketPort()
        outside = qs.run_gate(*self.flaky(), ledger_doc=qs.ledger_document(events=[qs.event(A, -15)]), port=port)
        self.assertFindings(outside, [("QG-FLAKE-EVENT", "fail", A)], "fail")
        self.assertEqual((port.requests, outside["ledger_delta"]["quarantines"]), ([], []))

    def test_security_privacy_money_tagged_test_cannot_be_quarantined(self):
        history = qs.ledger_document(events=[qs.event(A, -1)])
        control = qs.run_gate(*self.flaky(), ledger_doc=history)
        self.assertFindings(control, [("QG-FLAKE-EVENT", "fail", A), ("QG-QUARANTINE-PROPOSED", "fail", A)], "fail")
        for classname in (qs.SECURITY, qs.PRIVACY, qs.MONEY):
            with self.subTest(classname=classname):
                test = qs.identity(classname, "test_a")
                port = qs.FakeTicketPort()
                report = qs.run_gate(*self.flaky(classname), ledger_doc=qs.ledger_document(events=[qs.event(test, -1)]),
                                     port=port)
                self.assertFindings(report, [("QG-FLAKE-EVENT", "fail", test),
                                             ("QG-QUARANTINE-REFUSED-PROTECTED", "fail", test)], "fail")
                self.assertEqual((port.requests, report["ledger_delta"]["quarantines"]), ([], []))

    def test_committed_quarantine_of_a_protected_test_is_refused_and_stays_gating(self):
        control = qs.run_gate(run(("test_a", "failed"), ("test_b", "passed")), ledger_doc=quarantined_a())
        self.assertFindings(control, [("QG-QUARANTINED-FAILURE", "report", A)], "pass")
        for classname, job in ((qs.SECURITY, qs.JOB), (qs.PRIVACY, qs.JOB), (qs.MONEY, qs.JOB),
                               (qs.MONEY_PATH, qs.MONEY_JOB)):
            with self.subTest(classname=classname):
                test = qs.identity(classname, "test_a")
                events, record = qs.justified(test, -3, job=job)
                attempt = [(classname, "test_a", "failed"), (qs.PLAIN, "test_b", "passed")] + FILLER
                report = qs.run_gate(attempt, job=job,
                                     ledger_doc=qs.ledger_document(events=events, quarantines=[record]))
                self.assertFindings(report, [("QG-QUARANTINE-PROTECTED", "fail", test),
                                             ("QG-REAL-FAILURE", "fail", test)], "fail")
                self.assertFalse(report["quarantined_tests"][0]["exempt"])

    def test_quarantine_without_owner_ticket_or_expiry_refused(self):
        history = qs.ledger_document(events=[qs.event(A, -1)])
        control = qs.run_gate(*self.flaky(), ledger_doc=history)
        self.assertIn(("QG-QUARANTINE-PROPOSED", "fail", A), qs.findings(control))
        for label, ticket in (("no-ticket", None), ("invalid-ticket", "infra#28")):
            with self.subTest(label=label):
                port = qs.FakeTicketPort(ticket)
                report = qs.run_gate(*self.flaky(), ledger_doc=history, port=port)
                self.assertFindings(report, [("QG-FLAKE-EVENT", "fail", A),
                                             ("QG-QUARANTINE-TICKET-MISSING", "fail", A)], "fail")
                self.assertEqual((len(port.requests), report["ledger_delta"]["quarantines"]), (1, []))
        manifest = qs.manifest_document()
        manifest["packages"][1]["owner"] = None
        port = qs.FakeTicketPort()
        report = qs.run_gate(*self.flaky(), ledger_doc=history, manifest_doc=manifest, port=port)
        self.assertFindings(report, [("QG-FLAKE-EVENT", "fail", A), ("QG-QUARANTINE-OWNER-MISSING", "fail", A)],
                            "fail")
        self.assertEqual(port.requests, [])
        events, record = qs.justified(A, -3)
        complete = qs.ledger_document(events=events, quarantines=[record])
        self.assertEqual(qs.run_gate(run(("test_a", "passed")), ledger_doc=complete)["decision"], "pass")
        del complete["quarantines"][0]["expires_on"]
        with self.assertRaises(Refused) as caught:
            qs.run_gate(run(("test_a", "passed")), ledger_doc=complete)
        self.assertEqual(caught.exception.code, "LEDGER-QUARANTINE-INCOMPLETE")


class ClassificationGateTests(GateCase):
    def test_unknown_classification_fails_closed(self):
        control = qs.run_gate(qs.cases(("test_a", "passed"), ("test_b", "passed")))
        self.assertFindings(control, [], "pass")
        unlisted = qs.identity("synthetic.unlisted.Cases", "test_b")
        report = qs.run_gate([(qs.PLAIN, "test_a", "passed"), ("synthetic.unlisted.Cases", "test_b", "passed")])
        self.assertFindings(report, [("QG-CLASSIFICATION-UNKNOWN", "fail", unlisted)], "fail")
        self.assertEqual(report["retry"]["allowed_reexecutions"], 0)

    def test_ambiguous_classification_fails_closed(self):
        manifest = qs.manifest_document()
        manifest["rules"].append({"id": "PT-006", "field": "suite", "kind": "package", "value": "synthetic",
                                  "package": "infra.tooling", "tags": [], "reason": "Synthetic suite rule"})
        self.assertFindings(qs.run_gate(qs.cases(("test_a", "passed")), manifest_doc=manifest), [], "pass")
        manifest["rules"][-1]["package"] = "infra.synthetic_money"
        report = qs.run_gate(qs.cases(("test_a", "passed")), manifest_doc=manifest)
        self.assertFindings(report, [("QG-CLASSIFICATION-AMBIGUOUS", "fail", A)], "fail")

    def test_quarantined_test_with_unknown_classification_stays_gating(self):
        unlisted = qs.identity("synthetic.unlisted.Cases", "test_a")
        events, record = qs.justified(unlisted, -3)
        attempt = [("synthetic.unlisted.Cases", "test_a", "failed")] + FILLER
        report = qs.run_gate(attempt, ledger_doc=qs.ledger_document(events=events, quarantines=[record]))
        self.assertFindings(report, [("QG-CLASSIFICATION-UNKNOWN", "fail", unlisted),
                                     ("QG-REAL-FAILURE", "fail", unlisted)], "fail")


class RetryTests(GateCase):
    FLAKY = (qs.cases(("test_a", "failed"), ("test_b", "passed")), qs.cases(("test_a", "passed")))

    def test_money_path_zero_retries(self):
        # Passing control: a quarantined (unprotected) test fails once on the money-path job, no re-execution.
        ledger = quarantined_a(job=qs.MONEY_JOB)
        first = run(("test_a", "failed"), ("test_b", "passed"))
        control = qs.run_gate(first, job=qs.MONEY_JOB, ledger_doc=ledger)
        self.assertFindings(control, [("QG-QUARANTINED-FAILURE", "report", A)], "pass")
        self.assertEqual((control["retry"]["money_path"], control["retry"]["allowed_reexecutions"]), (True, 0))
        mutated = qs.run_gate(first, qs.cases(("test_a", "passed")), job=qs.MONEY_JOB, ledger_doc=ledger)
        self.assertFindings(mutated, [("QG-RETRY-LIMIT", "fail", None), ("QG-QUARANTINED-FAILURE", "report", A)],
                            "fail")
        # The same attempts on a job that runs no money-path package get the one permitted re-execution.
        self.assertFindings(qs.run_gate(*self.FLAKY, job=qs.JOB), [("QG-FLAKE-EVENT", "fail", A)], "fail")
        report = qs.run_gate(*self.FLAKY, job=qs.MONEY_JOB)
        self.assertFindings(report, [("QG-RETRY-LIMIT", "fail", None), ("QG-REAL-FAILURE", "fail", A)], "fail")
        self.assertEqual(report["retry"], {"money_path": True, "allowed_reexecutions": 0,
                                           "observed_reexecutions": 1, "reexecuted_tests": 1})
        self.assertEqual(report["ledger_delta"]["flake_events"], [])

    def test_money_path_package_in_the_run_forces_zero_retries(self):
        self.assertFindings(qs.run_gate(*self.FLAKY), [("QG-FLAKE-EVENT", "fail", A)], "fail")
        money = qs.identity(qs.MONEY_PATH, "test_m")
        first = self.FLAKY[0] + [(qs.MONEY_PATH, "test_m", "passed")]
        report = qs.run_gate(first, self.FLAKY[1])
        self.assertFindings(report, [("QG-JOB-PACKAGE-UNMAPPED", "fail", money), ("QG-RETRY-LIMIT", "fail", None),
                                     ("QG-REAL-FAILURE", "fail", A)], "fail")
        self.assertTrue(report["retry"]["money_path"])

    def test_retry_boundary_one_versus_two_reexecutions(self):
        # Passing control: one re-execution of a quarantined test; the mutation adds a second re-execution.
        attempts = [run(("test_a", "failed"), ("test_b", "passed")), qs.cases(("test_a", "failed"))]
        one = qs.run_gate(*attempts, ledger_doc=quarantined_a())
        self.assertFindings(one, [("QG-QUARANTINED-FAILURE", "report", A)], "pass")
        self.assertEqual(one["retry"]["observed_reexecutions"], 1)
        two = qs.run_gate(*attempts, qs.cases(("test_a", "passed")), ledger_doc=quarantined_a())
        self.assertFindings(two, [("QG-RETRY-LIMIT", "fail", None), ("QG-QUARANTINED-FAILURE", "report", A)], "fail")
        self.assertEqual(two["retry"]["observed_reexecutions"], 2)
        gating = qs.run_gate(self.FLAKY[0], qs.cases(("test_a", "failed")), qs.cases(("test_a", "passed")))
        self.assertFindings(gating, [("QG-RETRY-LIMIT", "fail", None), ("QG-REAL-FAILURE", "fail", A)], "fail")


class QuarantinedTestTests(GateCase):
    def test_quarantined_test_still_runs_and_is_reported(self):
        failing = run(("test_a", "failed"), ("test_b", "passed"))
        self.assertFindings(qs.run_gate(failing), [("QG-REAL-FAILURE", "fail", A)], "fail")
        report = qs.run_gate(failing, ledger_doc=quarantined_a())
        self.assertFindings(report, [("QG-QUARANTINED-FAILURE", "report", A)], "pass")
        self.assertEqual(report["quarantined_tests"], [{
            "test": A, "job": qs.JOB, "owner": qs.OWNER, "ticket_ref": qs.TICKET, "quarantined_on": qs.day(-3),
            "expires_on": qs.day(11), "age_days": 3, "outcome": "failed", "exempt": True,
        }])
        self.assertEqual(report["counts"]["failed"], 1)
        flaky = qs.run_gate(failing, qs.cases(("test_a", "passed")), ledger_doc=quarantined_a())
        self.assertFindings(flaky, [("QG-QUARANTINED-FLAKE", "report", A)], "pass")
        self.assertEqual([event["test"] for event in flaky["ledger_delta"]["flake_events"]], [A])

    def test_quarantined_test_skipped_fails(self):
        self.assertFindings(qs.run_gate(run(("test_a", "passed"), ("test_b", "passed")), ledger_doc=quarantined_a()),
                            [], "pass")
        report = qs.run_gate(run(("test_a", "skipped"), ("test_b", "passed")), ledger_doc=quarantined_a())
        self.assertFindings(report, [("QG-QUARANTINED-NOT-RUN", "fail", A)], "fail")

    def test_quarantined_test_disappearance_fails(self):
        self.assertFindings(qs.run_gate(run(("test_a", "passed"), ("test_b", "passed")), ledger_doc=quarantined_a()),
                            [], "pass")
        report = qs.run_gate(run(("test_b", "passed")), ledger_doc=quarantined_a())
        self.assertFindings(report, [("QG-QUARANTINED-TEST-MISSING", "fail", A)], "fail")
        self.assertEqual(report["quarantined_tests"][0]["outcome"], "missing")

    def test_approved_deletion_record_allows_the_test_to_disappear(self):
        deleted = quarantined_a()
        deleted["deletions"].append(qs.deletion(A, -1))
        self.assertFindings(qs.run_gate(run(("test_b", "passed")), ledger_doc=deleted), [], "pass")

    def test_quarantine_age_boundary_14_versus_15_days(self):
        ledger = quarantined_a(start=-14, expires_after=14)
        attempt = run(("test_a", "passed"), ("test_b", "passed"))
        at_limit = qs.run_gate(attempt, ledger_doc=ledger)
        self.assertFindings(at_limit, [], "pass")
        self.assertEqual(at_limit["quarantined_tests"][0]["age_days"], 14)
        over = qs.run_gate(attempt, ledger_doc=ledger, today=qs.TODAY + datetime.timedelta(days=1))
        self.assertFindings(over, [("QG-QUARANTINE-AGE", "fail", A)], "fail")
        self.assertEqual(over["quarantined_tests"][0]["age_days"], 15)

    def test_quarantine_expiry_boundary(self):
        ledger = quarantined_a(start=-7, expires_after=7)
        attempt = run(("test_a", "passed"), ("test_b", "passed"))
        self.assertFindings(qs.run_gate(attempt, ledger_doc=ledger), [], "pass")
        report = qs.run_gate(attempt, ledger_doc=ledger, today=qs.TODAY + datetime.timedelta(days=1))
        self.assertFindings(report, [("QG-QUARANTINE-EXPIRED", "fail", A)], "fail")

    def test_released_quarantine_returns_the_test_to_the_gating_set(self):
        released = quarantined_a()
        released["releases"].append(qs.release(A, -1))
        failing = run(("test_a", "failed"), ("test_b", "passed"))
        self.assertFindings(qs.run_gate(failing, ledger_doc=quarantined_a()),
                            [("QG-QUARANTINED-FAILURE", "report", A)], "pass")
        self.assertFindings(qs.run_gate(failing, ledger_doc=released), [("QG-REAL-FAILURE", "fail", A)], "fail")


    def test_released_test_cannot_disappear_in_the_releasing_change(self):
        # Review round 1, PS-3 / ADVSEC-R1-03: a release needs no approval, so it must not bypass the deletion rule.
        released = quarantined_a()
        released["releases"].append(qs.release(A, -1))
        base = quarantined_a()
        self.assertFindings(qs.run_gate(run(("test_a", "passed")), ledger_doc=released, base_doc=base), [], "pass")
        report = qs.run_gate(run(("test_b", "passed")), ledger_doc=released, base_doc=base)
        self.assertFindings(report, [("QG-RELEASED-TEST-MISSING", "fail", A)], "fail")

    def test_released_test_skipped_in_the_releasing_change_fails(self):
        released = quarantined_a()
        released["releases"].append(qs.release(A, -1))
        report = qs.run_gate(run(("test_a", "skipped")), ledger_doc=released, base_doc=quarantined_a())
        self.assertFindings(report, [("QG-RELEASED-TEST-MISSING", "fail", A)], "fail")

    def test_released_test_may_disappear_in_a_later_change(self):
        # Review round 2, PS-3: a release already in the base ledger no longer holds the test (no approval path
        # exists for a released test); only the releasing change must still run it.
        released = quarantined_a(start=-10)
        released["releases"].append(qs.release(A, -5))
        self.assertFindings(qs.run_gate(run(("test_b", "passed")), ledger_doc=released, base_doc=released), [], "pass")
        report = qs.run_gate(run(("test_b", "passed")), ledger_doc=released, base_doc=quarantined_a(start=-10))
        self.assertFindings(report, [("QG-RELEASED-TEST-MISSING", "fail", A), ("QG-CLOSURE-BACKDATED", "fail", A)],
                            "fail")

    def test_closure_appended_in_this_change_must_be_recent(self):
        # Review round 2, ADVSEC-R2-01: a backdated release must not end the hold or reuse evidence.
        expired = quarantined_a(start=-20)
        for offset, expected in ((-gate.CLOSURE_DATE_TOLERANCE_DAYS, []),
                                 (-gate.CLOSURE_DATE_TOLERANCE_DAYS - 1, [("QG-CLOSURE-BACKDATED", "fail", A)])):
            with self.subTest(offset=offset):
                head = copy.deepcopy(expired)
                head["releases"].append(qs.release(A, offset))
                self.assertFindings(qs.run_gate(run(("test_a", "passed")), ledger_doc=head, base_doc=expired),
                                    expected, "fail" if expected else "pass")
        deleted = copy.deepcopy(expired)
        deleted["deletions"].append(qs.deletion(A, -15))
        self.assertFindings(qs.run_gate(run(("test_b", "passed")), ledger_doc=deleted, base_doc=expired),
                            [("QG-CLOSURE-BACKDATED", "fail", A)], "fail")

    def test_deletion_after_release_requarantine_allows_disappearance(self):
        ledger = quarantined_a(start=-10)
        ledger["releases"].append(qs.release(A, -9))
        ledger["flake_events"] += [qs.event(A, -3, run="synthetic-again"), qs.event(A, -3, run="synthetic-twice")]
        ledger["quarantines"].append(qs.quarantine(A, -3, ticket=qs.OTHER_TICKET))
        ledger["deletions"].append(qs.deletion(A, -1, ticket=qs.OTHER_TICKET,
                                               approval=qs.APPROVAL.replace("/900001#", "/900002#")))
        self.assertFindings(qs.run_gate(run(("test_b", "passed")), ledger_doc=ledger), [], "pass")


class NothingRanTests(GateCase):
    def test_all_skipped_first_attempt_fails(self):
        # Review round 1, ADVSEC-R1-10: a report in which nothing ran is not a pass.
        self.assertFindings(qs.run_gate(qs.cases(("test_a", "passed"), ("test_b", "skipped"))), [], "pass")
        report = qs.run_gate(qs.cases(("test_a", "skipped"), ("test_b", "skipped")))
        self.assertFindings(report, [("QG-NOTHING-RAN", "fail", None)], "fail")

    def test_only_exempt_quarantined_tests_ran_fails(self):
        # Review round 2, ADVSEC-R2-05: exempt tests running do not make a gating run.
        control = qs.run_gate(qs.cases(("test_a", "failed"), ("test_b", "passed"), ("test_c", "skipped")),
                              ledger_doc=quarantined_a(start=-1))
        self.assertFindings(control, [("QG-QUARANTINED-FAILURE", "report", A)], "pass")
        report = qs.run_gate(qs.cases(("test_a", "failed"), ("test_b", "skipped"), ("test_c", "skipped")),
                             ledger_doc=quarantined_a(start=-1))
        self.assertFindings(report, [("QG-QUARANTINED-FAILURE", "report", A), ("QG-NOTHING-RAN", "fail", None)], "fail")


class LedgerInputTests(GateCase):
    def test_ledger_not_append_only_fails(self):
        base = qs.ledger_document(events=[qs.event(A, -1)])
        attempt = qs.cases(("test_a", "passed"))
        self.assertFindings(qs.run_gate(attempt, ledger_doc=base, base_doc=base), [], "pass")
        report = qs.run_gate(attempt, ledger_doc=qs.ledger_document(), base_doc=base)
        self.assertFindings(report, [("QG-LEDGER-NOT-APPEND-ONLY", "fail", None)], "fail")
        self.assertIsNotNone(report["inputs"]["base_ledger_sha256"])

    def test_missing_base_ledger_or_base_manifest_fails(self):
        # Review round 1, ADVSEC-R1-05 / ADVSEC-R1-04: append-only and no-relaxation hold by default.
        attempt = qs.cases(("test_a", "passed"))
        self.assertFindings(qs.run_gate(attempt), [], "pass")
        self.assertFindings(qs.run_gate(attempt, base_doc=None), [("QG-LEDGER-BASE-MISSING", "fail", None)], "fail")
        self.assertFindings(qs.run_gate(attempt, base_manifest_doc=None),
                            [("QG-MANIFEST-BASE-MISSING", "fail", None)], "fail")

    def test_manifest_relaxed_in_the_same_change_fails(self):
        # Review round 1, ADVSEC-R1-04: removing a protected tag must not let its test be quarantined.
        security = qs.identity(qs.SECURITY, "test_rejects_untrusted")
        attempt = [(qs.SECURITY, "test_rejects_untrusted", "passed")] + list(FILLER)
        self.assertFindings(qs.run_gate(attempt), [], "pass")
        relaxed = qs.manifest_document()
        relaxed["rules"][1]["tags"] = []
        report = qs.run_gate(attempt, manifest_doc=relaxed, base_manifest_doc=qs.manifest_document())
        self.assertFindings(report, [("QG-MANIFEST-RELAXED", "fail", security)], "fail")

    def test_money_path_job_relaxed_in_the_same_change_fails(self):
        attempt = qs.cases(("test_a", "passed"))
        self.assertFindings(qs.run_gate(attempt, job=qs.MONEY_JOB), [], "pass")
        relaxed = qs.manifest_document()
        relaxed["jobs"][1]["packages"] = ["infra.tooling"]
        report = qs.run_gate(attempt, job=qs.MONEY_JOB, manifest_doc=relaxed, base_manifest_doc=qs.manifest_document())
        self.assertFindings(report, [("QG-MANIFEST-RELAXED", "fail", None)], "fail")

    def test_reused_run_id_and_unknown_job_refused(self):
        ledger = qs.ledger_document(events=[qs.event(A, -1, run="synthetic-history-used")])
        attempt = qs.cases(("test_a", "passed"))
        self.assertEqual(qs.run_gate(attempt, ledger_doc=ledger)["decision"], "pass")
        for code, options in (("INPUT-RUN-ID-REUSED", {"run_id": "synthetic-history-used"}),
                              ("MANIFEST-UNKNOWN-JOB", {"job": "synthetic-unknown-job"})):
            with self.subTest(code=code):
                with self.assertRaises(Refused) as caught:
                    qs.run_gate(attempt, ledger_doc=ledger, **options)
                self.assertEqual(caught.exception.code, code)

    def test_evaluate_validates_run_id_clock_and_job(self):
        attempt = qs.cases(("test_a", "passed"))
        self.assertEqual(qs.run_gate(attempt)["decision"], "pass")
        for code, options in (
            ("INPUT-RUN-ID", {"run_id": "synthetic run"}), ("INPUT-RUN-ID", {"run_id": None}),
            ("INPUT-CLOCK", {"today": datetime.datetime(2026, 3, 16, tzinfo=datetime.timezone.utc)}),
            ("MANIFEST-UNKNOWN-JOB", {"job": ["synthetic-job"]}),
        ):
            with self.subTest(code=code, options=sorted(options)):
                policy, manifest, ledger = qs.parse_inputs()
                arguments = {"policy": policy, "manifest": manifest, "ledger": ledger, "job_id": qs.JOB,
                             "run_id": qs.RUN, "today": qs.TODAY, "ticket_port": qs.FakeTicketPort(),
                             "attempts": [qs.junit.parse_attempt(qs.junit_xml(attempt))]}
                arguments.update({"job_id" if key == "job" else key: value for key, value in options.items()})
                with self.assertRaises(Refused) as caught:
                    gate.evaluate(**arguments)
                self.assertEqual(caught.exception.code, code)

    def test_report_is_deterministic_and_carries_no_message_text(self):
        attempts = (qs.cases(("test_a", "failed"), ("test_b", "passed")), qs.cases(("test_a", "passed")))
        first = json.dumps(qs.run_gate(*attempts), sort_keys=True)
        self.assertEqual(first, json.dumps(qs.run_gate(*attempts), sort_keys=True))
        for planted in ("synthetic failure", "synthetic trace", "AssertionError"):
            self.assertNotIn(planted, first)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pennilogic-qa-gate-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def write(self, name, data):
        path = self.directory / name
        path.write_bytes(data)
        return str(path)

    def main(self, argv, port=None):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = gate.main(argv, clock=lambda: qs.TODAY, ticket_port=port)
        self.assertEqual(stderr.getvalue(), "")
        output = stdout.getvalue()
        self.assertTrue(output.isascii())
        self.assertEqual(output.count("\n"), 1)
        return code, json.loads(output)

    def synthetic_argv(self, *extra, attempts=None):
        manifest = self.write("manifest.json", qs.encode(qs.manifest_document()))
        ledger = self.write("ledger.json", qs.encode(qs.ledger_document()))
        if attempts is None:
            attempts = [self.write("attempt-1.xml", qs.junit_xml(qs.cases(("test_a", "passed"))))]
        argv = ["--job", qs.JOB, "--run-id", qs.RUN, "--manifest", manifest, "--ledger", ledger,
                "--base-ledger", ledger, "--base-manifest", manifest]
        for path in attempts:
            argv += ["--attempt", path]
        return argv + list(extra)

    def test_cli_missing_input_exit_nonzero(self):
        code, report = self.main(self.synthetic_argv())
        self.assertEqual((code, report["decision"]), (0, "pass"))
        missing = str(self.directory / "absent.xml")
        cases = (
            ("USAGE", [arg for arg in self.synthetic_argv() if arg != "--attempt" and not arg.endswith(".xml")]),
            ("USAGE", self.synthetic_argv("--unexpected")),
            ("INPUT-UNREADABLE", self.synthetic_argv(attempts=[missing])),
            ("INPUT-UNREADABLE", self.synthetic_argv(attempts=[str(self.directory)])),
            ("LEDGER-UNREADABLE", self.synthetic_argv("--ledger", missing)),
            ("MANIFEST-UNREADABLE", self.synthetic_argv("--manifest", missing)),
            ("LEDGER-UNREADABLE", self.synthetic_argv("--base-ledger", missing)),
        )
        for code_name, argv in cases:
            with self.subTest(code=code_name, argv=len(argv)):
                code, report = self.main(argv)
                self.assertEqual((code, report), (2, {"schema": gate.REPORT_SCHEMA, "decision": "refused",
                                                      "reason": code_name, "test": None}))

    def test_cli_refuses_malformed_arguments(self):
        self.assertEqual(self.main(self.synthetic_argv())[0], 0)
        attempt = self.write("attempt-x.xml", qs.junit_xml(qs.cases(("test_a", "passed"))))
        for code_name, argv in (
            ("INPUT-RUN-ID", [arg if arg != qs.RUN else "bad run id" for arg in self.synthetic_argv()]),
            ("USAGE", self.synthetic_argv("--fix-only", qs.TICKET)),
            ("USAGE", self.synthetic_argv("--help")),
            ("USAGE", self.synthetic_argv("-h")),
            ("INPUT-ATTEMPTS", self.synthetic_argv(attempts=[attempt] * (gate.MAX_ATTEMPTS + 1))),
        ):
            with self.subTest(code=code_name):
                code, report = self.main(argv)
                self.assertEqual((code, report["reason"]), (2, code_name))

    def test_cli_failing_run_exits_one_and_refused_input_names_only_a_validated_test(self):
        flaky = [self.write("a1.xml", qs.junit_xml(qs.cases(("test_a", "failed"), ("test_b", "passed")))),
                 self.write("a2.xml", qs.junit_xml(qs.cases(("test_a", "passed"))))]
        code, report = self.main(self.synthetic_argv(attempts=flaky))
        self.assertEqual((code, report["decision"]), (1, "fail"))
        self.assertEqual(report["findings"], [{"rule": "QG-FLAKE-EVENT", "effect": "fail", "test": A}])
        duplicate = [self.write("dup.xml", qs.junit_xml(qs.cases(("test_a", "passed"), ("test_a", "passed"))))]
        code, report = self.main(self.synthetic_argv(attempts=duplicate))
        self.assertEqual((code, report["reason"], report["test"]), (2, "JUNIT-DUPLICATE-CASE", A))

    def test_cli_defaults_to_the_committed_manifest_and_ledger(self):
        infra_cases = [("test_integration_stack.StackLifecycleTests", "test_x", "passed"),
                       ("test_bootstrap.EnvFileTests", "test_y", "passed")]
        attempt = self.write("infra.xml", qs.junit_xml(infra_cases, suite="unittest"))
        committed = ["--base-ledger", str(ledgers.LEDGER_FILE), "--base-manifest", str(tags.MANIFEST_FILE)]
        code, report = self.main(["--job", "infra-ci-linux", "--run-id", "synthetic-infra-run", "--attempt", attempt,
                                  *committed])
        self.assertEqual((code, report["decision"], report["findings"]), (0, "pass", []))
        self.assertEqual(report["inputs"]["manifest_sha256"],
                         hashlib.sha256(tags.MANIFEST_FILE.read_bytes()).hexdigest())
        self.assertEqual(report["inputs"]["ledger_sha256"], hashlib.sha256(ledgers.LEDGER_FILE.read_bytes()).hexdigest())
        self.assertEqual((report["inputs"]["manifest_status"], report["inputs"]["ticket_creation"]), ("proposed", "held"))

    def test_cli_held_ticket_port_leaves_the_threshold_visibly_incomplete(self):
        test = "unittest::test_integration_stack.StackLifecycleTests::test_x"
        ledger = self.write("history.json", qs.encode({
            "schema": ledgers.SCHEMA, "repository": "PenniLogic/infra",
            "flake_events": [{"test": test, "job": "infra-ci-linux", "run_id": "synthetic-history",
                              "observed_on": qs.day(-1)}],
            "quarantines": [], "releases": [], "deletions": [],
        }))
        first = [("test_integration_stack.StackLifecycleTests", "test_x", "failed"),
                 ("test_bootstrap.EnvFileTests", "test_y", "passed")]
        attempts = [self.write("i1.xml", qs.junit_xml(first, suite="unittest")),
                    self.write("i2.xml", qs.junit_xml([(first[0][0], "test_x", "passed")], suite="unittest"))]
        argv = ["--job", "infra-ci-linux", "--run-id", "synthetic-infra-run", "--ledger", ledger,
                "--base-ledger", ledger, "--base-manifest", str(tags.MANIFEST_FILE)]
        for path in attempts:
            argv += ["--attempt", path]
        code, report = self.main(argv, port=qs.FakeTicketPort())
        self.assertEqual((code, report["ledger_delta"]["quarantines"][0]["ticket_ref"]), (1, qs.TICKET))
        code, report = self.main(argv)
        self.assertEqual((code, report["inputs"]["ticket_creation"]), (1, "held"))
        self.assertEqual({(finding["rule"], finding["test"]) for finding in report["findings"]},
                         {("QG-FLAKE-EVENT", test), ("QG-QUARANTINE-TICKET-MISSING", test)})
        self.assertEqual(report["ledger_delta"]["quarantines"], [])


if __name__ == "__main__":
    unittest.main()
