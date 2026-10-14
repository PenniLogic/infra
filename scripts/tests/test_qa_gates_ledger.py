"""Quarantine ledger: append-only facts, complete quarantines, approved deletions (PenniLogic/infra#28).

Each negative has a passing control and exactly one mutation, and asserts the exact static refusal code.
"""

import copy
import unittest

import qa_gates_support as qs
import qa_gates_ledger as ledgers
import qa_gates_tags as tags
from qa_gates_common import Refused


TEST = qs.identity()


def parse(document, today=qs.TODAY):
    return qs.parse_inputs(ledger_doc=document, today=today)[2]


def quarantined_ledger(**options):
    events, record = qs.justified(TEST, -3, **options)
    return qs.ledger_document(events=events, quarantines=[record])


class LedgerCase(unittest.TestCase):
    def assertRefused(self, code, document, test=None, today=qs.TODAY):
        with self.assertRaises(Refused) as caught:
            parse(document, today)
        self.assertEqual((caught.exception.code, caught.exception.test), (code, test))


class CommittedLedgerTests(LedgerCase):
    def test_committed_ledger_is_valid_and_empty(self):
        policy = qs.parse_inputs()[0]
        committed = ledgers.load_ledger(ledgers.LEDGER_FILE, manifest=tags.load_manifest(), policy=policy,
                                        today=qs.TODAY)
        self.assertEqual((committed.repository, committed.events, committed.quarantines, committed.active),
                         ("PenniLogic/infra", (), (), {}))
        self.assertEqual(ledgers.LEDGER_FILE.read_bytes(), qs.encode(committed.document))

    def test_committed_manifest_admits_no_deletion_by_its_only_user(self):
        # Review round 3, PS-2: pins the disclosed effect of the proposed approver-distinctness control. Every
        # committed package owner is @basiltt, the organization's only GitHub user, so a deletion approved by that
        # handle (any case) is refused while one by another handle is accepted. Changing this is a held decision.
        policy, manifest = qs.parse_inputs()[0], tags.load_manifest()
        test = "scripts.tests::test_api_build_coverage.Cases::test_x"
        self.assertEqual({package.owner for package in manifest.packages.values()}, {"@basiltt"})
        job = sorted(manifest.jobs)[0]
        events, record = qs.justified(test, -5, owner="@basiltt", job=job)

        def ledger(approver):
            deletion = qs.deletion(test, 0, job=job, approver=approver)
            return qs.encode(qs.ledger_document(events, [record], deletions=[deletion]))

        ledgers.parse_ledger(ledger("@synthetic-reviewer"), manifest=manifest, policy=policy, today=qs.TODAY)
        for approver in ("@basiltt", "@BasilTT"):
            with self.subTest(approver=approver):
                with self.assertRaises(Refused) as caught:
                    ledgers.parse_ledger(ledger(approver), manifest=manifest, policy=policy, today=qs.TODAY)
                self.assertEqual((caught.exception.code, caught.exception.test), ("LEDGER-SELF-APPROVAL", test))


class QuarantineRecordTests(LedgerCase):
    def test_quarantine_without_owner_ticket_or_expiry_refused(self):
        document = quarantined_ledger()
        self.assertEqual(set(parse(document).active), {(qs.JOB, TEST)})
        for key in ("owner", "ticket_ref", "expires_on"):
            for change in ("null", "empty", "missing"):
                with self.subTest(key=key, change=change):
                    mutated = copy.deepcopy(document)
                    if change == "missing":
                        del mutated["quarantines"][0][key]
                    else:
                        mutated["quarantines"][0][key] = None if change == "null" else ""
                    self.assertRefused("LEDGER-QUARANTINE-INCOMPLETE", mutated)

    def test_expiry_is_bounded_by_the_maximum_age(self):
        events, record = qs.justified(TEST, -3, expires_after=14)
        parse(qs.ledger_document(events=events, quarantines=[record]))
        for label, expires_after in (("beyond-max-age", 15), ("before-start", -1)):
            with self.subTest(label=label):
                events, record = qs.justified(TEST, -3, expires_after=expires_after)
                self.assertRefused("LEDGER-EXPIRY", qs.ledger_document(events=events, quarantines=[record]))

    def test_quarantine_needs_recorded_flake_events_within_the_window(self):
        record = qs.quarantine(TEST, -2)
        inside = [qs.event(TEST, -16, run="synthetic-old"), qs.event(TEST, -2, run="synthetic-new")]
        parse(qs.ledger_document(events=inside, quarantines=[record]))
        outside = [qs.event(TEST, -17, run="synthetic-old"), qs.event(TEST, -2, run="synthetic-new")]
        self.assertRefused("LEDGER-QUARANTINE-UNJUSTIFIED",
                           qs.ledger_document(events=outside, quarantines=[record]), TEST)
        after = [qs.event(TEST, -2, run="synthetic-new"), qs.event(TEST, -1, run="synthetic-later")]
        self.assertRefused("LEDGER-QUARANTINE-UNJUSTIFIED",
                           qs.ledger_document(events=after, quarantines=[record]), TEST)

    def test_events_from_another_job_justify_the_same_test(self):
        record = qs.quarantine(TEST, -2)
        events = [qs.event(TEST, -3, job=qs.MONEY_JOB, run="synthetic-other"), qs.event(TEST, -2, run="synthetic-own")]
        self.assertIn((qs.JOB, TEST), parse(qs.ledger_document(events=events, quarantines=[record])).active)

    def test_overlapping_quarantines_refused(self):
        document = quarantined_ledger()
        document["releases"].append(qs.release(TEST, -2))
        document["quarantines"].append(qs.quarantine(TEST, -1, ticket=qs.OTHER_TICKET))
        document["flake_events"] += [qs.event(TEST, -1, run="synthetic-again"), qs.event(TEST, -1, run="synthetic-twice")]
        self.assertEqual(parse(document).active[(qs.JOB, TEST)].ticket_ref, qs.OTHER_TICKET)
        document["releases"] = []
        self.assertRefused("LEDGER-OVERLAP", document, TEST)

    def test_same_day_requarantine_after_release_overlaps(self):
        document = quarantined_ledger()
        document["releases"].append(qs.release(TEST, -2))
        document["quarantines"].append(qs.quarantine(TEST, -1, ticket=qs.OTHER_TICKET))
        document["flake_events"] += [qs.event(TEST, -1, run="synthetic-again"), qs.event(TEST, -1, run="synthetic-twice")]
        parse(document)
        document["releases"][0]["released_on"] = qs.day(-1)
        self.assertRefused("LEDGER-OVERLAP", document, TEST)


    def test_events_before_a_release_do_not_justify_a_new_quarantine(self):
        # Review round 1, ADVSEC-R1-06: pre-release events must not stretch the 14-day maximum to about 28 days.
        events = [qs.event(TEST, -27, run="synthetic-runA"), qs.event(TEST, -27, run="synthetic-runB")]
        fresh = [qs.event(TEST, -13, run="synthetic-runC"), qs.event(TEST, -13, run="synthetic-runD")]
        second = qs.quarantine(TEST, -13, ticket=qs.OTHER_TICKET)
        control = qs.ledger_document(events + fresh, [qs.quarantine(TEST, -27), second], [qs.release(TEST, -14)])
        parse(control)
        mutated = qs.ledger_document(events + fresh[:1], [qs.quarantine(TEST, -27), second], [qs.release(TEST, -14)])
        mutated["flake_events"].append(qs.event(TEST, -14, run="synthetic-runD"))
        self.assertRefused("LEDGER-QUARANTINE-UNJUSTIFIED", mutated, TEST)

    def test_events_before_a_closure_in_another_job_do_not_justify(self):
        # Review round 2, ADVSEC-R2-06: the post-closure rule is per test, across jobs.
        events = [qs.event(TEST, -27, run="synthetic-runA"), qs.event(TEST, -27, run="synthetic-runB")]
        fresh = [qs.event(TEST, -13, run="synthetic-runC"), qs.event(TEST, -13, run="synthetic-runD")]
        second = qs.quarantine(TEST, -13, job=qs.MONEY_JOB, ticket=qs.OTHER_TICKET)
        parse(qs.ledger_document(events + fresh, [qs.quarantine(TEST, -27), second], [qs.release(TEST, -14)]))
        mutated = qs.ledger_document(events, [qs.quarantine(TEST, -27), second], [qs.release(TEST, -14)])
        self.assertRefused("LEDGER-QUARANTINE-UNJUSTIFIED", mutated, TEST)

    def test_quarantine_on_a_closure_day_in_another_job_is_not_justified_by_earlier_events(self):
        # Review round 3, PS-5: a closure on the quarantine's first day counts, in any job.
        events = [qs.event(TEST, -11, run="synthetic-runA"), qs.event(TEST, -10, run="synthetic-runB")]
        for start, accepted in ((-3, True), (-2, False)):
            with self.subTest(start=start):
                document = qs.ledger_document(events, [qs.quarantine(TEST, -10),
                                                       qs.quarantine(TEST, start, job=qs.MONEY_JOB,
                                                                     ticket=qs.OTHER_TICKET)],
                                              [qs.release(TEST, -2)])
                if accepted:
                    parse(document)
                else:
                    self.assertRefused("LEDGER-QUARANTINE-UNJUSTIFIED", document, TEST)


class ClosureTests(LedgerCase):
    def test_release_closes_only_the_matching_active_quarantine(self):
        document = quarantined_ledger()
        document["releases"].append(qs.release(TEST, -1))
        self.assertEqual(parse(document).active, {})
        for label, change in (
            ("other-ticket", lambda record: record.update(ticket_ref=qs.OTHER_TICKET)),
            ("before-start", lambda record: record.update(released_on=qs.day(-4))),
            ("other-job", lambda record: record.update(job=qs.MONEY_JOB)),
        ):
            with self.subTest(label=label):
                mutated = copy.deepcopy(document)
                change(mutated["releases"][0])
                self.assertRefused("LEDGER-CLOSURE-UNMATCHED", mutated, TEST)

    def test_deletion_requires_reviewer_approval_on_the_owning_ticket(self):
        document = quarantined_ledger()
        document["deletions"].append(qs.deletion(TEST, -1))
        self.assertEqual(parse(document).active, {})
        for key in ("approval_ref", "approved_by"):
            for change in ("null", "missing"):
                with self.subTest(key=key, change=change):
                    mutated = copy.deepcopy(document)
                    if change == "missing":
                        del mutated["deletions"][0][key]
                    else:
                        mutated["deletions"][0][key] = None
                    self.assertRefused("LEDGER-DELETION-UNAPPROVED", mutated)
        other_issue = copy.deepcopy(document)
        other_issue["deletions"][0]["approval_ref"] = qs.APPROVAL.replace("/900001#", "/900002#")
        self.assertRefused("LEDGER-APPROVAL", other_issue)
        for approver in (qs.OWNER, qs.OWNER.upper()):
            with self.subTest(approver=approver):
                self_approved = copy.deepcopy(document)
                self_approved["deletions"][0]["approved_by"] = approver
                self.assertRefused("LEDGER-SELF-APPROVAL", self_approved, TEST)

    def test_package_owner_cannot_approve_when_someone_else_is_named_owner(self):
        # Review round 2, ADVSEC-R2-07: the quarantine owner is free text; the package owner still may not approve.
        events, record = qs.justified(TEST, -3, owner="@synthetic-other")
        parse(qs.ledger_document(events=events, quarantines=[record], deletions=[qs.deletion(TEST, -1)]))
        mutated = qs.ledger_document(events=events, quarantines=[record],
                                     deletions=[qs.deletion(TEST, -1, approver=qs.OWNER.upper())])
        self.assertRefused("LEDGER-SELF-APPROVAL", mutated, TEST)


class RecordTests(LedgerCase):
    def test_record_refusals(self):
        document = quarantined_ledger()
        parse(document)
        cases = (
            ("LEDGER-UNKNOWN-JOB", lambda doc: doc["flake_events"][0].update(job="synthetic-unknown")),
            ("LEDGER-FUTURE-DATE", lambda doc: doc["flake_events"][0].update(observed_on=qs.day(1))),
            ("LEDGER-DUPLICATE", lambda doc: doc["flake_events"].append(dict(doc["flake_events"][0]))),
            ("LEDGER-VALUE", lambda doc: doc["flake_events"][0].update(test="synthetic.suite::only-two")),
            ("LEDGER-VALUE", lambda doc: doc["flake_events"][0].update(observed_on="2026-02-30")),
            ("LEDGER-VALUE", lambda doc: doc["quarantines"][0].update(ticket_ref="infra#28")),
            ("LEDGER-VALUE", lambda doc: doc["quarantines"][0].update(owner="synthetic-owner")),
            ("LEDGER-KEYS", lambda doc: doc["flake_events"][0].update(note="synthetic")),
            ("LEDGER-KEYS", lambda doc: doc.update(note="synthetic")),
            ("LEDGER-SCHEMA", lambda doc: doc.update(schema="pennilogic.qa-gates.quarantine-ledger/2")),
            ("LEDGER-REPOSITORY", lambda doc: doc.update(repository="PenniLogic/docs")),
        )
        for index, (code, change) in enumerate(cases):
            with self.subTest(index=index, code=code):
                mutated = copy.deepcopy(document)
                change(mutated)
                self.assertRefused(code, mutated)

    def test_strict_json_refusals(self):
        policy, manifest, _ = qs.parse_inputs()
        data = qs.encode(qs.ledger_document())
        ledgers.parse_ledger(data, manifest=manifest, policy=policy, today=qs.TODAY)
        for code, mutated in (("LEDGER-JSON", data.replace(b'"deletions": []', b'"deletions": [], "deletions": []')),
                              ("LEDGER-SIZE", b"")):
            with self.subTest(code=code):
                with self.assertRaises(Refused) as caught:
                    ledgers.parse_ledger(mutated, manifest=manifest, policy=policy, today=qs.TODAY)
                self.assertEqual(caught.exception.code, code)


class AppendOnlyTests(unittest.TestCase):
    def test_base_arrays_must_be_unchanged_prefixes(self):
        base = parse(quarantined_ledger())
        grown = quarantined_ledger()
        grown["flake_events"].append(qs.event(qs.identity(name="test_other"), -1, run="synthetic-appended"))
        self.assertTrue(ledgers.is_append_only(base, parse(grown)))
        for label, change in (
            ("removed", lambda doc: doc["quarantines"].clear()),
            ("edited", lambda doc: doc["quarantines"][0].update(expires_on=qs.day(-1))),
            ("reordered", lambda doc: doc["flake_events"].reverse()),
        ):
            with self.subTest(label=label):
                mutated = quarantined_ledger()
                change(mutated)
                self.assertFalse(ledgers.is_append_only(base, parse(mutated)))


if __name__ == "__main__":
    unittest.main()
