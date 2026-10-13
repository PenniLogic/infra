"""Quarantine ledger for the infra#28 gate: a committed, append-only fact log changed only by reviewed PRs.

Facts are never edited or removed; new facts are appended to `flake_events`, `quarantines`, `releases` (the
test was fixed) and `deletions` (the test was deleted with recorded reviewer approval on its owning ticket).
Every record names the manifest job it belongs to. A quarantine needs an owner, an owning ticket and an expiry
no later than the policy's maximum age, and it must be justified by the policy's number of recorded flake events
of that test within the flake window ending on its first day and after the last closure of that test in any job
(`basis`, also used by the gate's proposal), so a real failure cannot be filed under the flaky label without
recorded flake evidence (E25-F01) and the evidence of a closed quarantine is not reused for another one. Releases and deletions close the active quarantine of the same
job and test with the same ticket; a deletion's approval must be a comment on that ticket by someone other than
the quarantine owner and the test's manifest package owner.
"""

from dataclasses import dataclass
import datetime
import hashlib
from pathlib import Path

from qa_gates_common import (
    APPROVAL, HANDLE, REFERENCE, RUN_ID, Refused, array, date, exact, json_document, pattern, read_bounded,
    split_test_id,
)


LEDGER_FILE = Path(__file__).resolve().parent / "qa-gates" / "quarantine-ledger.json"
LEDGER_LIMIT = 4 * 1024 * 1024
SCHEMA = "pennilogic.qa-gates.quarantine-ledger/1"
DOCUMENT_KEYS = ("schema", "repository", "flake_events", "quarantines", "releases", "deletions")
ARRAYS = ("flake_events", "quarantines", "releases", "deletions")
EVENT_KEYS = ("test", "job", "run_id", "observed_on")
QUARANTINE_KEYS = ("test", "job", "owner", "ticket_ref", "quarantined_on", "expires_on")
RELEASE_KEYS = ("test", "job", "ticket_ref", "fix_ref", "released_on")
DELETION_KEYS = ("test", "job", "ticket_ref", "approval_ref", "approved_by", "approved_on")


@dataclass(frozen=True)
class FlakeEvent:
    test: str
    job: str
    run_id: str
    observed_on: datetime.date


@dataclass(frozen=True)
class Quarantine:
    test: str
    job: str
    owner: str
    ticket_ref: str
    quarantined_on: datetime.date
    expires_on: datetime.date

    def record(self):
        return {
            "test": self.test, "job": self.job, "owner": self.owner, "ticket_ref": self.ticket_ref,
            "quarantined_on": self.quarantined_on.isoformat(), "expires_on": self.expires_on.isoformat(),
        }


@dataclass(frozen=True)
class Ledger:
    repository: str
    events: tuple
    quarantines: tuple
    active: dict
    document: dict
    sha256: str
    events_by_test: dict
    released: dict
    closed_on: dict

    def active_for(self, job):
        """Active quarantines of one job, keyed by test identity."""
        return {test: record for (record_job, test), record in self.active.items() if record_job == job}

    def released_for(self, job):
        """Release dates of tests of one job whose latest closure is a release (not a deletion), by test."""
        return {test: day for (record_job, test), day in self.released.items() if record_job == job}

    def flake_dates(self, test, today, window_days):
        """Dates of the recorded events of ``test`` that would justify a quarantine starting ``today``."""
        return sorted(event.observed_on for event in basis(self.events_by_test.get(test, ()), today, window_days,
                                                           self.closed_on.get(test)))

    def run_ids(self):
        return {event.run_id for event in self.events}


def basis(events, start, window_days, closed_on):
    """The one trigger definition, used by the ledger and by the gate's proposal (review round 2, PS-2).

    Events of the test (any job) dated 0 to ``window_days`` days before ``start`` and, when the test had a
    closure before (release or deletion, in any job; ADVSEC-R2-06), strictly after its last closure. The
    post-closure exclusion is a proposed rule beyond flake_policy (pending QA/Reliability): a closed quarantine's
    evidence is not reused for the next one.
    """
    return [event for event in events if 0 <= (start - event.observed_on).days <= window_days
            and (closed_on is None or event.observed_on > closed_on)]


def _common(record, keys, manifest):
    exact(record, keys, "LEDGER-KEYS")
    split_test_id(record["test"], "LEDGER-VALUE")
    if not isinstance(record["job"], str) or record["job"] not in manifest.jobs:
        raise Refused("LEDGER-UNKNOWN-JOB")


def _day(value, today):
    day = date(value, "LEDGER-VALUE")
    if day > today:
        raise Refused("LEDGER-FUTURE-DATE")
    return day


def _quarantine(record, manifest, policy, today):
    # Missing or empty owner, ticket or expiry is the refusal the policy names, before the generic key check.
    if not isinstance(record, dict) or any(record.get(key) in (None, "") for key in ("owner", "ticket_ref", "expires_on")):
        raise Refused("LEDGER-QUARANTINE-INCOMPLETE")
    _common(record, QUARANTINE_KEYS, manifest)
    pattern(record["owner"], HANDLE, "LEDGER-VALUE")
    pattern(record["ticket_ref"], REFERENCE, "LEDGER-VALUE")
    start = _day(record["quarantined_on"], today)
    expires = date(record["expires_on"], "LEDGER-VALUE")
    if not start <= expires <= start + datetime.timedelta(days=policy.quarantine_max_age_days):
        raise Refused("LEDGER-EXPIRY")
    return Quarantine(record["test"], record["job"], record["owner"], record["ticket_ref"], start, expires)


def _closure(record, keys, manifest):
    _common(record, keys, manifest)
    pattern(record["ticket_ref"], REFERENCE, "LEDGER-VALUE")


def _owners(quarantine, manifest):
    """Lower-case handles that may not approve the deletion: the quarantine owner and the test's package owner."""
    classification = manifest.classify(quarantine.test)
    package_owner = classification.package.owner if classification.state == "known" else None
    return {owner.lower() for owner in (quarantine.owner, package_owner) if owner is not None}


def parse_ledger(data, *, manifest, policy, today):
    document = exact(json_document(data, LEDGER_LIMIT, "LEDGER"), DOCUMENT_KEYS, "LEDGER-KEYS")
    if document["schema"] != SCHEMA:
        raise Refused("LEDGER-SCHEMA")
    if document["repository"] != manifest.repository:
        raise Refused("LEDGER-REPOSITORY")
    for name in ARRAYS:
        array(document[name], "LEDGER-VALUE")

    events, seen, by_test = [], set(), {}
    for record in document["flake_events"]:
        _common(record, EVENT_KEYS, manifest)
        pattern(record["run_id"], RUN_ID, "LEDGER-VALUE")
        event = FlakeEvent(record["test"], record["job"], record["run_id"], _day(record["observed_on"], today))
        if (event.test, event.job, event.run_id) in seen:
            raise Refused("LEDGER-DUPLICATE")
        seen.add((event.test, event.job, event.run_id))
        events.append(event)
        by_test.setdefault(event.test, []).append(event)

    quarantines = [_quarantine(record, manifest, policy, today) for record in document["quarantines"]]

    closures = []
    for record in document["releases"]:
        _closure(record, RELEASE_KEYS, manifest)
        pattern(record["fix_ref"], REFERENCE, "LEDGER-VALUE")
        closures.append((_day(record["released_on"], today), record, None))
    for record in document["deletions"]:
        # A deletion without recorded approval is the refusal the policy names, before the generic key check.
        if not isinstance(record, dict) or any(record.get(key) in (None, "") for key in ("approval_ref", "approved_by")):
            raise Refused("LEDGER-DELETION-UNAPPROVED")
        _closure(record, DELETION_KEYS, manifest)
        approval = pattern(record["approval_ref"], APPROVAL, "LEDGER-VALUE")
        pattern(record["approved_by"], HANDLE, "LEDGER-VALUE")
        if APPROVAL.fullmatch(approval).group(1, 2) != REFERENCE.fullmatch(record["ticket_ref"]).group(1, 2):
            raise Refused("LEDGER-APPROVAL")
        closures.append((_day(record["approved_on"], today), record, record["approved_by"]))

    # Replay per (job, test): quarantines before closures on the same day, so a same-day re-quarantine overlaps.
    timeline = sorted(
        [(quarantine.quarantined_on, 0, index, quarantine) for index, quarantine in enumerate(quarantines)]
        + [(day, 1, index, (record, approver)) for index, (day, record, approver) in enumerate(closures)],
        key=lambda item: item[:3],
    )
    active, released, closed_on = {}, {}, {}
    for day, kind, _index, item in timeline:
        if kind == 0:
            key = (item.job, item.test)
            if key in active:
                raise Refused("LEDGER-OVERLAP", item.test)
            justified = basis(by_test.get(item.test, ()), item.quarantined_on, policy.flake_window_days,
                              closed_on.get(item.test))
            if len(justified) < policy.quarantine_after_flakes:
                raise Refused("LEDGER-QUARANTINE-UNJUSTIFIED", item.test)
            released.pop(key, None)
            active[key] = item
            continue
        record, approver = item
        key = (record["job"], record["test"])
        current = active.get(key)
        if current is None or current.ticket_ref != record["ticket_ref"] or day < current.quarantined_on:
            raise Refused("LEDGER-CLOSURE-UNMATCHED", record["test"])
        # GitHub logins and team slugs are case-insensitive. The quarantine owner is free text, so the approver must
        # also differ from the manifest package owner of the test (review round 2, ADVSEC-R2-07).
        if approver is not None and approver.lower() in _owners(current, manifest):
            raise Refused("LEDGER-SELF-APPROVAL", record["test"])
        del active[key]
        closed_on[record["test"]] = day
        if approver is None:
            released[key] = day
    return Ledger(document["repository"], tuple(events), tuple(quarantines), active, document,
                  hashlib.sha256(data).hexdigest(), {test: tuple(items) for test, items in by_test.items()}, released,
                  closed_on)


def load_ledger(path, *, manifest, policy, today):
    data = read_bounded(path, LEDGER_LIMIT, "LEDGER-UNREADABLE")
    return parse_ledger(data, manifest=manifest, policy=policy, today=today)


def is_append_only(base, current):
    """True when every base array is an unchanged prefix of the current one (nothing edited or removed)."""
    if base.document["schema"] != current.document["schema"] or base.repository != current.repository:
        return False
    return all(current.document[name][:len(base.document[name])] == base.document[name] for name in ARRAYS)
