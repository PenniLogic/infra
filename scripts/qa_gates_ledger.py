"""Quarantine ledger for the infra#28 gate: a committed, append-only fact log changed only by reviewed PRs.

Facts are never edited or removed; new facts are appended to `flake_events`, `quarantines`, `releases` (the
test was fixed) and `deletions` (the test was deleted with recorded reviewer approval on its owning ticket).
Every record names the manifest job it belongs to. A quarantine needs an owner, an owning ticket and an expiry
no later than the policy's maximum age, and it must be justified by the policy's number of recorded flake events
of that test within the flake window ending on its first day and after the last closure of that job and test, so
a real failure cannot be filed under the flaky label without recorded flake evidence (E25-F01) and evidence is never
reused for a second quarantine. Releases and deletions close the active quarantine of the same
job and test with the same ticket; a deletion's approval must be a comment on that ticket by someone other than
the quarantine owner.
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

    def active_for(self, job):
        """Active quarantines of one job, keyed by test identity."""
        return {test: record for (record_job, test), record in self.active.items() if record_job == job}

    def released_for(self, job):
        """Release dates of tests of one job whose latest closure is a release (not a deletion), by test."""
        return {test: day for (record_job, test), day in self.released.items() if record_job == job}

    def flake_dates(self, test, today, window_days):
        """Dates of recorded events of ``test`` (any job) that are 0 to ``window_days`` days old."""
        return sorted(event.observed_on for event in self.events_by_test.get(test, ())
                      if 0 <= (today - event.observed_on).days <= window_days)

    def run_ids(self):
        return {event.run_id for event in self.events}


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
            # Only events after the last closure of this job and test justify a new quarantine (no reuse).
            basis = [event for event in by_test.get(item.test, ())
                     if 0 <= (item.quarantined_on - event.observed_on).days <= policy.flake_window_days
                     and (key not in closed_on or event.observed_on > closed_on[key])]
            if len(basis) < policy.quarantine_after_flakes:
                raise Refused("LEDGER-QUARANTINE-UNJUSTIFIED", item.test)
            released.pop(key, None)
            active[key] = item
            continue
        record, approver = item
        key = (record["job"], record["test"])
        current = active.get(key)
        if current is None or current.ticket_ref != record["ticket_ref"] or day < current.quarantined_on:
            raise Refused("LEDGER-CLOSURE-UNMATCHED", record["test"])
        # GitHub logins and team slugs are case-insensitive.
        if approver is not None and approver.lower() == current.owner.lower():
            raise Refused("LEDGER-SELF-APPROVAL", record["test"])
        del active[key]
        closed_on[key] = day
        if approver is None:
            released[key] = day
    return Ledger(document["repository"], tuple(events), tuple(quarantines), active, document,
                  hashlib.sha256(data).hexdigest(), {test: tuple(items) for test, items in by_test.items()}, released)


def load_ledger(path, *, manifest, policy, today):
    data = read_bounded(path, LEDGER_LIMIT, "LEDGER-UNREADABLE")
    return parse_ledger(data, manifest=manifest, policy=policy, today=today)


def is_append_only(base, current):
    """True when every base array is an unchanged prefix of the current one (nothing edited or removed)."""
    if base.document["schema"] != current.document["schema"] or base.repository != current.repository:
        return False
    return all(current.document[name][:len(base.document[name])] == base.document[name] for name in ARRAYS)
