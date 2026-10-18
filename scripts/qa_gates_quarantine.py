"""Quarantine gate for PenniLogic/infra#28 (T-QA-04; E25-F01): flake events, quarantine and its limits.

    python scripts/qa_gates_quarantine.py --job JOB --run-id RUN --attempt FIRST.xml [--attempt RETRY.xml]
        --ledger PATH --manifest PATH --base-ledger PATH --base-manifest PATH

Inputs are one JUnit XML report per attempt (the first run, then at most the policy's re-executions of the
cases that failed), the committed quarantine ledger and the committed protected-tag manifest. The numbers come
only from the vendored, pinned docs flake policy; the date is the real UTC date (tests inject a clock).

Semantics (docs governance/test-strategy.json `flake_policy`): a job that runs a money-path package gets no
re-execution, any other job one; a re-execution beyond that fails the run and never clears a failure. A case that
still fails is a real failure. A pass on re-execution is a flake event, never a clean pass: the run fails and the
report carries the exact event for a reviewed ledger change, because CI cannot write the committed ledger. When
the recorded events of that test within the flake window (after its last closure, the ledger's own trigger) plus
this one reach the trigger, the report proposes a
quarantine with the package owner, a ticket requested through the TicketPort and an expiry at the maximum age;
security, privacy and money tests are never quarantined. Active quarantines of the job are taken out of the
gating set, still run and are reported. The run fails when a quarantine is older than the maximum age or past its
expiry, when a quarantined test is skipped or disappears without an approved deletion record (a test released in
this change must still run in it), when a release or deletion appended in this change predates a fact of its test
in the base ledger, when a quarantine appended in this change does not start after the test's last closure, or
when a deletion appended in this change is approved by the base manifest's package owner (all proposed controls
beyond flake_policy), when the base-revision
ledger or manifest is missing, when the ledger is not append-only against it, or when the manifest relaxes a
protected test, a protecting rule or a money-path job against it (a new untagged rule is reported for review).
The quarantine rate ceiling counts a repository's tests and is judged by scripts/qa_gates_rate.py; this report
publishes the job's share only.

Exit 0 pass, 1 fail, 2 refused input or usage. stdout carries one ASCII JSON report with static rule codes
and grammar-validated test identities only (no messages, captured output, paths or file content).
"""

import argparse
import datetime
from dataclasses import dataclass
import json
import sys
from typing import Protocol

import qa_gates_junit as junit
import qa_gates_ledger as ledgers
import qa_gates_policy as policies
import qa_gates_tags as tags
from qa_gates_common import (
    REFERENCE, RUN_ID, Refused, canonical_sha256, read_bounded, refuse_embedded_help,
)


REPORT_SCHEMA = "pennilogic.qa-gates.quarantine-report/1"
MAX_ATTEMPTS = 8
# Ledger fields that date a fact about a test, by array.
FACT_DATES = (("flake_events", "observed_on"), ("quarantines", "quarantined_on"), ("releases", "released_on"),
              ("deletions", "approved_on"))
OUTCOMES = ("passed", "failed", "flaky", "skipped")


@dataclass(frozen=True)
class TicketRequest:
    repository: str
    job: str
    test: str
    owner: str
    flake_dates: tuple
    idempotency_key: str


class TicketPort(Protocol):
    def request_ticket(self, request: TicketRequest) -> str | None:
        """Return the owning ticket reference (PenniLogic/<repo>#N), or None when no ticket was created."""


class HeldTicketPort:
    """The CLI default: real ticket creation is held (infra#28 criterion 5), so no ticket is ever returned."""

    def request_ticket(self, request):
        return None


def _latest_fact(document, test, arrays=("flake_events", "quarantines", "releases", "deletions")):
    """The latest date the ledger ``document`` records for ``test`` in ``arrays`` (None when it records none)."""
    days = [datetime.date.fromisoformat(record[field]) for name, field in FACT_DATES if name in arrays
            for record in document[name] if record["test"] == test]
    return max(days, default=None)


def _closed_after(document, quarantine):
    """True when the test of ``quarantine`` has a closure (any job) on or after its start other than its own.

    Its own closure is the first one of the same job and ticket dated on or after its start (the ledger replay
    matches closures that way)."""
    start = datetime.date.fromisoformat(quarantine["quarantined_on"])
    closures = sorted((datetime.date.fromisoformat(record[field]), record["job"], record["ticket_ref"])
                      for name, field in FACT_DATES[2:] for record in document[name]
                      if record["test"] == quarantine["test"])
    own = next((item for item in closures if item[0] >= start and item[1:] == (quarantine["job"],
                                                                               quarantine["ticket_ref"])), None)
    return any(item[0] >= start and item is not own for item in closures)


def _utc_today():
    return datetime.datetime.now(datetime.timezone.utc).date()


def _rule_tags(manifest, rule):
    """The protection a rule gives: its tags, plus money for a money-path package (as ``classify`` adds it)."""
    return rule.tags | ({"money"} if manifest.packages[rule.package].money_path else set())


def _rule_relaxed(base_manifest, manifest):
    """(relaxed, added): a protecting base rule was removed or lost protection (tags, or its package's money_path);
    rules new in the head manifest give no protection (review round 2, ADVSEC-R2-02). Compared by rule id, whatever
    tests ran, so renaming a protected module and pointing its rule at the new name with the tags dropped is seen."""
    head = {rule.id: rule for rule in manifest.rules}
    relaxed = False
    for rule in base_manifest.rules:
        before = _rule_tags(base_manifest, rule)
        after = head.get(rule.id)
        if before and (after is None or not before <= _rule_tags(manifest, after)):
            relaxed = True
    base_ids = {rule.id for rule in base_manifest.rules}
    added = any(rule.id not in base_ids and not _rule_tags(manifest, rule) for rule in manifest.rules)
    return relaxed, added


def _relaxations(base_manifest, manifest, job_id, identities):
    """Tests (and the job or a rule, as None) whose protection the head manifest removed against the base."""
    if base_manifest.repository != manifest.repository:
        return [None]
    relaxed = []
    base_job = base_manifest.jobs.get(job_id)
    if base_job is not None and base_job.money_path and not manifest.jobs[job_id].money_path:
        relaxed.append(None)
    if _rule_relaxed(base_manifest, manifest)[0] and None not in relaxed:
        relaxed.append(None)
    for identity in identities:
        before, after = base_manifest.classify(identity), manifest.classify(identity)
        if before.state == "known" and after.state == "known" and before.tags - after.tags:
            relaxed.append(identity)
    return relaxed


def evaluate(*, policy, manifest, ledger, attempts, job_id, run_id, today, ticket_port, base_ledger=None,
             base_manifest=None):
    """Combine the attempts with the ledger and the manifest; return the report (refusals raise Refused)."""
    if not isinstance(run_id, str) or RUN_ID.fullmatch(run_id) is None:
        raise Refused("INPUT-RUN-ID")
    if type(today) is not datetime.date:
        raise Refused("INPUT-CLOCK")
    job = manifest.jobs.get(job_id) if isinstance(job_id, str) else None
    if job is None:
        raise Refused("MANIFEST-UNKNOWN-JOB")
    if run_id in ledger.run_ids():
        raise Refused("INPUT-RUN-ID-REUSED")
    junit.check_chain(attempts)
    findings = []

    def find(rule, effect, test=None):
        findings.append({"rule": rule, "effect": effect, "test": test})

    first = attempts[0].cases
    active = ledger.active_for(job_id)
    classes = {identity: manifest.classify(identity) for identity in [*first, *(t for t in active if t not in first)]}
    for identity, classification in classes.items():
        if classification.state == "unknown":
            find("QG-CLASSIFICATION-UNKNOWN", "fail", identity)
        elif classification.state == "ambiguous":
            find("QG-CLASSIFICATION-AMBIGUOUS", "fail", identity)
        elif identity in first and classification.package.id not in job.packages:
            find("QG-JOB-PACKAGE-UNMAPPED", "fail", identity)

    # The head manifest decides protection, so a change must not relax it in the same change (E25-F01): compare
    # with the base revision's manifest, as the ledger is compared with the base ledger.
    if base_manifest is None:
        find("QG-MANIFEST-BASE-MISSING", "fail")
    else:
        for identity in _relaxations(base_manifest, manifest, job_id, classes):
            find("QG-MANIFEST-RELAXED", "fail", identity)
        # A new rule without protection is listed for review: moving a protected test under it is a relaxation
        # only review can see (Known limits).
        if _rule_relaxed(base_manifest, manifest)[1]:
            find("QG-MANIFEST-RULE-UNPROTECTED", "report")
        # A package owner change decides who may approve deletions; it is listed for review (ADVSEC-R3-05).
        if any(package.owner != base_manifest.packages[package_id].owner
               for package_id, package in manifest.packages.items() if package_id in base_manifest.packages):
            find("QG-MANIFEST-OWNER-CHANGED", "report")

    money_path = job.money_path or any(classes[identity].money_path for identity in first)
    allowed = policy.money_path_retry_limit if money_path else policy.retry_limit
    combination = junit.combine(attempts, allowed)
    if combination.over_limit:
        find("QG-RETRY-LIMIT", "fail")

    exempt, quarantined_tests = set(), []
    for test, record in sorted(active.items()):
        classification = classes[test]
        if classification.state == "known" and classification.protected:
            find("QG-QUARANTINE-PROTECTED", "fail", test)
        elif classification.state == "known":
            exempt.add(test)
        age = (today - record.quarantined_on).days
        if age > policy.quarantine_max_age_days:
            find("QG-QUARANTINE-AGE", "fail", test)
        elif today > record.expires_on:
            find("QG-QUARANTINE-EXPIRED", "fail", test)
        outcome = combination.outcomes.get(test, "missing")
        if outcome == "missing":
            find("QG-QUARANTINED-TEST-MISSING", "fail", test)
        elif outcome == "skipped":
            find("QG-QUARANTINED-NOT-RUN", "fail", test)
        quarantined_tests.append({**record.record(), "age_days": age, "outcome": outcome, "exempt": test in exempt})

    # Closures appended in this change compared with the base ledger (every closure when the base is missing,
    # which fails on its own). A release closes a quarantine without approval, so a test released in this change
    # must still run in it (review round 1 PS-3; round 2 PS-3: a release already in the base no longer holds the
    # test, so it can be renamed or removed in a later change). Its date must be recent (ADVSEC-R2-01).
    appended = {name: ledger.document[name][len(base_ledger.document[name]) if base_ledger is not None else 0:]
                for name in ("quarantines", "releases", "deletions")}
    # A closure appended in this change may not predate a fact the base ledger already records for its test, so it
    # cannot move the post-closure trigger back over recorded evidence. The approval or release date is never
    # bounded against the run date (review round 3, PS-4, replacing the 3-day tolerance of ADVSEC-R2-01).
    for name, field in (("releases", "released_on"), ("deletions", "approved_on")):
        for record in appended[name]:
            latest = None if base_ledger is None else _latest_fact(base_ledger.document, record["test"])
            if latest is not None and datetime.date.fromisoformat(record[field]) < latest:
                find("QG-CLOSURE-BACKDATED", "fail", record["test"])
    # A quarantine appended in this change must start strictly after the last closure of its test in the head
    # ledger (any job), so it cannot reuse a closed quarantine's events (review round 3, ADVSEC-R3-04).
    for record in appended["quarantines"]:
        if _closed_after(ledger.document, record):
            find("QG-QUARANTINE-BACKDATED", "fail", record["test"])
    # The deletion approver must also differ from the base manifest's package owner, so the change cannot move the
    # owner away from the approver (review round 3, ADVSEC-R3-05; proposed control, see ledger docstring).
    for record in appended["deletions"]:
        classification = None if base_manifest is None else base_manifest.classify(record["test"])
        if (classification is not None and classification.state == "known"
                and classification.package.owner is not None
                and classification.package.owner.lower() == record["approved_by"].lower()):
            find("QG-SELF-APPROVAL", "fail", record["test"])
    new_releases = {record["test"] for record in appended["releases"] if record["job"] == job_id}
    for test in sorted(ledger.released_for(job_id)):
        if test in new_releases and combination.outcomes.get(test, "missing") in ("missing", "skipped"):
            find("QG-RELEASED-TEST-MISSING", "fail", test)

    events, proposals = [], []
    for test, outcome in combination.outcomes.items():
        if outcome == "flaky":
            events.append({"test": test, "job": job_id, "run_id": run_id, "observed_on": today.isoformat()})
        if test in exempt:
            if outcome in ("failed", "flaky"):
                find("QG-QUARANTINED-FAILURE" if outcome == "failed" else "QG-QUARANTINED-FLAKE", "report", test)
            continue
        if outcome == "failed":
            find("QG-REAL-FAILURE", "fail", test)
        if outcome != "flaky":
            continue
        find("QG-FLAKE-EVENT", "fail", test)
        # Same trigger as the ledger (ledgers.basis): this event counts only if it is after the last closure.
        dates = [*ledger.flake_dates(test, today, policy.flake_window_days)]
        if ledger.closed_on.get(test) is None or today > ledger.closed_on[test]:
            dates.append(today)
        classification = classes[test]
        if len(dates) < policy.quarantine_after_flakes or classification.state != "known" or test in active:
            continue
        if classification.protected:
            find("QG-QUARANTINE-REFUSED-PROTECTED", "fail", test)
            continue
        owner = classification.package.owner
        if owner is None:
            find("QG-QUARANTINE-OWNER-MISSING", "fail", test)
            continue
        ticket = ticket_port.request_ticket(TicketRequest(
            repository=manifest.repository, job=job_id, test=test, owner=owner,
            flake_dates=tuple(day.isoformat() for day in dates),
            idempotency_key=canonical_sha256([manifest.repository, job_id, test, run_id]),
        ))
        if not isinstance(ticket, str) or REFERENCE.fullmatch(ticket) is None:
            find("QG-QUARANTINE-TICKET-MISSING", "fail", test)
            continue
        proposals.append({
            "test": test, "job": job_id, "owner": owner, "ticket_ref": ticket, "quarantined_on": today.isoformat(),
            "expires_on": (today + datetime.timedelta(days=policy.quarantine_max_age_days)).isoformat(),
        })
        find("QG-QUARANTINE-PROPOSED", "fail", test)

    tests = len(first)
    # Quarantined tests are outside the gating set, so a run in which only they ran checked nothing (ADVSEC-R2-05).
    if all(outcome == "skipped" or test in exempt for test, outcome in combination.outcomes.items()):
        find("QG-NOTHING-RAN", "fail")
    if base_ledger is None:
        find("QG-LEDGER-BASE-MISSING", "fail")
    elif not ledgers.is_append_only(base_ledger, ledger):
        find("QG-LEDGER-NOT-APPEND-ONLY", "fail")

    counts = {state: sum(outcome == state for outcome in combination.outcomes.values()) for state in OUTCOMES}
    return {
        "schema": REPORT_SCHEMA,
        "decision": "fail" if any(finding["effect"] == "fail" for finding in findings) else "pass",
        "reason": None,
        "job": job_id, "run_id": run_id, "evaluated_on": today.isoformat(),
        "policy": policy.summary(),
        "inputs": {
            "attempts": [{"sha256": attempt.sha256, "bytes": attempt.size, "cases": len(attempt.cases)}
                         for attempt in attempts],
            "ledger_sha256": ledger.sha256, "base_ledger_sha256": None if base_ledger is None else base_ledger.sha256,
            "manifest_sha256": manifest.sha256, "manifest_status": manifest.status,
            "base_manifest_sha256": None if base_manifest is None else base_manifest.sha256,
            "ticket_creation": "held" if isinstance(ticket_port, HeldTicketPort) else "injected",
        },
        "retry": {"money_path": money_path, "allowed_reexecutions": allowed,
                  "observed_reexecutions": combination.observed_reexecutions,
                  "reexecuted_tests": len(combination.reexecuted)},
        "counts": {"tests": tests, **counts},
        # Job scope, basis points rounded down; the repository rates and the ceiling are in qa_gates_rate.py.
        "flake_rate": {"scope": "job", "flaky": counts["flaky"], "tests": tests,
                       "basis_points": counts["flaky"] * 10000 // tests},
        "quarantine_rate": {"scope": "job", "quarantined": len(active), "tests": tests,
                            "basis_points": len(active) * 10000 // tests},
        "quarantined_tests": quarantined_tests,
        "findings": sorted(findings, key=lambda finding: (finding["rule"], finding["test"] or "")),
        "ledger_delta": {"flake_events": sorted(events, key=lambda event: event["test"]),
                         "quarantines": sorted(proposals, key=lambda proposal: proposal["test"])},
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused("USAGE")


def _arguments(argv):
    refuse_embedded_help(argv)
    parser = _Parser(prog="qa_gates_quarantine.py", description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("--job", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt", action="append", required=True)
    # Head inputs are named explicitly: a default relative to this script would name the base checkout's
    # files when CI runs the base code (review round 3, ADVSEC-R3-03).
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--base-ledger")
    parser.add_argument("--base-manifest")
    return parser.parse_args(argv)


def main(argv=None, *, clock=None, ticket_port=None):
    try:
        arguments = _arguments(sys.argv[1:] if argv is None else argv)
        if RUN_ID.fullmatch(arguments.run_id) is None:
            raise Refused("INPUT-RUN-ID")
        if len(arguments.attempt) > MAX_ATTEMPTS:
            raise Refused("INPUT-ATTEMPTS")
        today = (clock or _utc_today)()
        if type(today) is not datetime.date:
            raise Refused("INPUT-CLOCK")
        policy = policies.load_policy()
        manifest = tags.load_manifest(arguments.manifest)
        ledger = ledgers.load_ledger(arguments.ledger, manifest=manifest, policy=policy, today=today)
        base = None if arguments.base_ledger is None else ledgers.load_ledger(
            arguments.base_ledger, manifest=manifest, policy=policy, today=today)
        base_manifest = None if arguments.base_manifest is None else tags.load_manifest(arguments.base_manifest)
        attempts = [junit.parse_attempt(read_bounded(path, junit.MAX_BYTES, "INPUT-UNREADABLE"))
                    for path in arguments.attempt]
        report = evaluate(policy=policy, manifest=manifest, ledger=ledger, attempts=attempts,
                          job_id=arguments.job, run_id=arguments.run_id, today=today,
                          ticket_port=HeldTicketPort() if ticket_port is None else ticket_port,
                          base_ledger=base, base_manifest=base_manifest)
    except Refused as error:
        report = {"schema": REPORT_SCHEMA, "decision": "refused", "reason": error.code, "test": error.test}
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return {"pass": 0, "fail": 1}.get(report["decision"], 2)


if __name__ == "__main__":
    sys.exit(main())
