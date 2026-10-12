"""Quarantine gate for PenniLogic/infra#28 (T-QA-04; E25-F01): flake events, quarantine and its limits.

    python scripts/qa_gates_quarantine.py --job JOB --run-id RUN --attempt FIRST.xml [--attempt RETRY.xml]
        [--ledger PATH] [--manifest PATH] [--base-ledger PATH] [--fix-only PenniLogic/<repo>#N]

Inputs are one JUnit XML report per attempt (the first run, then at most the policy's re-executions of the
cases that failed), the committed quarantine ledger and the committed protected-tag manifest. The numbers come
only from the vendored, pinned docs flake policy; the date is the real UTC date (tests inject a clock).

Semantics (docs governance/test-strategy.json `flake_policy`): a job that runs a money-path package gets no
re-execution, any other job one; a re-execution beyond that fails the run and never clears a failure. A case that
still fails is a real failure. A pass on re-execution is a flake event, never a clean pass: the run fails and the
report carries the exact event for a reviewed ledger change, because CI cannot write the committed ledger. When
the recorded events of that test within the flake window plus this one reach the trigger, the report proposes a
quarantine with the package owner, a ticket requested through the TicketPort and an expiry at the maximum age;
security, privacy and money tests are never quarantined. Active quarantines of the job are taken out of the
gating set, still run and are reported. The run fails when a quarantine is older than the maximum age or past its
expiry, when a quarantined test is skipped or disappears without an approved deletion record, or when the share
of quarantined tests exceeds the ceiling, unless `--fix-only` names an active quarantine's ticket.

Exit 0 pass, 1 fail, 2 refused input or usage. stdout carries one ASCII JSON report with static rule codes
and grammar-validated test identities only (no messages, captured output, paths or file content).
"""

import argparse
import datetime
from dataclasses import dataclass
from fractions import Fraction
import json
import sys
from typing import Protocol

import qa_gates_junit as junit
import qa_gates_ledger as ledgers
import qa_gates_policy as policies
import qa_gates_tags as tags
from qa_gates_common import REFERENCE, RUN_ID, Refused, canonical_sha256, read_bounded


REPORT_SCHEMA = "pennilogic.qa-gates.quarantine-report/1"
MAX_ATTEMPTS = 8
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


def _utc_today():
    return datetime.datetime.now(datetime.timezone.utc).date()


def evaluate(*, policy, manifest, ledger, attempts, job_id, run_id, today, ticket_port, fix_only=None,
             base_ledger=None):
    """Combine the attempts with the ledger and the manifest; return the report (refusals raise Refused)."""
    if not isinstance(run_id, str) or RUN_ID.fullmatch(run_id) is None:
        raise Refused("INPUT-RUN-ID")
    if fix_only is not None and (not isinstance(fix_only, str) or REFERENCE.fullmatch(fix_only) is None):
        raise Refused("INPUT-FIX-ONLY")
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
        dates = [*ledger.flake_dates(test, today, policy.flake_window_days), today]
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
    exceeded = Fraction(len(active) * 100, tests) > policy.quarantine_rate_ceiling_percent
    bound = fix_only is not None and any(record.ticket_ref == fix_only for record in ledger.active.values())
    if fix_only is not None and not bound:
        find("QG-FIX-ONLY-UNBOUND", "fail")
    if exceeded:
        find("QG-QUARANTINE-RATE", "report" if bound else "fail")
    if base_ledger is not None and not ledgers.is_append_only(base_ledger, ledger):
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
            "ticket_creation": "held" if isinstance(ticket_port, HeldTicketPort) else "injected",
        },
        "retry": {"money_path": money_path, "allowed_reexecutions": allowed,
                  "observed_reexecutions": combination.observed_reexecutions,
                  "reexecuted_tests": len(combination.reexecuted)},
        "counts": {"tests": tests, **counts},
        "flake_rate": {"flaky": counts["flaky"], "tests": tests, "basis_points": counts["flaky"] * 10000 // tests},
        "quarantine_rate": {"quarantined": len(active), "tests": tests,
                            "basis_points": len(active) * 10000 // tests, "exceeded": exceeded,
                            "fix_only": fix_only, "fix_only_bound": bound},
        "quarantined_tests": quarantined_tests,
        "findings": sorted(findings, key=lambda finding: (finding["rule"], finding["test"] or "")),
        "ledger_delta": {"flake_events": sorted(events, key=lambda event: event["test"]),
                         "quarantines": sorted(proposals, key=lambda proposal: proposal["test"])},
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused("USAGE")


def _arguments(argv):
    parser = _Parser(prog="qa_gates_quarantine.py", description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("--job", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt", action="append", required=True)
    parser.add_argument("--ledger", default=str(ledgers.LEDGER_FILE))
    parser.add_argument("--manifest", default=str(tags.MANIFEST_FILE))
    parser.add_argument("--base-ledger")
    parser.add_argument("--fix-only")
    return parser.parse_args(argv)


def main(argv=None, *, clock=None, ticket_port=None):
    try:
        arguments = _arguments(sys.argv[1:] if argv is None else argv)
        if RUN_ID.fullmatch(arguments.run_id) is None:
            raise Refused("INPUT-RUN-ID")
        if arguments.fix_only is not None and REFERENCE.fullmatch(arguments.fix_only) is None:
            raise Refused("INPUT-FIX-ONLY")
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
        attempts = [junit.parse_attempt(read_bounded(path, junit.MAX_BYTES, "INPUT-UNREADABLE"))
                    for path in arguments.attempt]
        report = evaluate(policy=policy, manifest=manifest, ledger=ledger, attempts=attempts,
                          job_id=arguments.job, run_id=arguments.run_id, today=today,
                          ticket_port=HeldTicketPort() if ticket_port is None else ticket_port,
                          fix_only=arguments.fix_only,
                          base_ledger=base)
    except Refused as error:
        report = {"schema": REPORT_SCHEMA, "decision": "refused", "reason": error.code, "test": error.test}
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return {"pass": 0, "fail": 1}.get(report["decision"], 2)


if __name__ == "__main__":
    sys.exit(main())
