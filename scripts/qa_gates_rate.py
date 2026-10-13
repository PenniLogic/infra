"""Repository quarantine-rate ceiling for PenniLogic/infra#28 (T-QA-04; E25-F01).

    python scripts/qa_gates_rate.py --attempt JOB=FIRST.xml [--attempt JOB=RETRY.xml ...] --base-ledger PATH
        --ledger PATH --manifest PATH [--fix-only PenniLogic/<repo>#N]

Docs governance/test-strategy.json 1.1.1 section 8 sets the quarantine rate ceiling as a share of "a repository's
tests" and asks for a per-repository flake rate. This step therefore runs once per pipeline, after every job of
the committed manifest: it takes each job's attempt reports (first run, then re-executions, in order, as
`JOB=PATH`), counts distinct test identities across all jobs, distinct actively quarantined tests of the whole
ledger and distinct tests that flaked in any job (classified with each job's re-execution allowance, as the
per-job gate does), and fails when the quarantine share exceeds the ceiling, unless `--fix-only` names the ticket of
a quarantine active in the base revision's ledger (`--base-ledger`; without it the step fails,
QG-LEDGER-BASE-MISSING) and the change adds no active quarantine (QG-FIX-ONLY-ADDS-QUARANTINE otherwise). A job of the manifest without a report refuses the step: an absent
job is never treated as a passing one. Per-job verdicts (flakes, real failures, retry limits, quarantine expiry)
stay with the per-job quarantine gate.

Exit 0 pass, 1 fail, 2 refused input or usage. stdout carries one ASCII JSON report with static rule codes, job
ids and counts only.
"""

import argparse
import datetime
from fractions import Fraction
import json
import sys

import qa_gates_junit as junit
import qa_gates_ledger as ledgers
import qa_gates_policy as policies
import qa_gates_tags as tags
from qa_gates_common import REFERENCE, Refused, read_bounded, refuse_embedded_help


REPORT_SCHEMA = "pennilogic.qa-gates.rate-report/1"
MAX_ATTEMPTS = 8
MAX_INPUTS = 64


def _rate(count, tests):
    """``basis_points`` is rounded down; ``count``/``tests`` is the exact fraction."""
    return {"count": count, "tests": tests, "basis_points": count * 10000 // tests}


def _allowance(policy, manifest, job, first):
    """The per-job gate's re-execution allowance: none for a money-path job or a run with a money-path case."""
    money_path = manifest.jobs[job].money_path or any(manifest.classify(test).money_path for test in first.cases)
    return policy.money_path_retry_limit if money_path else policy.retry_limit


def evaluate(*, policy, manifest, ledger, attempts, fix_only=None, base_ledger=None):
    """``attempts``: {manifest job id: [first Attempt, re-executions...]}; return the repository report.

    ``base_ledger`` is the protected base revision's ledger: ``fix_only`` binds to a quarantine active there, so a
    change that fixes a quarantined test and appends its release stays exempt (review round 2, PS-1).
    """
    if fix_only is not None and (not isinstance(fix_only, str) or REFERENCE.fullmatch(fix_only) is None):
        raise Refused("INPUT-FIX-ONLY")
    if not isinstance(attempts, dict) or any(job not in manifest.jobs for job in attempts):
        raise Refused("MANIFEST-UNKNOWN-JOB")
    if set(attempts) != set(manifest.jobs):
        raise Refused("INPUT-JOBS-MISSING")
    tests, flaky = set(), set()
    for job in sorted(attempts):
        chain = attempts[job]
        if not chain or len(chain) > MAX_ATTEMPTS:
            raise Refused("INPUT-ATTEMPTS")
        # Classified with the per-job gate's allowance, so a pass on a re-execution the policy does not permit is a
        # real failure here too, not a flake (review round 2, PS-6).
        outcomes = junit.combine(chain, _allowance(policy, manifest, job, chain[0])).outcomes
        tests.update(outcomes)
        flaky.update(test for test, outcome in outcomes.items() if outcome == "flaky")
    quarantined = {test for (_job, test) in ledger.active}
    # A quarantined test that no job reported is still one of the repository's tests (the per-job gate fails it).
    population = len(tests | quarantined)
    exceeded = Fraction(len(quarantined) * 100, population) > policy.quarantine_rate_ceiling_percent
    bound = fix_only is not None and base_ledger is not None and any(
        record.ticket_ref == fix_only for record in base_ledger.active.values())
    # A change that adds an active quarantine is not a fix to a quarantined test: it raises the rate, so the
    # exemption is withheld (review round 3, PS-3 and ADVSEC-R3-06).
    added = 0 if base_ledger is None else len(set(ledger.active) - set(base_ledger.active))
    findings = []
    if base_ledger is None:
        findings.append({"rule": "QG-LEDGER-BASE-MISSING", "effect": "fail"})
    if fix_only is not None and not bound:
        findings.append({"rule": "QG-FIX-ONLY-UNBOUND", "effect": "fail"})
    if exceeded:
        findings.append({"rule": "QG-QUARANTINE-RATE", "effect": "report" if bound and not added else "fail"})
        if bound and added:
            findings.append({"rule": "QG-FIX-ONLY-ADDS-QUARANTINE", "effect": "fail"})
    return {
        "schema": REPORT_SCHEMA,
        "decision": "fail" if any(finding["effect"] == "fail" for finding in findings) else "pass",
        "reason": None,
        "scope": "repository", "repository": manifest.repository, "jobs": sorted(attempts),
        "policy": policy.summary(),
        "inputs": {
            "attempts": {job: [{"sha256": attempt.sha256, "cases": len(attempt.cases)} for attempt in chain]
                         for job, chain in sorted(attempts.items())},
            "ledger_sha256": ledger.sha256, "manifest_sha256": manifest.sha256, "manifest_status": manifest.status,
            "base_ledger_sha256": None if base_ledger is None else base_ledger.sha256,
        },
        "flake_rate": _rate(len(flaky), population),
        "quarantine_rate": {**_rate(len(quarantined), population), "exceeded": exceeded,
                            "fix_only": fix_only, "fix_only_bound": bound, "added_quarantines": added},
        "findings": sorted(findings, key=lambda finding: finding["rule"]),
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused("USAGE")


def _arguments(argv):
    refuse_embedded_help(argv)
    parser = _Parser(prog="qa_gates_rate.py", description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("--attempt", action="append", required=True)
    # Head inputs are named explicitly: a default relative to this script would name the base checkout's
    # files when CI runs the base code (review round 3, ADVSEC-R3-03).
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--fix-only")
    parser.add_argument("--base-ledger")
    return parser.parse_args(argv)


def main(argv=None, *, clock=None):
    try:
        arguments = _arguments(sys.argv[1:] if argv is None else argv)
        if arguments.fix_only is not None and REFERENCE.fullmatch(arguments.fix_only) is None:
            raise Refused("INPUT-FIX-ONLY")
        if len(arguments.attempt) > MAX_INPUTS:
            raise Refused("INPUT-ATTEMPTS")
        named = []
        for value in arguments.attempt:
            job, separator, path = value.partition("=")
            if not separator or not job or not path:
                raise Refused("USAGE")
            named.append((job, path))
        today = (clock or (lambda: datetime.datetime.now(datetime.timezone.utc).date()))()
        if type(today) is not datetime.date:
            raise Refused("INPUT-CLOCK")
        policy = policies.load_policy()
        manifest = tags.load_manifest(arguments.manifest)
        if any(job not in manifest.jobs for job, _path in named):
            raise Refused("MANIFEST-UNKNOWN-JOB")
        ledger = ledgers.load_ledger(arguments.ledger, manifest=manifest, policy=policy, today=today)
        base = None if arguments.base_ledger is None else ledgers.load_ledger(
            arguments.base_ledger, manifest=manifest, policy=policy, today=today)
        attempts = {}
        for job, path in named:
            attempts.setdefault(job, []).append(
                junit.parse_attempt(read_bounded(path, junit.MAX_BYTES, "INPUT-UNREADABLE")))
        report = evaluate(policy=policy, manifest=manifest, ledger=ledger, attempts=attempts,
                          fix_only=arguments.fix_only, base_ledger=base)
    except Refused as error:
        report = {"schema": REPORT_SCHEMA, "decision": "refused", "reason": error.code, "test": error.test}
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return {"pass": 0, "fail": 1}.get(report["decision"], 2)


if __name__ == "__main__":
    sys.exit(main())
