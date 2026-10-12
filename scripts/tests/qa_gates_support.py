"""Synthetic builders for the PenniLogic/infra#28 QA-gate tests; not a test module.

Every identity, owner, reviewer, ticket, approval and run id here is synthetic: the `#9000NN` references and
the `@synthetic-*` handles do not name existing issues or people, and nothing here is evidence of a real flake,
quarantine, ticket or approval.
"""

import datetime
import json
from xml.sax.saxutils import quoteattr

import support  # noqa: F401  (puts scripts/ on sys.path)
import qa_gates_junit as junit
import qa_gates_ledger as ledgers
import qa_gates_policy as policies
import qa_gates_quarantine as gate
import qa_gates_tags as tags


TODAY = datetime.date(2026, 3, 16)
SUITE = "synthetic.suite"
JOB = "synthetic-job"
MONEY_JOB = "synthetic-money-job"
RUN = "synthetic-run-current"
OWNER = "@synthetic-owner"
REVIEWER = "@synthetic-reviewer"
TICKET = "PenniLogic/infra#900001"
OTHER_TICKET = "PenniLogic/infra#900002"
FIX_REF = "PenniLogic/infra#900003"
APPROVAL = "https://github.com/PenniLogic/infra/issues/900001#issuecomment-900001"
PLAIN = "synthetic.plain.Cases"
SECURITY = "synthetic.security.Cases"
PRIVACY = "synthetic.privacy.Cases"
MONEY = "synthetic.money.Cases"
MONEY_PATH = "synthetic.ledger.Cases"


def day(offset):
    return (TODAY + datetime.timedelta(days=offset)).isoformat()


def identity(classname=PLAIN, name="test_case"):
    return f"{SUITE}::{classname}::{name}"


def encode(document):
    return (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def manifest_document():
    def rule(number, value, package, tag_list):
        return {"id": f"PT-{number:03d}", "field": "classname", "kind": "package", "value": value,
                "package": package, "tags": tag_list, "reason": "Synthetic classification for tests"}

    return {
        "schema": tags.SCHEMA, "repository": "PenniLogic/infra", "status": "proposed", "confirmation_ref": None,
        "packages": [
            {"id": "infra.synthetic_money", "money_path": True, "owner": OWNER, "basis": "Synthetic money-path package"},
            {"id": "infra.tooling", "money_path": False, "owner": OWNER, "basis": "Synthetic package"},
        ],
        "rules": [
            rule(1, "synthetic.plain", "infra.tooling", []),
            rule(2, "synthetic.security", "infra.tooling", ["security"]),
            rule(3, "synthetic.privacy", "infra.tooling", ["privacy"]),
            rule(4, "synthetic.money", "infra.tooling", ["money"]),
            rule(5, "synthetic.ledger", "infra.synthetic_money", []),
        ],
        "jobs": [
            {"id": JOB, "workflow": ".github/workflows/ci.yml", "job": "ci", "packages": ["infra.tooling"]},
            {"id": MONEY_JOB, "workflow": ".github/workflows/ci.yml", "job": "money",
             "packages": ["infra.synthetic_money", "infra.tooling"]},
        ],
    }


def ledger_document(events=(), quarantines=(), releases=(), deletions=()):
    return {
        "schema": ledgers.SCHEMA, "repository": "PenniLogic/infra", "flake_events": list(events),
        "quarantines": list(quarantines), "releases": list(releases), "deletions": list(deletions),
    }


def event(test, offset, job=JOB, run=None):
    return {"test": test, "job": job, "run_id": run or f"synthetic-history{offset}", "observed_on": day(offset)}


def quarantine(test, start, *, expires_after=14, job=JOB, owner=OWNER, ticket=TICKET):
    return {"test": test, "job": job, "owner": owner, "ticket_ref": ticket,
            "quarantined_on": day(start), "expires_on": day(start + expires_after)}


def justified(test, start, **options):
    """Two recorded flake events on the quarantine's first day and the day before, plus the quarantine."""
    job = options.get("job", JOB)
    events = [event(test, start - 1, job=job, run=f"synthetic-basis{start}a"),
              event(test, start, job=job, run=f"synthetic-basis{start}b")]
    return events, quarantine(test, start, **options)


def release(test, offset, *, job=JOB, ticket=TICKET):
    return {"test": test, "job": job, "ticket_ref": ticket, "fix_ref": FIX_REF, "released_on": day(offset)}


def deletion(test, offset, *, job=JOB, ticket=TICKET, approval=APPROVAL, approver=REVIEWER):
    return {"test": test, "job": job, "ticket_ref": ticket, "approval_ref": approval, "approved_by": approver,
            "approved_on": day(offset)}


OUTCOME_ELEMENTS = {
    "passed": "",
    "failed": '<failure message="synthetic failure" type="AssertionError">synthetic trace</failure>',
    "error": '<error message="synthetic error" type="RuntimeError">synthetic trace</error>',
    "skipped": '<skipped message="synthetic skip"/>',
}


def case_xml(classname, name, outcome="passed"):
    body = OUTCOME_ELEMENTS[outcome]
    opening = f"<testcase classname={quoteattr(classname)} name={quoteattr(name)} time=\"0.001\""
    return f"{opening}/>" if not body else f"{opening}>{body}</testcase>"


def junit_xml(cases, *, suite=SUITE, root="testsuites", declaration=True):
    """``cases``: (classname, name, outcome) triples; outcome is passed, failed, error or skipped."""
    cases = list(cases)
    count = {outcome: sum(case[2] == outcome for case in cases) for outcome in OUTCOME_ELEMENTS}
    suite_xml = (
        f"<testsuite name={quoteattr(suite)} tests=\"{len(cases)}\" failures=\"{count['failed']}\" "
        f"errors=\"{count['error']}\" skipped=\"{count['skipped']}\" time=\"0.010\">\n"
        + "".join(f"  {case_xml(*case)}\n" for case in cases)
        + "</testsuite>"
    )
    document = f"<testsuites>\n{suite_xml}\n</testsuites>" if root == "testsuites" else suite_xml
    prefix = '<?xml version="1.0" encoding="UTF-8"?>\n' if declaration else ""
    return (prefix + document + "\n").encode("utf-8")


def cases(*items, classname=PLAIN):
    """(name, outcome) pairs in one class -> (classname, name, outcome) triples."""
    return [(classname, name, outcome) for name, outcome in items]


class FakeTicketPort:
    """Records requests and returns a fixed synthetic reference (or None/invalid when configured)."""

    def __init__(self, ticket=TICKET):
        self.ticket = ticket
        self.requests = []

    def request_ticket(self, request):
        self.requests.append(request)
        return self.ticket


def parse_inputs(manifest_doc=None, ledger_doc=None, *, today=TODAY):
    policy = policies.load_policy()
    manifest = tags.parse_manifest(encode(manifest_doc if manifest_doc is not None else manifest_document()))
    ledger = ledgers.parse_ledger(encode(ledger_doc if ledger_doc is not None else ledger_document()),
                                  manifest=manifest, policy=policy, today=today)
    return policy, manifest, ledger


def run_gate(*attempt_cases, ledger_doc=None, manifest_doc=None, job=JOB, today=TODAY, port=None, fix_only=None,
             base_doc=None, run_id=RUN):
    policy, manifest, ledger = parse_inputs(manifest_doc, ledger_doc, today=today)
    base = None if base_doc is None else ledgers.parse_ledger(encode(base_doc), manifest=manifest, policy=policy,
                                                              today=today)
    attempts = [junit.parse_attempt(junit_xml(items)) for items in attempt_cases]
    return gate.evaluate(policy=policy, manifest=manifest, ledger=ledger, attempts=attempts, job_id=job,
                         run_id=run_id, today=today, ticket_port=FakeTicketPort() if port is None else port,
                         fix_only=fix_only, base_ledger=base)


def findings(report):
    return {(finding["rule"], finding["effect"], finding["test"]) for finding in report["findings"]}
