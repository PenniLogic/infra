"""In-memory exceptions port of the PenniLogic/infra#31 supply-chain gates and the gate evaluation over it.

PenniLogic/infra#23 owns the exception mechanism (owner, reason, expiry, storage and audit). This module defines
no exception record, file format or schema and never forks infra#23's interface. Until infra#23 integrates, the
only production binding is :class:`UnavailableExceptions`: every finding stays unexcepted and blocking at its
severity, and every report states ``exceptions unavailable (infra#23 not integrated)``.

Planned binding (by name, from infra draft PR #88 at cc17385c7277f607ddbbf42ffa5cb9a6fc81a18c, not copied):
``security_exceptions.Exceptions.load(path, now)`` once per run and
``Exceptions.suppression(kind, repository, pattern, artifact)`` per finding, returning an exception id or None.
Its ``kind`` set (``secret``, ``advisory``) has no supply-chain kind yet; that mapping is an open question for the
infra#23 owner. The ``available`` branch below is exercised only by test fakes.
"""

import re

from supply_chain_common import (
    RANK, REPORT_SCHEMA, REPORT_STATUS, SCANNERS, SEVERITIES, Refused, blocking, never_exceptable,
)


UNAVAILABLE_REASON = "exceptions unavailable (infra#23 not integrated)"
EXCEPTION_ID = re.compile(r"[a-z][a-z0-9-]{0,63}")
EFFECTS = ("fail", "report", "excepted")
# On a fingerprint collision the strictest entry is kept: most severe first, then the least trusted basis.
BASIS_ORDER = {"unrated": 0, "scanner": 1, "rule": 2}


def _strictest(findings):
    """One finding per fingerprint, independent of input order (a lower-severity duplicate never hides one)."""
    kept = {}
    for item in findings:
        key = (RANK[item["severity"]], BASIS_ORDER[item["severity_basis"]])
        current = kept.get(item["fingerprint"])
        if current is None or key < current[0]:
            kept[item["fingerprint"]] = (key, item)
    return [entry for _, entry in kept.values()]


class UnavailableExceptions:
    """The production port until infra#23 integrates: nothing is ever excepted."""

    available = False

    def status(self):
        return {"status": "unavailable", "reason": UNAVAILABLE_REASON}

    def suppression(self, _finding):
        return None


def _status(port):
    available = getattr(port, "available", None)
    if available is False:
        return {"status": "unavailable", "reason": UNAVAILABLE_REASON}, False
    if available is True:
        return {"status": "available"}, True
    raise Refused("SC-EXCEPTIONS-PORT")


def evaluate(findings, threshold, port=None):
    """The gate decision and its scrubbed report; ``findings`` come from the built-in rules and ingested reports.

    A finding fails at or above ``threshold``; signature and subject-binding rules always fail and are never
    excepted. A suppression returned by an available port is published with its id, never hidden.
    """
    port = UnavailableExceptions() if port is None else port
    exceptions, available = _status(port)
    if threshold not in SEVERITIES:
        raise Refused("SC-POLICY-THRESHOLD")
    published = []
    counts = {scanner: {severity: 0 for severity in SEVERITIES} for scanner in SCANNERS}
    effects = {effect: 0 for effect in EFFECTS}
    by_rule = {}
    for item in _strictest(findings):
        exception_id = None
        if available and not never_exceptable(item["rule_id"]):
            try:
                exception_id = port.suppression(dict(item))
            except Exception:  # an erroring port fails closed with one static code
                raise Refused("SC-EXCEPTIONS-PORT-ERROR") from None
            if exception_id is not None and (not isinstance(exception_id, str)
                                             or EXCEPTION_ID.fullmatch(exception_id) is None):
                raise Refused("SC-EXCEPTIONS-ID")
        if exception_id is not None:
            effect = "excepted"
        else:
            effect = "fail" if blocking(item, threshold) else "report"
        counts[item["scanner"]][item["severity"]] += 1
        effects[effect] += 1
        by_rule[item["rule_id"]] = by_rule.get(item["rule_id"], 0) + 1
        published.append({**item, "effect": effect, "exception_id": exception_id})
    published.sort(key=lambda entry: (entry["fingerprint"], entry["rule_id"]))
    return {
        "schema": REPORT_SCHEMA,
        "vocabulary_status": REPORT_STATUS,
        "decision": "fail" if effects["fail"] else "pass",
        "blocking_threshold": threshold,
        "exceptions": exceptions,
        "counts": {
            "by_scanner": {scanner: dict(row) for scanner, row in counts.items() if any(row.values())},
            "by_effect": effects,
            "by_rule": dict(sorted(by_rule.items())),
        },
        "findings": published,
    }
