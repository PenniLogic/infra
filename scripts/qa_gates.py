"""Single entry point of the PenniLogic/infra#28 QA gates (T-QA-04; E25-F01); see QA_GATES.md.

    python scripts/qa_gates.py quarantine --job JOB --run-id RUN --attempt FIRST.xml [--attempt RETRY.xml] ...
    python scripts/qa_gates.py rate --attempt JOB=FIRST.xml [--attempt JOB=RETRY.xml ...] [--fix-only REF] ...
    python scripts/qa_gates.py retry --root DIR --manifest PATH [--workflow .github/workflows/NAME.yml ...] ...
    python scripts/qa_gates.py policy

`quarantine` runs the per-job flake and quarantine gate (scripts/qa_gates_quarantine.py), `rate` the repository
quarantine-rate ceiling over every manifest job (scripts/qa_gates_rate.py), `retry` the retry-limit
configuration check (scripts/qa_gates_retry.py) and `policy` validates the vendored, pinned docs flake policy and
prints its provenance and numbers. Exit 0 pass, 1 gate failure, 2 refused input or usage (including a missing or
unknown subcommand). stdout carries one ASCII JSON report; `--help` on a subcommand prints its usage and exits 0.
"""

import json
import sys

import qa_gates_policy as policies
import qa_gates_quarantine as quarantine
import qa_gates_rate as rate
import qa_gates_retry as retry
from qa_gates_common import Refused


REPORT_SCHEMA = "pennilogic.qa-gates.cli/1"
POLICY_SCHEMA = "pennilogic.qa-gates.policy-report/1"
SUBCOMMANDS = ("quarantine", "rate", "retry", "policy")


def _print(report):
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _policy(argv):
    if argv:
        _print({"schema": POLICY_SCHEMA, "decision": "refused", "reason": "USAGE"})
        return 2
    try:
        summary = policies.load_policy().summary()
    except Refused as error:
        _print({"schema": POLICY_SCHEMA, "decision": "refused", "reason": error.code})
        return 2
    _print({"schema": POLICY_SCHEMA, "decision": "pass", "policy": summary})
    return 0


def main(argv=None, *, clock=None, ticket_port=None):
    """Dispatch to one gate; ``clock`` and ``ticket_port`` are test seams of the quarantine gate only."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["-h"], ["--help"]):
        print(__doc__.strip())
        return 0
    if not argv or argv[0] not in SUBCOMMANDS:
        _print({"schema": REPORT_SCHEMA, "decision": "refused", "reason": "USAGE"})
        return 2
    command, rest = argv[0], argv[1:]
    if command == "quarantine":
        return quarantine.main(rest, clock=clock, ticket_port=ticket_port)
    if command == "rate":
        return rate.main(rest, clock=clock)
    if command == "retry":
        return retry.main(rest)
    return _policy(rest)


if __name__ == "__main__":
    sys.exit(main())
