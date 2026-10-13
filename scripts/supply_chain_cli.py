"""Command line of the PenniLogic/infra#31 supply-chain gates (T-QA-11); see SUPPLY_CHAIN.md.

    python scripts/supply_chain_cli.py <gate> --artifact-id <id> [--policy <path>] <gate options>

Gates: ``compose``, ``android``, ``trivy``, ``checkov``, ``sbom``, ``provenance``, ``deploy``. Every run prints
exactly one ASCII JSON line and exits 0 (pass), 1 (gate failure) or 2 (usage error, or missing, unreadable,
malformed or incomplete input: refused, never a pass). Options take exactly one separate value
(``--name value``); unknown, repeated or missing options are usage errors. No argument value, path, file content
or exception text is ever echoed: refusals print a static rule code and, for unreadable inputs, the option name.

The production bindings are fixed: signature verification is :class:`supply_chain_verifier.UnavailableVerifier`
(held for the managed cosign integration, so ``deploy`` fails closed today) and exceptions are
:class:`supply_chain_exceptions.UnavailableExceptions` (infra#23 not integrated). Only in-process callers (tests)
can inject other ports through :func:`main`'s keyword arguments; the command line cannot.
"""

import json
import sys

from supply_chain_common import (
    ARTIFACT_ID, DIGEST, DOCUMENT_LIMIT, POLICY_PATH, REPORT_LIMIT, REPORT_SCHEMA, Refused, load_policy, pattern,
    read_bounded, sha256_file,
)
from supply_chain_config import android_findings, compose_findings
from supply_chain_deploy import SIGNATURES_LIMIT, deploy_findings, signatures_document
from supply_chain_exceptions import UnavailableExceptions, evaluate
from supply_chain_provenance import provenance_findings
from supply_chain_reports import checkov_findings, trivy_findings
from supply_chain_sbom import sbom_findings


EXIT_PASS, EXIT_FAIL, EXIT_REFUSED = 0, 1, 2
COMMON = {"artifact-id": True, "policy": False}
GATES = {
    "compose": {"input": True},
    "android": {"manifest": True, "network-config": False},
    "trivy": {"kind": True, "input": True, "expected-digest": False},
    "checkov": {"input": True},
    "sbom": {"artifact": True, "sbom": True},
    "provenance": {"artifact": True, "provenance": True},
    "deploy": {"artifact": True, "sbom": True, "provenance": True, "signatures": True},
}


class Usage(Refused):
    """A command-line usage error; ``code`` is static."""


class Unreadable(Refused):
    """An input file that cannot be read; ``option`` is the static option name."""

    def __init__(self, code, option):
        super().__init__(code)
        self.option = option


def _gate(argv):
    if isinstance(argv, (list, tuple)) and argv and isinstance(argv[0], str) and argv[0] in GATES:
        return argv[0]
    return None


def parse(argv):
    """``(gate, {option: value})``; any deviation from the static option table is a usage error."""
    if _gate(argv) is None:
        raise Usage("SC-CLI-USAGE-GATE")
    gate, spec = argv[0], {**COMMON, **GATES[argv[0]]}
    rest, options = list(argv[1:]), {}
    if len(rest) % 2:
        raise Usage("SC-CLI-USAGE-ARITY")
    for flag, value in zip(rest[0::2], rest[1::2]):
        if not isinstance(flag, str) or not flag.startswith("--") or flag[2:] not in spec:
            raise Usage("SC-CLI-USAGE-OPTION")
        if flag[2:] in options:
            raise Usage("SC-CLI-USAGE-REPEATED")
        if not isinstance(value, str) or value == "" or value.startswith("--"):
            raise Usage("SC-CLI-USAGE-VALUE")
        options[flag[2:]] = value
    if any(required and name not in options for name, required in spec.items()):
        raise Usage("SC-CLI-USAGE-MISSING")
    return gate, options


def _read(options, name, limit):
    try:
        return read_bounded(options[name], limit, "SC-CLI-READ")
    except Refused as refused:
        raise Unreadable(refused.code, name) from None


def _digest(options, name):
    try:
        return sha256_file(options[name], "SC-CLI-READ")[0]
    except Refused as refused:
        raise Unreadable(refused.code, name) from None


def findings(gate, options, verifier):
    """The findings of one gate run; inputs are read here, once, and never echoed."""
    artifact_id = options["artifact-id"]
    if gate == "compose":
        return compose_findings(_read(options, "input", DOCUMENT_LIMIT), artifact_id)
    if gate == "android":
        network = None
        if "network-config" in options:
            network = _read(options, "network-config", DOCUMENT_LIMIT)
        return android_findings(_read(options, "manifest", DOCUMENT_LIMIT), artifact_id, network)
    if gate == "trivy":
        expected = options.get("expected-digest")
        if expected is not None:
            pattern(expected, DIGEST, "SC-CLI-USAGE-DIGEST")
        return trivy_findings(_read(options, "input", REPORT_LIMIT), artifact_id, options["kind"], expected)
    if gate == "checkov":
        return checkov_findings(_read(options, "input", REPORT_LIMIT), artifact_id)
    artifact_sha256 = _digest(options, "artifact")
    if gate == "sbom":
        return sbom_findings(_read(options, "sbom", REPORT_LIMIT), artifact_id, artifact_sha256)
    if gate == "provenance":
        return provenance_findings(_read(options, "provenance", REPORT_LIMIT), artifact_id, artifact_sha256)
    signatures = signatures_document(_read(options, "signatures", SIGNATURES_LIMIT))
    return deploy_findings(artifact_id, artifact_sha256, _read(options, "sbom", REPORT_LIMIT),
                           _read(options, "provenance", REPORT_LIMIT), signatures, verifier)


def _line(document):
    return json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def main(argv, *, verifier=None, exceptions_port=None):
    """Run one gate; prints one ASCII JSON line and returns the exit code (0 pass, 1 fail, 2 refused)."""
    port = UnavailableExceptions() if exceptions_port is None else exceptions_port
    gate = _gate(argv)
    try:
        gate, options = parse(argv)
        pattern(options["artifact-id"], ARTIFACT_ID, "SC-CLI-USAGE-ARTIFACT")
        threshold = load_policy(options.get("policy", POLICY_PATH))
        report = evaluate(findings(gate, options, verifier), threshold, port)
    except Refused as refused:
        result = {"schema": REPORT_SCHEMA, "gate": gate, "decision": "refused", "code": refused.code}
        if isinstance(refused, Unreadable):
            result["option"] = refused.option
        print(_line(result))
        return EXIT_REFUSED
    except Exception:  # an unexpected error is never a pass and never echoed
        print(_line({"schema": REPORT_SCHEMA, "gate": gate, "decision": "refused", "code": "SC-CLI-INTERNAL"}))
        return EXIT_REFUSED
    report["gate"] = gate
    print(_line(report))
    return EXIT_PASS if report["decision"] == "pass" else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
