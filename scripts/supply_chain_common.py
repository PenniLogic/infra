"""Shared strict input rules and the finding vocabulary of the PenniLogic/infra#31 supply-chain gates (T-QA-11).

Every refusal is a static rule code. Reports carry static rule codes, grammar-validated identifiers, severity
classes, counts and `sha256:` fingerprints only; no file content, message text, path or value is ever echoed.

The finding vocabulary (severity enum, `sha256:<hex>` fingerprint) is copied by value from the proposed
PenniLogic/infra#28 scan-report vocabulary and is *proposed, pending infra#28 and infra#23 owner alignment*.
"""

import hashlib
import json
import math
import os
import re
import stat


SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {name: index for index, name in enumerate(SEVERITIES)}
ARTIFACT_ID = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}")
RULE_ID = re.compile(r"[A-Za-z][A-Za-z0-9._:-]{1,79}")
SHA256 = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
REPORT_LIMIT = 32 * 1024 * 1024
DOCUMENT_LIMIT = 4 * 1024 * 1024


class Refused(ValueError):
    """Input that is missing, unreadable, malformed or incomplete; ``code`` is a static rule code."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def json_document(data, limit, prefix):
    """One strict UTF-8 JSON document: no BOM, no duplicate key, no NaN/Infinity, at most ``limit`` bytes."""
    if not isinstance(data, bytes) or not data or len(data) > limit:
        raise Refused(prefix + "-SIZE")
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused(prefix + "-JSON") from None
    if decoded.startswith("\ufeff"):
        raise Refused(prefix + "-JSON")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refused(prefix + "-JSON")
            result[key] = value
        return result

    def finite(literal):
        value = float(literal)
        if not math.isfinite(value):
            raise Refused(prefix + "-JSON")
        return value

    def constant(_literal):
        raise Refused(prefix + "-JSON")

    try:
        return json.loads(decoded, object_pairs_hook=unique, parse_float=finite, parse_constant=constant)
    except Refused:
        raise
    except (ValueError, RecursionError):
        raise Refused(prefix + "-JSON") from None


def read_bounded(path, limit, code):
    """Read at most ``limit`` + 1 bytes of a regular file; any other or unreadable path is refused with ``code``."""
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise Refused(code)
        with open(path, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise Refused(code)
            return handle.read(limit + 1)
    except (OSError, ValueError):
        raise Refused(code) from None


def pattern(value, expression, code):
    if not isinstance(value, str) or expression.fullmatch(value) is None:
        raise Refused(code)
    return value


def fingerprint(*parts):
    """``sha256:<hex>`` over length-prefixed UTF-8 parts, so raw locations are bound but never published."""
    digest = hashlib.sha256()
    for part in parts:
        encoded = str(part).encode("utf-8", "surrogatepass")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return "sha256:" + digest.hexdigest()


SCANNERS = ("builtin-compose", "builtin-android", "trivy", "checkov", "verifier")
LOCATION_CLASS = re.compile(r"[a-z][a-z0-9-]{0,31}(?:\.[a-z][a-z0-9-]{0,31}){0,3}")
# Signature, verifier and subject-binding findings are never exceptable and never below the threshold.
NEVER_EXCEPTABLE = ("SC-SIG-", "SC-SUBJECT-")
REPORT_SCHEMA = "pennilogic.supply-chain.scan-report/1"
REPORT_STATUS = "proposed, pending PenniLogic/infra#28 and PenniLogic/infra#23 owner alignment"


SEVERITY_BASES = ("rule", "scanner", "unrated")


def finding(scanner, rule_id, severity, artifact_id, location_class, *location, basis="rule"):
    """One normalised finding; ``location`` parts are bound into the fingerprint and never published.

    ``basis`` says where the severity came from: a built-in ``rule``, the ``scanner`` report, or ``unrated``
    (the scanner gave none or UNKNOWN; normalised fail-closed to ``high``).
    """
    if basis not in SEVERITY_BASES:
        raise Refused("SC-FINDING-BASIS")
    if scanner not in SCANNERS:
        raise Refused("SC-FINDING-SCANNER")
    pattern(rule_id, RULE_ID, "SC-FINDING-RULE")
    if severity not in SEVERITIES:
        raise Refused("SC-FINDING-SEVERITY")
    pattern(artifact_id, ARTIFACT_ID, "SC-FINDING-ARTIFACT")
    pattern(location_class, LOCATION_CLASS, "SC-FINDING-LOCATION")
    return {
        "scanner": scanner, "rule_id": rule_id, "severity": severity, "artifact_id": artifact_id,
        "location_class": location_class, "severity_basis": basis,
        "fingerprint": fingerprint(scanner, rule_id, artifact_id, location_class, *location),
    }


def never_exceptable(rule_id):
    return rule_id.startswith(NEVER_EXCEPTABLE)


def blocking(item, threshold):
    """True when the finding fails the gate: at or above ``threshold``, or a never-exceptable rule."""
    if threshold not in SEVERITIES:
        raise Refused("SC-POLICY-THRESHOLD")
    return never_exceptable(item["rule_id"]) or RANK[item["severity"]] <= RANK[threshold]


POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "supply-chain", "policy.json")
POLICY_SCHEMA = "pennilogic.supply-chain.policy/1"
POLICY_STATUSES = ("proposed, not agreed", "agreed")
# Never weaker than the ticket's "high and critical findings blocking"; there is deliberately no mode,
# report-only, per-rule or signature key: any other key is refused.
POLICY_THRESHOLDS = ("high", "medium", "low", "info")


def load_policy(path=POLICY_PATH):
    """The validated gate policy; returns the blocking threshold."""
    document = json_document(read_bounded(path, 65536, "SC-POLICY-READ"), 65536, "SC-POLICY")
    if not isinstance(document, dict) or set(document) != {"schema", "status", "blocking_threshold"}:
        raise Refused("SC-POLICY-SHAPE")
    if document["schema"] != POLICY_SCHEMA:
        raise Refused("SC-POLICY-SCHEMA")
    if document["status"] not in POLICY_STATUSES:
        raise Refused("SC-POLICY-STATUS")
    if document["blocking_threshold"] not in POLICY_THRESHOLDS:
        raise Refused("SC-POLICY-THRESHOLD")
    return document["blocking_threshold"]
