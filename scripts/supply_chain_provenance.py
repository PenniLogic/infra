"""Provenance subject-digest verification of the PenniLogic/infra#31 deployment gate (T-QA-11).

Input is one in-toto Statement v1 (``_type`` ``https://in-toto.io/Statement/v1``) whose predicate is SLSA
provenance v1 (``predicateType`` ``https://slsa.dev/provenance/v1``), as bytes, plus the SHA-256 the caller
computed from the artifact bytes. Other statement or predicate types, non-strict JSON and malformed subjects are
refused. The artifact must be a subject: a ``subject[].digest.sha256`` equal to the artifact digest, otherwise a
never-exceptable critical ``SC-SUBJECT-PROVENANCE-MISMATCH``. The builder id and build type must be present.

Builder trust (which builder ids are allowed), expected-source checks (``externalParameters`` and
``resolvedDependencies`` naming the expected repository and ref) and DSSE/attestation-bundle verification belong
to the held managed signing (cosign) integration; the statement's detached signature is checked through the Verifier port by the
deployment gate.
"""

import re

from supply_chain_common import (
    ARTIFACT_ID, REPORT_LIMIT, SHA256, Refused, finding, json_document, pattern, printable,
)


SCANNER = "builtin-provenance"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
# in-toto DigestSet algorithm names are short ASCII names such as sha256, sha512 or gitCommit.
ALGORITHM = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}")
SUBJECT_LIMIT = 1024
DIGEST_LIMIT = 16


def _subject_digests(subjects):
    """Every subject's lower-case sha256; malformed subjects are refused."""
    if not isinstance(subjects, list) or not subjects or len(subjects) > SUBJECT_LIMIT:
        raise Refused("SC-PROV-SUBJECT")
    digests = []
    for subject in subjects:
        if not isinstance(subject, dict) or not isinstance(subject.get("name"), str):
            raise Refused("SC-PROV-SUBJECT")
        digest = subject.get("digest")
        if not isinstance(digest, dict) or not digest or len(digest) > DIGEST_LIMIT or not all(
                isinstance(key, str) and ALGORITHM.fullmatch(key) and isinstance(value, str)
                for key, value in digest.items()):
            raise Refused("SC-PROV-SUBJECT")
        if "sha256" in digest:
            digests.append(pattern(digest["sha256"], SHA256, "SC-PROV-SUBJECT"))
    return digests


def provenance_findings(data, artifact_id, artifact_sha256):
    """Findings for one in-toto/SLSA provenance statement (bytes) of the artifact ``artifact_sha256``."""
    pattern(artifact_id, ARTIFACT_ID, "SC-PROV-ARTIFACT")
    pattern(artifact_sha256, SHA256, "SC-PROV-DIGEST")
    document = json_document(data, REPORT_LIMIT, "SC-PROV")
    if not isinstance(document, dict) or document.get("_type") != STATEMENT_TYPE:
        raise Refused("SC-PROV-TYPE")
    if document.get("predicateType") != PREDICATE_TYPE:
        raise Refused("SC-PROV-PREDICATE-TYPE")
    predicate = document.get("predicate")
    if not isinstance(predicate, dict):
        raise Refused("SC-PROV-SHAPE")
    definition = predicate.get("buildDefinition")
    details = predicate.get("runDetails")
    if not isinstance(definition, dict) or not isinstance(details, dict):
        raise Refused("SC-PROV-SHAPE")
    builder = details.get("builder")
    if builder is not None and not isinstance(builder, dict):
        raise Refused("SC-PROV-SHAPE")
    digests = _subject_digests(document.get("subject"))
    found = []

    def add(rule, severity, location_class, *where):
        found.append(finding(SCANNER, rule, severity, artifact_id, location_class, *where))

    if artifact_sha256 not in digests:
        add("SC-SUBJECT-PROVENANCE-MISMATCH", "critical", "provenance.subject", *digests)
    if not printable((builder or {}).get("id")):
        add("SC-PROV-BUILDER-MISSING", "high", "provenance.builder")
    if not printable(definition.get("buildType")):
        add("SC-PROV-BUILD-TYPE-MISSING", "high", "provenance.build")
    return found
