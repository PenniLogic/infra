"""Signature verification port of the PenniLogic/infra#31 deployment gate (T-QA-11).

This module contains no cryptography and no keys. Real signature verification (a managed tool such as cosign
under managed key custody) is held for integration; until then the only production binding is
:class:`UnavailableVerifier`, which makes every signature check fail closed. Tests drive the orchestration with
fakes. Signature findings are always blocking: there is no report-only mode, threshold or exception for them.

A verifier is any object with ``verify(subject_sha256, signature) -> bool`` that raises
:class:`VerifierUnavailable` when it cannot run. ``subject_sha256`` is the 64-hex SHA-256 the caller computed
from the artifact bytes; ``signature`` is the artifact's signature object (a non-empty JSON object, passed
through unchanged).
"""

from supply_chain_common import ARTIFACT_ID, SHA256, Refused, finding, pattern


SCANNER = "verifier"
LOCATION = "artifact.signature"
# The signed members of one deployable artifact: the artifact bytes, its SBOM and its provenance statement.
LOCATIONS = (LOCATION, "sbom.signature", "provenance.signature")
SIGNATURE_LIMIT = 64


class VerifierUnavailable(Exception):
    """The verifier cannot run (not integrated, tool missing, trust root unavailable)."""


class UnavailableVerifier:
    """The production binding until the managed signing integration lands: always unavailable."""

    def verify(self, _subject_sha256, _signature):
        raise VerifierUnavailable("signature verification held for managed-tool integration")


def _signature_shape(signature):
    return (isinstance(signature, dict) and 0 < len(signature) <= SIGNATURE_LIMIT
            and all(isinstance(key, str) and key for key in signature))


def check_signature(artifact_id, subject_sha256, signature, verifier=None, location=LOCATION):
    """Findings for one signed member; an empty list only when the verifier positively accepted it.

    ``signature`` is None (or absent from the artifact record) for an unsigned member; ``location`` names the
    member (one of :data:`LOCATIONS`) and ``subject_sha256`` is the SHA-256 of that member's exact bytes.
    """
    pattern(artifact_id, ARTIFACT_ID, "SC-SIG-ARTIFACT")
    if location not in LOCATIONS:
        raise Refused("SC-SIG-LOCATION")
    if not isinstance(subject_sha256, str) or SHA256.fullmatch(subject_sha256) is None:
        raise Refused("SC-SIG-SUBJECT")
    verifier = UnavailableVerifier() if verifier is None else verifier

    def failed(rule):
        return [finding(SCANNER, rule, "critical", artifact_id, location, subject_sha256)]

    if signature is None:
        return failed("SC-SIG-UNSIGNED")
    if not _signature_shape(signature):
        return failed("SC-SIG-SHAPE")
    try:
        accepted = verifier.verify(subject_sha256, signature)
    except VerifierUnavailable:
        return failed("SC-SIG-VERIFIER-UNAVAILABLE")
    except Exception:  # any verifier error fails closed with one static rule
        return failed("SC-SIG-VERIFIER-ERROR")
    if accepted is True:
        return []
    if accepted is False:
        return failed("SC-SIG-INVALID")
    return failed("SC-SIG-VERIFIER-RESULT")
