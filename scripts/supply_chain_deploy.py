"""Deployment gate of the PenniLogic/infra#31 supply-chain checks (T-QA-11): signature, SBOM and provenance.

One deployable artifact is allowed only when all of these hold for the exact bytes read:

* the artifact, its CycloneDX SBOM and its provenance statement each carry a detached signature object that the
  Verifier port positively accepts over that member's SHA-256 (missing object = unsigned, ``SC-SIG-UNSIGNED``;
  an unavailable verifier fails closed, ``SC-SIG-VERIFIER-UNAVAILABLE``);
* the SBOM is complete and its ``metadata.component`` SHA-256 equals the artifact digest;
* the provenance statement names the artifact digest as a subject.

Signature and subject findings are critical and never exceptable; there is no report-only mode. The production
verifier is :class:`supply_chain_verifier.UnavailableVerifier` until the managed cosign integration lands, so the
production gate cannot pass yet: that is the intended fail-closed state, not a defect.
"""

import hashlib

from supply_chain_common import ARTIFACT_ID, SHA256, Refused, json_document, pattern
from supply_chain_provenance import provenance_findings
from supply_chain_sbom import sbom_findings
from supply_chain_verifier import check_signature


MEMBERS = ("artifact", "sbom", "provenance")
SIGNATURES_LIMIT = 1024 * 1024


def signatures_document(data):
    """The detached signature objects of one artifact: ``{member: object|null}`` for members in :data:`MEMBERS`.

    An absent or null member is unsigned (a finding, not a refusal); unknown members are refused.
    """
    document = json_document(data, SIGNATURES_LIMIT, "SC-DEPLOY-SIGNATURES")
    if not isinstance(document, dict) or not set(document) <= set(MEMBERS):
        raise Refused("SC-DEPLOY-SIGNATURES-SHAPE")
    return document


def deploy_findings(artifact_id, artifact_sha256, sbom_data, provenance_data, signatures, verifier=None):
    """Every finding of the deployment gate for one artifact; an empty list is the only passing result."""
    pattern(artifact_id, ARTIFACT_ID, "SC-DEPLOY-ARTIFACT")
    pattern(artifact_sha256, SHA256, "SC-DEPLOY-DIGEST")
    if not isinstance(signatures, dict) or not set(signatures) <= set(MEMBERS):
        raise Refused("SC-DEPLOY-SIGNATURES-SHAPE")
    if not isinstance(sbom_data, bytes) or not isinstance(provenance_data, bytes):
        raise Refused("SC-DEPLOY-INPUT")
    subjects = {
        "artifact": artifact_sha256,
        "sbom": hashlib.sha256(sbom_data).hexdigest(),
        "provenance": hashlib.sha256(provenance_data).hexdigest(),
    }
    found = []
    for member in MEMBERS:
        found.extend(check_signature(artifact_id, subjects[member], signatures.get(member), verifier,
                                     location=member + ".signature"))
    found.extend(sbom_findings(sbom_data, artifact_id, artifact_sha256))
    found.extend(provenance_findings(provenance_data, artifact_id, artifact_sha256))
    return found
