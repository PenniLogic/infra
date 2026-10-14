"""Test-only fakes and synthetic builders for the PenniLogic/infra#31 supply-chain gates (never used by gates).

The fakes hold no key and perform no cryptography: :class:`IssuedTableFakeVerifier` accepts exactly the
signature objects it recorded as issued. They prove gate orchestration only, not production signature fidelity
(held for the managed-tool integration).
"""

import hashlib
import itertools
import json

import support  # noqa: F401  (puts scripts/ on sys.path)
from supply_chain_verifier import VerifierUnavailable


TEST_SCHEME = "test-only-issued-table"
_ISSUERS = itertools.count(1)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class IssuedTableFakeVerifier:
    """Key-free allow-table fake: accepts a signature object only if this instance issued it for that subject.

    A signature object is ``{"scheme", "issuer", "subject"}``; ``issuer`` is a per-instance counter value, so a
    signature issued by another instance, for another subject, or never issued at all is rejected.
    """

    def __init__(self):
        self.issuer = next(_ISSUERS)
        self._issued = set()
        self.calls = 0

    def sign(self, subject_sha256):
        self._issued.add(subject_sha256)
        return {"scheme": TEST_SCHEME, "issuer": self.issuer, "subject": subject_sha256}

    def verify(self, subject_sha256, signature):
        self.calls += 1
        expected = {"scheme": TEST_SCHEME, "issuer": self.issuer, "subject": subject_sha256}
        return signature == expected and subject_sha256 in self._issued


class TableFakeVerifier:
    """Returns a fixed answer (or raises a fixed exception) for every call."""

    def __init__(self, answer=True, error=None):
        self.answer = answer
        self.error = error
        self.calls = 0

    def verify(self, _subject_sha256, _signature):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.answer


def unavailable():
    return TableFakeVerifier(error=VerifierUnavailable("synthetic: trust root unavailable"))


ARTIFACT = b"synthetic deployable artifact bytes v1\n"
COMPONENT_SHA = "1" * 64


def component(index):
    return {
        "type": "library", "bom-ref": "pkg:generic/synthetic-lib-%d@1.0.%d" % (index, index),
        "name": "synthetic-lib-%d" % index, "version": "1.0.%d" % index,
        "purl": "pkg:generic/synthetic-lib-%d@1.0.%d" % (index, index),
        "hashes": [{"alg": "SHA-256", "content": COMPONENT_SHA}],
    }


def sbom_document(artifact_sha256, spec="1.6"):
    """A complete synthetic CycloneDX JSON SBOM bound to ``artifact_sha256`` (the passing control)."""
    subject = {"type": "application", "bom-ref": "synthetic-app", "name": "synthetic-app", "version": "1.0.0",
               "hashes": [{"alg": "SHA-256", "content": artifact_sha256}]}
    return {
        "bomFormat": "CycloneDX", "specVersion": spec,
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001", "version": 1,
        "metadata": {"component": subject},
        "components": [component(1), component(2)],
        "dependencies": [{"ref": "synthetic-app", "dependsOn": [component(1)["bom-ref"], component(2)["bom-ref"]]}],
    }


def encode(document):
    return json.dumps(document, indent=2, ensure_ascii=True).encode("utf-8")


def provenance_statement(artifact_sha256):
    """A synthetic in-toto Statement v1 / SLSA provenance v1 naming ``artifact_sha256`` (the passing control)."""
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "synthetic-app.bin", "digest": {"sha256": artifact_sha256}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {"buildType": "https://example.invalid/synthetic-build/v1",
                                "externalParameters": {"source": "synthetic"}},
            "runDetails": {"builder": {"id": "https://example.invalid/synthetic-builder"}},
        },
    }
