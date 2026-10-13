"""Test-only fakes for the PenniLogic/infra#31 supply-chain gates (never imported by gate code).

Keys are generated at runtime per fake instance with ``secrets`` and never written anywhere; the HMAC fake proves
gate orchestration only, not production signature fidelity (held for the managed-tool integration).
"""

import hashlib
import hmac
import secrets

import support  # noqa: F401  (puts scripts/ on sys.path)
from supply_chain_verifier import VerifierUnavailable


TEST_SCHEME = "test-only-hmac-sha256"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class HmacFakeVerifier:
    """Accepts exactly the signature objects it issued for a subject digest; a runtime key, never persisted."""

    def __init__(self):
        self._key = secrets.token_bytes(32)
        self.calls = 0

    def sign(self, subject_sha256):
        value = hmac.new(self._key, subject_sha256.encode("ascii"), hashlib.sha256).hexdigest()
        return {"scheme": TEST_SCHEME, "value": value}

    def verify(self, subject_sha256, signature):
        self.calls += 1
        if signature.get("scheme") != TEST_SCHEME or not isinstance(signature.get("value"), str):
            return False
        return hmac.compare_digest(self.sign(subject_sha256)["value"], signature["value"])


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
