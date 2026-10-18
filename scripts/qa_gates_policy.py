"""Vendored PenniLogic/docs flake policy for the infra#28 quarantine and retry gates; fails closed.

`qa-gates/flake-policy.json` carries `/flake_policy` of docs `governance/test-strategy.json` verbatim, with
its pin. Two checks bind it: the file's pin must equal ``PIN`` below (so a re-pin is a reviewed code change, not
a data edit), and the canonical SHA-256 of the vendored object must equal the pinned digest. Missing or extra
keys at any level are refused before any number is used. The re-pin trigger and the offline limitation are
recorded in the file's `re_pin` block: infra CI cannot read docs, so this only detects edits to the copy.
"""

from dataclasses import dataclass
from fractions import Fraction
import math
from pathlib import Path

from qa_gates_common import CANONICALIZATION, Refused, canonical_sha256, exact, json_document, read_bounded, text


POLICY_FILE = Path(__file__).resolve().parent / "qa-gates" / "flake-policy.json"
POLICY_LIMIT = 65536
SCHEMA = "pennilogic.qa-gates.vendored-flake-policy/1"
PIN = {
    "repository": "PenniLogic/docs",
    "commit": "1722fc79ab2abee15d3adc2ed2f3baaad4bd6ed4",
    "path": "governance/test-strategy.json",
    "json_pointer": "/flake_policy",
    "strategy_version": "1.1.1",
    "canonicalization": CANONICALIZATION,
    "canonical_sha256": "ed5626f8c95b2c1919c5ebbdd039a966fc7e4494077f2a786fd1ae29ecf6db2c",
}
DOCUMENT_KEYS = ("schema", "pin", "re_pin", "flake_policy")
RE_PIN_KEYS = ("trigger", "offline_limitation")
# The ten keys docs governance/test-strategy.schema.json requires (additionalProperties false), in source order.
POLICY_KEYS = (
    "quarantine_rate_ceiling_percent", "retry_limit", "money_path_retry_limit", "quarantine_after_flakes",
    "flake_window_days", "quarantine_max_age_days", "retry_semantics", "on_quarantine_ceiling_exceeded",
    "on_retry_limit_exceeded", "on_quarantine_expired",
)
STATEMENTS = ("retry_semantics", "on_quarantine_ceiling_exceeded", "on_retry_limit_exceeded", "on_quarantine_expired")


@dataclass(frozen=True)
class FlakePolicy:
    quarantine_rate_ceiling_percent: Fraction
    retry_limit: int
    money_path_retry_limit: int
    quarantine_after_flakes: int
    flake_window_days: int
    quarantine_max_age_days: int
    commit: str
    strategy_version: str
    canonical_sha256: str

    def summary(self):
        """Provenance and numbers for reports; the percentage is an exact decimal string."""
        ceiling = self.quarantine_rate_ceiling_percent
        return {
            "repository": PIN["repository"], "commit": self.commit, "path": PIN["path"],
            "strategy_version": self.strategy_version, "canonical_sha256": self.canonical_sha256,
            "quarantine_rate_ceiling_percent": str(ceiling.numerator) if ceiling.denominator == 1 else str(float(ceiling)),
            "retry_limit": self.retry_limit, "money_path_retry_limit": self.money_path_retry_limit,
            "quarantine_after_flakes": self.quarantine_after_flakes, "flake_window_days": self.flake_window_days,
            "quarantine_max_age_days": self.quarantine_max_age_days,
        }


def _count(value, minimum):
    if type(value) is not int or value < minimum:
        raise Refused("POLICY-VALUE")
    return value


def _percent(value):
    if type(value) is int:
        result = Fraction(value)
    elif type(value) is float and math.isfinite(value):
        result = Fraction(repr(value))
    else:
        raise Refused("POLICY-VALUE")
    if not 0 <= result <= 100:
        raise Refused("POLICY-VALUE")
    return result


def parse_policy(data):
    """Validate vendored-policy bytes against the pin and return the numbers the gates use."""
    document = exact(json_document(data, POLICY_LIMIT, "POLICY"), DOCUMENT_KEYS, "POLICY-KEYS")
    if document["schema"] != SCHEMA:
        raise Refused("POLICY-SCHEMA")
    pin = exact(document["pin"], PIN, "POLICY-KEYS")
    re_pin = exact(document["re_pin"], RE_PIN_KEYS, "POLICY-KEYS")
    policy = exact(document["flake_policy"], POLICY_KEYS, "POLICY-KEYS")
    if pin != PIN:
        raise Refused("POLICY-PIN-MISMATCH")
    if canonical_sha256(policy) != PIN["canonical_sha256"]:
        raise Refused("POLICY-DIGEST-MISMATCH")
    for key in RE_PIN_KEYS:
        text(re_pin[key], "POLICY-VALUE")
    for key in STATEMENTS:
        if not isinstance(policy[key], str) or not policy[key].strip():
            raise Refused("POLICY-VALUE")
    retry_limit = _count(policy["retry_limit"], 0)
    money_path_retry_limit = _count(policy["money_path_retry_limit"], 0)
    if money_path_retry_limit > retry_limit:
        raise Refused("POLICY-VALUE")
    return FlakePolicy(
        quarantine_rate_ceiling_percent=_percent(policy["quarantine_rate_ceiling_percent"]),
        retry_limit=retry_limit,
        money_path_retry_limit=money_path_retry_limit,
        quarantine_after_flakes=_count(policy["quarantine_after_flakes"], 1),
        flake_window_days=_count(policy["flake_window_days"], 1),
        quarantine_max_age_days=_count(policy["quarantine_max_age_days"], 1),
        commit=PIN["commit"],
        strategy_version=PIN["strategy_version"],
        canonical_sha256=PIN["canonical_sha256"],
    )


def load_policy(path=POLICY_FILE):
    return parse_policy(read_bounded(path, POLICY_LIMIT, "POLICY-UNREADABLE"))
