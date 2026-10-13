"""Shared strict input rules for the PenniLogic/infra#28 QA gates (flake policy, JUnit, tags, ledger, quarantine).

Every refusal is a static rule code. Only grammar-validated test identities may accompany a code; no file
content, message text or path is ever echoed.
"""

import datetime
import hashlib
import json
import math
import os
import re
import stat


CANONICALIZATION = "sorted-keys-compact-ascii-json-sha256"
REPOSITORY_NAMES = ("\\.github", "docs", "contracts", "api", "ai-service", "android", "web", "admin", "infra")
REPOSITORY = re.compile(r"PenniLogic/(" + "|".join(REPOSITORY_NAMES) + r")")
# The accepted PenniLogic/docs test-strategy `reference_format` (issue or pull request), with a bounded number.
REFERENCE = re.compile(r"PenniLogic/(" + "|".join(REPOSITORY_NAMES) + r")#([1-9][0-9]{0,8})")
APPROVAL = re.compile(
    r"https://github\.com/PenniLogic/(" + "|".join(REPOSITORY_NAMES) + r")/issues/([1-9][0-9]{0,8})"
    r"#issuecomment-([1-9][0-9]{0,19})"
)
HANDLE = re.compile(r"@[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:/[A-Za-z0-9][A-Za-z0-9_.-]{0,99})?")
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
JOB_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
SHA256 = re.compile(r"[0-9a-f]{64}")
SEPARATOR = "::"
COMPONENT_LIMIT = 512
TEXT_LIMIT = 400


class Refused(ValueError):
    """A static rule code; ``test`` is either None or a grammar-validated test identity."""

    def __init__(self, code, test=None):
        super().__init__(code)
        self.code = code
        self.test = test


def canonical(value):
    """The canonical JSON bytes the vendored policy pin is computed over."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def canonical_sha256(value):
    return hashlib.sha256(canonical(value)).hexdigest()


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
    """Read at most ``limit`` + 1 bytes of a regular file; any other or unreadable path is refused with ``code``.

    The type is checked before opening (a FIFO would block the open) and again on the open handle. A path the
    platform cannot represent (for example one with a NUL character) raises ValueError and is refused the same way.
    """
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise Refused(code)
        with open(path, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise Refused(code)
            return handle.read(limit + 1)
    except (OSError, ValueError):
        raise Refused(code) from None


def exact(value, keys, code):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Refused(code)
    return value


def array(value, code, limit=100000):
    if not isinstance(value, list) or len(value) > limit:
        raise Refused(code)
    return value


def text(value, code, limit=TEXT_LIMIT):
    if (not isinstance(value, str) or not value or len(value) > limit or not value.isprintable()
            or value != value.strip()):
        raise Refused(code)
    return value


def pattern(value, expression, code):
    if not isinstance(value, str) or expression.fullmatch(value) is None:
        raise Refused(code)
    return value


def date(value, code):
    if not isinstance(value, str) or DATE.fullmatch(value) is None:
        raise Refused(code)
    try:
        return datetime.date.fromisoformat(value)
    except ValueError:
        raise Refused(code) from None


def component(value):
    """True for one identity component: printable, trimmed, bounded, free of the separator and edge colons."""
    return (isinstance(value, str) and 0 < len(value) <= COMPONENT_LIMIT and value.isprintable()
            and value == value.strip() and SEPARATOR not in value
            and not value.startswith(":") and not value.endswith(":"))


def make_test_id(suite, classname, name, code="JUNIT-IDENTITY"):
    """The defined test identity ``suite::classname::name``; components are validated, never echoed on refusal."""
    if not (component(suite) and component(classname) and component(name)):
        raise Refused(code)
    return SEPARATOR.join((suite, classname, name))


def split_test_id(value, code):
    """Validate a stored identity and return its three components."""
    if not isinstance(value, str) or len(value) > 3 * COMPONENT_LIMIT + 2 * len(SEPARATOR):
        raise Refused(code)
    parts = value.split(SEPARATOR)
    if len(parts) != 3 or not all(component(part) for part in parts):
        raise Refused(code)
    return tuple(parts)


def refuse_embedded_help(argv):
    """Help only alone: a help token inside a gate command must not turn it into exit 0 without evaluation.

    Any token starting with `-h` (argparse expands `-hh` into two help actions) or `--help` counts (review round 3,
    ADVSEC-R3-08)."""
    if len(argv) > 1 and any(argument.startswith(("-h", "--help")) for argument in argv):
        raise Refused("USAGE")
