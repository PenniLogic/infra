"""Private strict-input helpers of the PenniLogic/infra#28 SAST and DAST report gates (slice 2).

Every refusal is a static rule code (`Refused.code`); no file content, message text or unvalidated value is
echoed. These helpers mirror the strict JSON and bounded-read rules of the slice-1 quarantine gates, which are not
merged yet; they are consolidated with that module once both slices are on main.
"""

import datetime
import hashlib
import json
import math
import os
import re
import stat


CANONICALIZATION = "sorted-keys-compact-ascii-json-sha256"
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
# Parentheses and brackets admit Next.js route groups and dynamic or catch-all segments (`(customer)`,
# `[[...path]]`) of the web and admin repositories; `.` and `..` stay refused as whole segments.
SEGMENT = re.compile(r"[A-Za-z0-9._@+()\[\]-]{1,128}")
PATH_LIMIT = 512
TEXT_LIMIT = 400


class Refused(ValueError):
    """One static rule code; the message never carries input content."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def canonical(value):
    """Canonical JSON bytes: sorted keys, compact separators, ASCII only, no NaN."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def canonical_sha256(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


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


def exact(value, keys, code):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Refused(code)
    return value


def text(value, code, limit=TEXT_LIMIT):
    if (not isinstance(value, str) or not value or len(value) > limit or not value.isprintable()
            or value != value.strip()):
        raise Refused(code)
    return value


def date(value, code):
    if not isinstance(value, str) or DATE.fullmatch(value) is None:
        raise Refused(code)
    try:
        return datetime.date.fromisoformat(value)
    except ValueError:
        raise Refused(code) from None


def relative_path(value, code):
    """A normalized repository-relative POSIX path: bounded, no root, drive, empty, `.` or `..` segment.

    A Windows separator is normalized to `/` first, so the same finding has one identity on both platforms.
    """
    if not isinstance(value, str) or not 0 < len(value) <= PATH_LIMIT:
        raise Refused(code)
    parts = value.replace("\\", "/").split("/")
    if any(SEGMENT.fullmatch(part) is None or part in (".", "..") for part in parts):
        raise Refused(code)
    return "/".join(parts)
