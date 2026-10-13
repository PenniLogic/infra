"""DAST report ingestion gate of PenniLogic/infra#28 (T-QA-04, slice 2); see QA_GATES_SCANNING.md.

    python scripts/qa_gates_dast.py --alerts ZAP.json --manifest SCAN-MANIFEST.json --surface SURFACE.json
        [--policy POLICY.json]

Reads two digest-bound inputs: a ZAP traditional JSON alerts report and the executor's scan manifest (target, ZAP
version, contexts and users with credentials named by environment variable only, the scanned URL set and the
SHA-256 of the alerts report and of the expected-surface manifest). The target must pass `preflight_target()`
(loopback IP literal or a declared ephemeral host suffix), every report site and alert instance must be on it, an
authenticated and an unauthenticated context must both have scanned URLs, and every expected-surface entry must be
covered; anything missing is incomplete, and incomplete fails. Every alert blocks, whatever its risk (high,
medium, low or info), unless its plugin is in a recorded warn window of at most seven days (injected clock); no
risk is report-only, because no accepted source or recorded decision relaxes any risk. Exceptions are unavailable until infra#23 integrates. Parser fidelity is unverified until a real ZAP sample exists.

The output carries plugin IDs, alert references, risk and confidence levels, CWE IDs, methods, counts, validated
surface IDs and fingerprints only: never URIs, parameters, evidence, attack strings, alert text or credentials.
Exit 0 pass, 1 gate failure (including an incomplete scan), 2 refused input or usage; stdout carries one ASCII
JSON report.
"""

import datetime
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

from qa_gates_scan_common import (
    Refused, canonical_sha256, date, exact, json_document, read_bounded, sha256_bytes, text,
)


SCRIPTS = Path(__file__).resolve().parent
POLICY_FILE = SCRIPTS / "qa-gates" / "rules" / "dast-policy.json"
PROPOSED = "proposed, not agreed"
POLICY_SCHEMA = "pennilogic.qa-gates.dast-policy/1"
MANIFEST_SCHEMA = "pennilogic.qa-gates.dast-scan-manifest/1"
SURFACE_SCHEMA = "pennilogic.qa-gates.dast-surface/1"
REPORT_SCHEMA = "pennilogic.qa-gates.dast-report/1"
VOCABULARY_STATUS = "proposed, pending infra#23 owner alignment"
EXCEPTIONS_STATUS = "unavailable: infra#23 not integrated"
PLANNED_EXCEPTIONS_BINDING = "security_exceptions.Exceptions.suppression"
PARSER_FIDELITY = "unverified: no real ZAP sample exists"
RISKS = {"3": "high", "2": "medium", "1": "low", "0": "info"}
CONFIDENCES = {"4": "confirmed", "3": "high", "2": "medium", "1": "low", "0": "false-positive"}
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
WARN_WINDOW_DAYS = 7
POLICY_LIMIT = 65536
MANIFEST_LIMIT = 8 * 1024 * 1024
SURFACE_LIMIT = 1024 * 1024
ALERTS_LIMIT = 32 * 1024 * 1024
URL_LIMIT = 2048
ITEM_LIMIT = 100000
VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")
SHA256 = re.compile(r"[0-9a-f]{64}")
PLUGIN_ID = re.compile(r"[0-9]{1,7}")
ALERT_REF = re.compile(r"[0-9]{1,7}(?:-[0-9]{1,4})?")
CWE_ID = re.compile(r"-1|0|[1-9][0-9]{0,5}")
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{2,63}")
SURFACE_ID = re.compile(r"[A-Z][A-Z0-9]{0,15}(?:-[A-Z0-9]{1,16}){1,4}")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
PATH_SEGMENT = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=:@%-]{1,256}")
TEMPLATE_SEGMENT = re.compile(r"[A-Za-z0-9._~-]{1,128}|\{[a-z][a-z0-9_]{0,31}\}")
URL_TEXT = re.compile(r"[\x21-\x7e]{1,2048}")


def _host_name(value, code):
    """A lowercase ASCII DNS name of at least two labels that is not an IP literal."""
    labels = value.split(".") if isinstance(value, str) and 0 < len(value) <= 253 else [""]
    if len(labels) < 2 or any(LABEL.fullmatch(label) is None for label in labels) or labels[-1].isdigit():
        raise Refused(code)
    return value


POLICY_KEYS = ("schema", "status", "basis", "decision_ref", "blocking_risks", "targets", "rules")


def parse_policy(data):
    """Validate the DAST policy: blocking risks (all four), target allowlist and per-plugin warn windows.

    `blocking_risks` must name every ZAP risk: a narrower set would be an invented severity relaxation, and
    `decision_ref` (the only place a recorded owner or Security decision could permit one) must stay null.
    Returns {"blocking": frozenset, "suffixes": tuple, "loopback": bool, "warn": {plugin_id: (start, until)}}.
    """
    document = exact(json_document(data, POLICY_LIMIT, "DAST-POLICY"), POLICY_KEYS, "DAST-POLICY-KEYS")
    if document["schema"] != POLICY_SCHEMA or document["status"] != PROPOSED:
        raise Refused("DAST-POLICY-SCHEMA")
    text(document["basis"], "DAST-POLICY-BASIS")
    if document["decision_ref"] is not None:
        raise Refused("DAST-POLICY-DECISION")
    risks = document["blocking_risks"]
    if (not isinstance(risks, list) or not all(isinstance(risk, str) for risk in risks)
            or len(set(risks)) != len(risks) or set(risks) != set(RISKS.values())):
        raise Refused("DAST-POLICY-RISK")
    targets = exact(document["targets"], ("loopback", "ephemeral_host_suffixes"), "DAST-POLICY-TARGETS")
    suffixes = targets["ephemeral_host_suffixes"]
    if type(targets["loopback"]) is not bool or not isinstance(suffixes, list):
        raise Refused("DAST-POLICY-TARGETS")
    for suffix in suffixes:
        _host_name(suffix, "DAST-POLICY-TARGETS")
    if len(set(suffixes)) != len(suffixes):
        raise Refused("DAST-POLICY-TARGETS")
    rules = document["rules"]
    if not isinstance(rules, dict):
        raise Refused("DAST-POLICY-RULES")
    warn = {}
    for plugin_id, entry in rules.items():
        if PLUGIN_ID.fullmatch(plugin_id) is None:
            raise Refused("DAST-POLICY-RULES")
        exact(entry, ("mode", "warn_from", "warn_until"), "DAST-POLICY-WARN")
        if entry["mode"] != "warn":
            raise Refused("DAST-POLICY-WARN")
        start = date(entry["warn_from"], "DAST-POLICY-WARN")
        until = date(entry["warn_until"], "DAST-POLICY-WARN")
        if not start < until or (until - start).days > WARN_WINDOW_DAYS:
            raise Refused("DAST-POLICY-WARN-WINDOW")
        warn[plugin_id] = (start, until)
    return {"blocking": frozenset(risks), "loopback": targets["loopback"], "suffixes": tuple(suffixes), "warn": warn}


def load_policy(path=POLICY_FILE):
    return parse_policy(read_bounded(path, POLICY_LIMIT, "DAST-POLICY-UNREADABLE"))


NETLOC = re.compile(r"(\[[0-9a-f:]{2,39}\]|[a-z0-9.-]{1,253})(?::([1-9][0-9]{0,4}))?")
DEFAULT_PORTS = {"http": 80, "https": 443}


def split_url(value, code):
    """(scheme, host, port, path segments, has query) of an absolute http(s) URL; no userinfo, fragment or dot segment.

    Pure and strict: printable ASCII only, lowercase scheme and host, explicit or default port, percent-encoded
    path segments. The URL itself is never returned or echoed.
    """
    if not isinstance(value, str) or URL_TEXT.fullmatch(value) is None:
        raise Refused(code)
    scheme, separator, rest = value.partition("://")
    if scheme not in DEFAULT_PORTS or not separator:
        raise Refused(code)
    netloc, slash, remainder = rest.partition("/")
    path_query, hash_mark, _fragment = remainder.partition("#")
    path, question, _query = path_query.partition("?")
    if hash_mark:
        raise Refused(code)
    match = NETLOC.fullmatch(netloc)
    if match is None:
        raise Refused(code)
    host, port = match.group(1), int(match.group(2) or DEFAULT_PORTS[scheme])
    if port > 65535:
        raise Refused(code)
    segments = path.split("/") if path else []
    if segments and segments[-1] == "" and slash:
        segments.pop()
    if any(PATH_SEGMENT.fullmatch(part) is None or part in (".", "..") for part in segments):
        raise Refused(code)
    return scheme, host, port, tuple(segments), bool(question)


def _host_class(host, policy):
    """`loopback` for 127.0.0.0/8 or [::1] (when allowed), `ephemeral` under a declared suffix, else None."""
    if host.startswith("["):
        return "loopback" if policy["loopback"] and host == "[::1]" else None
    if re.fullmatch(r"[0-9.]+", host):
        try:
            address = ipaddress.IPv4Address(host)
        except ValueError:
            return None
        return "loopback" if policy["loopback"] and address in ipaddress.IPv4Network("127.0.0.0/8") else None
    try:
        _host_name(host, "DAST-TARGET-URL")
    except Refused:
        return None
    if any(host.endswith("." + suffix) for suffix in policy["suffixes"]):
        return "ephemeral"
    return None


def preflight_target(url, policy, prefix="DAST-TARGET"):
    """Pure target check before any scan: an http(s) origin on the allowlist, else refused.

    Returns {"origin": "scheme://host:port", "class": "loopback"|"ephemeral"}. No DNS resolution happens, so a
    host name is allowed only under a declared ephemeral suffix and `localhost` is refused; resolution, rebinding
    and the first-request guard of E25-F04 are execution-time controls of the held scan executor. ``prefix``
    names the refusal codes (`<prefix>-URL`, `<prefix>-NOT-ALLOWLISTED`).
    """
    scheme, host, port, segments, has_query = split_url(url, prefix + "-URL")
    if segments or has_query:
        raise Refused(prefix + "-URL")
    target_class = _host_class(host, policy)
    if target_class is None:
        raise Refused(prefix + "-NOT-ALLOWLISTED")
    return {"origin": "%s://%s:%d" % (scheme, host, port), "class": target_class}


def on_target(url, target, code):
    """Path segments of a URL whose origin equals the preflighted target; another origin is `<code>-OFF-TARGET`."""
    scheme, host, port, segments, _has_query = split_url(url, code)
    if "%s://%s:%d" % (scheme, host, port) != target["origin"]:
        raise Refused(code + "-OFF-TARGET")
    return segments


def _template(value, code):
    """Segments of an expected-surface path template such as `/accounts/{id}`; `/` is the root."""
    if not isinstance(value, str) or not value.startswith("/") or len(value) > URL_LIMIT:
        raise Refused(code)
    segments = tuple(value[1:].split("/")) if value != "/" else ()
    if any(TEMPLATE_SEGMENT.fullmatch(part) is None or part in (".", "..") for part in segments):
        raise Refused(code)
    return segments


def parse_surface(data):
    """The expected-surface manifest: entries {id, auth, method, path}; returns (sha256, entries)."""
    document = exact(json_document(data, SURFACE_LIMIT, "DAST-SURFACE"), ("schema", "status", "entries"),
                     "DAST-SURFACE-KEYS")
    if document["schema"] != SURFACE_SCHEMA or document["status"] != PROPOSED:
        raise Refused("DAST-SURFACE-SCHEMA")
    entries = document["entries"]
    if not isinstance(entries, list) or not entries or len(entries) > ITEM_LIMIT:
        raise Refused("DAST-SURFACE-EMPTY")
    parsed, identifiers, keys = [], set(), set()
    for entry in entries:
        exact(entry, ("id", "auth", "method", "path"), "DAST-SURFACE-ENTRY")
        if not isinstance(entry["id"], str) or SURFACE_ID.fullmatch(entry["id"]) is None:
            raise Refused("DAST-SURFACE-ID")
        if entry["auth"] not in ("authenticated", "unauthenticated") or entry["method"] not in METHODS:
            raise Refused("DAST-SURFACE-ENTRY")
        segments = _template(entry["path"], "DAST-SURFACE-PATH")
        key = (entry["auth"] == "authenticated", entry["method"], segments)
        if entry["id"] in identifiers or key in keys:
            raise Refused("DAST-SURFACE-DUPLICATE")
        identifiers.add(entry["id"])
        keys.add(key)
        parsed.append({"id": entry["id"], "authenticated": key[0], "method": key[1], "segments": segments})
    return sha256_bytes(data), parsed


MANIFEST_KEYS = (
    "schema", "zap_version", "target", "synthetic_data", "alerts_sha256", "surface_sha256", "contexts", "scanned_urls",
)


def _context(value):
    exact(value, ("name", "authenticated", "user"), "DAST-MANIFEST-CONTEXT")
    if not isinstance(value["name"], str) or NAME.fullmatch(value["name"]) is None:
        raise Refused("DAST-MANIFEST-CONTEXT")
    if type(value["authenticated"]) is not bool:
        raise Refused("DAST-MANIFEST-CONTEXT")
    user = value["user"]
    if not value["authenticated"]:
        if user is not None:
            raise Refused("DAST-MANIFEST-USER")
        return value["name"], False
    exact(user, ("name", "credential_env"), "DAST-MANIFEST-USER")
    if not isinstance(user["name"], str) or NAME.fullmatch(user["name"]) is None:
        raise Refused("DAST-MANIFEST-USER")
    if not isinstance(user["credential_env"], str) or ENV_NAME.fullmatch(user["credential_env"]) is None:
        raise Refused("DAST-MANIFEST-CREDENTIAL-ENV")
    return value["name"], True


def parse_manifest(data, policy):
    """The executor scan manifest; the target passes `preflight_target` and every scanned URL is on it."""
    document = exact(json_document(data, MANIFEST_LIMIT, "DAST-MANIFEST"), MANIFEST_KEYS, "DAST-MANIFEST-KEYS")
    if document["schema"] != MANIFEST_SCHEMA:
        raise Refused("DAST-MANIFEST-SCHEMA")
    if not isinstance(document["zap_version"], str) or VERSION.fullmatch(document["zap_version"]) is None:
        raise Refused("DAST-MANIFEST-VERSION")
    if document["synthetic_data"] is not True:
        raise Refused("DAST-MANIFEST-SYNTHETIC")
    for key in ("alerts_sha256", "surface_sha256"):
        if not isinstance(document[key], str) or SHA256.fullmatch(document[key]) is None:
            raise Refused("DAST-MANIFEST-DIGEST")
    target = preflight_target(document["target"], policy)
    contexts, scanned = {}, []
    if not isinstance(document["contexts"], list) or len(document["contexts"]) > 64:
        raise Refused("DAST-MANIFEST-CONTEXT")
    for value in document["contexts"]:
        name, authenticated = _context(value)
        if name in contexts:
            raise Refused("DAST-MANIFEST-CONTEXT")
        contexts[name] = authenticated
    urls = document["scanned_urls"]
    if not isinstance(urls, list) or len(urls) > ITEM_LIMIT:
        raise Refused("DAST-MANIFEST-URL")
    for value in urls:
        exact(value, ("context", "method", "url"), "DAST-MANIFEST-URL")
        if not isinstance(value["context"], str) or value["context"] not in contexts or value["method"] not in METHODS:
            raise Refused("DAST-MANIFEST-URL")
        segments = on_target(value["url"], target, "DAST-MANIFEST-URL")
        scanned.append((contexts[value["context"]], value["method"], segments, value["context"]))
    return {
        "version": document["zap_version"], "target": target, "alerts_sha256": document["alerts_sha256"],
        "surface_sha256": document["surface_sha256"], "contexts": contexts, "scanned": scanned,
    }


PARAM_LIMIT = 1024


def fingerprint(alert_ref, method, segments, param):
    """`sha256:` over the canonical JSON of [alert ref, method, URL path, parameter name]; the query is excluded."""
    return "sha256:" + canonical_sha256([alert_ref, method, "/" + "/".join(segments), param])


def _alert(alert, target):
    if not isinstance(alert, dict):
        raise Refused("DAST-ALERT-SHAPE")
    plugin_id = alert.get("pluginid")
    if not isinstance(plugin_id, str) or PLUGIN_ID.fullmatch(plugin_id) is None:
        raise Refused("DAST-ALERT-PLUGIN")
    alert_ref = alert.get("alertRef", plugin_id)
    if (not isinstance(alert_ref, str) or ALERT_REF.fullmatch(alert_ref) is None
            or alert_ref.partition("-")[0] != plugin_id):
        raise Refused("DAST-ALERT-PLUGIN")
    risk, confidence, cwe = alert.get("riskcode"), alert.get("confidence"), alert.get("cweid")
    if not isinstance(risk, str) or risk not in RISKS:
        raise Refused("DAST-ALERT-RISK")
    if not isinstance(confidence, str) or confidence not in CONFIDENCES:
        raise Refused("DAST-ALERT-CONFIDENCE")
    if not isinstance(cwe, str) or CWE_ID.fullmatch(cwe) is None:
        raise Refused("DAST-ALERT-CWE")
    instances = alert.get("instances")
    if not isinstance(instances, list) or not instances or len(instances) > ITEM_LIMIT:
        raise Refused("DAST-ALERT-INSTANCES")
    for instance in instances:
        if not isinstance(instance, dict):
            raise Refused("DAST-INSTANCE-SHAPE")
        method, param = instance.get("method"), instance.get("param", "")
        if not isinstance(method, str) or method not in METHODS:
            raise Refused("DAST-INSTANCE-METHOD")
        if not isinstance(param, str) or len(param) > PARAM_LIMIT:
            raise Refused("DAST-INSTANCE-PARAM")
        segments = on_target(instance.get("uri"), target, "DAST-INSTANCE-URL")
        yield {
            "plugin_id": plugin_id, "alert_ref": alert_ref, "risk": RISKS[risk], "confidence": CONFIDENCES[confidence],
            "cwe_id": int(cwe), "method": method, "fingerprint": fingerprint(alert_ref, method, segments, param),
        }


def parse_alerts(data, policy, target):
    """Shape-check a ZAP traditional JSON report; every site must be the preflighted target.

    Returns (version, items). Unknown keys are ignored and never echoed; parser fidelity is unverified.
    """
    document = json_document(data, ALERTS_LIMIT, "DAST-ALERTS")
    if not isinstance(document, dict) or not {"@version", "site"} <= set(document):
        raise Refused("DAST-ALERTS-SHAPE")
    if document.get("@programName", "ZAP") != "ZAP":
        raise Refused("DAST-ALERTS-PROGRAM")
    version, sites = document["@version"], document["site"]
    if not isinstance(version, str) or VERSION.fullmatch(version) is None:
        raise Refused("DAST-ALERTS-VERSION")
    if not isinstance(sites, list) or len(sites) > 64:
        raise Refused("DAST-ALERTS-SHAPE")
    items = []
    for site in sites:
        if not isinstance(site, dict) or not isinstance(site.get("alerts"), list):
            raise Refused("DAST-SITE-SHAPE")
        if preflight_target(site.get("@name"), policy, "DAST-SITE")["origin"] != target["origin"]:
            raise Refused("DAST-SITE-OFF-TARGET")
        if len(site["alerts"]) > ITEM_LIMIT:
            raise Refused("DAST-SITE-SHAPE")
        for alert in site["alerts"]:
            items.extend(_alert(alert, target))
            if len(items) > ITEM_LIMIT:
                raise Refused("DAST-ALERTS-SIZE")
    return version, items


def coverage(entries, scanned):
    """IDs of the expected-surface entries no scanned URL covers (same auth kind, method and path shape).

    A `{name}` template segment matches any one path segment; literal segments match exactly. Scanned paths are
    indexed only at the first literal position of some template, so memory stays linear in the scanned set no
    matter how deep a hostile manifest's paths are.
    """
    shapes = []
    positions = {}
    for entry in entries:
        group = (entry["authenticated"], entry["method"], len(entry["segments"]))
        literals = [(position, part) for position, part in enumerate(entry["segments"]) if not part.startswith("{")]
        shapes.append((entry["id"], group, literals))
        if literals:
            positions.setdefault(group, set()).add(literals[0][0])
    groups, index = set(), {}
    for authenticated, method, segments, _context in scanned:
        group = (authenticated, method, len(segments))
        groups.add(group)
        for position in positions.get(group, ()):
            index.setdefault(group + (position, segments[position]), []).append(segments)
    missing = []
    for identifier, group, literals in shapes:
        if not literals:
            covered = group in groups
        else:
            candidates = index.get(group + literals[0], ())
            covered = any(all(segments[position] == part for position, part in literals) for segments in candidates)
        if not covered:
            missing.append(identifier)
    return sorted(missing)


def risk_mode(item, policy, today):
    """`block` unless the alert's plugin is inside a recorded warn window (`warn`); there is no report-only mode."""
    if item["risk"] not in policy["blocking"]:
        raise Refused("DAST-POLICY-RISK")
    window = policy["warn"].get(item["plugin_id"])
    return "warn" if window is not None and window[0] <= today <= window[1] else "block"


def evaluate(alerts_data, manifest_data, surface_data, policy, today):
    """Gate one DAST run: digest bindings and targets are refused first, then incomplete fails, then blocking alerts."""
    manifest = parse_manifest(manifest_data, policy)
    if sha256_bytes(alerts_data) != manifest["alerts_sha256"]:
        raise Refused("DAST-MANIFEST-ALERTS-DIGEST")
    surface_sha256, entries = parse_surface(surface_data)
    if surface_sha256 != manifest["surface_sha256"]:
        raise Refused("DAST-MANIFEST-SURFACE-DIGEST")
    version, items = parse_alerts(alerts_data, policy, manifest["target"])
    if version != manifest["version"]:
        raise Refused("DAST-ALERTS-VERSION-MISMATCH")
    used = {context for _auth, _method, _segments, context in manifest["scanned"]}
    kinds = list(manifest["contexts"].values())
    empty = sum(name not in used for name in manifest["contexts"])
    missing = coverage(entries, manifest["scanned"])
    findings = sorted(
        (dict(item, mode=risk_mode(item, policy, today)) for item in items),
        key=lambda item: (item["plugin_id"], item["alert_ref"], item["method"], item["fingerprint"], item["risk"],
                          item["confidence"], item["cwe_id"]),
    )
    counts = {"block": 0, "warn": 0}
    by_risk = {risk: 0 for risk in RISKS.values()}
    for item in findings:
        counts[item["mode"]] += 1
        by_risk[item["risk"]] += 1
    if True not in kinds:
        reason = "DAST-INCOMPLETE-NO-AUTHENTICATED-CONTEXT"
    elif False not in kinds:
        reason = "DAST-INCOMPLETE-NO-UNAUTHENTICATED-CONTEXT"
    elif empty:
        reason = "DAST-INCOMPLETE-EMPTY-CONTEXT"
    elif missing:
        reason = "DAST-INCOMPLETE-SURFACE"
    elif counts["block"]:
        reason = "DAST-BLOCKING-FINDINGS"
    else:
        reason = None
    return {
        "schema": REPORT_SCHEMA, "vocabulary_status": VOCABULARY_STATUS, "policy_status": PROPOSED,
        "parser_fidelity": PARSER_FIDELITY, "decision": "pass" if reason is None else "fail", "reason": reason,
        "complete": reason in (None, "DAST-BLOCKING-FINDINGS"),
        "scanner": {"name": "zap", "version": version, "kind": "dast"},
        "target_class": manifest["target"]["class"], "evaluated_on": today.isoformat(),
        "contexts": {"authenticated": kinds.count(True), "unauthenticated": kinds.count(False), "empty": empty},
        "scanned_url_count": len(manifest["scanned"]),
        "surface": {"expected": len(entries), "covered": len(entries) - len(missing), "missing": missing},
        "counts": {"blocking": counts["block"], "warning": counts["warn"], "by_risk": by_risk},
        "expired_warnings": sorted(plugin for plugin, window in policy["warn"].items() if today > window[1]),
        "exceptions": {"status": EXCEPTIONS_STATUS, "planned_binding": PLANNED_EXCEPTIONS_BINDING, "count": 0},
        "findings": findings,
    }


def _print(report):
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


FLAGS = ("--alerts", "--manifest", "--surface", "--policy")


def _arguments(argv):
    """`--alerts`, `--manifest` and `--surface` exactly once, `--policy` at most once; anything else is refused."""
    values = {}
    if len(argv) % 2:
        raise Refused("USAGE")
    for flag, value in zip(argv[::2], argv[1::2]):
        if flag not in FLAGS or flag in values or not value:
            raise Refused("USAGE")
        values[flag] = value
    if not set(FLAGS[:3]) <= set(values):
        raise Refused("USAGE")
    return values


def main(argv=None, *, clock=None):
    """CLI; ``clock`` is a test seam returning the UTC date the warn windows are judged against."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["-h"], ["--help"]):
        print(__doc__.strip())
        return 0
    today = (clock or (lambda: datetime.datetime.now(datetime.timezone.utc).date()))()
    try:
        values = _arguments(argv)
        policy = load_policy(Path(values.get("--policy", POLICY_FILE)))
        alerts = read_bounded(values["--alerts"], ALERTS_LIMIT, "DAST-ALERTS-UNREADABLE")
        manifest = read_bounded(values["--manifest"], MANIFEST_LIMIT, "DAST-MANIFEST-UNREADABLE")
        surface = read_bounded(values["--surface"], SURFACE_LIMIT, "DAST-SURFACE-UNREADABLE")
        report = evaluate(alerts, manifest, surface, policy, today)
    except Refused as error:
        _print({"schema": REPORT_SCHEMA, "decision": "refused", "reason": error.code})
        return 2
    _print(report)
    return 0 if report["decision"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
