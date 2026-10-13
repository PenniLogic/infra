"""CycloneDX SBOM completeness and artifact binding of the PenniLogic/infra#31 supply-chain gates (T-QA-11).

Input is one CycloneDX JSON document (specVersion 1.4-1.6) as bytes plus the SHA-256 the caller computed from the
artifact bytes. A document that is not strict JSON, not a CycloneDX object or structurally malformed is refused.
Completeness gaps are findings (``SC-SBOM-*``, high): every component, at any nesting depth, needs a name,
version, ``pkg:`` purl and at least one well-formed strong hash; ``bom-ref`` values are unique and every
dependency reference resolves. The binding to the artifact is a never-exceptable critical finding
(``SC-SUBJECT-SBOM-*``): ``metadata.component`` must carry a SHA-256 hash equal to the artifact digest.

Linking the SBOM from the release record is owned by PenniLogic/docs#23 and is held.
"""

import re

from supply_chain_common import ARTIFACT_ID, REPORT_LIMIT, SHA256, Refused, finding, json_document, pattern


SCANNER = "builtin-sbom"
SPEC_VERSIONS = ("1.4", "1.5", "1.6")
SERIAL = re.compile(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
PURL = re.compile(r"pkg:[A-Za-z.+-][A-Za-z0-9.+-]*/[^\s]+")
# Strong algorithms only; MD5 and SHA-1 never satisfy completeness.
HASH_LENGTHS = {"SHA-256": 64, "SHA-384": 96, "SHA-512": 128, "SHA3-256": 64, "SHA3-384": 96, "SHA3-512": 128}
HEX = re.compile(r"[0-9a-fA-F]+")
COMPONENT_LIMIT = 100000
DEPTH_LIMIT = 16
LIST_LIMIT = 10000


def _list(value, code, limit=LIST_LIMIT):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > limit:
        raise Refused(code)
    return value


def _text(value):
    return isinstance(value, str) and value.strip() != "" and len(value) <= 4096


def _hashes(value):
    """``{alg: lower-case hex}`` of well-formed strong hashes; None when any entry is malformed."""
    entries = _list(value, "SC-SBOM-SHAPE", 64)
    result = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("alg"), str) or not isinstance(
                entry.get("content"), str):
            return None
        length = HASH_LENGTHS.get(entry["alg"])
        if length is None:
            continue
        content = entry["content"]
        if len(content) != length or HEX.fullmatch(content) is None:
            return None
        if result.setdefault(entry["alg"], content.lower()) != content.lower():
            return None
    return result


def _walk(components, depth, path, out):
    """Flatten ``components`` (and nested ones) depth-first into ``(index path, component)`` pairs."""
    if depth > DEPTH_LIMIT:
        raise Refused("SC-SBOM-SHAPE")
    for index, component in enumerate(_list(components, "SC-SBOM-SHAPE")):
        if not isinstance(component, dict):
            raise Refused("SC-SBOM-SHAPE")
        where = path + (str(index),)
        out.append((where, component))
        if len(out) > COMPONENT_LIMIT:
            raise Refused("SC-SBOM-SIZE")
        _walk(component.get("components"), depth + 1, where, out)
    return out


def _bom_ref(component, refs, add, where):
    ref = component.get("bom-ref")
    if ref is None:
        return
    if not isinstance(ref, str) or not ref:
        raise Refused("SC-SBOM-SHAPE")
    if ref in refs:
        add("SC-SBOM-BOM-REF-DUPLICATE", "high", "sbom.component", *where)
    refs.add(ref)


def _component(component, add, where):
    if not _text(component.get("name")):
        add("SC-SBOM-COMPONENT-NAME", "high", "sbom.component", *where)
    if not _text(component.get("version")):
        add("SC-SBOM-COMPONENT-VERSION", "high", "sbom.component", *where)
    purl = component.get("purl")
    if not isinstance(purl, str) or len(purl) > 4096 or PURL.fullmatch(purl) is None:
        add("SC-SBOM-COMPONENT-PURL", "high", "sbom.component", *where)
    if not _hashes(component.get("hashes")):
        add("SC-SBOM-COMPONENT-HASH", "high", "sbom.component", *where)


def _dependencies(value, refs, add):
    for index, entry in enumerate(_list(value, "SC-SBOM-SHAPE")):
        if not isinstance(entry, dict) or not isinstance(entry.get("ref"), str):
            raise Refused("SC-SBOM-SHAPE")
        targets = _list(entry.get("dependsOn"), "SC-SBOM-SHAPE")
        if not all(isinstance(target, str) for target in targets):
            raise Refused("SC-SBOM-SHAPE")
        for position, ref in enumerate([entry["ref"]] + targets):
            if ref not in refs:
                add("SC-SBOM-DEPENDENCY-DANGLING", "high", "sbom.dependency", str(index), str(position))


def sbom_findings(data, artifact_id, artifact_sha256):
    """Findings for one CycloneDX JSON SBOM (bytes) of the artifact whose SHA-256 is ``artifact_sha256``."""
    pattern(artifact_id, ARTIFACT_ID, "SC-SBOM-ARTIFACT")
    pattern(artifact_sha256, SHA256, "SC-SBOM-SUBJECT")
    document = json_document(data, REPORT_LIMIT, "SC-SBOM")
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise Refused("SC-SBOM-FORMAT")
    if document.get("specVersion") not in SPEC_VERSIONS:
        raise Refused("SC-SBOM-SPEC")
    metadata = document.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        raise Refused("SC-SBOM-SHAPE")
    found = []

    def add(rule, severity, location_class, *where):
        found.append(finding(SCANNER, rule, severity, artifact_id, location_class, *where))

    serial = document.get("serialNumber")
    if not isinstance(serial, str) or SERIAL.fullmatch(serial) is None:
        add("SC-SBOM-SERIAL", "high", "sbom.document")
    subject = (metadata or {}).get("component")
    refs = set()
    if subject is None:
        add("SC-SUBJECT-SBOM-MISSING", "critical", "sbom.subject")
    elif not isinstance(subject, dict):
        raise Refused("SC-SBOM-SHAPE")
    else:
        _bom_ref(subject, refs, add, ("metadata",))
        digests = _hashes(subject.get("hashes"))
        if not digests or "SHA-256" not in digests:
            add("SC-SUBJECT-SBOM-MISSING", "critical", "sbom.subject")
        elif digests["SHA-256"] != artifact_sha256:
            add("SC-SUBJECT-SBOM-MISMATCH", "critical", "sbom.subject", digests["SHA-256"])
    components = _walk(document.get("components"), 1, (), [])
    if not components:
        add("SC-SBOM-COMPONENTS-EMPTY", "high", "sbom.document")
    for where, component in components:
        _bom_ref(component, refs, add, where)
        _component(component, add, where)
    _dependencies(document.get("dependencies"), refs, add)
    return found
