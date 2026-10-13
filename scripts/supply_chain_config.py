"""Built-in configuration rules of the PenniLogic/infra#31 gates over JSON and XML renderings (T-QA-11).

Compose: the JSON rendering produced by ``docker compose config --format json`` (long-form volumes and ports).
Producing that rendering in CI is held wiring; here the rules read the rendering's bytes. Android: the merged
release ``AndroidManifest.xml`` text and, when referenced, its network-security-config XML text.

Rule IDs and severities are *proposed, not agreed*; they await the infra#31 Security and QA reviews. Reports
carry rule IDs, severities, artifact ids, location classes and fingerprints only; service, component and host
names are bound into fingerprints and never published.
"""

import re
from xml.etree import ElementTree

from supply_chain_common import ARTIFACT_ID, DOCUMENT_LIMIT, Refused, finding, json_document, pattern


SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
IMAGE_DIGEST = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}")
DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock", "//./pipe/docker_engine", "\\\\.\\pipe\\docker_engine")
DANGEROUS_CAPABILITIES = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"}
UNCONFINED = re.compile(r"(?:seccomp|apparmor)[:=]unconfined|label[:=]disable", re.IGNORECASE)
LOOPBACK = {"127.0.0.1", "::1"}
HOST_NAMESPACES = ("network_mode", "pid", "ipc", "userns_mode")
SERVICE_LIMIT = 500
LIST_LIMIT = 1000


def _list(value, code):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > LIST_LIMIT:
        raise Refused(code)
    return value


def _service_findings(artifact_id, name, service):
    if not isinstance(service, dict):
        raise Refused("SC-COMPOSE-SHAPE")
    found = []

    def add(rule, severity, *where):
        found.append(finding("builtin-compose", rule, severity, artifact_id, "compose.service", name, *where))

    if service.get("privileged", False) is not False:
        add("SC-COMPOSE-PRIVILEGED", "critical")
    for key in HOST_NAMESPACES:
        if service.get(key) == "host":
            add("SC-COMPOSE-HOST-NAMESPACE", "high", key)
    for index, volume in enumerate(_list(service.get("volumes"), "SC-COMPOSE-SHAPE")):
        if not isinstance(volume, dict) or not isinstance(volume.get("source", ""), str):
            raise Refused("SC-COMPOSE-SHAPE")
        if volume.get("type") == "bind" and volume.get("source", "").rstrip("/") in DOCKER_SOCKETS:
            add("SC-COMPOSE-DOCKER-SOCKET", "critical", "volume", index)
    for capability in _list(service.get("cap_add"), "SC-COMPOSE-SHAPE"):
        if not isinstance(capability, str):
            raise Refused("SC-COMPOSE-SHAPE")
        if capability.upper().removeprefix("CAP_") in DANGEROUS_CAPABILITIES:
            add("SC-COMPOSE-CAPABILITY", "high", capability.upper())
    for option in _list(service.get("security_opt"), "SC-COMPOSE-SHAPE"):
        if not isinstance(option, str):
            raise Refused("SC-COMPOSE-SHAPE")
        if UNCONFINED.fullmatch(option.strip()):
            add("SC-COMPOSE-UNCONFINED", "high", option)
    for index, port in enumerate(_list(service.get("ports"), "SC-COMPOSE-SHAPE")):
        if not isinstance(port, dict):
            raise Refused("SC-COMPOSE-SHAPE")
        if port.get("published") not in (None, "") and port.get("host_ip") not in LOOPBACK:
            add("SC-COMPOSE-PUBLIC-PORT", "high", "port", index)
    image = service.get("image")
    if image is not None and (not isinstance(image, str) or IMAGE_DIGEST.fullmatch(image) is None):
        add("SC-COMPOSE-IMAGE-DIGEST", "medium")
    if image is None and "build" not in service:
        raise Refused("SC-COMPOSE-SHAPE")
    return found


def compose_findings(data, artifact_id):
    """Findings for one ``docker compose config --format json`` rendering given as bytes."""
    pattern(artifact_id, ARTIFACT_ID, "SC-COMPOSE-ARTIFACT")
    document = json_document(data, DOCUMENT_LIMIT, "SC-COMPOSE")
    if not isinstance(document, dict) or not isinstance(document.get("services"), dict):
        raise Refused("SC-COMPOSE-SHAPE")
    services = document["services"]
    if not services:
        raise Refused("SC-COMPOSE-EMPTY")
    if len(services) > SERVICE_LIMIT:
        raise Refused("SC-COMPOSE-SHAPE")
    found = []
    for name in sorted(services):
        pattern(name, SERVICE, "SC-COMPOSE-SHAPE")
        found.extend(_service_findings(artifact_id, name, services[name]))
    return found


ANDROID = "{http://schemas.android.com/apk/res/android}"
COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")
XML_DECLARATIONS = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)
CLEARTEXT_DEFAULT_OFF_FROM = 28


def _xml(data, prefix):
    """Parse bounded UTF-8 XML; DTDs and entity declarations are refused before parsing.

    The bytes are decoded as UTF-8 and the decoded text is what is both scanned and parsed: expat is handed a
    ``str``, which pins its encoding to UTF-8 whatever an XML declaration or byte pattern suggests, so UTF-16/32
    input cannot slip a DTD past the scan. NUL characters (never legal in XML 1.0) are refused.
    """
    if not isinstance(data, bytes) or not data or len(data) > DOCUMENT_LIMIT:
        raise Refused(prefix + "-SIZE")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused(prefix + "-XML") from None
    if "\x00" in text or XML_DECLARATIONS.search(text):
        raise Refused(prefix + "-XML")
    try:
        return ElementTree.fromstring(text)
    except (ElementTree.ParseError, ValueError, RecursionError):
        raise Refused(prefix + "-XML") from None


def _attribute(element, name):
    return element.get(ANDROID + name)


BOOLEANS = {"true": True, "TRUE": True, "True": True, "false": False, "FALSE": False, "False": False}


def _boolean(value, code="SC-ANDROID-VALUE"):
    """None when absent, else the boolean the platform parser would read (surrounding whitespace stripped and
    true/TRUE/True or false/FALSE/False accepted). Any other value, including an ``@bool/...`` resource reference
    resolved only at link time, cannot be judged from the text and is refused, never treated as safe."""
    if value is None:
        return None
    parsed = BOOLEANS.get(value.strip())
    if parsed is None:
        raise Refused(code)
    return parsed


def _launcher(component):
    for intent_filter in component.findall("intent-filter"):
        actions = {_attribute(item, "name") for item in intent_filter.findall("action")}
        categories = {_attribute(item, "name") for item in intent_filter.findall("category")}
        if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
            return True
    return False


def _protected(component):
    if _attribute(component, "permission"):
        return True
    return (component.tag == "provider" and bool(_attribute(component, "readPermission"))
            and bool(_attribute(component, "writePermission")))


def _target_sdk(manifest):
    uses = manifest.findall("uses-sdk")
    value = _attribute(uses[0], "targetSdkVersion") if len(uses) == 1 else None
    return int(value) if value is not None and value.isascii() and value.isdigit() and len(value) <= 3 else None


def _network_findings(root, artifact_id):
    if root.tag != "network-security-config":
        raise Refused("SC-ANDROID-NSC-SHAPE")
    found = []
    scopes = [("base-config", element) for element in root.iter("base-config")]
    scopes += [("domain-config", element) for element in root.iter("domain-config")]
    for index, (kind, element) in enumerate(scopes):
        if _boolean(element.get("cleartextTrafficPermitted"), "SC-ANDROID-NSC-VALUE") is True:
            found.append(finding("builtin-android", "SC-ANDROID-NSC-CLEARTEXT", "high", artifact_id,
                                 "android.network-config", kind, index))
        for anchors in element.findall("trust-anchors"):
            if any(item.get("src") == "user" for item in anchors.findall("certificates")):
                found.append(finding("builtin-android", "SC-ANDROID-NSC-USER-CA", "high", artifact_id,
                                     "android.network-config", kind, index))
    return found


def android_findings(manifest, artifact_id, network_config=None):
    """Findings for one merged release manifest (bytes) and its network-security-config (bytes or None).

    A manifest that references a network security config without it being supplied, or a supplied config the
    manifest does not reference, is incomplete input and refused.
    """
    pattern(artifact_id, ARTIFACT_ID, "SC-ANDROID-ARTIFACT")
    root = _xml(manifest, "SC-ANDROID")
    applications = root.findall("application")
    if root.tag != "manifest" or len(applications) != 1:
        raise Refused("SC-ANDROID-SHAPE")
    application = applications[0]
    found = []

    def add(rule, severity, location_class, *where):
        found.append(finding("builtin-android", rule, severity, artifact_id, location_class, *where))

    if _boolean(_attribute(application, "debuggable")) is True:
        add("SC-ANDROID-DEBUGGABLE", "critical", "android.application")
    if _boolean(_attribute(application, "allowBackup")) is not False:
        add("SC-ANDROID-ALLOW-BACKUP", "high", "android.application")
    if _boolean(_attribute(application, "requestLegacyExternalStorage")) is True:
        add("SC-ANDROID-LEGACY-STORAGE", "medium", "android.application")
    cleartext = _boolean(_attribute(application, "usesCleartextTraffic"))
    target = _target_sdk(root)
    if cleartext is True or (cleartext is None and (target is None or target < CLEARTEXT_DEFAULT_OFF_FROM)):
        add("SC-ANDROID-CLEARTEXT", "high", "android.application")
    for tag in COMPONENTS:
        for index, component in enumerate(application.findall(tag)):
            name = _attribute(component, "name") or ""
            exported = _boolean(_attribute(component, "exported"))
            if exported is None and component.findall("intent-filter"):
                add("SC-ANDROID-EXPORTED-UNDECLARED", "high", "android.component", tag, index, name)
            elif exported is True and not _protected(component) and not (
                    tag in ("activity", "activity-alias") and _launcher(component)):
                add("SC-ANDROID-EXPORTED", "high", "android.component", tag, index, name)
    referenced = _attribute(application, "networkSecurityConfig") is not None
    if referenced and network_config is None:
        raise Refused("SC-ANDROID-NSC-MISSING")
    if network_config is not None:
        if not referenced:
            raise Refused("SC-ANDROID-NSC-UNREFERENCED")
        found.extend(_network_findings(_xml(network_config, "SC-ANDROID-NSC"), artifact_id))
    return found
