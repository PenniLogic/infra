"""Ingestion of checkov- and trivy-shaped JSON reports for the PenniLogic/infra#31 gates (T-QA-11).

Real scanner execution, versions and CI wiring are held; this module reads report bytes only. A report that is
incomplete, errored, empty, inconsistent with its own summary, or not bound to the expected artifact is refused
(fail closed); it never yields an empty success. Scanner-native suppressions (trivy ``EXCEPTION`` status, checkov
``skipped_checks``) are not honored: exceptions come only from PenniLogic/infra#23 once it integrates. A finding
without a scanner severity (trivy ``UNKNOWN``, checkov ``null``) is normalised fail-closed to ``high`` with
``severity_basis`` ``unrated``. Package names, targets, file paths and resources are bound into fingerprints and
never published.
"""

from supply_chain_common import (
    ARTIFACT_ID, DIGEST, REPORT_LIMIT, RULE_ID, Refused, finding, json_document, pattern,
)


SCANNER_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
UNRATED = {None, "UNKNOWN"}
ITEM_LIMIT = 100000
TRIVY_KINDS = {"image": ("container_image",), "config": ("filesystem",)}
TRIVY_PACKAGE_CLASSES = {"os-pkgs", "lang-pkgs"}
TRIVY_OUT_OF_SCOPE = {"secret", "license", "license-file"}
TRIVY_CLASSES = TRIVY_PACKAGE_CLASSES | TRIVY_OUT_OF_SCOPE | {"config", "custom"}


def _severity(value, code):
    if value in UNRATED:
        return "high", "unrated"
    if isinstance(value, str) and value in SCANNER_SEVERITY:
        return SCANNER_SEVERITY[value], "scanner"
    raise Refused(code)


def _items(value, code):
    """An optional list (absent or null means none) of JSON objects."""
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > ITEM_LIMIT or not all(isinstance(i, dict) for i in value):
        raise Refused(code)
    return value


def _text(value, code):
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise Refused(code)
    return value


def _count(value, code):
    if type(value) is not int or value < 0:
        raise Refused(code)
    return value


def _trivy_subject(document, expected_digest):
    pattern(expected_digest, DIGEST, "SC-TRIVY-SUBJECT")
    metadata = document.get("Metadata")
    if not isinstance(metadata, dict):
        raise Refused("SC-TRIVY-SUBJECT")
    repo_digests = _items_or_strings(metadata.get("RepoDigests"))
    if metadata.get("ImageID") != expected_digest and not any(
            entry.endswith("@" + expected_digest) for entry in repo_digests):
        raise Refused("SC-TRIVY-SUBJECT")


def _items_or_strings(value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 1000 or not all(isinstance(i, str) for i in value):
        raise Refused("SC-TRIVY-SUBJECT")
    return value


def trivy_findings(data, artifact_id, kind, expected_digest=None):
    """Findings of one ``trivy image|config --format json`` (SchemaVersion 2) report.

    ``kind`` is ``image`` (requires ``expected_digest`` ``sha256:<hex>`` matching ImageID or a RepoDigest) or
    ``config``. An image report yields container package vulnerabilities only: it must contain at least one
    ``os-pkgs`` or ``lang-pkgs`` result; ``secret`` and licence results are ignored (T-QA-04/other owners) and
    any other class is refused. A config report (ArtifactType ``filesystem``) yields misconfigurations only:
    every result must be Class ``config`` with a ``MisconfSummary`` and no vulnerabilities, secrets or
    licences. Repository dependency advisories and secret findings are T-QA-04/infra#23 scope and refused
    (``SC-TRIVY-SCOPE``).
    """
    pattern(artifact_id, ARTIFACT_ID, "SC-TRIVY-ARTIFACT")
    if kind not in TRIVY_KINDS:
        raise Refused("SC-TRIVY-KIND")
    document = json_document(data, REPORT_LIMIT, "SC-TRIVY")
    if not isinstance(document, dict) or document.get("SchemaVersion") != 2 or type(
            document.get("SchemaVersion")) is not int:
        raise Refused("SC-TRIVY-SCHEMA")
    if document.get("ArtifactType") not in TRIVY_KINDS[kind]:
        raise Refused("SC-TRIVY-KIND")
    if kind == "image":
        _trivy_subject(document, expected_digest)
    elif expected_digest is not None:
        raise Refused("SC-TRIVY-SUBJECT")
    results = _items(document.get("Results"), "SC-TRIVY-SHAPE")
    if not results:
        raise Refused("SC-TRIVY-INCOMPLETE")
    found, scanned = [], False
    for result in results:
        target = _text(result.get("Target"), "SC-TRIVY-SHAPE")
        result_class = _text(result.get("Class"), "SC-TRIVY-SHAPE")
        if result_class not in TRIVY_CLASSES:
            raise Refused("SC-TRIVY-SHAPE")
        if kind == "image":
            if result_class in TRIVY_OUT_OF_SCOPE:
                continue  # secret and licence results belong to T-QA-04/other owners, not this gate
            if result_class not in TRIVY_PACKAGE_CLASSES:
                raise Refused("SC-TRIVY-SCOPE")
            _absent(result, ("Misconfigurations", "MisconfSummary"))
            scanned = True
            found.extend(_trivy_vulnerabilities(result, artifact_id, target))
        else:
            if result_class != "config":
                raise Refused("SC-TRIVY-SCOPE")
            _absent(result, ("Vulnerabilities", "Secrets", "Licenses"))
            scanned = True
            found.extend(_trivy_misconfigurations(result, artifact_id, target))
    if not scanned:
        raise Refused("SC-TRIVY-INCOMPLETE")
    return found


def _absent(result, keys):
    """Data this kind of report must not carry (dependency, secret or licence review is out of scope)."""
    if any(result.get(key) not in (None, []) for key in keys):
        raise Refused("SC-TRIVY-SCOPE")


def _trivy_vulnerabilities(result, artifact_id, target):
    found = []
    for item in _items(result.get("Vulnerabilities"), "SC-TRIVY-SHAPE"):
        rule = pattern(item.get("VulnerabilityID"), RULE_ID, "SC-TRIVY-SHAPE")
        severity, basis = _severity(item.get("Severity"), "SC-TRIVY-SHAPE")
        package = _text(item.get("PkgName"), "SC-TRIVY-SHAPE")
        version = item.get("InstalledVersion", "")
        found.append(finding("trivy", rule, severity, artifact_id, "image.package", target, package,
                             str(version), basis=basis))
    return found


def _trivy_misconfigurations(result, artifact_id, target):
    found, failures, exceptions = [], 0, 0
    for item in _items(result.get("Misconfigurations"), "SC-TRIVY-SHAPE"):
        status = item.get("Status")
        if status not in ("FAIL", "PASS", "EXCEPTION"):
            raise Refused("SC-TRIVY-SHAPE")
        rule = pattern(item.get("ID"), RULE_ID, "SC-TRIVY-SHAPE")
        severity, basis = _severity(item.get("Severity"), "SC-TRIVY-SHAPE")
        if status == "PASS":
            continue
        failures += status == "FAIL"
        exceptions += status == "EXCEPTION"
        cause = item.get("CauseMetadata") if isinstance(item.get("CauseMetadata"), dict) else {}
        found.append(finding("trivy", rule, severity, artifact_id, "iac.resource", target,
                             str(cause.get("Resource", "")), str(cause.get("StartLine", "")), basis=basis))
    summary = result.get("MisconfSummary")
    if summary is None:
        raise Refused("SC-TRIVY-INCOMPLETE")  # every config result must show the misconfiguration scan ran
    if not isinstance(summary, dict):
        raise Refused("SC-TRIVY-SHAPE")
    if (_count(summary.get("Failures"), "SC-TRIVY-INCOMPLETE") != failures
            or _count(summary.get("Exceptions", 0), "SC-TRIVY-INCOMPLETE") != exceptions):
        raise Refused("SC-TRIVY-INCOMPLETE")
    return found


CHECKOV_FRAMEWORKS = {
    "ansible", "arm", "bicep", "cloudformation", "dockerfile", "github_actions", "gitlab_ci", "helm", "kubernetes",
    "kustomize", "serverless", "terraform", "terraform_json", "terraform_plan",
}  # infrastructure-as-code only; secrets and sca_* results are T-QA-04/infra#23 scope (SC-CHECKOV-SCOPE)
CHECKOV_LISTS = ("passed_checks", "failed_checks", "skipped_checks", "parsing_errors")
CHECKOV_COUNTS = (("passed", "passed_checks"), ("failed", "failed_checks"), ("skipped", "skipped_checks"))


def _checkov_section(section, artifact_id):
    if not isinstance(section, dict):
        raise Refused("SC-CHECKOV-SHAPE")
    results, summary = section.get("results"), section.get("summary")
    if "results" not in section and ("summary" in section or "resource_count" in section):
        raise Refused("SC-CHECKOV-INCOMPLETE")  # checkov's bare summary object: nothing was scanned
    if _text(section.get("check_type"), "SC-CHECKOV-SHAPE") not in CHECKOV_FRAMEWORKS:
        raise Refused("SC-CHECKOV-SCOPE")
    if not isinstance(results, dict) or not isinstance(summary, dict):
        raise Refused("SC-CHECKOV-SHAPE")
    lists = {}
    for key in CHECKOV_LISTS:
        value = results.get(key, [])
        if not isinstance(value, list) or len(value) > ITEM_LIMIT:
            raise Refused("SC-CHECKOV-SHAPE")
        lists[key] = value
    if lists["parsing_errors"] or _count(summary.get("parsing_errors"), "SC-CHECKOV-INCOMPLETE"):
        raise Refused("SC-CHECKOV-INCOMPLETE")
    if not _count(summary.get("resource_count"), "SC-CHECKOV-INCOMPLETE"):
        raise Refused("SC-CHECKOV-INCOMPLETE")
    for count, key in CHECKOV_COUNTS:
        if _count(summary.get(count), "SC-CHECKOV-INCOMPLETE") != len(lists[key]):
            raise Refused("SC-CHECKOV-INCOMPLETE")
    found = []
    for key in ("failed_checks", "skipped_checks"):
        for item in lists[key]:
            if not isinstance(item, dict):
                raise Refused("SC-CHECKOV-SHAPE")
            rule = pattern(item.get("check_id"), RULE_ID, "SC-CHECKOV-SHAPE")
            severity, basis = _severity(item.get("severity"), "SC-CHECKOV-SHAPE")
            found.append(finding("checkov", rule, severity, artifact_id, "iac.resource",
                                 str(item.get("file_path", "")), str(item.get("resource", "")), basis=basis))
    return found


def checkov_findings(data, artifact_id):
    """Findings of one ``checkov -o json`` report (one framework object or a list of them).

    Parsing errors, zero scanned resources, a bare summary or counts that disagree with the listed checks make
    the report incomplete. Skipped checks are treated as failed: inline skips are not an infra#23 exception.
    Only infrastructure-as-code frameworks are accepted; ``secrets`` and ``sca_*`` sections are refused.
    """
    pattern(artifact_id, ARTIFACT_ID, "SC-CHECKOV-ARTIFACT")
    document = json_document(data, REPORT_LIMIT, "SC-CHECKOV")
    sections = document if isinstance(document, list) else [document]
    if not sections or len(sections) > 100:
        raise Refused("SC-CHECKOV-INCOMPLETE")
    found = []
    for section in sections:
        found.extend(_checkov_section(section, artifact_id))
    return found
