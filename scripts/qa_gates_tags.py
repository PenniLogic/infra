"""Protected-tag manifest for the infra#28 quarantine gate: committed, separately reviewed, fails closed.

Tests are classified only by this manifest, never by a quarantine request (E25-F01: a requester could omit a
tag). A rule matches a test identity component (`classname` or `suite`) either as a `package` (equal, or a
prefix followed by `.`) or as a `path` (equal, or a prefix followed by `/`). A test's tags are the union of
its matching rules' tags plus `money` when its package is a money-path package; it is protected when it has
any tag. No matching rule means the classification is unknown, and matching rules that name different packages
make it ambiguous; the gate fails closed on both. Jobs declare the packages they run; a job is a money-path job
when any declared package is, and then gets the money-path retry limit.
"""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re

from qa_gates_common import (
    JOB_ID, HANDLE, REFERENCE, REPOSITORY, Refused, array, exact, json_document, pattern, read_bounded,
    split_test_id, text,
)


MANIFEST_FILE = Path(__file__).resolve().parent / "qa-gates" / "protected-tests.json"
MANIFEST_LIMIT = 1024 * 1024
SCHEMA = "pennilogic.qa-gates.protected-tests/1"
TAGS = frozenset({"money", "privacy", "security"})
FIELDS = ("suite", "classname")
KINDS = ("package", "path")
STATUSES = ("proposed", "confirmed")
DOCUMENT_KEYS = ("schema", "repository", "status", "confirmation_ref", "packages", "rules", "jobs")
PACKAGE_KEYS = ("id", "money_path", "owner", "basis")
RULE_KEYS = ("id", "field", "kind", "value", "package", "tags", "reason")
JOB_KEYS = ("id", "workflow", "job", "packages")
PACKAGE_ID = re.compile(r"([a-z][a-z0-9_]*)\.([a-z][a-z0-9_]*)")
RULE_ID = re.compile(r"PT-[0-9]{3}")
PACKAGE_VALUE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*")
PATH_VALUE = re.compile(r"(?!\.{1,2}(?:/|\Z))[A-Za-z0-9_.-]+(?:/(?!\.{1,2}(?:/|\Z))[A-Za-z0-9_.-]+)*")
WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml")
WORKFLOW_JOB = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,99}")


@dataclass(frozen=True)
class Package:
    id: str
    money_path: bool
    owner: str | None


@dataclass(frozen=True)
class Rule:
    id: str
    field: str
    kind: str
    value: str
    package: str
    tags: frozenset

    def matches(self, components):
        candidate = components[0] if self.field == "suite" else components[1]
        boundary = "." if self.kind == "package" else "/"
        return candidate == self.value or candidate.startswith(self.value + boundary)


@dataclass(frozen=True)
class Job:
    id: str
    workflow: str
    job: str
    packages: tuple
    money_path: bool


@dataclass(frozen=True)
class Classification:
    """``state`` is known, unknown or ambiguous; only a known classification names a package."""

    state: str
    package: Package | None
    tags: frozenset
    rules: tuple

    @property
    def protected(self):
        return self.state != "known" or bool(self.tags)

    @property
    def money_path(self):
        return self.state != "known" or self.package.money_path


@dataclass(frozen=True)
class Manifest:
    repository: str
    status: str
    confirmation_ref: str | None
    packages: dict
    rules: tuple
    jobs: dict
    sha256: str

    def classify(self, identity):
        components = split_test_id(identity, "MANIFEST-TEST-ID")
        matched = tuple(rule for rule in self.rules if rule.matches(components))
        if not matched:
            return Classification("unknown", None, frozenset(), ())
        names = {rule.package for rule in matched}
        if len(names) != 1:
            return Classification("ambiguous", None, frozenset(), tuple(rule.id for rule in matched))
        package = self.packages[names.pop()]
        tags = frozenset().union(*(rule.tags for rule in matched))
        if package.money_path:
            tags |= {"money"}
        return Classification("known", package, tags, tuple(rule.id for rule in matched))


def _package(value, repository):
    record = exact(value, PACKAGE_KEYS, "MANIFEST-KEYS")
    identity = pattern(record["id"], PACKAGE_ID, "MANIFEST-VALUE")
    if PACKAGE_ID.fullmatch(identity).group(1) != repository.split("/")[1].replace("-", "_"):
        raise Refused("MANIFEST-VALUE")
    if type(record["money_path"]) is not bool:
        raise Refused("MANIFEST-VALUE")
    if record["owner"] is not None:
        pattern(record["owner"], HANDLE, "MANIFEST-VALUE")
    text(record["basis"], "MANIFEST-VALUE")
    return Package(identity, record["money_path"], record["owner"])


def _rule(value, packages):
    record = exact(value, RULE_KEYS, "MANIFEST-KEYS")
    pattern(record["id"], RULE_ID, "MANIFEST-VALUE")
    if record["field"] not in FIELDS or record["kind"] not in KINDS:
        raise Refused("MANIFEST-VALUE")
    pattern(record["value"], PACKAGE_VALUE if record["kind"] == "package" else PATH_VALUE, "MANIFEST-VALUE")
    if len(record["value"]) > 512:
        raise Refused("MANIFEST-VALUE")
    if not isinstance(record["package"], str):
        raise Refused("MANIFEST-VALUE")
    if record["package"] not in packages:
        raise Refused("MANIFEST-UNKNOWN-PACKAGE")
    tags = array(record["tags"], "MANIFEST-VALUE", 3)
    if not all(isinstance(tag, str) and tag in TAGS for tag in tags) or tags != sorted(set(tags)):
        raise Refused("MANIFEST-VALUE")
    text(record["reason"], "MANIFEST-VALUE")
    return Rule(record["id"], record["field"], record["kind"], record["value"], record["package"], frozenset(tags))


def _job(value, packages):
    record = exact(value, JOB_KEYS, "MANIFEST-KEYS")
    pattern(record["id"], JOB_ID, "MANIFEST-VALUE")
    pattern(record["workflow"], WORKFLOW, "MANIFEST-VALUE")
    pattern(record["job"], WORKFLOW_JOB, "MANIFEST-VALUE")
    names = array(record["packages"], "MANIFEST-VALUE", 256)
    if not names or not all(isinstance(name, str) for name in names) or names != sorted(set(names)):
        raise Refused("MANIFEST-VALUE")
    if any(name not in packages for name in names):
        raise Refused("MANIFEST-UNKNOWN-PACKAGE")
    return Job(record["id"], record["workflow"], record["job"], tuple(names),
               any(packages[name].money_path for name in names))


def parse_manifest(data):
    document = exact(json_document(data, MANIFEST_LIMIT, "MANIFEST"), DOCUMENT_KEYS, "MANIFEST-KEYS")
    if document["schema"] != SCHEMA:
        raise Refused("MANIFEST-SCHEMA")
    repository = pattern(document["repository"], REPOSITORY, "MANIFEST-VALUE")
    if document["status"] not in STATUSES:
        raise Refused("MANIFEST-VALUE")
    # A confirmed manifest names where the owner confirmed it; a proposed one must not pretend to.
    if (document["status"] == "confirmed") != (document["confirmation_ref"] is not None):
        raise Refused("MANIFEST-STATUS")
    if document["confirmation_ref"] is not None:
        pattern(document["confirmation_ref"], REFERENCE, "MANIFEST-VALUE")
    packages = {}
    for value in array(document["packages"], "MANIFEST-VALUE", 1024):
        package = _package(value, repository)
        if package.id in packages:
            raise Refused("MANIFEST-DUPLICATE")
        packages[package.id] = package
    rules, rule_ids, rule_keys = [], set(), set()
    for value in array(document["rules"], "MANIFEST-VALUE", 4096):
        rule = _rule(value, packages)
        if rule.id in rule_ids or (rule.field, rule.kind, rule.value) in rule_keys:
            raise Refused("MANIFEST-DUPLICATE")
        rule_ids.add(rule.id)
        rule_keys.add((rule.field, rule.kind, rule.value))
        rules.append(rule)
    jobs = {}
    for value in array(document["jobs"], "MANIFEST-VALUE", 1024):
        job = _job(value, packages)
        if job.id in jobs or any((job.workflow, job.job) == (other.workflow, other.job) for other in jobs.values()):
            raise Refused("MANIFEST-DUPLICATE")
        jobs[job.id] = job
    if not packages or not rules or not jobs:
        raise Refused("MANIFEST-VALUE")
    return Manifest(repository, document["status"], document["confirmation_ref"], packages, tuple(rules), jobs,
                    hashlib.sha256(data).hexdigest())


def load_manifest(path=MANIFEST_FILE):
    data = read_bounded(path, MANIFEST_LIMIT, "MANIFEST-UNREADABLE")
    return parse_manifest(data)
