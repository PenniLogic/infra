"""Bounded JUnit XML ingestion for the infra#28 quarantine gate: one report per test attempt.

Accepted shape (the infra#22 JUnit rules plus explicit bounds): a `testsuites` root holding `testsuite`
elements, or a single `testsuite` root; `testcase` elements directly inside a suite; every suite declares
`tests`, `failures`, `errors` and `skipped` and they equal what it contains; at most one of `failure`, `error`
or `skipped` per case. No DOCTYPE, entity or notation declaration, external entity or processing instruction is
admitted, the declared encoding must be UTF-8, and size, depth, element, attribute and case counts are bounded.
In-file re-run elements (`rerunFailure`, `flakyFailure`, ...) are refused: a retry inside one report would hide
an attempt. The identity of a case is `suite::classname::name`; duplicates are refused. Text content (failure
messages, captured output) is never retained.

Attempts form a chain: attempt k+1 may contain only cases that failed or errored in attempt k. A pass on
re-execution makes the case `flaky` (a flake event), never `passed`.
"""

from dataclasses import dataclass
import hashlib
import re
from xml.parsers import expat

from qa_gates_common import Refused, make_test_id


MAX_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 5
MAX_ELEMENTS = 400000
MAX_CASES = 100000
MAX_ATTRIBUTES = 64
COUNTERS = ("tests", "failures", "errors", "skipped")
COUNTER = re.compile(r"0|[1-9][0-9]{0,8}")
CHILDREN = {
    None: frozenset({"testsuites", "testsuite"}),
    "testsuites": frozenset({"testsuite"}),
    "testsuite": frozenset({"properties", "testcase", "system-out", "system-err"}),
    "testcase": frozenset({"failure", "error", "skipped", "system-out", "system-err", "properties"}),
    "properties": frozenset({"property"}),
}
RERUN_ELEMENTS = frozenset({"rerunFailure", "rerunError", "flakyFailure", "flakyError"})
OUTCOME_ELEMENTS = {"failure": "failed", "error": "error", "skipped": "skipped"}
FAILED = frozenset({"failed", "error"})


@dataclass(frozen=True)
class Attempt:
    """One parsed report: identity -> passed | failed | error | skipped, in document order."""

    cases: dict
    sha256: str
    size: int


@dataclass(frozen=True)
class Combination:
    """Per-test run outcome over the permitted attempts: passed | failed | flaky | skipped."""

    outcomes: dict
    observed_reexecutions: int
    allowed_reexecutions: int
    reexecuted: frozenset

    @property
    def over_limit(self):
        return self.observed_reexecutions > self.allowed_reexecutions


def _refuse(code):
    def handler(*_arguments):
        raise Refused(code)
    return handler


def _counters(attributes, required):
    values = {}
    for name in COUNTERS:
        value = attributes.get(name)
        if value is None:
            if required:
                raise Refused("JUNIT-COUNTS")
            continue
        if COUNTER.fullmatch(value) is None:
            raise Refused("JUNIT-COUNTS")
        values[name] = int(value)
    return values


class _Reader:
    def __init__(self):
        self.stack = []
        self.elements = 0
        self.cases = {}
        self.root_counters = None
        self.totals = dict.fromkeys(COUNTERS, 0)
        self.suite = None
        self.case = None

    def declaration(self, version, encoding, _standalone):
        if version != "1.0":
            raise Refused("JUNIT-MALFORMED")
        if encoding is not None and encoding.lower() != "utf-8":
            raise Refused("JUNIT-ENCODING")

    def start(self, name, attributes):
        self.elements += 1
        if self.elements > MAX_ELEMENTS or len(attributes) > MAX_ATTRIBUTES:
            raise Refused("JUNIT-LIMIT")
        if len(self.stack) >= MAX_DEPTH:
            raise Refused("JUNIT-DEPTH")
        parent = self.stack[-1] if self.stack else None
        if parent == "testcase" and name in RERUN_ELEMENTS:
            raise Refused("JUNIT-RERUN-ELEMENT")
        if name not in CHILDREN.get(parent, frozenset()):
            raise Refused("JUNIT-ELEMENT")
        self.stack.append(name)
        if name == "testsuites":
            self.root_counters = _counters(attributes, required=False)
        elif name == "testsuite":
            suite_name = attributes.get("name")
            self.suite = {
                "name": suite_name, "declared": _counters(attributes, required=True),
                "actual": dict.fromkeys(COUNTERS, 0),
            }
        elif name == "testcase":
            identity = make_test_id(self.suite["name"], attributes.get("classname"), attributes.get("name"))
            self.case = {"id": identity, "outcomes": []}
        elif name in OUTCOME_ELEMENTS:
            self.case["outcomes"].append(OUTCOME_ELEMENTS[name])

    def end(self, name):
        self.stack.pop()
        if name == "testcase":
            case, self.case = self.case, None
            if len(case["outcomes"]) > 1:
                raise Refused("JUNIT-AMBIGUOUS-OUTCOME", case["id"])
            if case["id"] in self.cases:
                raise Refused("JUNIT-DUPLICATE-CASE", case["id"])
            if len(self.cases) >= MAX_CASES:
                raise Refused("JUNIT-LIMIT")
            outcome = case["outcomes"][0] if case["outcomes"] else "passed"
            self.cases[case["id"]] = outcome
            actual = self.suite["actual"]
            actual["tests"] += 1
            counter = {"failed": "failures", "error": "errors", "skipped": "skipped"}.get(outcome)
            if counter is not None:
                actual[counter] += 1
        elif name == "testsuite":
            suite, self.suite = self.suite, None
            if suite["declared"] != suite["actual"]:
                raise Refused("JUNIT-COUNTS")
            for counter in COUNTERS:
                self.totals[counter] += suite["actual"][counter]
        elif name == "testsuites":
            if any(self.root_counters[counter] != self.totals[counter] for counter in self.root_counters):
                raise Refused("JUNIT-COUNTS")


def parse_attempt(data):
    """Parse one attempt's JUnit XML bytes; any deviation from the accepted shape is refused."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise Refused("JUNIT-SIZE")
    try:
        document = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("JUNIT-ENCODING") from None
    if document.startswith("\ufeff"):
        document = document[1:]
    reader = _Reader()
    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.XmlDeclHandler = reader.declaration
    parser.StartDoctypeDeclHandler = _refuse("JUNIT-DTD")
    parser.EntityDeclHandler = _refuse("JUNIT-DTD")
    parser.UnparsedEntityDeclHandler = _refuse("JUNIT-DTD")
    parser.NotationDeclHandler = _refuse("JUNIT-DTD")
    parser.ExternalEntityRefHandler = _refuse("JUNIT-ENTITY")
    parser.SkippedEntityHandler = _refuse("JUNIT-ENTITY")
    parser.ProcessingInstructionHandler = _refuse("JUNIT-PI")
    parser.StartElementHandler = reader.start
    parser.EndElementHandler = reader.end
    try:
        parser.Parse(document, True)
    except expat.ExpatError as error:
        undefined = expat.errors.codes[expat.errors.XML_ERROR_UNDEFINED_ENTITY]
        raise Refused("JUNIT-ENTITY" if error.code == undefined else "JUNIT-MALFORMED") from None
    if not reader.cases:
        raise Refused("JUNIT-EMPTY")
    return Attempt(cases=reader.cases, sha256=hashlib.sha256(data).hexdigest(), size=len(data))


def check_chain(attempts):
    """Refuse a re-execution that names a case the previous attempt did not fail."""
    if not attempts:
        raise Refused("JUNIT-EMPTY")
    first = attempts[0].cases
    for previous, current in zip(attempts, attempts[1:]):
        for identity in current.cases:
            if identity not in first:
                raise Refused("ATTEMPT-UNKNOWN-CASE", identity)
            if previous.cases.get(identity) not in FAILED:
                raise Refused("ATTEMPT-NOT-A-FAILURE", identity)


def combine(attempts, allowed_reexecutions):
    """Classify every case of the first attempt using at most ``allowed_reexecutions`` re-executions.

    Attempts beyond the allowance are validated but never used to clear a failure.
    """
    if type(allowed_reexecutions) is not int or allowed_reexecutions < 0:
        raise Refused("ATTEMPT-ALLOWANCE")
    check_chain(attempts)
    permitted = attempts[1:1 + allowed_reexecutions]
    outcomes = {}
    for identity, first in attempts[0].cases.items():
        if first not in FAILED:
            outcomes[identity] = first
            continue
        outcome = "failed"
        for attempt in permitted:
            later = attempt.cases.get(identity)
            if later is None or later == "skipped":
                break
            if later == "passed":
                outcome = "flaky"
                break
        outcomes[identity] = outcome
    reexecuted = frozenset(identity for attempt in attempts[1:] for identity in attempt.cases)
    return Combination(
        outcomes=outcomes, observed_reexecutions=len(attempts) - 1,
        allowed_reexecutions=allowed_reexecutions, reexecuted=reexecuted,
    )
