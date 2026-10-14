"""Bounded JUnit ingestion and attempt combination (PenniLogic/infra#28; TS-M17).

Each negative has a passing control and exactly one mutation, and asserts the exact static refusal code.
"""

from pathlib import Path
import unittest
from unittest import mock

import qa_gates_support as qs
import qa_gates_junit as junit
from qa_gates_common import Refused


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "qa_gates"
VALID = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<testsuites>\n'
    '<testsuite name="s" tests="1" failures="0" errors="0" skipped="0">\n'
    '{case}\n'
    '</testsuite>\n'
    '</testsuites>\n'
)
CASE = '<testcase classname="c.K" name="t"/>'


def document(case=CASE, template=VALID):
    return template.replace("{case}", case).encode("utf-8")


class JunitCase(unittest.TestCase):
    def assertRefused(self, code, data, test=None):
        with self.assertRaises(Refused) as caught:
            junit.parse_attempt(data)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(caught.exception.test, test)


class ParseTests(JunitCase):
    def test_valid_attempt_yields_identities_and_outcomes(self):
        attempt = junit.parse_attempt(qs.junit_xml(qs.cases(
            ("test_a", "passed"), ("test_b", "failed"), ("test_c", "error"), ("test_d", "skipped"))))
        self.assertEqual(attempt.cases, {
            qs.identity(name="test_a"): "passed", qs.identity(name="test_b"): "failed",
            qs.identity(name="test_c"): "error", qs.identity(name="test_d"): "skipped",
        })
        self.assertEqual(len(attempt.sha256), 64)
        single = junit.parse_attempt(qs.junit_xml(qs.cases(("test_a", "passed")), root="testsuite", declaration=False))
        self.assertEqual(single.cases, {qs.identity(name="test_a"): "passed"})

    def test_duplicate_junit_case_refused(self):
        junit.parse_attempt(qs.junit_xml(qs.cases(("test_a", "passed"), ("test_b", "passed"))))
        self.assertRefused("JUNIT-DUPLICATE-CASE", qs.junit_xml(qs.cases(("test_a", "passed"), ("test_a", "passed"))),
                           qs.identity(name="test_a"))

    def test_duplicate_across_suites_with_the_same_name_refused(self):
        two = ('<testsuites><testsuite name="s" tests="1" failures="0" errors="0" skipped="0">{one}</testsuite>'
               '<testsuite name="s" tests="1" failures="0" errors="0" skipped="0">{two}</testsuite></testsuites>')
        junit.parse_attempt(two.format(one=CASE, two=CASE.replace('"t"', '"u"')).encode("utf-8"))
        self.assertRefused("JUNIT-DUPLICATE-CASE", two.format(one=CASE, two=CASE).encode("utf-8"), "s::c.K::t")

    def test_dtd_and_entity_declarations_refused(self):
        junit.parse_attempt(document())
        for label, prefix in (
            ("internal", '<!DOCTYPE testsuites [<!ENTITY x "y">]>\n'),
            ("expansion", '<!DOCTYPE testsuites [<!ENTITY a "aa"><!ENTITY b "&a;&a;&a;&a;">]>\n'),
            ("external", '<!DOCTYPE testsuites SYSTEM "file:///synthetic-not-read.dtd">\n'),
            ("bare", "<!DOCTYPE testsuites>\n"),
        ):
            with self.subTest(label=label):
                template = VALID.replace("<testsuites>\n", prefix + "<testsuites>\n", 1)
                self.assertRefused("JUNIT-DTD", document(template=template))

    def test_undeclared_entity_refused(self):
        junit.parse_attempt(document('<testcase classname="c.K" name="t &amp; u"/>'))
        self.assertRefused("JUNIT-ENTITY", document('<testcase classname="c.K" name="t &synthetic; u"/>'))

    def test_processing_instruction_refused(self):
        junit.parse_attempt(document('<!-- comment -->' + CASE))
        self.assertRefused("JUNIT-PI", document('<?synthetic data?>' + CASE))

    def test_size_bound_is_exact(self):
        data = document()
        with mock.patch.object(junit, "MAX_BYTES", len(data)):
            junit.parse_attempt(data)
        with mock.patch.object(junit, "MAX_BYTES", len(data) - 1):
            self.assertRefused("JUNIT-SIZE", data)
        self.assertRefused("JUNIT-SIZE", b"")

    def test_depth_bound_is_exact(self):
        properties = '<testcase classname="c.K" name="t"><properties><property name="p" value="v"/></properties></testcase>'
        junit.parse_attempt(document(properties))
        nested = properties.replace('<property name="p" value="v"/>',
                                    '<property name="p" value="v"><property name="q" value="w"/></property>')
        self.assertRefused("JUNIT-DEPTH", document(nested))

    def test_element_bound_and_case_bound_are_exact(self):
        data = qs.junit_xml(qs.cases(("test_a", "passed"), ("test_b", "passed")))
        with mock.patch.object(junit, "MAX_CASES", 2):
            junit.parse_attempt(data)
        with mock.patch.object(junit, "MAX_CASES", 1):
            self.assertRefused("JUNIT-LIMIT", data)
        with mock.patch.object(junit, "MAX_ELEMENTS", 4):
            junit.parse_attempt(data)
        with mock.patch.object(junit, "MAX_ELEMENTS", 3):
            self.assertRefused("JUNIT-LIMIT", data)

    def test_attribute_count_bound_is_exact(self):
        attributes = " ".join(f'a{index}="v"' for index in range(junit.MAX_ATTRIBUTES - 2))
        junit.parse_attempt(document(f'<testcase classname="c.K" name="t" {attributes}/>'))
        self.assertRefused("JUNIT-LIMIT", document(f'<testcase classname="c.K" name="t" {attributes} extra="v"/>'))

    def test_unknown_or_misplaced_element_refused(self):
        junit.parse_attempt(document('<testcase classname="c.K" name="t"><system-out>o</system-out></testcase>'))
        for label, case in (
            ("unknown", '<testcase classname="c.K" name="t"><synthetic/></testcase>'),
            ("nested-case", '<testcase classname="c.K" name="t"><testcase classname="c.K" name="u"/></testcase>'),
            ("child-of-failure", '<testcase classname="c.K" name="t"><failure><detail/></failure></testcase>'),
            ("prefixed", '<testcase classname="c.K" name="t"><x:skipped xmlns:x="urn:synthetic"/></testcase>'),
        ):
            with self.subTest(label=label):
                self.assertRefused("JUNIT-ELEMENT", document(case))

    def test_in_file_rerun_elements_refused(self):
        junit.parse_attempt(document('<testcase classname="c.K" name="t"><system-err>e</system-err></testcase>'))
        for name in sorted(junit.RERUN_ELEMENTS):
            with self.subTest(element=name):
                self.assertRefused("JUNIT-RERUN-ELEMENT",
                                   document(f'<testcase classname="c.K" name="t"><{name} message="m"/></testcase>'))

    def test_suite_counters_are_required_and_exact(self):
        junit.parse_attempt(document())
        for label, replacement in (
            ("tests-off-by-one", 'tests="2"'), ("missing-tests", ""), ("signed", 'tests="+1"'),
            ("leading-zero", 'tests="01"'), ("non-ascii-digit", 'tests="\u0661"'),
        ):
            with self.subTest(label=label):
                self.assertRefused("JUNIT-COUNTS", document(template=VALID.replace('tests="1"', replacement, 1)))
        failing = '<testcase classname="c.K" name="t"><failure/></testcase>'
        self.assertRefused("JUNIT-COUNTS", document(failing))
        self.assertEqual(
            junit.parse_attempt(document(failing, VALID.replace('failures="0"', 'failures="1"'))).cases,
            {"s::c.K::t": "failed"},
        )

    def test_root_counters_when_present_are_exact(self):
        template = VALID.replace("<testsuites>", '<testsuites tests="1" failures="0">', 1)
        junit.parse_attempt(document(template=template))
        self.assertRefused("JUNIT-COUNTS", document(template=template.replace('<testsuites tests="1"', '<testsuites tests="2"')))

    def test_identity_rules(self):
        longest = "n" * 512
        junit.parse_attempt(document(f'<testcase classname="c.K" name="{longest}"/>'))
        for label, case in (
            ("too-long", f'<testcase classname="c.K" name="{longest}n"/>'),
            ("missing-classname", '<testcase name="t"/>'),
            ("empty-name", '<testcase classname="c.K" name=""/>'),
            ("separator", '<testcase classname="c.K" name="a::b"/>'),
            ("edge-colon", '<testcase classname="c.K:" name="t"/>'),
            ("control", '<testcase classname="c.K" name="a&#10;b"/>'),
            ("whitespace", '<testcase classname="c.K" name=" t"/>'),
        ):
            with self.subTest(label=label):
                self.assertRefused("JUNIT-IDENTITY", document(case))
        self.assertRefused("JUNIT-IDENTITY", document(template=VALID.replace('name="s" ', "", 1)))

    def test_one_outcome_element_per_case(self):
        junit.parse_attempt(document('<testcase classname="c.K" name="t"><skipped/></testcase>',
                                     VALID.replace('skipped="0"', 'skipped="1"')))
        self.assertRefused("JUNIT-AMBIGUOUS-OUTCOME",
                           document('<testcase classname="c.K" name="t"><skipped/><failure/></testcase>',
                                    VALID.replace('skipped="0"', 'skipped="1"')), "s::c.K::t")

    def test_encoding_must_be_utf8(self):
        junit.parse_attempt(document(template=VALID.replace('encoding="UTF-8"', 'encoding="utf-8"')))
        junit.parse_attempt(b"\xef\xbb\xbf" + document())
        self.assertRefused("JUNIT-ENCODING", document(template=VALID.replace('encoding="UTF-8"', 'encoding="ISO-8859-1"')))
        self.assertRefused("JUNIT-ENCODING", document().replace(b'name="t"', b'name="\xe9"'))

    def test_malformed_or_empty_documents_refused(self):
        junit.parse_attempt(document())
        self.assertRefused("JUNIT-MALFORMED", document().replace(b"</testsuites>", b"</testsuite>"))
        self.assertRefused("JUNIT-MALFORMED", document(template=VALID.replace('version="1.0"', 'version="1.1"')))
        empty = '<testsuites><testsuite name="s" tests="0" failures="0" errors="0" skipped="0"/></testsuites>'
        self.assertRefused("JUNIT-EMPTY", empty.encode("utf-8"))

    def test_failure_text_is_never_retained(self):
        planted = "synthetic-planted-message-7f3a"
        attempt = junit.parse_attempt(document(
            f'<testcase classname="c.K" name="t"><failure message="{planted}">{planted}</failure></testcase>',
            VALID.replace('failures="0"', 'failures="1"')))
        self.assertNotIn(planted, repr(attempt))


class FixtureShapeTests(JunitCase):
    """Committed synthetic samples shaped after documented producer output (fidelity unverified)."""

    def test_producer_shaped_samples_parse(self):
        expected = {
            "gradle-shaped.xml": {"passed": 2, "failed": 1, "skipped": 1},
            "pytest-shaped.xml": {"passed": 1, "failed": 1, "error": 1, "skipped": 1},
            "vitest-shaped.xml": {"passed": 2, "failed": 1},
        }
        for name, counts in expected.items():
            with self.subTest(fixture=name):
                attempt = junit.parse_attempt((FIXTURES / name).read_bytes())
                observed = {}
                for outcome in attempt.cases.values():
                    observed[outcome] = observed.get(outcome, 0) + 1
                self.assertEqual(observed, counts)

    def test_surefire_shaped_rerun_sample_refused(self):
        self.assertRefused("JUNIT-RERUN-ELEMENT", (FIXTURES / "surefire-rerun-shaped.xml").read_bytes())


class CombinationTests(unittest.TestCase):
    def attempts(self, *items):
        return [junit.parse_attempt(qs.junit_xml(cases)) for cases in items]

    def test_flake_pass_on_retry_is_not_clean(self):
        clean = junit.combine(self.attempts(qs.cases(("test_a", "passed"))), 1)
        self.assertEqual(clean.outcomes, {qs.identity(name="test_a"): "passed"})
        flaky = junit.combine(self.attempts(qs.cases(("test_a", "failed")), qs.cases(("test_a", "passed"))), 1)
        self.assertEqual(flaky.outcomes, {qs.identity(name="test_a"): "flaky"})
        self.assertFalse(flaky.over_limit)

    def test_failure_that_persists_or_is_not_reexecuted_is_real(self):
        for label, later in (("fails-again", [qs.cases(("test_a", "failed"))]),
                             ("errors-again", [qs.cases(("test_a", "error"))]),
                             ("skipped-on-retry", [qs.cases(("test_a", "skipped"))]),
                             ("not-reexecuted", [])):
            with self.subTest(label=label):
                combination = junit.combine(self.attempts(qs.cases(("test_a", "failed"), ("test_b", "passed")), *later), 1)
                self.assertEqual(combination.outcomes[qs.identity(name="test_a")], "failed")
                self.assertEqual(combination.outcomes[qs.identity(name="test_b")], "passed")

    def test_reexecution_beyond_the_allowance_never_clears_a_failure(self):
        attempts = self.attempts(qs.cases(("test_a", "failed")), qs.cases(("test_a", "passed")))
        self.assertEqual(junit.combine(attempts, 1).outcomes[qs.identity(name="test_a")], "flaky")
        zero = junit.combine(attempts, 0)
        self.assertEqual(zero.outcomes[qs.identity(name="test_a")], "failed")
        self.assertTrue(zero.over_limit)

    def test_reexecution_of_a_case_that_did_not_fail_is_refused(self):
        junit.combine(self.attempts(qs.cases(("test_a", "failed")), qs.cases(("test_a", "passed"))), 1)
        for label, code, first, later in (
            ("passed-first", "ATTEMPT-NOT-A-FAILURE", qs.cases(("test_a", "passed"), ("test_b", "failed")),
             qs.cases(("test_a", "passed"))),
            ("skipped-first", "ATTEMPT-NOT-A-FAILURE", qs.cases(("test_a", "skipped"), ("test_b", "failed")),
             qs.cases(("test_a", "passed"))),
            ("unknown", "ATTEMPT-UNKNOWN-CASE", qs.cases(("test_b", "failed")), qs.cases(("test_a", "passed"))),
        ):
            with self.subTest(label=label):
                with self.assertRaises(Refused) as caught:
                    junit.combine(self.attempts(first, later), 1)
                self.assertEqual((caught.exception.code, caught.exception.test), (code, qs.identity(name="test_a")))

    def test_third_attempt_must_reexecute_a_second_attempt_failure(self):
        first = qs.cases(("test_a", "failed"), ("test_b", "failed"))
        junit.combine(self.attempts(first, qs.cases(("test_a", "failed"), ("test_b", "passed")),
                                    qs.cases(("test_a", "passed"))), 1)
        with self.assertRaises(Refused) as caught:
            junit.combine(self.attempts(first, qs.cases(("test_a", "failed"), ("test_b", "passed")),
                                        qs.cases(("test_b", "passed"))), 1)
        self.assertEqual(caught.exception.code, "ATTEMPT-NOT-A-FAILURE")


if __name__ == "__main__":
    unittest.main()
