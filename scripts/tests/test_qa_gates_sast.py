"""Tests of the infra#28 SAST report ingestion and severity gate (scripts/qa_gates_sast.py).

Each negative pairs a passing control with exactly one mutation and asserts the exact static rule code. Inputs are
the committed canned Semgrep report (a local-fixture input, never acceptance evidence), its provenance and
in-memory mutations; temporary copies live in the system temporary directory, never inside the repository.
"""

import contextlib
import datetime
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
import qa_gates_sast as sast
from qa_gates_scan_common import Refused


ROOT = support.ROOT
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "qa_gates_sast"
CANNED = FIXTURES / "semgrep-planted.json"
PROVENANCE = FIXTURES / "semgrep-planted.provenance.json"
TODAY = datetime.date(2026, 10, 13)
RULE_IDS = sast.load_rule_ids()
BLOCK_ALL = {rule_id: ("block", None, None) for rule_id in RULE_IDS}
EVAL_RULE = "pennilogic-python-dynamic-eval"


def canned():
    return json.loads(CANNED.read_text(encoding="utf-8"))


def dump(document):
    return (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def clean():
    """The canned report with no results: the passing control of most negatives."""
    document = canned()
    document["results"] = []
    return document


def only(rule_id):
    """The canned report reduced to the findings of one rule."""
    document = canned()
    document["results"] = [item for item in document["results"] if item["check_id"].endswith("." + rule_id)]
    return document


def gate(document, modes=None, today=TODAY, root=ROOT):
    return sast.evaluate(dump(document), root, BLOCK_ALL if modes is None else modes, today, RULE_IDS)


def warn(rule_id, start, until):
    modes = dict(BLOCK_ALL)
    modes[rule_id] = ("warn", start, until)
    return modes


class SastReportGateTests(unittest.TestCase):
    def assertRefused(self, code, function, *args):
        with self.assertRaises(Refused) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)

    def test_clean_complete_report_passes(self):
        report = gate(clean())
        self.assertEqual((report["decision"], report["reason"], report["complete"]), ("pass", None, True))
        self.assertEqual(report["scanned_path_count"], 6)
        self.assertEqual(report["counts"], {"blocking": 0, "warning": 0, "by_scanner_severity": {}})

    def test_planted_sql_injection_fails_sast(self):
        self.assertEqual(gate(clean())["decision"], "pass")
        report = gate(only("pennilogic-python-sql-built-string"))
        self.assertEqual((report["decision"], report["reason"]), ("fail", "SAST-BLOCKING-FINDINGS"))
        self.assertEqual([item["line"] for item in report["findings"]], [12, 16])
        self.assertEqual({item["rule_id"] for item in report["findings"]}, {"pennilogic-python-sql-built-string"})

    def test_every_rule_catches_its_planted_source_and_no_clean_control(self):
        report = gate(canned())
        self.assertEqual((report["decision"], report["reason"]), ("fail", "SAST-BLOCKING-FINDINGS"))
        self.assertEqual(report["counts"]["blocking"], 13)
        self.assertEqual({item["rule_id"] for item in report["findings"]}, set(RULE_IDS))
        paths = {item["path"].rsplit("/", 1)[1] for item in report["findings"]}
        self.assertEqual(paths, {"planted_injection.py", "planted-injection.ts", "PlantedInjection.kt"})

    def test_partial_semgrep_report_errors_fail(self):
        document = clean()
        document["errors"] = [{"code": 3, "level": "warn", "type": "Syntax error"}]
        report = gate(document)
        self.assertEqual((report["decision"], report["reason"], report["complete"]),
                         ("fail", "SAST-INCOMPLETE-ERRORS", False))

    def test_zero_scanned_paths_is_incomplete(self):
        document = clean()
        document["paths"]["scanned"] = []
        report = gate(document)
        self.assertEqual((report["decision"], report["reason"]), ("fail", "SAST-INCOMPLETE-NO-PATHS"))

    def test_skipped_rule_is_incomplete(self):
        document = clean()
        document["skipped_rules"] = [{"rule_id": EVAL_RULE}]
        report = gate(document)
        self.assertEqual((report["decision"], report["reason"]), ("fail", "SAST-INCOMPLETE-SKIPPED-RULES"))

    def test_incomplete_outranks_blocking_findings(self):
        self.assertEqual(gate(only(EVAL_RULE))["reason"], "SAST-BLOCKING-FINDINGS")
        document = only(EVAL_RULE)
        document["errors"] = [{"code": 2}]
        self.assertEqual(gate(document)["reason"], "SAST-INCOMPLETE-ERRORS")

    def test_missing_report_key_refused(self):
        self.assertEqual(gate(clean())["decision"], "pass")
        document = clean()
        del document["errors"]
        self.assertRefused("SAST-REPORT-SHAPE", gate, document)

    def test_duplicate_json_key_refused(self):
        data = dump(clean())
        self.assertEqual(sast.evaluate(data, ROOT, BLOCK_ALL, TODAY)["decision"], "pass")
        mutated = data.replace(b'"errors": []', b'"errors": [], "errors": []', 1)
        self.assertRefused("SAST-REPORT-JSON", sast.evaluate, mutated, ROOT, BLOCK_ALL, TODAY)

    def test_report_version_grammar_refused(self):
        document = clean()
        document["version"] = "latest"
        self.assertRefused("SAST-REPORT-VERSION", gate, document)
    def test_report_version_control(self):
        self.assertEqual(gate(clean())["scanner"], {"name": "semgrep", "version": "1.178.0", "kind": "sast"})


    def test_warning_rule_does_not_fail_but_counts(self):
        self.assertEqual(gate(only(EVAL_RULE))["reason"], "SAST-BLOCKING-FINDINGS")
        report = gate(only(EVAL_RULE), warn(EVAL_RULE, TODAY, TODAY + datetime.timedelta(days=7)))
        self.assertEqual((report["decision"], report["reason"]), ("pass", None))
        self.assertEqual((report["counts"]["blocking"], report["counts"]["warning"]), (0, 1))
        self.assertEqual(report["findings"][0]["mode"], "warn")

    def test_expired_warning_rule_becomes_blocking(self):
        modes = warn(EVAL_RULE, TODAY - datetime.timedelta(days=7), TODAY)
        control = gate(only(EVAL_RULE), modes, TODAY)
        self.assertEqual((control["decision"], control["expired_warnings"]), ("pass", []))
        report = gate(only(EVAL_RULE), modes, TODAY + datetime.timedelta(days=1))
        self.assertEqual((report["decision"], report["reason"]), ("fail", "SAST-BLOCKING-FINDINGS"))
        self.assertEqual(report["expired_warnings"], [EVAL_RULE])

    def test_warning_window_not_started_blocks(self):
        modes = warn(EVAL_RULE, TODAY, TODAY + datetime.timedelta(days=3))
        self.assertEqual(gate(only(EVAL_RULE), modes, TODAY)["decision"], "pass")
        report = gate(only(EVAL_RULE), modes, TODAY - datetime.timedelta(days=1))
        self.assertEqual((report["decision"], report["reason"]), ("fail", "SAST-BLOCKING-FINDINGS"))

    def test_warning_on_one_rule_keeps_other_rules_blocking(self):
        modes = warn(EVAL_RULE, TODAY, TODAY + datetime.timedelta(days=1))
        self.assertEqual(gate(only(EVAL_RULE), modes)["decision"], "pass")
        document = only(EVAL_RULE)
        document["results"] += only("pennilogic-kotlin-runtime-exec")["results"]
        report = gate(document, modes)
        self.assertEqual((report["decision"], report["counts"]["blocking"], report["counts"]["warning"]),
                         ("fail", 1, 1))

    def test_unknown_rule_blocks_even_when_every_known_rule_warns(self):
        modes = {rule_id: ("warn", TODAY, TODAY + datetime.timedelta(days=1)) for rule_id in RULE_IDS}
        self.assertEqual(gate(only(EVAL_RULE), modes)["decision"], "pass")
        document = only(EVAL_RULE)
        document["results"][0]["check_id"] = "vendor.rules.python-eval"
        report = gate(document, modes)
        self.assertEqual((report["decision"], report["reason"]), ("fail", "SAST-BLOCKING-FINDINGS"))
        self.assertEqual(report["findings"][0]["rule_id"], "vendor.rules.python-eval")

    def test_check_id_prefix_maps_to_the_rule_id(self):
        document = only(EVAL_RULE)
        self.assertEqual(gate(document)["findings"][0]["rule_id"], EVAL_RULE)
        document["results"][0]["check_id"] = EVAL_RULE
        self.assertEqual(gate(document)["findings"][0]["rule_id"], EVAL_RULE)
        document["results"][0]["check_id"] = "x" + EVAL_RULE
        self.assertEqual(gate(document)["findings"][0]["rule_id"], "x" + EVAL_RULE)

    def test_check_id_grammar_refused(self):
        document = only(EVAL_RULE)
        self.assertEqual(gate(document)["decision"], "fail")
        document["results"][0]["check_id"] = "bad id"
        self.assertRefused("SAST-RESULT-RULE", gate, document)

    def test_result_outside_scanned_paths_refused(self):
        document = only(EVAL_RULE)
        self.assertEqual(gate(document)["decision"], "fail")
        document["paths"]["scanned"].remove(document["results"][0]["path"])
        self.assertRefused("SAST-RESULT-PATH-NOT-SCANNED", gate, document)

    def test_result_path_traversal_refused(self):
        document = only(EVAL_RULE)
        document["results"][0]["path"] = "scripts/../scripts/qa-gates/fixtures/planted/python/planted_injection.py"
        self.assertRefused("SAST-RESULT-PATH", gate, document)

    def test_result_span_past_end_of_source_refused(self):
        document = only(EVAL_RULE)
        self.assertEqual(gate(document)["decision"], "fail")
        document["results"][0]["end"]["offset"] = 10 ** 7
        self.assertRefused("SAST-RESULT-SPAN", gate, document)

    def test_dot_directory_path_accepted_but_dot_segments_refused(self):
        document = clean()
        document["paths"]["scanned"].append(".github/scripts/check.py")
        self.assertEqual(gate(document)["scanned_path_count"], 7)
        for bad in ("scripts/./check.py", "/etc/passwd", "C:/x.py", "a//b.py"):
            document = clean()
            document["paths"]["scanned"].append(bad)
            self.assertRefused("SAST-REPORT-PATH", gate, document)

    def test_result_empty_span_refused(self):
        document = only(EVAL_RULE)
        document["results"][0]["end"]["offset"] = document["results"][0]["start"]["offset"]
        self.assertRefused("SAST-RESULT-SPAN", gate, document)

    def test_result_position_type_refused(self):
        document = only(EVAL_RULE)
        document["results"][0]["start"]["line"] = True
        self.assertRefused("SAST-RESULT-POSITION", gate, document)

    def test_result_severity_outside_semgrep_levels_refused(self):
        document = only(EVAL_RULE)
        document["results"][0]["extra"]["severity"] = "error"
        self.assertRefused("SAST-RESULT-SEVERITY", gate, document)

    def test_missing_source_file_refused(self):
        document = only(EVAL_RULE)
        with tempfile.TemporaryDirectory() as empty:
            self.assertRefused("SAST-SOURCE-UNREADABLE", gate, document, None, TODAY, Path(empty))


    def test_fingerprint_binds_rule_path_and_matched_span(self):
        result = only(EVAL_RULE)["results"][0]
        source = (ROOT / result["path"]).read_bytes()
        span = source[result["start"]["offset"]:result["end"]["offset"]]
        self.assertEqual(span, b"eval(expression)")
        expected = sast.fingerprint(EVAL_RULE, result["path"], span)
        self.assertEqual(gate(only(EVAL_RULE))["findings"][0]["fingerprint"], expected)
        self.assertRegex(expected, r"\Asha256:[0-9a-f]{64}\Z")
        self.assertNotEqual(sast.fingerprint(EVAL_RULE, result["path"], b"eval(other)"), expected)
        self.assertNotEqual(sast.fingerprint("pennilogic-other", result["path"], span), expected)
        self.assertNotEqual(sast.fingerprint(EVAL_RULE, "other/" + result["path"], span), expected)

    def test_fingerprint_ignores_semgrep_fingerprint_lines_and_line_number(self):
        expected = gate(only(EVAL_RULE))["findings"][0]["fingerprint"]
        document = only(EVAL_RULE)
        document["results"][0]["extra"].update(fingerprint="changed", lines="changed")
        document["results"][0]["start"]["line"] = 1
        self.assertEqual(gate(document)["findings"][0]["fingerprint"], expected)

    def test_windows_separator_normalizes_to_the_same_finding(self):
        expected = gate(only(EVAL_RULE))["findings"][0]
        document = only(EVAL_RULE)
        document["results"][0]["path"] = document["results"][0]["path"].replace("/", "\\")
        self.assertEqual(gate(document)["findings"][0], expected)

    def test_report_contains_no_message_snippet_or_metadata(self):
        document = canned()
        output = json.dumps(gate(document))
        for result in document["results"]:
            self.assertNotIn(result["extra"]["message"], output)
        for forbidden in ("requires login", "SELECT", "CWE-", "synthetic_accounts", "eval(", "metadata", "PenniLogic/infra#28"):
            self.assertNotIn(forbidden, output)
        finding_keys = {key for item in gate(document)["findings"] for key in item}
        self.assertEqual(finding_keys, {"rule_id", "scanner_severity", "path", "line", "fingerprint", "mode"})

    def test_exceptions_are_unavailable_until_infra_23_integrates(self):
        report = gate(canned())
        self.assertEqual(report["exceptions"], {"status": "unavailable: infra#23 not integrated",
                                                "planned_binding": "security_exceptions.Exceptions.suppression",
                                                "count": 0})
        self.assertEqual(report["vocabulary_status"], "proposed, pending infra#23 owner alignment")
        self.assertEqual(report["rule_set_status"], "proposed, not agreed")


def policy_document():
    return json.loads(sast.POLICY_FILE.read_text(encoding="utf-8"))


def policy_bytes(document):
    return dump(document)


class SastPolicyTests(unittest.TestCase):
    def assertRefused(self, code, function, *args):
        with self.assertRaises(Refused) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)

    def test_committed_policy_blocks_every_rule(self):
        modes = sast.load_policy()
        self.assertEqual(tuple(sorted(modes)), RULE_IDS)
        self.assertEqual(set(modes.values()), {("block", None, None)})
        self.assertEqual(len(RULE_IDS), 8)
        self.assertIsNone(policy_document()["decision_ref"])

    def test_warn_window_of_seven_days_accepted_and_eight_refused(self):
        document = policy_document()
        document["rules"][EVAL_RULE] = {"mode": "warn", "warn_from": "2026-10-13", "warn_until": "2026-10-20"}
        self.assertEqual(sast.parse_policy(policy_bytes(document), RULE_IDS)[EVAL_RULE],
                         ("warn", datetime.date(2026, 10, 13), datetime.date(2026, 10, 20)))
        document["rules"][EVAL_RULE]["warn_until"] = "2026-10-21"
        self.assertRefused("SAST-POLICY-WARN-WINDOW", sast.parse_policy, policy_bytes(document), RULE_IDS)

    def test_warn_without_expiry_refused(self):
        document = policy_document()
        document["rules"][EVAL_RULE] = {"mode": "warn", "warn_from": "2026-10-13", "warn_until": "2026-10-14"}
        sast.parse_policy(policy_bytes(document), RULE_IDS)
        del document["rules"][EVAL_RULE]["warn_until"]
        self.assertRefused("SAST-POLICY-WARN", sast.parse_policy, policy_bytes(document), RULE_IDS)

    def test_warn_until_not_after_warn_from_refused(self):
        document = policy_document()
        document["rules"][EVAL_RULE] = {"mode": "warn", "warn_from": "2026-10-13", "warn_until": "2026-10-13"}
        self.assertRefused("SAST-POLICY-WARN-WINDOW", sast.parse_policy, policy_bytes(document), RULE_IDS)

    def test_invalid_calendar_date_refused(self):
        document = policy_document()
        document["rules"][EVAL_RULE] = {"mode": "warn", "warn_from": "2026-02-27", "warn_until": "2026-02-30"}
        self.assertRefused("SAST-POLICY-WARN", sast.parse_policy, policy_bytes(document), RULE_IDS)

    def test_block_with_extra_key_refused(self):
        document = policy_document()
        document["rules"][EVAL_RULE] = {"mode": "block", "warn_until": "2026-10-14"}
        self.assertRefused("SAST-POLICY-MODE", sast.parse_policy, policy_bytes(document), RULE_IDS)

    def test_unknown_mode_refused(self):
        document = policy_document()
        document["rules"][EVAL_RULE] = {"mode": "off"}
        self.assertRefused("SAST-POLICY-MODE", sast.parse_policy, policy_bytes(document), RULE_IDS)

    def test_policy_rule_set_must_equal_rule_files(self):
        document = policy_document()
        del document["rules"][EVAL_RULE]
        self.assertRefused("SAST-POLICY-RULES", sast.parse_policy, policy_bytes(document), RULE_IDS)

    def test_recorded_decision_reference_refused(self):
        document = policy_document()
        document["decision_ref"] = "PenniLogic/infra#28"
        self.assertRefused("SAST-POLICY-DECISION", sast.parse_policy, policy_bytes(document), RULE_IDS)

    def test_policy_claiming_agreement_refused(self):
        document = policy_document()
        document["status"] = "agreed"
        self.assertRefused("SAST-POLICY-SCHEMA", sast.parse_policy, policy_bytes(document), RULE_IDS)

    def test_policy_extra_key_refused(self):
        document = policy_document()
        document["severity_threshold"] = "high"
        self.assertRefused("SAST-POLICY-KEYS", sast.parse_policy, policy_bytes(document), RULE_IDS)



@contextlib.contextmanager
def copied_root():
    """A temporary root holding copies of the rule files and planted sources (never inside the repository)."""
    with tempfile.TemporaryDirectory() as directory:
        for relative in ("scripts/qa-gates/rules", "scripts/qa-gates/fixtures/planted"):
            shutil.copytree(ROOT / relative, Path(directory, relative))
        yield Path(directory)


def edit_json(path, change):
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    path.write_bytes(dump(document))


class SastRuleFileTests(unittest.TestCase):
    def assertRefused(self, code, function, *args):
        with self.assertRaises(Refused) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)

    def test_rule_files_load_from_a_copy(self):
        with copied_root() as root:
            self.assertEqual(sast.load_rule_ids(root / "scripts/qa-gates/rules"), RULE_IDS)

    def test_rule_without_proposed_status_refused(self):
        with copied_root() as root:
            rules = root / "scripts/qa-gates/rules"
            edit_json(rules / "python.yml", lambda document: document["rules"][0]["metadata"].update(status="agreed"))
            self.assertRefused("SAST-RULES-STATUS", sast.load_rule_ids, rules)

    def test_duplicate_rule_id_refused(self):
        with copied_root() as root:
            rules = root / "scripts/qa-gates/rules"
            edit_json(rules / "kotlin.yml",
                      lambda document: document["rules"][1].update(id="pennilogic-python-dynamic-eval"))
            self.assertRefused("SAST-RULES-DUPLICATE", sast.load_rule_ids, rules)

    def test_rule_id_outside_namespace_refused(self):
        with copied_root() as root:
            rules = root / "scripts/qa-gates/rules"
            edit_json(rules / "kotlin.yml", lambda document: document["rules"][1].update(id="Kotlin.Exec"))
            self.assertRefused("SAST-RULES-ID", sast.load_rule_ids, rules)

    def test_empty_rule_directory_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertRefused("SAST-RULES-EMPTY", sast.load_rule_ids, Path(directory))


class SastCannedReportBindingTests(unittest.TestCase):
    def assertRefused(self, code, function, *args):
        with self.assertRaises(Refused) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)

    def setUp(self):
        self.report = CANNED.read_bytes()
        self.provenance = PROVENANCE.read_bytes()

    def test_canned_report_is_bound_to_current_rules_and_planted_sources(self):
        provenance = sast.verify_canned(self.report, self.provenance, ROOT)
        self.assertEqual((provenance["kind"], provenance["acceptance_evidence"]), ("local-fixture", False))
        self.assertEqual(provenance["scanned_paths"], sast.tree_files(ROOT, "scripts/qa-gates/fixtures/planted"))
        self.assertEqual(len(provenance["scanned_paths"]), 6)
        for flag in ("--metrics=off", "--disable-version-check"):
            self.assertIn(flag, provenance["command"])

    def test_canned_report_binding_detects_stale_fixture_or_rules(self):
        with copied_root() as root:
            sast.verify_canned(self.report, self.provenance, root)
            planted = root / "scripts/qa-gates/fixtures/planted/python/planted_injection.py"
            planted.write_bytes(planted.read_bytes() + b"\n")
            self.assertRefused("SAST-CANNED-FIXTURE-STALE", sast.verify_canned, self.report, self.provenance, root)
        with copied_root() as root:
            rule = root / "scripts/qa-gates/rules/typescript.yml"
            rule.write_bytes(rule.read_bytes().replace(b"Non-literal", b"Untrusted", 1))
            self.assertRefused("SAST-CANNED-RULES-STALE", sast.verify_canned, self.report, self.provenance, root)

    def test_policy_mode_change_does_not_stale_the_canned_report(self):
        with copied_root() as root:
            edit_json(root / "scripts/qa-gates/rules/sast-policy.json",
                      lambda document: document["rules"][EVAL_RULE].update(
                          mode="warn", warn_from="2026-10-13", warn_until="2026-10-14"))
            sast.verify_canned(self.report, self.provenance, root)

    def test_added_planted_source_not_in_the_report_is_stale(self):
        with copied_root() as root:
            (root / "scripts/qa-gates/fixtures/planted/python/extra.py").write_bytes(b"x = 1\n")
            self.assertRefused("SAST-CANNED-FIXTURE-STALE", sast.verify_canned, self.report, self.provenance, root)

    def test_edited_report_bytes_refused(self):
        mutated = self.report.replace(b'"line": 28', b'"line": 29', 1)
        self.assertNotEqual(mutated, self.report)
        self.assertRefused("SAST-CANNED-REPORT-DIGEST", sast.verify_canned, mutated, self.provenance, ROOT)


    def provenance_with(self, change):
        document = json.loads(self.provenance)
        change(document)
        return dump(document)

    def test_provenance_version_mismatch_refused(self):
        same = self.provenance_with(lambda document: None)
        sast.verify_canned(self.report, same, ROOT)
        mutated = self.provenance_with(lambda document: document.update(semgrep_version="1.179.0"))
        self.assertRefused("SAST-CANNED-VERSION", sast.verify_canned, self.report, mutated, ROOT)

    def test_provenance_scanned_path_list_mismatch_refused(self):
        mutated = self.provenance_with(lambda document: document["scanned_paths"].pop())
        self.assertRefused("SAST-CANNED-PATHS", sast.verify_canned, self.report, mutated, ROOT)

    def test_registry_config_command_refused(self):
        def registry(document):
            document["command"][document["command"].index("--config") + 1] = "auto"
        self.assertRefused("SAST-CANNED-COMMAND", sast.verify_canned, self.report,
                           self.provenance_with(registry), ROOT)

    def test_command_without_metrics_off_refused(self):
        mutated = self.provenance_with(lambda document: document["command"].remove("--metrics=off"))
        self.assertRefused("SAST-CANNED-COMMAND", sast.verify_canned, self.report, mutated, ROOT)

    def test_second_inline_config_refused(self):
        mutated = self.provenance_with(lambda document: document["command"].insert(2, "--config=p/default"))
        self.assertRefused("SAST-CANNED-COMMAND", sast.verify_canned, self.report, mutated, ROOT)

    def test_canned_report_claimed_as_acceptance_evidence_refused(self):
        mutated = self.provenance_with(lambda document: document.update(acceptance_evidence=True))
        self.assertRefused("SAST-CANNED-KIND", sast.verify_canned, self.report, mutated, ROOT)

    def test_provenance_missing_key_refused(self):
        mutated = self.provenance_with(lambda document: document.pop("rules_sha256"))
        self.assertRefused("SAST-CANNED-KEYS", sast.verify_canned, self.report, mutated, ROOT)


def run_cli(argv, today=TODAY):
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = sast.main(argv, clock=lambda: today)
    text = stdout.getvalue()
    return code, (json.loads(text) if text.startswith("{") else text)


class SastCliTests(unittest.TestCase):
    def test_canned_planted_report_exits_one(self):
        code, report = run_cli(["--report", str(CANNED), "--root", str(ROOT)])
        self.assertEqual((code, report["decision"], report["reason"]), (1, "fail", "SAST-BLOCKING-FINDINGS"))
        self.assertEqual(report["evaluated_on"], "2026-10-13")

    def test_clean_report_exits_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "clean.json")
            path.write_bytes(dump(clean()))
            code, report = run_cli(["--report", str(path), "--root", str(ROOT)])
        self.assertEqual((code, report["decision"]), (0, "pass"))

    def test_incomplete_report_exits_one(self):
        with tempfile.TemporaryDirectory() as directory:
            document = clean()
            document["errors"] = [{"code": 3}]
            path = Path(directory, "partial.json")
            path.write_bytes(dump(document))
            code, report = run_cli(["--report", str(path), "--root", str(ROOT)])
        self.assertEqual((code, report["reason"]), (1, "SAST-INCOMPLETE-ERRORS"))

    def test_sast_missing_report_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            code, report = run_cli(["--report", str(Path(directory, "absent.json")), "--root", str(ROOT)])
        self.assertEqual((code, report), (2, {"schema": sast.REPORT_SCHEMA, "decision": "refused",
                                              "reason": "SAST-REPORT-UNREADABLE"}))

    def test_cli_missing_input_exit_nonzero(self):
        self.assertEqual(run_cli(["--report", str(CANNED), "--root", str(ROOT)])[0], 1)
        code, report = run_cli(["--report", str(CANNED)])
        self.assertEqual((code, report["reason"]), (2, "USAGE"))

    def test_repeated_or_unknown_flag_is_usage(self):
        for argv in (["--report", str(CANNED), "--report", str(CANNED), "--root", str(ROOT)],
                     ["--report", str(CANNED), "--root", str(ROOT), "--mode", "warn"],
                     ["--report", str(CANNED), "--root"]):
            code, report = run_cli(argv)
            self.assertEqual((code, report["reason"]), (2, "USAGE"))

    def test_unreadable_policy_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            code, report = run_cli(["--report", str(CANNED), "--root", str(ROOT),
                                    "--policy", str(Path(directory, "absent.json"))])
        self.assertEqual((code, report["reason"]), (2, "SAST-POLICY-UNREADABLE"))

    def test_help_exits_zero(self):
        code, text = run_cli(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("qa_gates_sast.py --report", text)



class TiedFindingOrder(unittest.TestCase):
    def test_tied_findings_order_is_input_order_independent(self):
        document = only(EVAL_RULE)
        first = document["results"][0]
        second = json.loads(json.dumps(first))
        second["extra"]["severity"] = "INFO" if first["extra"]["severity"] != "INFO" else "ERROR"
        document["results"] = [first]
        self.assertEqual(gate(document)["findings"], gate(document)["findings"])
        forward, backward = dict(document, results=[first, second]), dict(document, results=[second, first])
        self.assertEqual(gate(forward)["findings"], gate(backward)["findings"])

if __name__ == "__main__":
    unittest.main()
