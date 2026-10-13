"""Tests of the infra#28 DAST report ingestion gate (scripts/qa_gates_dast.py).

No ZAP exists here, so every alerts report, scan manifest and expected surface is synthetic and built in memory;
the shapes follow ZAP's traditional JSON report as documented, and parser fidelity stays unverified until a real
ZAP sample exists. Each negative pairs a passing control with exactly one mutation and asserts the exact static
rule code. CLI inputs are written to the system temporary directory, never inside the repository.
"""

import contextlib
import datetime
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import unittest.mock

import support  # noqa: F401  (puts scripts/ on sys.path)
import qa_gates_dast as dast
from qa_gates_scan_common import Refused, sha256_bytes


TODAY = datetime.date(2026, 10, 13)
POLICY = dast.load_policy()
EPHEMERAL = dict(POLICY, suffixes=("ephemeral.example.test",))
ORIGIN = "http://127.0.0.1:18080"
CREDENTIAL_ENV = "PENNILOGIC_DAST_SYNTHETIC_TOKEN"


def dump(document):
    return (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def surface():
    entries = [
        ("SURF-PUBLIC-1", "unauthenticated", "GET", "/health"),
        ("SURF-PUBLIC-2", "unauthenticated", "POST", "/session"),
        ("SURF-ACCOUNT-1", "authenticated", "GET", "/accounts/{account_id}"),
        ("SURF-ACCOUNT-2", "authenticated", "GET", "/"),
    ]
    return {"schema": dast.SURFACE_SCHEMA, "status": dast.PROPOSED,
            "entries": [{"id": i, "auth": a, "method": m, "path": p} for i, a, m, p in entries]}


def alert(plugin="40018", risk="3", uri_path="/accounts/7?page=1", method="GET", param="q"):
    return {
        "pluginid": plugin, "alertRef": plugin, "alert": "synthetic alert text", "name": "synthetic alert text",
        "riskcode": risk, "confidence": "2", "riskdesc": "synthetic", "desc": "<p>synthetic</p>", "count": "1",
        "cweid": "89", "wascid": "19", "sourceid": "1", "solution": "", "otherinfo": "", "reference": "",
        "instances": [{"uri": ORIGIN + uri_path, "method": method, "param": param, "attack": "synthetic-attack",
                       "evidence": "synthetic-evidence", "otherinfo": ""}],
    }


def alerts(*items):
    return {"@programName": "ZAP", "@version": "2.16.1", "@generated": "synthetic",
            "site": [{"@name": ORIGIN, "@host": "127.0.0.1", "@port": "18080", "@ssl": "false",
                      "alerts": list(items)}]}


def manifest(alerts_doc, surface_doc):
    return {
        "schema": dast.MANIFEST_SCHEMA, "zap_version": "2.16.1", "target": ORIGIN, "synthetic_data": True,
        "alerts_sha256": sha256_bytes(dump(alerts_doc)), "surface_sha256": sha256_bytes(dump(surface_doc)),
        "contexts": [
            {"name": "anonymous", "authenticated": False, "user": None},
            {"name": "member", "authenticated": True,
             "user": {"name": "synthetic-member", "credential_env": CREDENTIAL_ENV}},
        ],
        "scanned_urls": [
            {"context": "anonymous", "method": "GET", "url": ORIGIN + "/health"},
            {"context": "anonymous", "method": "POST", "url": ORIGIN + "/session"},
            {"context": "member", "method": "GET", "url": ORIGIN + "/accounts/7?page=1"},
            {"context": "member", "method": "GET", "url": ORIGIN + "/"},
        ],
    }


def gate(alerts_doc=None, surface_doc=None, manifest_doc=None, policy=POLICY, today=TODAY, rebind=True):
    """Evaluate synthetic inputs; ``rebind`` recomputes the manifest digests after a mutation."""
    alerts_doc = alerts() if alerts_doc is None else alerts_doc
    surface_doc = surface() if surface_doc is None else surface_doc
    manifest_doc = manifest(alerts_doc, surface_doc) if manifest_doc is None else manifest_doc
    if rebind:
        manifest_doc = dict(manifest_doc, alerts_sha256=sha256_bytes(dump(alerts_doc)),
                            surface_sha256=sha256_bytes(dump(surface_doc)))
    return dast.evaluate(dump(alerts_doc), dump(manifest_doc), dump(surface_doc), policy, today)


class Control(unittest.TestCase):
    def test_clean_complete_scan_passes(self):
        report = gate()
        self.assertEqual((report["decision"], report["reason"], report["complete"]), ("pass", None, True))
        self.assertEqual(report["surface"], {"expected": 4, "covered": 4, "missing": []})
        self.assertEqual(report["contexts"], {"authenticated": 1, "unauthenticated": 1, "empty": 0})
        self.assertEqual(report["scanned_url_count"], 4)
        self.assertEqual(report["target_class"], "loopback")
        self.assertEqual(report["parser_fidelity"], "unverified: no real ZAP sample exists")
        self.assertEqual(report["exceptions"]["status"], "unavailable: infra#23 not integrated")

    def test_committed_policy_blocks_high_only_and_declares_no_ephemeral_suffix(self):
        self.assertEqual(POLICY, {"blocking": frozenset({"high"}), "loopback": True, "suffixes": (), "warn": {}})


class Preflight(unittest.TestCase):
    def test_loopback_and_declared_ephemeral_targets_pass(self):
        self.assertEqual(dast.preflight_target("http://127.0.0.1:18080/", POLICY),
                         {"origin": "http://127.0.0.1:18080", "class": "loopback"})
        self.assertEqual(dast.preflight_target("https://[::1]", POLICY),
                         {"origin": "https://[::1]:443", "class": "loopback"})
        self.assertEqual(dast.preflight_target("http://pr-7.ephemeral.example.test", EPHEMERAL)["class"], "ephemeral")

    def test_non_allowlisted_targets_refused(self):
        for url in ("http://10.0.0.5", "http://localhost:18080", "http://2130706433", "http://127.000.0.1",
                    "https://[::2]", "https://[0::1]", "http://ephemeral.example.test", "http://pr-7.example.test",
                    "http://pr-7.ephemeral.example.test.evil.test"):
            with self.subTest(url=url):
                with self.assertRaises(Refused) as caught:
                    dast.preflight_target(url, EPHEMERAL)
                self.assertEqual(caught.exception.code, "DAST-TARGET-NOT-ALLOWLISTED")

    def test_malformed_targets_refused(self):
        for url in ("ftp://127.0.0.1", "HTTP://127.0.0.1", "http://user@127.0.0.1", "http://127.0.0.1/app",
                    "http://127.0.0.1?x=1", "http://127.0.0.1/?x=1", "http://127.0.0.1#x", "http://127.0.0.1/#x", "http://127.0.0.1:0", "http://127.0.0.1:65536",
                    "http://127.0.0.1 ", "http://١٢٧.0.0.1", "https://[::ffff:127.0.0.1]", "http://LOCALHOST", None, 7):
            with self.subTest(url=url):
                with self.assertRaises(Refused) as caught:
                    dast.preflight_target(url, EPHEMERAL)
                self.assertEqual(caught.exception.code, "DAST-TARGET-URL")

    def test_loopback_disallowed_by_policy_refused(self):
        self.assertEqual(dast.preflight_target(ORIGIN, POLICY)["class"], "loopback")
        with self.assertRaises(Refused) as caught:
            dast.preflight_target(ORIGIN, dict(POLICY, loopback=False))
        self.assertEqual(caught.exception.code, "DAST-TARGET-NOT-ALLOWLISTED")



class Severity(unittest.TestCase):
    def test_dast_high_finding_fails(self):
        self.assertEqual(gate(alerts())["decision"], "pass")
        report = gate(alerts(alert(risk="3")))
        self.assertEqual((report["decision"], report["reason"], report["complete"]),
                         ("fail", "DAST-BLOCKING-FINDINGS", True))
        self.assertEqual(report["counts"], {"blocking": 1, "warning": 0, "reported": 0,
                                            "by_risk": {"high": 1, "medium": 0, "low": 0, "info": 0}})
        finding = report["findings"][0]
        self.assertEqual({key: finding[key] for key in ("plugin_id", "alert_ref", "risk", "confidence", "cwe_id",
                                                        "method", "mode")},
                         {"plugin_id": "40018", "alert_ref": "40018", "risk": "high", "confidence": "medium",
                          "cwe_id": 89, "method": "GET", "mode": "block"})
        self.assertRegex(finding["fingerprint"], r"\Asha256:[0-9a-f]{64}\Z")

    def test_medium_low_info_are_reported_not_blocking(self):
        for code, risk in (("2", "medium"), ("1", "low"), ("0", "info")):
            with self.subTest(risk=risk):
                report = gate(alerts(alert(risk=code)))
                self.assertEqual((report["decision"], report["reason"]), ("pass", None))
                self.assertEqual((report["counts"]["reported"], report["counts"]["by_risk"][risk]), (1, 1))
                self.assertEqual(report["findings"][0]["mode"], "report")

    def test_policy_blocking_medium_fails_medium(self):
        self.assertEqual(gate(alerts(alert(risk="2")))["decision"], "pass")
        report = gate(alerts(alert(risk="2")), policy=dict(POLICY, blocking=frozenset({"high", "medium"})))
        self.assertEqual(report["reason"], "DAST-BLOCKING-FINDINGS")

    def test_warn_window_and_expiry(self):
        policy = dict(POLICY, warn={"40018": (datetime.date(2026, 10, 10), datetime.date(2026, 10, 13))})
        self.assertEqual(gate(alerts(alert()), policy=policy)["reason"], None)
        self.assertEqual(gate(alerts(alert()), policy=policy)["counts"]["warning"], 1)
        expired = gate(alerts(alert()), policy=policy, today=datetime.date(2026, 10, 14))
        self.assertEqual((expired["reason"], expired["expired_warnings"]), ("DAST-BLOCKING-FINDINGS", ["40018"]))
        early = gate(alerts(alert()), policy=policy, today=datetime.date(2026, 10, 9))
        self.assertEqual((early["reason"], early["expired_warnings"]), ("DAST-BLOCKING-FINDINGS", []))

    def test_warn_window_of_another_plugin_does_not_relax(self):
        policy = dict(POLICY, warn={"40019": (datetime.date(2026, 10, 10), datetime.date(2026, 10, 13))})
        self.assertEqual(gate(alerts(alert(plugin="40019")), policy=policy)["reason"], None)
        self.assertEqual(gate(alerts(alert(plugin="40018")), policy=policy)["reason"], "DAST-BLOCKING-FINDINGS")

    def test_fingerprint_ignores_query_and_text_but_not_path_or_param(self):
        base = gate(alerts(alert()))["findings"][0]["fingerprint"]
        variant = alert(uri_path="/accounts/7?page=2")
        variant["desc"] = "other synthetic text"
        self.assertEqual(gate(alerts(variant))["findings"][0]["fingerprint"], base)
        self.assertNotEqual(gate(alerts(alert(uri_path="/accounts/8")))["findings"][0]["fingerprint"], base)
        self.assertNotEqual(gate(alerts(alert(param="r")))["findings"][0]["fingerprint"], base)

    def test_findings_sorted_deterministically(self):
        items = [alert(plugin="40019"), alert(plugin="40018", uri_path="/health"), alert(plugin="40018")]
        first = gate(alerts(*items))
        second = gate(alerts(*reversed(items)))
        self.assertEqual(first["findings"], second["findings"])
        self.assertEqual([item["plugin_id"] for item in first["findings"]], ["40018", "40018", "40019"])


class Completeness(unittest.TestCase):
    def mutate_manifest(self, change):
        alerts_doc, surface_doc = alerts(), surface()
        document = manifest(alerts_doc, surface_doc)
        change(document)
        return gate(alerts_doc, surface_doc, document)

    def test_dast_unauthenticated_only_rejected(self):
        self.assertEqual(self.mutate_manifest(lambda doc: None)["reason"], None)

        def drop_member(doc):
            doc["contexts"] = doc["contexts"][:1]
            doc["scanned_urls"] = [item for item in doc["scanned_urls"] if item["context"] == "anonymous"]
        report = self.mutate_manifest(drop_member)
        self.assertEqual((report["decision"], report["reason"], report["complete"]),
                         ("fail", "DAST-INCOMPLETE-NO-AUTHENTICATED-CONTEXT", False))

    def test_authenticated_only_rejected(self):
        def drop_anonymous(doc):
            doc["contexts"] = doc["contexts"][1:]
            doc["scanned_urls"] = [item for item in doc["scanned_urls"] if item["context"] == "member"]
        self.assertEqual(self.mutate_manifest(drop_anonymous)["reason"], "DAST-INCOMPLETE-NO-UNAUTHENTICATED-CONTEXT")

    def test_context_without_scanned_url_fails(self):
        def empty_member(doc):
            doc["scanned_urls"] = [item for item in doc["scanned_urls"] if item["context"] == "anonymous"]
        report = self.mutate_manifest(empty_member)
        self.assertEqual((report["reason"], report["contexts"]["empty"]), ("DAST-INCOMPLETE-EMPTY-CONTEXT", 1))

    def test_dast_empty_surface_rejected(self):
        report = self.mutate_manifest(lambda doc: doc.__setitem__("scanned_urls", []))
        self.assertEqual(report["reason"], "DAST-INCOMPLETE-EMPTY-CONTEXT")
        document = surface()
        document["entries"] = []
        with self.assertRaises(Refused) as caught:
            gate(surface_doc=document)
        self.assertEqual(caught.exception.code, "DAST-SURFACE-EMPTY")

    def test_uncovered_surface_entry_fails_with_its_id(self):
        def drop_session(doc):
            doc["scanned_urls"] = [item for item in doc["scanned_urls"] if item["method"] != "POST"]
        report = self.mutate_manifest(drop_session)
        self.assertEqual((report["reason"], report["surface"]),
                         ("DAST-INCOMPLETE-SURFACE", {"expected": 4, "covered": 3, "missing": ["SURF-PUBLIC-2"]}))

    def test_coverage_requires_matching_auth_kind_method_and_shape(self):
        for field, value in (("context", "anonymous"), ("method", "POST"), ("url", ORIGIN + "/accounts/7/x"),
                             ("url", ORIGIN + "/account/7")):
            with self.subTest(field=field, value=value):
                def change(doc):
                    doc["scanned_urls"][2][field] = value
                report = self.mutate_manifest(change)
                self.assertEqual((report["reason"], report["surface"]["missing"]),
                                 ("DAST-INCOMPLETE-SURFACE", ["SURF-ACCOUNT-1"]))

    def test_incomplete_outranks_blocking_findings(self):
        alerts_doc, surface_doc = alerts(alert()), surface()
        document = manifest(alerts_doc, surface_doc)
        document["scanned_urls"] = document["scanned_urls"][:3]
        report = gate(alerts_doc, surface_doc, document)
        self.assertEqual((report["reason"], report["counts"]["blocking"]), ("DAST-INCOMPLETE-SURFACE", 1))


class Binding(unittest.TestCase):
    def refused(self, code, **kwargs):
        with self.assertRaises(Refused) as caught:
            gate(**kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_alerts_digest_mismatch_refused(self):
        alerts_doc = alerts()
        document = manifest(alerts_doc, surface())
        self.assertEqual(gate(alerts_doc, manifest_doc=document, rebind=False)["decision"], "pass")
        self.refused("DAST-MANIFEST-ALERTS-DIGEST", alerts_doc=alerts(alert()), manifest_doc=document, rebind=False)

    def test_surface_digest_mismatch_refused(self):
        surface_doc = surface()
        document = manifest(alerts(), surface_doc)
        surface_doc["entries"] = surface_doc["entries"][:3]
        self.refused("DAST-MANIFEST-SURFACE-DIGEST", surface_doc=surface_doc, manifest_doc=document, rebind=False)

    def test_zap_version_mismatch_refused(self):
        alerts_doc = alerts()
        alerts_doc["@version"] = "2.16.0"
        self.refused("DAST-ALERTS-VERSION-MISMATCH", alerts_doc=alerts_doc)

    def test_weekly_or_malformed_zap_version_refused(self):
        alerts_doc = alerts()
        alerts_doc["@version"] = "D-2026-10-12"
        self.refused("DAST-ALERTS-VERSION", alerts_doc=alerts_doc)

    def test_zap_report_from_non_allowlisted_host_rejected(self):
        alerts_doc = alerts()
        alerts_doc["site"][0]["@name"] = "http://10.1.2.3:18080"
        self.refused("DAST-SITE-NOT-ALLOWLISTED", alerts_doc=alerts_doc)

    def test_site_on_another_allowlisted_origin_refused(self):
        alerts_doc = alerts()
        alerts_doc["site"][0]["@name"] = "http://127.0.0.2:18080"
        self.refused("DAST-SITE-OFF-TARGET", alerts_doc=alerts_doc)

    def test_alert_instance_off_target_refused(self):
        item = alert()
        item["instances"][0]["uri"] = "http://127.0.0.1:18081/accounts/7"
        self.refused("DAST-INSTANCE-URL-OFF-TARGET", alerts_doc=alerts(item))

    def test_scanned_url_off_target_refused(self):
        document = manifest(alerts(), surface())
        document["scanned_urls"][0]["url"] = "https://127.0.0.1:18080/health"
        self.refused("DAST-MANIFEST-URL-OFF-TARGET", manifest_doc=document)

    def test_dast_non_ephemeral_target_refused(self):
        document = manifest(alerts(), surface())
        document["target"] = "https://staging.pennilogic.example"
        self.refused("DAST-TARGET-NOT-ALLOWLISTED", manifest_doc=document)

    def test_non_synthetic_data_refused(self):
        document = manifest(alerts(), surface())
        document["synthetic_data"] = False
        self.refused("DAST-MANIFEST-SYNTHETIC", manifest_doc=document)

    def test_credential_value_field_refused(self):
        document = manifest(alerts(), surface())
        document["contexts"][1]["user"]["credential"] = "x"
        self.refused("DAST-MANIFEST-USER", manifest_doc=document)

    def test_credential_env_must_be_a_variable_name(self):
        document = manifest(alerts(), surface())
        document["contexts"][1]["user"]["credential_env"] = "Bearer abc"
        self.refused("DAST-MANIFEST-CREDENTIAL-ENV", manifest_doc=document)

    def test_unauthenticated_context_with_user_refused(self):
        document = manifest(alerts(), surface())
        document["contexts"][0]["user"] = {"name": "synthetic-member", "credential_env": CREDENTIAL_ENV}
        self.refused("DAST-MANIFEST-USER", manifest_doc=document)

    def test_scanned_url_with_undeclared_context_refused(self):
        document = manifest(alerts(), surface())
        document["scanned_urls"][0]["context"] = "admin"
        self.refused("DAST-MANIFEST-URL", manifest_doc=document)

    def test_duplicate_context_name_refused(self):
        document = manifest(alerts(), surface())
        document["contexts"].append(dict(document["contexts"][0]))
        self.refused("DAST-MANIFEST-CONTEXT", manifest_doc=document)


class Scrubbing(unittest.TestCase):
    def test_report_contains_no_uri_param_or_snippet(self):
        item = alert(param="synthetic_param_name")
        output = json.dumps(gate(alerts(item)))
        for probe in ("127.0.0.1", "/accounts", "page=1", "synthetic_param_name", "synthetic-attack",
                      "synthetic-evidence", "synthetic alert text", "<p>", "anonymous", "member", "SURF-PUBLIC"):
            with self.subTest(probe=probe):
                self.assertNotIn(probe, output)

    def test_missing_surface_ids_are_the_only_surface_text(self):
        document = surface()
        document["entries"].append({"id": "SURF-EXTRA-1", "auth": "authenticated", "method": "DELETE",
                                    "path": "/accounts/{account_id}"})
        report = gate(surface_doc=document)
        self.assertEqual(report["surface"]["missing"], ["SURF-EXTRA-1"])
        self.assertNotIn("/accounts", json.dumps(report))

    def test_dast_credential_never_in_report_or_log(self):
        secret = "-".join(("synthetic", "credential", "value", str(os.getpid())))
        with tempfile.TemporaryDirectory() as directory:
            paths = write_inputs(Path(directory), alerts(alert()), surface())
            stdout, stderr = io.StringIO(), io.StringIO()
            with unittest.mock.patch.dict(os.environ, {CREDENTIAL_ENV: secret}):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = dast.main(cli_argv(paths), clock=lambda: TODAY)
        self.assertEqual(code, 1)
        for stream in (stdout.getvalue(), stderr.getvalue()):
            self.assertNotIn(secret, stream)
            self.assertNotIn(CREDENTIAL_ENV, stream)
            self.assertNotIn("synthetic-member", stream)


def write_inputs(directory, alerts_doc, surface_doc, manifest_doc=None):
    manifest_doc = manifest(alerts_doc, surface_doc) if manifest_doc is None else manifest_doc
    paths = {}
    for name, document in (("alerts", alerts_doc), ("manifest", manifest_doc), ("surface", surface_doc)):
        paths[name] = directory / (name + ".json")
        paths[name].write_bytes(dump(document))
    return paths


def cli_argv(paths):
    return ["--alerts", str(paths["alerts"]), "--manifest", str(paths["manifest"]), "--surface", str(paths["surface"])]


class AlertShape(unittest.TestCase):
    def refused_alert(self, code, change):
        item = alert()
        self.assertEqual(gate(alerts(item))["reason"], "DAST-BLOCKING-FINDINGS")
        change(item)
        with self.assertRaises(Refused) as caught:
            gate(alerts(item))
        self.assertEqual(caught.exception.code, code)

    def test_alert_field_refusals(self):
        cases = (
            ("DAST-ALERT-PLUGIN", lambda item: item.__setitem__("pluginid", 40018)),
            ("DAST-ALERT-PLUGIN", lambda item: item.__setitem__("alertRef", "40019-1")),
            ("DAST-ALERT-RISK", lambda item: item.__setitem__("riskcode", "4")),
            ("DAST-ALERT-RISK", lambda item: item.__setitem__("riskcode", 3)),
            ("DAST-ALERT-CONFIDENCE", lambda item: item.__setitem__("confidence", "5")),
            ("DAST-ALERT-CWE", lambda item: item.__setitem__("cweid", "089")),
            ("DAST-ALERT-INSTANCES", lambda item: item.__setitem__("instances", [])),
            ("DAST-INSTANCE-SHAPE", lambda item: item["instances"].append("x")),
            ("DAST-INSTANCE-METHOD", lambda item: item["instances"][0].__setitem__("method", "TRACE")),
            ("DAST-INSTANCE-METHOD", lambda item: item["instances"][0].__setitem__("method", ["GET"])),
            ("DAST-INSTANCE-PARAM", lambda item: item["instances"][0].__setitem__("param", None)),
            ("DAST-INSTANCE-URL", lambda item: item["instances"][0].__setitem__("uri", "/accounts/7")),
            ("DAST-INSTANCE-URL", lambda item: item["instances"][0].__setitem__("uri", ORIGIN + "/a/../b")),
            ("DAST-INSTANCE-URL", lambda item: item["instances"][0].__setitem__("uri", ORIGIN + "/accounts/7#x")),
        )
        for code, change in cases:
            with self.subTest(code=code):
                self.refused_alert(code, change)

    def test_alert_ref_variant_and_missing_alert_ref_accepted(self):
        item = alert()
        item["alertRef"] = "40018-2"
        self.assertEqual(gate(alerts(item))["findings"][0]["alert_ref"], "40018-2")
        del item["alertRef"]
        self.assertEqual(gate(alerts(item))["findings"][0]["alert_ref"], "40018")

    def test_report_shape_refusals(self):
        cases = (
            ("DAST-ALERTS-SHAPE", lambda doc: doc.pop("site")),
            ("DAST-ALERTS-PROGRAM", lambda doc: doc.__setitem__("@programName", "Other")),
            ("DAST-SITE-SHAPE", lambda doc: doc["site"][0].pop("alerts")),
            ("DAST-SITE-URL", lambda doc: doc["site"][0].__setitem__("@name", ORIGIN + "/app")),
        )
        for code, change in cases:
            with self.subTest(code=code):
                document = alerts()
                change(document)
                with self.assertRaises(Refused) as caught:
                    gate(document)
                self.assertEqual(caught.exception.code, code)

    def test_strict_json_refusals(self):
        good = dump(alerts())
        hostile = {
            "duplicate key": good.replace(b'"@generated"', b'"@version": "2.16.1",\n  "@generated"', 1),
            "byte order mark": b"\xef\xbb\xbf" + good,
            "nan": good.replace(b'"site": [', b'"x": NaN, "site": [', 1),
            "invalid utf-8": good.replace(b"synthetic", b"synth\xffetic", 1),
        }
        self.assertEqual(dast.evaluate(good, dump(manifest(alerts(), surface())), dump(surface()), POLICY,
                                       TODAY)["decision"], "pass")
        for label, data in hostile.items():
            with self.subTest(label=label):
                document = manifest(alerts(), surface())
                document["alerts_sha256"] = sha256_bytes(data)
                with self.assertRaises(Refused) as caught:
                    dast.evaluate(data, dump(document), dump(surface()), POLICY, TODAY)
                self.assertEqual(caught.exception.code, "DAST-ALERTS-JSON")


def policy_document(**changes):
    document = json.loads(dast.POLICY_FILE.read_text(encoding="utf-8"))
    document.update(changes)
    return dump(document)


class Policy(unittest.TestCase):
    def refused(self, code, **changes):
        self.assertEqual(dast.parse_policy(policy_document()), POLICY)
        with self.assertRaises(Refused) as caught:
            dast.parse_policy(policy_document(**changes))
        self.assertEqual(caught.exception.code, code)

    def test_policy_refusals(self):
        warn = {"mode": "warn", "warn_from": "2026-10-10", "warn_until": "2026-10-17"}
        cases = (
            ("DAST-POLICY-SCHEMA", {"status": "agreed"}),
            ("DAST-POLICY-DECISION", {"decision_ref": "PenniLogic/infra#999"}),
            ("DAST-POLICY-RISK", {"blocking_risks": ["medium"]}),
            ("DAST-POLICY-RISK", {"blocking_risks": ["high", "high"]}),
            ("DAST-POLICY-RISK", {"blocking_risks": ["high", ["low"]]}),
            ("DAST-POLICY-TARGETS", {"targets": {"loopback": 1, "ephemeral_host_suffixes": []}}),
            ("DAST-POLICY-TARGETS", {"targets": {"loopback": True, "ephemeral_host_suffixes": ["test"]}}),
            ("DAST-POLICY-TARGETS", {"targets": {"loopback": True, "ephemeral_host_suffixes": [["a.test"]]}}),
            ("DAST-POLICY-RULES", {"rules": {"abc": warn}}),
            ("DAST-POLICY-WARN", {"rules": {"40018": {"mode": "block"}}}),
            ("DAST-POLICY-WARN-WINDOW", {"rules": {"40018": dict(warn, warn_until="2026-10-18")}}),
            ("DAST-POLICY-WARN-WINDOW", {"rules": {"40018": dict(warn, warn_until="2026-10-10")}}),
            ("DAST-POLICY-KEYS", {"extra": True}),
        )
        for code, changes in cases:
            with self.subTest(code=code, changes=changes):
                self.refused(code, **changes)

    def test_seven_day_warn_window_accepted(self):
        warn = {"mode": "warn", "warn_from": "2026-10-10", "warn_until": "2026-10-17"}
        parsed = dast.parse_policy(policy_document(rules={"40018": warn}))
        self.assertEqual(parsed["warn"], {"40018": (datetime.date(2026, 10, 10), datetime.date(2026, 10, 17))})


class Surface(unittest.TestCase):
    def test_surface_refusals(self):
        cases = (
            ("DAST-SURFACE-ID", lambda entries: entries[0].__setitem__("id", "surf-1")),
            ("DAST-SURFACE-ENTRY", lambda entries: entries[0].__setitem__("auth", "admin")),
            ("DAST-SURFACE-PATH", lambda entries: entries[0].__setitem__("path", "health")),
            ("DAST-SURFACE-PATH", lambda entries: entries[0].__setitem__("path", "/a/../b")),
            ("DAST-SURFACE-PATH", lambda entries: entries[0].__setitem__("path", "/a/{Id}")),
            ("DAST-SURFACE-DUPLICATE", lambda entries: entries.append(dict(entries[0], id="SURF-COPY-1"))),
            ("DAST-SURFACE-DUPLICATE", lambda entries: entries.append(dict(entries[0], path="/other"))),
        )
        self.assertEqual(len(dast.parse_surface(dump(surface()))[1]), 4)
        for code, change in cases:
            with self.subTest(code=code):
                document = surface()
                change(document["entries"])
                with self.assertRaises(Refused) as caught:
                    dast.parse_surface(dump(document))
                self.assertEqual(caught.exception.code, code)


class Cli(unittest.TestCase):
    def run_main(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = dast.main(argv, clock=lambda: TODAY)
        return code, stdout.getvalue()

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "clean").mkdir()
            (Path(directory) / "fail").mkdir()
            clean = write_inputs(Path(directory) / "clean", alerts(), surface())
            failing = write_inputs(Path(directory) / "fail", alerts(alert()), surface())
            code, output = self.run_main(cli_argv(clean))
            self.assertEqual((code, json.loads(output)["decision"]), (0, "pass"))
            code, output = self.run_main(cli_argv(failing))
            self.assertEqual((code, json.loads(output)["reason"]), (1, "DAST-BLOCKING-FINDINGS"))
            mixed = dict(clean, alerts=failing["alerts"])
            code, output = self.run_main(cli_argv(mixed))
            self.assertEqual((code, json.loads(output)), (2, {"schema": dast.REPORT_SCHEMA, "decision": "refused",
                                                              "reason": "DAST-MANIFEST-ALERTS-DIGEST"}))
        self.assertTrue(output.isascii() and output.endswith("}\n") and output.count("\n") == 1)

    def test_cli_missing_input_exit_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = write_inputs(Path(directory), alerts(), surface())
            self.assertEqual(self.run_main(cli_argv(paths))[0], 0)
            for name in ("alerts", "manifest", "surface"):
                with self.subTest(name=name):
                    missing = dict(paths, **{name: Path(directory) / "absent.json"})
                    code, output = self.run_main(cli_argv(missing))
                    self.assertEqual((code, json.loads(output)["reason"]),
                                     (2, "DAST-%s-UNREADABLE" % name.upper()))
            code, output = self.run_main(cli_argv(dict(paths, alerts=Path(directory))))
            self.assertEqual((code, json.loads(output)["reason"]), (2, "DAST-ALERTS-UNREADABLE"))

    def test_cli_usage_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            argv = cli_argv(write_inputs(Path(directory), alerts(), surface()))
            self.assertEqual(self.run_main(argv)[0], 0)
            cases = (
                (argv[:4], "USAGE"), (argv + ["--alerts", argv[1]], "USAGE"), (argv + ["--root", "."], "USAGE"),
                (argv + ["--policy"], "USAGE"), (argv[:5] + [""], "USAGE"),
                (argv + ["--policy", str(Path(directory) / "absent.json")], "DAST-POLICY-UNREADABLE"),
            )
            for bad, reason in cases:
                with self.subTest(reason=reason, tail=bad[-2:]):
                    code, output = self.run_main(bad)
                    self.assertEqual((code, json.loads(output)["reason"]), (2, reason))

    def test_help(self):
        code, output = self.run_main(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("qa_gates_dast.py --alerts", output)


class Determinism(unittest.TestCase):
    def test_tied_findings_order_is_input_order_independent(self):
        high, medium = alert(risk="3"), alert(risk="2")
        self.assertEqual(gate(alerts(high))["findings"], gate(alerts(high))["findings"])
        self.assertEqual(gate(alerts(high, medium))["findings"], gate(alerts(medium, high))["findings"])

if __name__ == "__main__":
    unittest.main()
