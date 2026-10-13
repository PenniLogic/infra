"""Tests for the Android rules of scripts/supply_chain_config.py over merged-manifest and network-config XML."""

import json
from pathlib import Path
import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
from supply_chain_common import Refused
import supply_chain_config as config
import supply_chain_exceptions as exceptions


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "supply_chain"
MANIFEST = (FIXTURES / "android-manifest-release-control.xml").read_text(encoding="utf-8")
NETWORK = (FIXTURES / "android-network-security-config-control.xml").read_text(encoding="utf-8")


def replaced(text, old, new):
    """Exactly one mutation: ``old`` must occur once."""
    if text.count(old) != 1:
        raise AssertionError("mutation anchor must occur exactly once")
    return text.replace(old, new)


def rules(manifest=MANIFEST, network=NETWORK):
    found = config.android_findings(manifest.encode("utf-8"), "android/release",
                                    None if network is None else network.encode("utf-8"))
    return [entry["rule_id"] for entry in found]


class ManifestRuleTests(unittest.TestCase):
    def test_control_release_fixture_has_no_finding(self):
        self.assertEqual(rules(), [])

    def test_insecure_android_release_fixture_fails(self):
        data = (FIXTURES / "android-manifest-planted-insecure.xml").read_bytes()
        found = config.android_findings(data, "android/release")
        self.assertEqual(sorted(entry["rule_id"] for entry in found), [
            "SC-ANDROID-ALLOW-BACKUP", "SC-ANDROID-CLEARTEXT", "SC-ANDROID-DEBUGGABLE", "SC-ANDROID-EXPORTED"])
        self.assertEqual(exceptions.evaluate(found, "high")["decision"], "fail")

    def test_debuggable(self):
        self.assertEqual(rules(replaced(MANIFEST, 'android:label=', 'android:debuggable="false" android:label=')), [])
        self.assertEqual(rules(replaced(MANIFEST, 'android:label=', 'android:debuggable="true" android:label=')),
                         ["SC-ANDROID-DEBUGGABLE"])

    def test_allow_backup_must_be_explicitly_false(self):
        self.assertEqual(rules(replaced(MANIFEST, 'android:allowBackup="false"', 'android:allowBackup="true"')),
                         ["SC-ANDROID-ALLOW-BACKUP"])
        self.assertEqual(rules(replaced(MANIFEST, 'android:allowBackup="false"', '')), ["SC-ANDROID-ALLOW-BACKUP"])

    def test_legacy_external_storage_is_medium(self):
        manifest = replaced(MANIFEST, 'android:label=', 'android:requestLegacyExternalStorage="true" android:label=')
        found = config.android_findings(manifest.encode("utf-8"), "android/release", NETWORK.encode("utf-8"))
        self.assertEqual([(entry["rule_id"], entry["severity"]) for entry in found],
                         [("SC-ANDROID-LEGACY-STORAGE", "medium")])

    def test_cleartext_attribute_and_target_sdk_default(self):
        self.assertEqual(rules(replaced(MANIFEST, 'android:usesCleartextTraffic="false"', 'android:usesCleartextTraffic="true"')),
                         ["SC-ANDROID-CLEARTEXT"])
        absent = replaced(MANIFEST, 'android:usesCleartextTraffic="false"', '')
        self.assertEqual(rules(absent), [])
        self.assertEqual(rules(replaced(absent, 'android:targetSdkVersion="35"', 'android:targetSdkVersion="27"')),
                         ["SC-ANDROID-CLEARTEXT"])
        self.assertEqual(rules(replaced(absent, ' android:targetSdkVersion="35"', '')), ["SC-ANDROID-CLEARTEXT"])

    def test_exported_component_without_permission(self):
        self.assertEqual(rules(replaced(MANIFEST, 'android:permission="org.example.synthetic.permission.SYNC"', '')),
                         ["SC-ANDROID-EXPORTED"])

    def test_exported_provider_needs_both_read_and_write_permission(self):
        exported = replaced(MANIFEST, 'android:authorities="org.example.synthetic.files" android:exported="false"',
                            'android:authorities="org.example.synthetic.files" android:exported="true"')
        self.assertEqual(rules(exported), ["SC-ANDROID-EXPORTED"])
        both = replaced(exported, 'android:exported="true" />',
                        'android:exported="true" android:readPermission="p.R" android:writePermission="p.W" />')
        self.assertEqual(rules(both), [])
        read_only = replaced(exported, 'android:exported="true" />', 'android:exported="true" android:readPermission="p.R" />')
        self.assertEqual(rules(read_only), ["SC-ANDROID-EXPORTED"])

    def test_launcher_exemption_needs_main_and_launcher(self):
        self.assertEqual(rules(replaced(MANIFEST, 'android.intent.category.LAUNCHER', 'android.intent.category.DEFAULT')),
                         ["SC-ANDROID-EXPORTED"])

    def test_intent_filter_without_exported_declaration(self):
        self.assertEqual(rules(replaced(MANIFEST, 'BootReceiver" android:exported="false"', 'BootReceiver"')),
                         ["SC-ANDROID-EXPORTED-UNDECLARED"])


class NetworkConfigTests(unittest.TestCase):
    def test_cleartext_in_base_and_domain_config(self):
        self.assertEqual(rules(network=replaced(NETWORK, '<base-config cleartextTrafficPermitted="false">',
                                                '<base-config cleartextTrafficPermitted="true">')),
                         ["SC-ANDROID-NSC-CLEARTEXT"])
        self.assertEqual(rules(network=replaced(NETWORK, '<domain-config cleartextTrafficPermitted="false">',
                                                '<domain-config cleartextTrafficPermitted="true">')),
                         ["SC-ANDROID-NSC-CLEARTEXT"])

    def test_user_certificates_outside_debug_overrides(self):
        self.assertEqual(rules(network=replaced(NETWORK, '<certificates src="system" />', '<certificates src="user" />')),
                         ["SC-ANDROID-NSC-USER-CA"])

    def test_missing_and_unreferenced_network_config_are_refused(self):
        with self.assertRaises(Refused) as caught:
            rules(network=None)
        self.assertEqual(caught.exception.code, "SC-ANDROID-NSC-MISSING")
        unreferenced = replaced(MANIFEST, 'android:networkSecurityConfig="@xml/network_security_config"', '')
        self.assertEqual(rules(unreferenced, None), [])
        with self.assertRaises(Refused) as caught:
            rules(unreferenced)
        self.assertEqual(caught.exception.code, "SC-ANDROID-NSC-UNREFERENCED")


class XmlRefusalTests(unittest.TestCase):
    def refused(self, code, manifest=MANIFEST, network=NETWORK):
        with self.assertRaises(Refused) as caught:
            rules(manifest, network)
        self.assertEqual(caught.exception.code, code)

    def test_doctype_and_entities_are_refused(self):
        doctype = replaced(MANIFEST, '<manifest ', '<!DOCTYPE manifest [<!ENTITY x "y">]>\n<manifest ')
        self.refused("SC-ANDROID-XML", manifest=doctype)
        self.refused("SC-ANDROID-NSC-XML", network=replaced(NETWORK, '<network-security-config>',
                                                            '<!doctype n>\n<network-security-config>'))

    def test_malformed_and_wrong_root_are_refused(self):
        self.refused("SC-ANDROID-XML", manifest=MANIFEST.replace("</manifest>", ""))
        self.refused("SC-ANDROID-SHAPE", manifest=replaced(MANIFEST, '</application>', '</application><application />'))
        self.refused("SC-ANDROID-NSC-SHAPE", network="<config />")
        with self.assertRaises(Refused) as caught:
            config.android_findings(b"", "android/release")
        self.assertEqual(caught.exception.code, "SC-ANDROID-SIZE")

    def test_report_never_names_components(self):
        manifest = replaced(MANIFEST, 'android:permission="org.example.synthetic.permission.SYNC"', '')
        found = config.android_findings(manifest.encode("utf-8"), "android/release", NETWORK.encode("utf-8"))
        self.assertNotIn("SyncService", json.dumps(exceptions.evaluate(found, "high")))


if __name__ == "__main__":
    unittest.main()
