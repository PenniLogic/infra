"""Tests for the compose rules of scripts/supply_chain_config.py over `docker compose config --format json` shapes."""

import copy
import json
from pathlib import Path
import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
from supply_chain_common import Refused
import supply_chain_config as config
import supply_chain_exceptions as exceptions


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "supply_chain"


def control():
    return json.loads((FIXTURES / "compose-rendered-control.json").read_text(encoding="utf-8"))


def encode(document):
    return json.dumps(document).encode("utf-8")


class ComposeRuleTests(unittest.TestCase):
    def rules(self, document):
        return [entry["rule_id"] for entry in config.compose_findings(encode(document), "infra/compose")]

    def mutated(self, service, key, value):
        document = control()
        document["services"][service][key] = value
        return self.rules(document)

    def test_control_rendering_has_no_finding(self):
        self.assertEqual(self.rules(control()), [])

    def test_planted_high_iac_misconfig_fails(self):
        data = (FIXTURES / "compose-rendered-planted-privileged.json").read_bytes()
        found = config.compose_findings(data, "infra/compose")
        self.assertEqual([(entry["rule_id"], entry["severity"]) for entry in found],
                         [("SC-COMPOSE-PRIVILEGED", "critical")])
        self.assertEqual(exceptions.evaluate(found, "high")["decision"], "fail")

    def test_privileged(self):
        self.assertEqual(self.mutated("redis", "privileged", False), [])
        self.assertEqual(self.mutated("redis", "privileged", True), ["SC-COMPOSE-PRIVILEGED"])

    def test_host_namespaces(self):
        self.assertEqual(self.mutated("redis", "network_mode", "bridge"), [])
        for key in ("network_mode", "pid", "ipc", "userns_mode"):
            with self.subTest(key=key):
                self.assertEqual(self.mutated("redis", key, "host"), ["SC-COMPOSE-HOST-NAMESPACE"])

    def test_docker_socket_bind(self):
        volume = {"type": "bind", "source": "/srv/data", "target": "/data"}
        self.assertEqual(self.mutated("redis", "volumes", [volume]), [])
        for source in ("/var/run/docker.sock", "/run/docker.sock", "//./pipe/docker_engine"):
            with self.subTest(source=source):
                self.assertEqual(self.mutated("redis", "volumes", [{**volume, "source": source}]),
                                 ["SC-COMPOSE-DOCKER-SOCKET"])

    def test_dangerous_capability(self):
        self.assertEqual(self.mutated("redis", "cap_add", ["CHOWN"]), [])
        for capability in ("SYS_ADMIN", "CAP_SYS_ADMIN", "all", "NET_ADMIN"):
            with self.subTest(capability=capability):
                self.assertEqual(self.mutated("redis", "cap_add", [capability]), ["SC-COMPOSE-CAPABILITY"])

    def test_unconfined_security_options(self):
        self.assertEqual(self.mutated("redis", "security_opt", ["no-new-privileges:true"]), [])
        for option in ("seccomp:unconfined", "seccomp=unconfined", "apparmor:unconfined", "label:disable"):
            with self.subTest(option=option):
                self.assertEqual(self.mutated("redis", "security_opt", [option]), ["SC-COMPOSE-UNCONFINED"])

    def test_published_port_must_bind_loopback(self):
        port = control()["services"]["redis"]["ports"][0]
        self.assertEqual(self.mutated("redis", "ports", [{**port, "host_ip": "::1"}]), [])
        self.assertEqual(self.mutated("redis", "ports", [{"target": 6379, "mode": "ingress"}]), [])
        for host_ip in ("0.0.0.0", "::", None, "192.0.2.10"):
            with self.subTest(host_ip=host_ip):
                changed = {**port, "host_ip": host_ip} if host_ip is not None else {
                    key: value for key, value in port.items() if key != "host_ip"}
                self.assertEqual(self.mutated("redis", "ports", [changed]), ["SC-COMPOSE-PUBLIC-PORT"])

    def test_image_without_digest_is_medium(self):
        document = control()
        document["services"]["redis"]["image"] = "redis:7.4.11-alpine3.21"
        found = config.compose_findings(encode(document), "infra/compose")
        self.assertEqual([(entry["rule_id"], entry["severity"]) for entry in found],
                         [("SC-COMPOSE-IMAGE-DIGEST", "medium")])
        self.assertEqual(exceptions.evaluate(found, "high")["decision"], "pass")

    def test_build_only_service_is_accepted(self):
        document = control()
        del document["services"]["redis"]["image"]
        document["services"]["redis"]["build"] = {"context": "."}
        self.assertEqual(self.rules(document), [])


class ComposeRefusalTests(unittest.TestCase):
    def refused(self, data, code):
        with self.assertRaises(Refused) as caught:
            config.compose_findings(data, "infra/compose")
        self.assertEqual(caught.exception.code, code)

    def test_shape_refusals(self):
        config.compose_findings(encode(control()), "infra/compose")
        cases = []
        for mutate in (
            lambda document: document.pop("services"),
            lambda document: document["services"]["redis"].__setitem__("volumes", ["/var/run/docker.sock:/s"]),
            lambda document: document["services"]["redis"].__setitem__("ports", ["6379:6379"]),
            lambda document: document["services"]["redis"].__setitem__("cap_add", "SYS_ADMIN"),
            lambda document: document["services"]["redis"].pop("image"),
            lambda document: document["services"].__setitem__("bad name", {"image": "x"}),
        ):
            document = copy.deepcopy(control())
            mutate(document)
            cases.append(encode(document))
        for index, data in enumerate(cases):
            with self.subTest(case=index):
                self.refused(data, "SC-COMPOSE-SHAPE")

    def test_empty_services_and_bad_json(self):
        self.refused(encode({"services": {}}), "SC-COMPOSE-EMPTY")
        self.refused(b'{"services": {}, "services": {}}', "SC-COMPOSE-JSON")
        with self.assertRaises(Refused) as caught:
            config.compose_findings(encode(control()), "Infra Compose")
        self.assertEqual(caught.exception.code, "SC-COMPOSE-ARTIFACT")

    def test_published_report_never_names_services(self):
        document = control()
        document["services"]["planted-service-marker"] = {"image": "x", "privileged": True}
        report = exceptions.evaluate(config.compose_findings(encode(document), "infra/compose"), "high")
        self.assertNotIn("planted-service-marker", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
