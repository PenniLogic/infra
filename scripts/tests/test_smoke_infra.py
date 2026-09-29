"""Docker-free tests for scripts/smoke_infra.py: protocol handling, contract shape, redaction."""

import base64
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import time
import unittest

import support  # noqa: F401  (puts scripts/ on sys.path)
import smoke_infra as smoke


def read_pg_message(reader):
    header = reader.read_exact(5)
    return header[0:1], reader.read_exact(struct.unpack("!i", header[1:5])[0] - 4)


def read_startup(conn):
    reader = smoke._Reader(conn)
    length = struct.unpack("!i", reader.read_exact(4))[0]
    payload = reader.read_exact(length - 4)
    assert payload[:4] == struct.pack("!i", 196608), "expected protocol 3.0 startup"
    return reader, payload


def error_response(code, message):
    return smoke._pg_message(b"E", b"SFATAL\0C" + code.encode() + b"\0M" + message.encode() + b"\0\0")


def settings_for(**overrides):
    values = dict(smoke.DEFAULTS)
    values.update(overrides)
    return values


class EnvironmentContractTests(unittest.TestCase):
    def test_parse_env_file_handles_comments_quotes_and_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text(
                "# comment\n\nexport A=1\nB = 'quoted # not comment'\nC=\"dq\"\nD=plain # trailing\n"
                "E=\nnot a pair\n9BAD=x\n", encoding="utf-8",
            )
            self.assertEqual(
                {"A": "1", "B": "quoted # not comment", "C": "dq", "D": "plain", "E": ""},
                smoke.parse_env_file(path),
            )

    def test_load_settings_precedence_and_empty_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("PENNILOGIC_POSTGRES_PORT=15432\nPENNILOGIC_POSTGRES_PASSWORD=from-file\nEXTRA=1\n")
            environ = {"PENNILOGIC_POSTGRES_PORT": "", "PENNILOGIC_REDIS_PORT": "16379",
                       "PENNILOGIC_POSTGRES_PASSWORD": ""}
            settings = smoke.load_settings(path, environ)
        self.assertEqual("5432", settings["PENNILOGIC_POSTGRES_PORT"], "empty env falls back like ${VAR:-default}")
        self.assertEqual("16379", settings["PENNILOGIC_REDIS_PORT"])
        self.assertEqual("", settings["PENNILOGIC_POSTGRES_PASSWORD"], "blank password stays blank, never defaulted")
        self.assertEqual("1", settings["EXTRA"])
        self.assertEqual("pennilogic", settings["PENNILOGIC_POSTGRES_DATABASE"])

    def test_load_settings_without_file_uses_defaults(self):
        settings = smoke.load_settings(Path("/nonexistent/.env"), {})
        self.assertEqual(smoke.DEFAULTS, settings)

    def test_port_of_rejects_invalid_values(self):
        for bad in ("0", "65536", "abc", "", "-1"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                smoke.port_of(settings_for(PENNILOGIC_POSTGRES_PORT=bad), "PENNILOGIC_POSTGRES_PORT")

    def test_redact_hides_every_secret_value(self):
        settings = settings_for(PENNILOGIC_POSTGRES_PASSWORD="pg-secret", PENNILOGIC_REDIS_PASSWORD="pg-secret-longer")
        text = smoke.redact("uri pg-secret-longer and pg-secret", smoke.secret_values(settings))
        self.assertEqual("uri [redacted] and [redacted]", text)
        self.assertEqual(("pg-secret", "pg-secret-longer"), smoke.secret_values(settings))


class ScramTests(unittest.TestCase):
    def test_matches_rfc7677_test_vector(self):
        client_final, server_signature = smoke.scram_messages(
            "pencil", "n=user,r=rOprNGfwEbeRWgbNEkqO",
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
        )
        self.assertEqual(
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
            client_final,
        )
        self.assertEqual("6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=", base64.b64encode(server_signature).decode())

    def test_rejects_server_nonce_that_does_not_continue_client_nonce(self):
        with self.assertRaisesRegex(smoke.ProbeError, "nonce"):
            smoke.scram_messages("pencil", "n=,r=abc", "r=xyz123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")

    def test_rejects_malformed_server_first(self):
        with self.assertRaisesRegex(smoke.ProbeError, "malformed"):
            smoke.scram_messages("pencil", "n=,r=abc", "r=abcdef,i=4096")


class ProbeClassificationTests(unittest.TestCase):
    def test_closed_port_is_unreachable(self):
        port = support.free_port()
        record = smoke.probe("redis", settings_for(PENNILOGIC_REDIS_PORT=str(port)), timeout=2.0)
        self.assertEqual({"service", "status", "latency_ms", "detail"}, set(record))
        self.assertEqual("unreachable", record["status"])
        self.assertIn(f"127.0.0.1:{port}", record["detail"])
        self.assertIsInstance(record["latency_ms"], int)

    def test_silent_decoy_is_error_not_unreachable(self):
        def stay_silent(conn):
            time.sleep(1.5)

        server = support.OneShotServer(stay_silent)
        record = smoke.probe("postgres", settings_for(
            PENNILOGIC_POSTGRES_PORT=str(server.port), PENNILOGIC_POSTGRES_PASSWORD="x"), timeout=0.5)
        server.close()
        self.assertEqual("error", record["status"])
        self.assertIn("no postgres protocol reply", record["detail"])
        self.assertIn("another program", record["detail"])

    def test_wrong_protocol_on_postgres_port_is_error(self):
        def http_server(conn):
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")

        server = support.OneShotServer(http_server)
        record = smoke.probe("postgres", settings_for(
            PENNILOGIC_POSTGRES_PORT=str(server.port), PENNILOGIC_POSTGRES_PASSWORD="x"), timeout=2.0)
        server.close()
        self.assertEqual("error", record["status"])
        self.assertIn("not with the PostgreSQL protocol", record["detail"])

    def test_wrong_protocol_on_redis_port_is_error(self):
        def http_server(conn):
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")

        server = support.OneShotServer(http_server)
        record = smoke.probe("redis", settings_for(PENNILOGIC_REDIS_PORT=str(server.port)), timeout=2.0)
        server.close()
        self.assertEqual("error", record["status"])
        self.assertIn("not with the Redis protocol", record["detail"])


class FakePostgresTests(unittest.TestCase):
    def test_cleartext_authentication_and_select_1(self):
        seen = {}

        def postgres(conn):
            reader, startup = read_startup(conn)
            seen["startup"] = startup
            conn.sendall(smoke._pg_message(b"R", struct.pack("!i", 3)))
            kind, payload = read_pg_message(reader)
            seen["password"] = (kind, payload)
            conn.sendall(smoke._pg_message(b"R", struct.pack("!i", 0)))
            conn.sendall(smoke._pg_message(b"S", b"server_version\0" + b"17.11\0"))
            conn.sendall(smoke._pg_message(b"Z", b"I"))
            kind, payload = read_pg_message(reader)
            seen["query"] = (kind, payload)
            conn.sendall(smoke._pg_message(b"T", struct.pack("!h", 1) + b"?column?\0" + struct.pack("!ihihih", 0, 0, 23, 4, -1, 0)))
            conn.sendall(smoke._pg_message(b"D", struct.pack("!hi", 1, 1) + b"1"))
            conn.sendall(smoke._pg_message(b"C", b"SELECT 1\0"))
            conn.sendall(smoke._pg_message(b"Z", b"I"))
            seen["terminate"] = read_pg_message(reader)[0]

        server = support.OneShotServer(postgres)
        record = smoke.probe("postgres", settings_for(
            PENNILOGIC_POSTGRES_PORT=str(server.port), PENNILOGIC_POSTGRES_PASSWORD="dev-only",
            PENNILOGIC_POSTGRES_USER="alice", PENNILOGIC_POSTGRES_DATABASE="ledger"), timeout=5.0)
        server.close()
        self.assertEqual("ok", record["status"], record)
        self.assertIsNone(record["detail"])
        self.assertIn(b"user\0alice\0", seen["startup"])
        self.assertIn(b"database\0ledger\0", seen["startup"])
        self.assertEqual((b"p", b"dev-only\0"), seen["password"])
        self.assertEqual((b"Q", b"SELECT 1\0"), seen["query"])
        self.assertEqual(b"X", seen["terminate"])

    def test_md5_authentication_uses_salt(self):
        def postgres(conn):
            reader, _ = read_startup(conn)
            conn.sendall(smoke._pg_message(b"R", struct.pack("!i", 5) + b"salt"))
            kind, payload = read_pg_message(reader)
            expected = b"md5" + __import__("hashlib").md5(
                __import__("hashlib").md5(b"dev-onlypennilogic").hexdigest().encode() + b"salt").hexdigest().encode()
            assert (kind, payload) == (b"p", expected + b"\0"), (kind, payload)
            conn.sendall(smoke._pg_message(b"R", struct.pack("!i", 0)))
            conn.sendall(smoke._pg_message(b"Z", b"I"))
            read_pg_message(reader)
            conn.sendall(smoke._pg_message(b"D", struct.pack("!hi", 1, 1) + b"1"))
            conn.sendall(smoke._pg_message(b"C", b"SELECT 1\0"))
            conn.sendall(smoke._pg_message(b"Z", b"I"))
            read_pg_message(reader)

        server = support.OneShotServer(postgres)
        record = smoke.probe("postgres", settings_for(
            PENNILOGIC_POSTGRES_PORT=str(server.port), PENNILOGIC_POSTGRES_PASSWORD="dev-only"), timeout=5.0)
        server.close()
        self.assertEqual("ok", record["status"], record)

    def test_authentication_failure_is_hinted_and_redacted(self):
        secret = "leaky-secret-value-42"

        def postgres(conn):
            reader, _ = read_startup(conn)
            conn.sendall(smoke._pg_message(b"R", struct.pack("!i", 3)))
            read_pg_message(reader)
            # A hostile/buggy server that echoes the password back must still not leak it.
            conn.sendall(error_response("28P01", f"password authentication failed for user \"pennilogic\" ({secret})"))

        server = support.OneShotServer(postgres)
        record = smoke.probe("postgres", settings_for(
            PENNILOGIC_POSTGRES_PORT=str(server.port), PENNILOGIC_POSTGRES_PASSWORD=secret), timeout=5.0)
        server.close()
        self.assertEqual("error", record["status"])
        self.assertIn("28P01", record["detail"])
        self.assertIn("--reset", record["detail"])
        self.assertNotIn(secret, json.dumps(record))
        self.assertIn("[redacted]", record["detail"])

    def test_blank_password_against_authenticating_server_is_explained(self):
        def postgres(conn):
            reader, _ = read_startup(conn)
            conn.sendall(smoke._pg_message(b"R", struct.pack("!i", 10) + b"SCRAM-SHA-256\0\0"))

        server = support.OneShotServer(postgres)
        record = smoke.probe("postgres", settings_for(PENNILOGIC_POSTGRES_PORT=str(server.port)), timeout=5.0)
        server.close()
        self.assertEqual("error", record["status"])
        self.assertIn("PENNILOGIC_POSTGRES_PASSWORD is blank", record["detail"])

    def test_scram_server_signature_mismatch_is_rejected(self):
        def postgres(conn):
            reader, _ = read_startup(conn)
            conn.sendall(smoke._pg_message(b"R", struct.pack("!i", 10) + b"SCRAM-SHA-256\0\0"))
            kind, payload = read_pg_message(reader)
            assert payload.startswith(b"SCRAM-SHA-256\0"), payload
            first = payload[len(b"SCRAM-SHA-256\0") + 4:].decode()
            client_nonce = first.split("r=", 1)[1]
            server_first = f"r={client_nonce}SERVER,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
            conn.sendall(smoke._pg_message(b"R", struct.pack("!i", 11) + server_first.encode()))
            read_pg_message(reader)
            conn.sendall(smoke._pg_message(b"R", struct.pack("!i", 12) + b"v=" + base64.b64encode(b"\0" * 32)))

        server = support.OneShotServer(postgres)
        record = smoke.probe("postgres", settings_for(
            PENNILOGIC_POSTGRES_PORT=str(server.port), PENNILOGIC_POSTGRES_PASSWORD="dev-only"), timeout=5.0)
        server.close()
        self.assertEqual("error", record["status"])
        self.assertIn("server signature mismatch", record["detail"])


class FakeRedisTests(unittest.TestCase):
    @staticmethod
    def resp_server(replies, transcript):
        def redis(conn):
            reader = smoke._Reader(conn)
            for reply in replies:
                count = int(reader.read_line()[1:])
                parts = []
                for _ in range(count):
                    length = int(reader.read_line()[1:])
                    parts.append(reader.read_exact(length).decode())
                    reader.read_exact(2)
                transcript.append(parts)
                conn.sendall(reply)
        return redis

    def test_ping_with_auth_and_database_select(self):
        transcript = []
        server = support.OneShotServer(self.resp_server(
            [b"+OK\r\n", b"+OK\r\n", b"+PONG\r\n", b"+OK\r\n"], transcript))
        record = smoke.probe("redis", settings_for(
            PENNILOGIC_REDIS_PORT=str(server.port), PENNILOGIC_REDIS_PASSWORD="r-secret",
            PENNILOGIC_REDIS_DATABASE="3"), timeout=5.0)
        server.close()
        self.assertEqual("ok", record["status"], record)
        self.assertEqual([["AUTH", "r-secret"], ["SELECT", "3"], ["PING"], ["QUIT"]], transcript)

    def test_noauth_reply_explains_blank_password(self):
        transcript = []
        server = support.OneShotServer(self.resp_server([b"-NOAUTH Authentication required.\r\n"], transcript))
        record = smoke.probe("redis", settings_for(PENNILOGIC_REDIS_PORT=str(server.port)), timeout=5.0)
        server.close()
        self.assertEqual("error", record["status"])
        self.assertIn("PENNILOGIC_REDIS_PASSWORD is blank", record["detail"])
        self.assertEqual([["SELECT", "0"]], transcript)

    def test_wrongpass_is_explained_without_echoing_secret(self):
        transcript = []
        server = support.OneShotServer(self.resp_server([b"-WRONGPASS invalid username-password pair\r\n"], transcript))
        record = smoke.probe("redis", settings_for(
            PENNILOGIC_REDIS_PORT=str(server.port), PENNILOGIC_REDIS_PASSWORD="r-secret"), timeout=5.0)
        server.close()
        self.assertEqual("error", record["status"])
        self.assertIn("do not match", record["detail"])
        self.assertNotIn("r-secret", json.dumps(record))

    def test_user_without_password_is_rejected_locally(self):
        transcript = []
        server = support.OneShotServer(self.resp_server([], transcript))
        record = smoke.probe("redis", settings_for(
            PENNILOGIC_REDIS_PORT=str(server.port), PENNILOGIC_REDIS_USER="alice"), timeout=5.0)
        server.close()
        self.assertEqual("error", record["status"])
        self.assertIn("no ACL users", record["detail"])


class DocumentTests(unittest.TestCase):
    def test_run_document_shape(self):
        closed = support.free_port()
        document = smoke.run(settings_for(
            PENNILOGIC_POSTGRES_PORT=str(closed), PENNILOGIC_REDIS_PORT=str(closed)), timeout=1.0)
        self.assertEqual(smoke.SCHEMA, document["schema"])
        self.assertFalse(document["ok"])
        self.assertEqual(["postgres", "redis"], [r["service"] for r in document["services"]])
        for record in document["services"]:
            self.assertEqual({"service", "status", "latency_ms", "detail"}, set(record))

    def test_main_prints_json_to_stdout_and_exits_nonzero_when_unreachable(self):
        closed = support.free_port()
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text(f"PENNILOGIC_POSTGRES_PORT={closed}\nPENNILOGIC_REDIS_PORT={closed}\n"
                                "PENNILOGIC_POSTGRES_PASSWORD=unused\n", encoding="utf-8")
            output = Path(tmp) / "smoke.json"
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = smoke.main(["--env-file", str(env_file), "--timeout", "1", "--output", str(output)])
            self.assertEqual(1, code)
            document = json.loads(stdout.getvalue())
            self.assertEqual(document, json.loads(output.read_text(encoding="utf-8")))
        self.assertEqual({"unreachable"}, {r["status"] for r in document["services"]})
        self.assertIn("postgres: unreachable", stderr.getvalue())
        self.assertNotIn("unused", stdout.getvalue() + stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
