"""Probe the local Postgres and Redis over their published ports and report readiness.

Usable by a person or CI without third-party packages: it speaks just enough of the
PostgreSQL wire protocol (SCRAM-SHA-256, MD5 or cleartext authentication, then
``SELECT 1``) and of Redis RESP (``AUTH``/``SELECT``/``PING``) to prove that the
service answering on each published port is the configured one.

Output contract (stdout, one JSON document)::

    {"schema": "pennilogic.infra.smoke/1", "ok": true,
     "services": [{"service": "postgres", "status": "ok", "latency_ms": 12, "detail": null},
                  {"service": "redis", "status": "ok", "latency_ms": 2, "detail": null}]}

``status`` is ``ok``, ``unreachable`` (no TCP answer) or ``error`` (answered, but not as the
configured service). The exit code is 0 only when every probed service is ``ok``.
Credentials never appear in the output: any surfaced text is redacted first.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = ROOT / ".env"
SCHEMA = "pennilogic.infra.smoke/1"
SERVICES = ("postgres", "redis")
STATUS_OK, STATUS_UNREACHABLE, STATUS_ERROR = "ok", "unreachable", "error"
REDACTED = "[redacted]"
DEFAULTS = {
    "PENNILOGIC_BIND_ADDRESS": "127.0.0.1",
    "PENNILOGIC_POSTGRES_HOST": "127.0.0.1",
    "PENNILOGIC_POSTGRES_PORT": "5432",
    "PENNILOGIC_POSTGRES_DATABASE": "pennilogic",
    "PENNILOGIC_POSTGRES_USER": "pennilogic",
    "PENNILOGIC_POSTGRES_PASSWORD": "",
    "PENNILOGIC_REDIS_HOST": "127.0.0.1",
    "PENNILOGIC_REDIS_PORT": "6379",
    "PENNILOGIC_REDIS_DATABASE": "0",
    "PENNILOGIC_REDIS_USER": "",
    "PENNILOGIC_REDIS_PASSWORD": "",
}
SECRET_KEYS = ("PENNILOGIC_POSTGRES_PASSWORD", "PENNILOGIC_REDIS_PASSWORD")
_ENV_LINE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


class ProbeError(Exception):
    """The service answered, but not as the configured service."""


class Unreachable(Exception):
    """No TCP connection could be established to the published port."""


# --- environment contract -----------------------------------------------------------------

def parse_env_file(path):
    """Parse KEY=VALUE lines the way Docker Compose reads ``.env`` (common subset)."""
    values = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].rstrip()
        values[key] = value
    return values


def load_settings(env_file=DEFAULT_ENV_FILE, environ=None):
    """Resolve the published variables: process environment > env file > defaults.

    Mirrors Compose's ``${VAR:-default}``: an empty value falls back to a non-empty default.
    """
    environ = os.environ if environ is None else environ
    from_file = parse_env_file(env_file) if env_file and Path(env_file).is_file() else {}
    settings = {}
    for key in list(DEFAULTS) + [k for k in from_file if k not in DEFAULTS]:
        value = environ[key] if key in environ else from_file.get(key)
        default = DEFAULTS.get(key, "")
        settings[key] = default if value is None or (value == "" and default) else value
    return settings


def port_of(settings, key):
    value = settings[key]
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError(f"{key} must be a TCP port between 1 and 65535, got {value!r}")
    return int(value)


def secret_values(settings):
    return tuple(settings[key] for key in SECRET_KEYS if settings.get(key))


def redact(text, values):
    """Replace every configured secret value in ``text`` with a marker (longest first)."""
    text = str(text)
    for value in sorted(values, key=len, reverse=True):
        if value:
            text = text.replace(value, REDACTED)
    return text


# --- byte helpers ---------------------------------------------------------------------------

class _Reader:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""

    def read_exact(self, size):
        while len(self.buffer) < size:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ProbeError("connection closed by the server before the reply was complete")
            self.buffer += chunk
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data

    def read_line(self):
        while b"\r\n" not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ProbeError("connection closed by the server before the reply was complete")
            self.buffer += chunk
            if len(self.buffer) > 65536:
                raise ProbeError("unexpected reply without a line terminator")
        line, self.buffer = self.buffer.split(b"\r\n", 1)
        return line


def _cstring(value):
    return value.encode("utf-8") + b"\0"


def _connect(host, port, timeout):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as error:
        raise Unreachable(f"no TCP answer from {host}:{port} within {timeout:g}s: {error}") from error
    sock.settimeout(timeout)
    return sock


# --- PostgreSQL wire protocol (version 3) ------------------------------------------------------

def scram_messages(password, client_first_bare, server_first):
    """Return (client_final_message, expected_server_signature) for SCRAM-SHA-256.

    Pure function over the exchanged strings so it can be checked against RFC 7677.
    """
    fields = dict(part.split("=", 1) for part in server_first.split(","))
    for name in ("r", "s", "i"):
        if name not in fields:
            raise ProbeError("malformed SCRAM server-first-message")
    client_nonce = dict(part.split("=", 1) for part in client_first_bare.split(","))["r"]
    if not fields["r"].startswith(client_nonce):
        raise ProbeError("SCRAM server nonce does not continue the client nonce")
    salted = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), base64.b64decode(fields["s"]), int(fields["i"]),
    )
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    without_proof = "c=" + base64.b64encode(b"n,,").decode("ascii") + ",r=" + fields["r"]
    auth_message = ",".join((client_first_bare, server_first, without_proof)).encode("utf-8")
    client_signature = hmac.new(stored_key, auth_message, hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, client_signature))
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    server_signature = hmac.new(server_key, auth_message, hashlib.sha256).digest()
    return without_proof + ",p=" + base64.b64encode(proof).decode("ascii"), server_signature


def _pg_message(kind, payload):
    return kind + struct.pack("!i", len(payload) + 4) + payload


def _pg_read(reader):
    header = reader.read_exact(5)
    length = struct.unpack("!i", header[1:5])[0]
    if length < 4 or length > 1 << 24:
        raise ProbeError("the port answered, but not with the PostgreSQL protocol")
    return header[0:1], reader.read_exact(length - 4)


def _pg_error(payload):
    fields = {}
    for part in payload.split(b"\0"):
        if part:
            fields[chr(part[0])] = part[1:].decode("utf-8", "replace")
    code, message = fields.get("C", "?"), fields.get("M", "unknown error")
    if code in ("28P01", "28000", "3D000"):
        message += (
            " - the configured PENNILOGIC_POSTGRES_USER/PASSWORD/DATABASE do not match the server on"
            " this port (another Postgres, or a data volume initialised with different settings;"
            " `python scripts/bootstrap.py --reset` re-initialises it)"
        )
    return ProbeError(f"server error {code}: {message}")


def _pg_authenticate(sock, reader, user, password):
    while True:
        kind, payload = _pg_read(reader)
        if kind == b"E":
            raise _pg_error(payload)
        if kind == b"N":
            continue
        if kind != b"R":
            raise ProbeError("the port answered, but not with the PostgreSQL protocol")
        code = struct.unpack("!i", payload[:4])[0]
        if code == 0:
            return
        if code in (3, 5, 10) and not password:
            raise ProbeError("the server requires a password but PENNILOGIC_POSTGRES_PASSWORD is blank")
        if code == 3:
            sock.sendall(_pg_message(b"p", _cstring(password)))
        elif code == 5:
            inner = hashlib.md5((password + user).encode("utf-8")).hexdigest().encode("ascii")
            digest = hashlib.md5(inner + payload[4:8]).hexdigest()
            sock.sendall(_pg_message(b"p", _cstring("md5" + digest)))
        elif code == 10:
            mechanisms = [m for m in payload[4:].split(b"\0") if m]
            if b"SCRAM-SHA-256" not in mechanisms:
                raise ProbeError("server offers no supported SASL mechanism")
            client_first_bare = "n=,r=" + secrets.token_urlsafe(18)
            first = ("n,," + client_first_bare).encode("utf-8")
            sock.sendall(_pg_message(b"p", b"SCRAM-SHA-256\0" + struct.pack("!i", len(first)) + first))
            kind, payload = _pg_read(reader)
            if kind == b"E":
                raise _pg_error(payload)
            if kind != b"R" or struct.unpack("!i", payload[:4])[0] != 11:
                raise ProbeError("unexpected reply during SCRAM authentication")
            server_first = payload[4:].decode("utf-8")
            client_final, expected = scram_messages(password, client_first_bare, server_first)
            sock.sendall(_pg_message(b"p", client_final.encode("utf-8")))
            kind, payload = _pg_read(reader)
            if kind == b"E":
                raise _pg_error(payload)
            if kind != b"R" or struct.unpack("!i", payload[:4])[0] != 12:
                raise ProbeError("unexpected reply during SCRAM authentication")
            final = dict(part.split("=", 1) for part in payload[4:].decode("utf-8").split(","))
            if not hmac.compare_digest(base64.b64decode(final.get("v", "")), expected):
                raise ProbeError("SCRAM server signature mismatch: the server did not prove it knows the password")
        else:
            raise ProbeError(f"unsupported PostgreSQL authentication method (code {code})")


def probe_postgres(settings, timeout):
    host, port = settings["PENNILOGIC_POSTGRES_HOST"], port_of(settings, "PENNILOGIC_POSTGRES_PORT")
    user, database = settings["PENNILOGIC_POSTGRES_USER"], settings["PENNILOGIC_POSTGRES_DATABASE"]
    with _connect(host, port, timeout) as sock:
        reader = _Reader(sock)
        params = b"".join(_cstring(k) + _cstring(v) for k, v in (
            ("user", user), ("database", database), ("client_encoding", "UTF8"),
            ("application_name", "pennilogic-smoke"),
        ))
        startup = struct.pack("!i", 196608) + params + b"\0"
        sock.sendall(struct.pack("!i", len(startup) + 4) + startup)
        _pg_authenticate(sock, reader, user, settings["PENNILOGIC_POSTGRES_PASSWORD"])
        while True:
            kind, payload = _pg_read(reader)
            if kind == b"E":
                raise _pg_error(payload)
            if kind == b"Z":
                break
        sock.sendall(_pg_message(b"Q", _cstring("SELECT 1")))
        rows = []
        while True:
            kind, payload = _pg_read(reader)
            if kind == b"E":
                raise _pg_error(payload)
            if kind == b"D":
                columns = struct.unpack("!h", payload[:2])[0]
                length = struct.unpack("!i", payload[2:6])[0]
                rows.append((columns, payload[6:6 + length]))
            if kind == b"Z":
                break
        sock.sendall(_pg_message(b"X", b""))
    if rows != [(1, b"1")]:
        raise ProbeError("SELECT 1 did not return a single row containing 1")


# --- Redis RESP -----------------------------------------------------------------------------------

def _resp_command(*parts):
    encoded = [p.encode("utf-8") for p in parts]
    return b"*%d\r\n" % len(encoded) + b"".join(b"$%d\r\n%s\r\n" % (len(p), p) for p in encoded)


def _redis_call(sock, reader, *parts):
    sock.sendall(_resp_command(*parts))
    line = reader.read_line()
    if not line or line[0:1] not in b"+-:$*_":
        raise ProbeError("the port answered, but not with the Redis protocol")
    if line[0:1] == b"-":
        message = line[1:].decode("utf-8", "replace")
        if message.startswith("NOAUTH"):
            message += " - the server requires a password but PENNILOGIC_REDIS_PASSWORD is blank"
        elif message.startswith("WRONGPASS"):
            message = "WRONGPASS - PENNILOGIC_REDIS_USER/PASSWORD do not match the server on this port"
        raise ProbeError(f"server error: {message}")
    return line[1:].decode("utf-8", "replace")


def probe_redis(settings, timeout):
    host, port = settings["PENNILOGIC_REDIS_HOST"], port_of(settings, "PENNILOGIC_REDIS_PORT")
    user, password = settings["PENNILOGIC_REDIS_USER"], settings["PENNILOGIC_REDIS_PASSWORD"]
    database = settings["PENNILOGIC_REDIS_DATABASE"]
    if not database.isdigit():
        raise ValueError(f"PENNILOGIC_REDIS_DATABASE must be a non-negative integer, got {database!r}")
    with _connect(host, port, timeout) as sock:
        reader = _Reader(sock)
        if password:
            _redis_call(sock, reader, "AUTH", *([user] if user else []), password)
        elif user and user != "default":
            raise ProbeError("PENNILOGIC_REDIS_USER is set without a password; this stack configures no ACL users")
        _redis_call(sock, reader, "SELECT", database)
        if _redis_call(sock, reader, "PING") != "PONG":
            raise ProbeError("PING was not answered with PONG")
        _redis_call(sock, reader, "QUIT")


# --- driver -----------------------------------------------------------------------------------------

PROBES = {"postgres": probe_postgres, "redis": probe_redis}


def probe(service, settings, timeout):
    """Return one contract record: {service, status, latency_ms, detail}."""
    started = time.perf_counter()
    status, detail = STATUS_OK, None
    try:
        PROBES[service](settings, timeout)
    except Unreachable as error:
        status, detail = STATUS_UNREACHABLE, str(error)
    except (socket.timeout, TimeoutError):
        status = STATUS_ERROR
        detail = (f"connected, but no {service} protocol reply within {timeout:g}s"
                  " (is another program bound to this port?)")
    except (ProbeError, OSError, ValueError, UnicodeDecodeError, KeyError, struct.error) as error:
        status, detail = STATUS_ERROR, str(error)
    latency_ms = int(round((time.perf_counter() - started) * 1000))
    if detail is not None:
        detail = redact(detail, secret_values(settings))
    return {"service": service, "status": status, "latency_ms": latency_ms, "detail": detail}


def run(settings, timeout=5.0, services=SERVICES):
    records = [probe(service, settings, timeout) for service in services]
    return {"schema": SCHEMA, "ok": all(r["status"] == STATUS_OK for r in records), "services": records}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE,
                        help="environment file to read (default: .env next to docker-compose.yml)")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-service timeout in seconds (default 5)")
    parser.add_argument("--service", action="append", choices=SERVICES, help="probe only this service (repeatable)")
    parser.add_argument("--output", type=Path, help="also write the JSON document to this file")
    args = parser.parse_args(argv)
    try:
        settings = load_settings(args.env_file)
    except (OSError, UnicodeDecodeError) as error:
        print(f"Cannot read {args.env_file}: {error}", file=sys.stderr)
        return 1
    document = run(settings, args.timeout, tuple(args.service or SERVICES))
    for record in document["services"]:
        note = "" if record["detail"] is None else f" - {record['detail']}"
        print(f"{record['service']}: {record['status']} ({record['latency_ms']} ms){note}", file=sys.stderr)
    text = json.dumps(document, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if document["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
