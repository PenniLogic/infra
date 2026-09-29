# Local infrastructure: Postgres 17 and Redis 7 for development

Development-only. Nothing here deploys, configures or protects a production system.
Schema migrations and seed data are **not** part of this stack; see
[Out of scope](#out-of-scope-and-owners).

## Prerequisites

- Docker Engine with Compose v2 (Docker Desktop on Windows/macOS, or the `docker` service
  with the `docker-compose-plugin` on Linux). Verify with `docker compose version`.
- Python 3.14 (the scripts use only the standard library).

## Setup: one command

```text
python scripts/bootstrap.py
```

On the first run it:

1. creates `.env` from `.env.example` (git-ignored) and fills in a random, development-only
   `PENNILOGIC_POSTGRES_PASSWORD`;
2. refuses to start if the publish address is not a loopback address, if a port is invalid or
   if `PENNILOGIC_POSTGRES_PASSWORD` is blank;
3. checks that ports 5432 and 6379 (or your overrides) are free and, if not, fails fast
   naming the port and its holder (see [Port conflicts](#port-conflicts));
4. runs `docker compose up --detach` for the Compose project `pennilogic`;
5. waits until both containers' own health checks report `healthy`
   (`pg_isready` inside Postgres, `redis-cli ping` inside Redis);
6. prints one JSON summary to stdout and a short human log to stderr, and exits 0.

Running it again is safe: an already healthy stack is left as it is, and the summary
confirms exactly one container per service and exactly the two named volumes.

```json
{
  "schema": "pennilogic.infra.bootstrap/1",
  "action": "up",
  "ok": true,
  "project": "pennilogic",
  "services": [
    {"service": "postgres", "healthy": true, "startup_ms": 2430},
    {"service": "redis", "healthy": true, "startup_ms": 1308}
  ],
  "checks": {
    "single_stack": true,
    "containers": {"postgres": 1, "redis": 1},
    "orphan_containers": 0,
    "volumes": ["pennilogic_pgdata", "pennilogic_redisdata"],
    "logs_free_of_credentials": true
  },
  "warnings": [],
  "error": null,
  "elapsed_ms": 4512
}
```

`startup_ms` is the time from container start to the first successful health probe, read
from Docker's health log; for a container that was already running it is `0`. On failure
`ok` is `false`, `error.kind` is one of `port_conflict`, `non_loopback_bind`,
`missing_password`, `invalid_port`, `invalid_project`, `docker_unavailable`,
`docker_missing`, `compose_failed`, `unhealthy`, `timeout`, `not_single_stack`,
`credential_in_logs`, `smoke_failed`, `teardown_incomplete`, `locked`, `io_error`, and the
exit code is 1. Concurrent runs for the same project wait for each other (a lock file in the
system temp directory) instead of racing Compose.
`--summary-file <path>` writes the same document to a file for CI artifacts.

Plain Compose also works once `.env` exists: `docker compose up -d --wait`.

## Health and status

```text
python scripts/bootstrap.py --status      # health + startup_ms for both services, starts nothing
docker compose ps                         # Docker's own view (State, Health, published ports)
```

## Smoke check over the published ports

```text
python scripts/smoke_infra.py             # exit 0 only if both services answer correctly
python scripts/bootstrap.py --smoke       # bootstrap, then embed the smoke document under "smoke"
```

The smoke check connects from the host like a client would: it authenticates to Postgres
(SCRAM-SHA-256, MD5 or cleartext, as the server requests) and runs `SELECT 1`, and sends
`PING` to Redis (with `AUTH` when `PENNILOGIC_REDIS_PASSWORD` is set). Its output is a
separate contract from the bootstrap summary:

```json
{
  "schema": "pennilogic.infra.smoke/1",
  "ok": true,
  "services": [
    {"service": "postgres", "status": "ok", "latency_ms": 16, "detail": null},
    {"service": "redis", "status": "ok", "latency_ms": 5, "detail": null}
  ]
}
```

`status` is `ok`, `unreachable` (nothing accepted the TCP connection) or `error` (something
answered, but not the configured service: wrong protocol, wrong credentials, silent decoy).
`detail` explains an error with credentials redacted. `--smoke` is optional for now; making it
the default is a later decision once it has run cleanly across consecutive CI runs.

## Teardown

```text
python scripts/bootstrap.py --down        # remove containers and network; KEEP the data volumes
```

Equivalent: `docker compose down --remove-orphans`. The next `python scripts/bootstrap.py`
recreates the containers against the existing data with no manual step.

## Reset (destroys development data)

```text
python scripts/bootstrap.py --reset       # remove containers, network AND named volumes together
```

Equivalent: `docker compose down --volumes --remove-orphans`. This is the only destructive
command and is never implied by any other action. Both teardown commands only act on
resources labelled with the `pennilogic` Compose project (or the `--project` you pass), so
other Compose projects, containers and volumes on the machine are never touched. After a
reset, `python scripts/bootstrap.py` initialises fresh data with the password in `.env`.

Use `--reset` when:

- Postgres rejects the credentials in `.env` (`28P01`), typically because the `pennilogic_pgdata`
  volume was initialised earlier with a different password. The bootstrap warns when it
  creates a new `.env` while such volumes already exist; it never wipes them for you.
- You want to re-run initialisation from scratch (locale, encoding, empty database).

## Port conflicts

The bootstrap checks each published port before starting anything. If port 5432 or 6379 is
already in use by a program outside this stack, it exits 1 without creating a container:

```text
bootstrap: Port conflict: service "postgres" needs 127.0.0.1:5432, but port 5432 is already in use by a process outside Docker (Windows: `netstat -ano | findstr :5432` then `tasklist /FI "PID eq <pid>"`; Linux/macOS: `ss -ltnp 'sport = :5432'` or `lsof -iTCP:5432 -sTCP:LISTEN`).
  Fix: set PENNILOGIC_POSTGRES_PORT=15432 in .env (a verified free port) and re-run, or stop the conflicting service.
Nothing was started.
```

When the holder is another Docker container, its name and Compose project are printed
instead. The JSON summary carries the same information under `error.kind = "port_conflict"`
and `error.ports`.

Resolution for a machine that already runs Postgres or Redis outside this stack:

1. Set a free port in `.env`, for example `PENNILOGIC_POSTGRES_PORT=15432` and/or
   `PENNILOGIC_REDIS_PORT=16379` (the message suggests a port verified free at that moment).
2. Point clients at the same variables; they read `PENNILOGIC_POSTGRES_PORT` / `PENNILOGIC_REDIS_PORT`.
3. Re-run `python scripts/bootstrap.py`.

Alternatively stop the conflicting service. Do **not** work around a conflict by binding to
another interface. If Docker itself reports a bind failure later (a port taken between the
check and the start, or a Windows excluded port range shown by `netsh interface ipv4 show
excludedportrange protocol=tcp`), the bootstrap translates it into the same named-port error.

## Configuration contract

All variables live in [`.env.example`](.env.example) and are read from `.env` by Docker
Compose and by both scripts with the same precedence: process environment, then `.env`, then
the documented default. Clients use the same names.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PENNILOGIC_BIND_ADDRESS` | `127.0.0.1` | Host interface the containers publish to (loopback only) |
| `PENNILOGIC_POSTGRES_HOST` / `_PORT` | `127.0.0.1` / `5432` | Where clients reach Postgres |
| `PENNILOGIC_POSTGRES_DATABASE` / `_USER` | `pennilogic` / `pennilogic` | Database and role created by the image |
| `PENNILOGIC_POSTGRES_PASSWORD` | *(generated into `.env`)* | Development-only; no default in the repository |
| `PENNILOGIC_REDIS_HOST` / `_PORT` | `127.0.0.1` / `6379` | Where clients reach Redis |
| `PENNILOGIC_REDIS_DATABASE` | `0` | Logical database index |
| `PENNILOGIC_REDIS_USER` / `_PASSWORD` | *(blank)* | Blank = no authentication on the loopback-only port |
| `COMPOSE_PROJECT_NAME` | `pennilogic` | Optional; names the containers, network and volumes |

Security boundaries of the default configuration:

- Ports are published on `127.0.0.1` only. A non-loopback `PENNILOGIC_BIND_ADDRESS` is
  refused unless you pass `--allow-non-loopback`, which exposes development credentials to
  your network and is never appropriate for shared or production use.
- No password is committed. `.env.example` leaves `PENNILOGIC_POSTGRES_PASSWORD` blank, the
  compose file has no fallback for it, and `.env` is git-ignored and created with owner-only
  permissions where the platform supports them.
- Credentials are passed to the containers as environment variables, never on a command line
  or in a mounted file that is committed. The bootstrap scans the fresh container logs and
  fails with `credential_in_logs` if a configured secret value appears; its own output
  redacts secrets.
- Images are pinned by tag **and** digest (`postgres:17.11-alpine3.24@sha256:...`,
  `redis:7.4.11-alpine3.21@sha256:...`) so every machine runs identical bytes. Upgrade by
  changing tag and digest together (`docker buildx imagetools inspect <image:tag>` prints the
  index digest).
- Postgres runs with `--locale=C --encoding=UTF8` so ordering is deterministic across
  machines. Redis runs with `appendonly yes` so quota-window data survives restarts. Redis
  keeps the image's privilege drop (the server runs as the `redis` user).

## Running the tests

```text
python -m unittest discover -s scripts/tests
```

`test_smoke_infra.py` and `test_bootstrap.py` need no Docker: they use fake Postgres/Redis
servers and decoy listeners on free loopback ports, and check the RFC 7677 SCRAM vector, the
env-file contract, the loopback refusal, credential redaction and the named-port diagnostic.
`test_integration_stack.py` runs the real stack in a uniquely named project
(`pennilogic-test-<random>`) on free loopback ports and removes only that project afterwards;
it is skipped with the reason when Docker is unreachable or `PENNILOGIC_SKIP_DOCKER_TESTS=1`.
It covers: fresh start healthy with smoke output, second start leaves one stack, `--down`
keeps data and recreate restores it, an existing volume with other credentials is warned
about and never wiped, `--reset` removes everything and recreate needs no manual step, an
occupied Postgres port fails fast naming the port, and `--status` is read-only.

## Out of scope and owners

- Schema migrations and seed data (including the awkward multi-currency, own-account transfer
  and 0 % APR cases): T-ENV-01, [PenniLogic/api#20](https://github.com/PenniLogic/api/issues/20),
  and the migration runner T-MIG-01, [PenniLogic/api#55](https://github.com/PenniLogic/api/issues/55).
  This stack asserts nothing about schemas.
- Production infrastructure, backup/restore of the local volume, and any deployment.
