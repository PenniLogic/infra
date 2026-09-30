# Local infrastructure: Postgres 17 and Redis 7 for development

Development-only. Nothing here deploys, configures or protects a production system.
Schema migrations and seed data are **not** part of this stack; see
[Out of scope](#out-of-scope-and-owners).

## Prerequisites

- Docker Engine with the Compose plugin (`docker compose`, any current version; Docker Desktop
  on Windows/macOS, or the `docker` service with `docker-compose-plugin` on Linux). Verify with
  `docker compose version`.
- Python 3.14 (the scripts use only the standard library).

## Commands at a glance

| Command | What it does |
| --- | --- |
| `python scripts/bootstrap.py` | Create `.env` on first run, start the stack, wait for health, print the JSON summary |
| `python scripts/bootstrap.py --smoke` | Same, then run the smoke check and embed its document under `"smoke"` |
| `python scripts/bootstrap.py --status` | Report health and `startup_ms`; starts nothing, never creates `.env` |
| `python scripts/bootstrap.py --down` | Remove containers and network; **keep** the data volumes |
| `python scripts/bootstrap.py --reset` | Remove containers, network **and** data volumes (destroys development data) |
| `python scripts/smoke_infra.py` | Probe both services over their published ports; exit 0 only if both answer correctly |
| `python -m unittest discover -s scripts/tests` | Run the tests (Docker-free ones always; the real-stack ones when Docker is reachable) |

Options shared by every `bootstrap.py` action: `--project <name>` (Compose project; default
`COMPOSE_PROJECT_NAME` from `.env`, else `pennilogic`), `--env-file <path>` (default `.env`),
`--summary-file <path>` (also write the JSON summary there), `--timeout <seconds>` (health wait
after `docker compose up` returns; default 120; image pulls are not counted),
`--allow-non-loopback`, `--verbose`. `python scripts/bootstrap.py --help` and
`python scripts/smoke_infra.py --help` list everything.

## Setup: one command

```text
python scripts/bootstrap.py
```

On the first run it:

1. creates `.env` from `.env.example` (git-ignored) and fills in a random, development-only
   `PENNILOGIC_POSTGRES_PASSWORD`;
2. refuses to start if the publish address is not a loopback IP address, if a port is invalid
   or if `PENNILOGIC_POSTGRES_PASSWORD` is blank;
3. checks that ports 5432 and 6379 (or your overrides) are free and, if not, exits within a
   few seconds naming the port and its holder (see [Port conflicts](#port-conflicts));
4. runs `docker compose up --detach` for the Compose project `pennilogic` (on a clean machine
   this pulls the two pinned images first; that time does not count against `--timeout`);
5. waits until both containers' own health checks report `healthy`
   (`pg_isready` inside Postgres, `redis-cli ping` inside Redis);
6. prints one JSON summary to stdout and a short human log to stderr, and exits 0.

Running it again is safe: an already healthy stack is left as it is, and the summary
confirms exactly one container per service and exactly the two named volumes. Concurrent
runs for the same project wait for each other instead of racing Compose: the lock is an OS
file lock on a zero-byte `<project>.lock` file in a per-user directory under the system temp
directory (`pennilogic-bootstrap-locks[-<uid>]`). It is released automatically when the
holder exits, so it can never be stale; the small files are intentionally left in place and
may be ignored.

```json
{
  "schema": "pennilogic.infra.bootstrap/1",
  "action": "up",
  "ok": true,
  "project": "pennilogic",
  "services": [
    {"service": "postgres", "healthy": true, "startup_ms": 2430, "startup_source": "health_log"},
    {"service": "redis", "healthy": true, "startup_ms": 1308, "startup_source": "health_log"}
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

`startup_ms` is the container's own time from start to its first successful health probe,
read from Docker's health log, and `startup_source` says where the number comes from:

| `startup_source` | `startup_ms` | When |
| --- | --- | --- |
| `health_log` | measured | The container was started by this run (or its first success is still in Docker's health log) |
| `already_running` | `0` | The container was already running and healthy before this run (idempotent re-run) |
| `unknown` | `null` | Docker's health log (last five probes, so about 25 s after the first success at the 5 s interval) no longer holds the first success, e.g. `--status` on a stack started half a minute or more ago, or the service is not healthy |

The script's own waiting time is never reported as `startup_ms`. For CI trend tracking,
filter on `startup_source == "health_log"`.

On failure `ok` is `false`, the exit code is 1, and `error.kind` is one of `port_conflict`,
`non_loopback_bind`, `missing_password`, `invalid_port`, `invalid_project`,
`missing_example`, `invalid_example`, `docker_missing`, `docker_unavailable`,
`docker_timeout`, `compose_failed`, `unhealthy`, `timeout`, `not_single_stack`,
`credential_in_logs`, `smoke_failed`, `teardown_incomplete`, `locked`, `io_error`;
`interrupted` (Ctrl-C) exits 130. `error.message` is human-readable and redacted;
`port_conflict` also carries `error.ports`.

Every `docker` command the bootstrap runs has its own time limit (`docker compose up`: 600 s or
`--timeout`, whichever is larger, so a slow first image pull is not cut short; `--down` and
`--reset`: 180 s; the read-only commands: 30-60 s), and `docker_timeout` names the command that
overran it. On Windows, `docker.exe` runs `docker compose` as a child process,
`docker-compose.exe`, which keeps the command's output open and keeps working after `docker.exe`
alone is killed. The bootstrap therefore runs each `docker` command inside a Windows job object
and, on a timeout, terminates docker and every process it started together: the error is raised
within the time limit plus about 5 s (the bounded teardown wait, plus a fraction of a second of
process start-up and teardown overhead), and `error.cleanup` states whether every process of that
tree was confirmed to have exited (the bootstrap waits on their process objects, which Windows
signals only after the process's handles are released) or what could not be confirmed. On Linux
and macOS only `docker` itself is killed, as before; a compose plugin that is still working may
finish on its own. Either way the containers belong to the Docker Engine, not to the bootstrap,
so a timed-out `up` can leave a partly created stack behind; the next `python scripts/bootstrap.py`
converges it (or `--down` removes it). If Windows refuses to create that job object, the command
is not started; if it refuses to place the already started command in it, the command is
terminated at once. Either way the run fails with `io_error` naming the refused call and the
Windows error; in practice that means the bootstrap itself is running inside a job object that
forbids nested jobs, so re-run it from a plain terminal.

Plain Compose also works once `.env` exists: `docker compose up -d --wait`.

## Health and status

```text
python scripts/bootstrap.py --status      # health + startup_ms/startup_source for both services, starts nothing
docker compose ps                         # Docker's own view (State, Health, published ports)
```

## Smoke check over the published ports

```text
python scripts/smoke_infra.py             # exit 0 only if both services answer correctly
python scripts/bootstrap.py --smoke       # bootstrap, then embed the smoke document under "smoke"
```

The smoke check connects from the host like a client would: it authenticates to Postgres
with SCRAM-SHA-256 **only** and runs `SELECT 1`, and sends `PING` to Redis (with `AUTH` when
`PENNILOGIC_REDIS_PASSWORD` is set). If whatever answers on the Postgres port asks for a weaker
method (cleartext, MD5, Kerberos, GSSAPI, SSPI) or for an unexpected SASL mechanism, the probe
reports `error` and does not send the password: the stack's Postgres 17 never asks for less,
so such a request means a different server holds the port. Its output is a separate contract
from the bootstrap summary:

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
answered, but not the configured service: wrong protocol, wrong credentials, authentication
downgrade, silent decoy). `detail` explains an error with credentials redacted. Limitation:
with the default blank `PENNILOGIC_REDIS_PASSWORD`, an `ok` for Redis proves that *a* Redis
answers `PING` on the configured port, not that it is this stack's container; the bootstrap's
port preflight is what prevents the stack from silently sharing a port with a foreign Redis.
`--smoke` is optional for now; making it the default is a later decision once it has run
cleanly across consecutive CI runs.

## Teardown

```text
python scripts/bootstrap.py --down        # remove containers and network; KEEP the data volumes
```

Equivalent: `docker compose down --remove-orphans`. The next `python scripts/bootstrap.py`
recreates the containers against the existing data with no manual step. To see for yourself
that data survives, write a marker before `--down` and read it after the recreate (run these
from PowerShell or a POSIX shell, where single quotes work as shown; `cmd.exe` quotes
differently and will fail on them verbatim):

```text
docker compose exec -T redis sh -c '[ -z "$REDIS_PASSWORD" ] || export REDISCLI_AUTH="$REDIS_PASSWORD"; redis-cli SET marker kept'
docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "CREATE TABLE IF NOT EXISTS marker(kept boolean)"'
python scripts/bootstrap.py --down && python scripts/bootstrap.py
docker compose exec -T redis sh -c '[ -z "$REDIS_PASSWORD" ] || export REDISCLI_AUTH="$REDIS_PASSWORD"; redis-cli GET marker'          # -> kept
docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "\dt marker"'   # -> lists public | marker
```

(The quoted `sh -c` scripts run inside the containers, where `POSTGRES_USER`, `POSTGRES_DB`
and `REDIS_PASSWORD` are already set, so no credential is typed on your host command line.
After `--reset` the Redis read prints an empty line (`redis-cli` without a terminal prints
nothing for a missing key) and psql says `Did not find any relation named "marker"`.)

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
  volume was initialised earlier with a different password. Whenever a run creates a new
  `.env` while such volumes already exist, the summary's `warnings` names those volumes and
  this command, on stderr as `bootstrap: warning: ...` (also when that run then stops at the
  port check); nothing is ever wiped for you.
- You want to re-run initialisation from scratch (locale, encoding, empty database).

## Port conflicts

The bootstrap checks each published port before starting anything. If port 5432 or 6379 is
already in use by a program outside this stack, it exits 1 within a few seconds without
creating a container:

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
another interface.

The preflight can only see ports that accept connections. If a program holds a port without
listening on it, or takes it between the check and the start, or the port is in a Windows
excluded range (`netsh interface ipv4 show excludedportrange protocol=tcp`), Docker itself
fails to bind. The bootstrap then reports the same `error.kind = "port_conflict"` with
`error.ports` naming the port and exits 1. If the project had no containers before the run,
the containers and network that Compose had already created are removed again so nothing
half-started is left behind; if the project already had containers (a failed re-run), the
rollback does not touch them (Compose itself may have recreated a container whose port
changed; the next successful run converges to one healthy stack). Either way the data volumes
are kept and the message states what was done (`error.rollback` carries the same sentence).
Fix the port in `.env` and re-run.

## Configuration contract

All variables live in [`.env.example`](.env.example) and are read from `.env` by Docker
Compose and by both scripts with the same precedence: process environment, then `.env`, then
the documented default. Clients use the same names.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PENNILOGIC_BIND_ADDRESS` | `127.0.0.1` | Host IP address the containers publish to (loopback only; an IP literal such as `127.0.0.1` or `::1`, not `localhost`) |
| `PENNILOGIC_POSTGRES_HOST` / `_PORT` | `127.0.0.1` / `5432` | Where clients reach Postgres |
| `PENNILOGIC_POSTGRES_DATABASE` / `_USER` | `pennilogic` / `pennilogic` | Database and role created by the image |
| `PENNILOGIC_POSTGRES_PASSWORD` | *(generated into `.env`)* | Development-only; no default in the repository |
| `PENNILOGIC_REDIS_HOST` / `_PORT` | `127.0.0.1` / `6379` | Where clients reach Redis |
| `PENNILOGIC_REDIS_DATABASE` | `0` | Logical database index |
| `PENNILOGIC_REDIS_USER` / `_PASSWORD` | *(blank)* | Blank = no authentication on the loopback-only port |
| `COMPOSE_PROJECT_NAME` | `pennilogic` | Optional; names the containers, network and volumes (same effect as `--project`) |

Security boundaries of the default configuration:

- Ports are published on `127.0.0.1` only. A non-loopback `PENNILOGIC_BIND_ADDRESS` is
  refused unless you pass `--allow-non-loopback`, which exposes the development Postgres and
  Redis to your network and is never appropriate for shared or production use. Because the
  Redis image ships with `protected-mode no`, that override is additionally refused while
  `PENNILOGIC_REDIS_PASSWORD` is blank: a network-exposed Redis must have a password.
- No password is committed. `.env.example` leaves `PENNILOGIC_POSTGRES_PASSWORD` blank, the
  compose file has no fallback for it, and `.env` is git-ignored. It is created exclusively
  with POSIX mode `0600`; on Windows the file inherits the folder's ACL (there is no mode bit),
  so keep the checkout in a folder only you can read.
- Credentials reach the containers as environment variables, not through any committed file.
  The optional Redis password is turned into `--requirepass` by the container's own shell at
  start (Redis then rewrites its process title, so it is not visible in `docker top` either);
  the Postgres password is read by the image's entrypoint from `POSTGRES_PASSWORD`. The
  bootstrap scans the fresh container logs and fails with `credential_in_logs` if a configured
  secret value appears; its own output redacts secrets.
- Images are pinned by tag **and** digest (`postgres:17.11-alpine3.24@sha256:...`,
  `redis:7.4.11-alpine3.21@sha256:...`) so every machine runs identical bytes. Upgrade by
  changing tag and digest together (`docker buildx imagetools inspect <image:tag>` prints the
  index digest).
- Postgres runs with `--locale=C --encoding=UTF8` so ordering is deterministic across
  machines and authenticates host connections with SCRAM-SHA-256 (the Postgres 17 default).
  Redis runs with `appendonly yes` so quota-window data survives restarts and keeps the
  image's privilege drop (the server runs as the `redis` user). Only the two named,
  project-labelled volumes are mounted; the stack creates no anonymous volumes.

## Running the tests

```text
python -m unittest discover -s scripts/tests
```

`test_smoke_infra.py` and `test_bootstrap.py` need no Docker: they use fake Postgres/Redis
servers and decoy listeners on free loopback ports, and check the RFC 7677 SCRAM vector, the
refusal of every weaker Postgres authentication method (the decoy must never receive the
password), the env-file contract, the loopback refusals, credential redaction, the real
Docker bind-failure texts and the named-port diagnostic. They also cover the command time
limit with a harmless fake `docker` (a Python script standing in for `docker.exe`, never the
real one): it starts a child that outlives a 2 s limit while inheriting or redirecting the
captured output, and the bootstrap must report `docker_timeout` within about the limit plus 5 s on
every platform and, on Windows, leave that child dead; further Windows-only tests exercise the job
object directly (job-scoped member list, process objects awaited, a held file deletable right after),
both fail-closed paths (job creation refused: nothing started; assignment refused: the started
command terminated), a command that exits before it can be assigned, and a failing cleanup that
must leave the timeout error primary.
`test_integration_stack.py` runs the real stack in a uniquely named project
(`pennilogic-test-<random>`) on free loopback ports and removes only that project afterwards;
it is skipped with the reason when Docker is unreachable or `PENNILOGIC_SKIP_DOCKER_TESTS=1`.
Its nine ordered steps cover: fresh start healthy with smoke output and `health_log` timings,
second start leaves one stack and reports `already_running`, `--down` keeps data and recreate
restores it, an existing volume with other credentials is warned about and never wiped,
`--reset` removes everything and recreate needs no manual step, an occupied Postgres port
fails within seconds naming the port, `--status` is read-only, a Docker bind failure after the
preflight is reported as `port_conflict` and rolled back without touching volumes, and two
simultaneous first runs share one `.env` and one stack.

## Out of scope and owners

- Schema migrations and seed data (including the awkward multi-currency, own-account transfer
  and 0 % APR cases): T-ENV-01, [PenniLogic/api#20](https://github.com/PenniLogic/api/issues/20),
  and the migration runner T-MIG-01, [PenniLogic/api#55](https://github.com/PenniLogic/api/issues/55).
  This stack asserts nothing about schemas.
- Production infrastructure, backup/restore of the local volume, and any deployment.
- The read-only CI conformance job over the nine PenniLogic repositories, its check-name registry and
  its planted-defect evidence: [CI_CONFORMANCE.md](CI_CONFORMANCE.md) (`governance/conformance/`).
