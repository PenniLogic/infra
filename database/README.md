# Database extension and semantic-column admission

`T-PLT-01-DATABASE-EXTENSION-GATE` is Infra's database **plan and pre-apply
admission boundary**, not a Docs checker or SQL runner. It is additive to
`PenniLogic/api#55`: API's `MigrationSet` / `MigrationRunner` remain the only
owners of SQL execution, migration locking, registry writes and compensation.
The development Compose bootstrap is deliberately not used as a substitute.

This source does **not** complete Infra25 or Docs56. The shipped installation
has no accepted embedding-policy binding and no accepted semantic inventory:
`admission-trust.json` denies admission. The exact policy source accepted through
Docs PR171 at `62a627f67ced1494679be6321ae9deb7f6af7692` is supported as an input
version, **not registered in this installation**. The obsolete draft ADR bytes
are not an alternate supported provider. No CLI argument, environment
flag, local `ACCEPTED` header, issue state, caller checksum or returned plan
digest can change that. Protected acceptance of the prohibited choice
authorizes no embedding persistence.

## Invocation and additive API contract

```text
python -B scripts/database_admission.py plan
python -B scripts/database_admission.py admit-apply
```

Each reads one bounded UTF-8 JSON request on stdin and prints exactly one
`pennilogic.database-admission.result/1` JSON document. Exit **0** means only
this narrow gate admitted the exact selected SQL; exit **1** means denial.
Unknown command-line arguments exit 2. Missing process, timeout, nonzero exit,
malformed/extra output and an unknown result version must also block consumers.
No SQL/data is returned or logged. Refusals contain static codes only.

Request fields are closed:

| Field | Value |
| --- | --- |
| `schema` | `pennilogic.database-admission.request/1` |
| `runtime` | `R4_LINUX_DOCKER_NFTABLES` |
| `policy` | `{repository_id, commit, files: [{path, content_base64}]}` |
| `inventory` | `{content_base64, source: {repository_id, commit, files: [{path, content_base64}]}}` |
| `packages` | Complete requested database-package additions; normally `[]` |
| `migrations` | Complete ordered set: `[{id, up: SQL_STRING, reverse: {direction, sql: SQL_STRING}}]` |
| `selection` | Ordered execution subset: `[{id, direction}]`; no duplicates/mixed forward and reverse |
| `plan_sha256` | **Only** for `admit-apply`; the preceding plan's digest |

Reverse direction is `down` or `compensating`, never inferred from a filename.
Every forward **and** reversal script is checked, including unselected scripts,
before any selection can be admitted. `selection: []` validates a nonempty
complete set for load/no-op/all-held/housekeeping paths without pretending SQL
will run; admission then returns `scripts: []`. An empty migration set remains
an explicit refusal. No-op registry/lock housekeeping still requires admission
before its first write. The returned `scripts` contain
`migration_index`, `direction` and SHA-256 of UTF-8 SQL with CRLF normalized to
LF, matching API's existing `Checksum.of`. The plan digest additionally binds
the complete request and installed trust bytes. It is a freshness check, **not**
an authorization token: `admit-apply` performs the whole evaluation again.

API's additive adapter must validate on load/build and before both forward and
reverse plan/apply. In particular, it must run **before `registry.bootstrap()`**,
not just before `statement.execute(sql)`, because bootstrap already writes.
Under its existing serialization lock, recheck the selected immutable SQL
buffers against the admission response before execution. Do not reopen changed
files after admission, accept a result for another selection, cache a positive
across source changes, or downgrade to an ungated runner if the gate is absent.
The adapter must establish PostgreSQL 17, `standard_conforming_strings = on`,
and a trusted `pg_catalog`-first search path; a request is not proof of session
settings, database drift, least privilege or deployment authority.

The API adapter and its real PostgreSQL no-write tests are a **separate pending
consumer integration**. This repository neither claims that API is already
wired nor provides an alternative apply command.

## Reviewed semantic inventory

The inventory bytes are an API-owned, reviewed source artifact. The fixed
installed trust file must pin their raw SHA-256, byte length, API repository ID,
accepted commit and the complete raw producer/contract source files used as
lineage evidence. Request content cannot supply its own trust root. The gate
opens no request path and performs no fetch: paths are manifest labels and
their base64 contents must match the installed pins.

Inventory schema `pennilogic.database-admission.inventory/1` has exactly:

- `nodes`: source nodes `{id, kind: "SOURCE", source_kind, evidence: [source_path]}`
  and derived nodes `{id, kind, inputs: [node_id]}`.
- `scripts`: `{migration, direction, sha256, grammar, columns}` for exactly every
  supplied up/reversal script. Each column is
  `{name: "schema.table.column", sql_type, provenance: node_id}`.

Source kinds are `IDENTIFIER`, `INTEGER_MINOR_UNITS`, `FIXED_SCALE_INTEGER`,
`CURRENCY_CODE`, `DATE_TIME`, `BOOLEAN`, `NUMERIC_MEASUREMENT`,
`NON_USER_REFERENCE`, `TRANSACTION`, `MERCHANT`, `MEMO`,
`ASSISTANT_CONVERSATION`. Derived kinds are `EMBED`, `ENCRYPT`, `ENCODE`, `HASH`,
`QUANTIZE`, `ALIAS`, `AGGREGATE`. `EMBED` marks a vector; every later transform
preserves that mark. Any marked database column is denied, including static
asset vectors: the policy permits reviewed static **assets**, not a vector
database exemption. Money/fixed-scale integers cannot become floating point.
Unknown sources/transforms, missing evidence/nodes, cycles, duplicate records
and a declared-versus-parsed column/type mismatch are refusals.

This is **reviewed, byte-bound provenance, not automatic inference of hidden
data semantics**. Arbitrary code can encode an embedding in an ordinary number,
JSON field, identifier or ciphertext; no SQL parser can decide that general
problem. Separate review must establish truthful complete lineage against the
pinned producer contracts. The gate rejects unregistered or changed inventories
and unknown SQL; it does not certify arbitrary runtime DML, existing database
contents, memory non-spill, or that a deliberately deceptive reviewed source
matches its claimed meaning. Runtime writers and catalog drift remain owning
API/platform obligations.

## Supported grammar and existing ledger preservation

`postgresql17-ddl-v1` consumes the complete SQL token stream. It supports
qualified `CREATE TABLE`, single-column `ALTER TABLE ... ADD [COLUMN]`,
`CREATE SCHEMA`, explicit `DROP TABLE/SCHEMA ... RESTRICT`, and
`CREATE EXTENSION identifier`. Types include ordinary integer/numeric, text,
UUID, date/time, boolean, JSON, bytea and arrays. A type/name is never evidence
of non-embedding semantics. It supports simple primary/unique/foreign-key,
literal-default and scalar CHECK constraints, including exact integer arithmetic,
comparisons, IN/BETWEEN/IS NULL, `isfinite` and `char_length`.
Identifiers are ASCII lowercase (including equivalent quoted identifiers).

Unrecognized statement/constraint/type syntax is explicitly refused. In
particular, generic DML, CTAS/SELECT INTO, COPY, aliases/domains, views,
renames/type changes, generated columns, casts, dynamic/procedural SQL, external
functions, extension dependencies/options and psql commands are **not** covered
by the general grammar. Supporting them requires a reviewed grammar change,
not a caller exception or a regex for suspicious names.

`api-ledger-v2-exact` is a separate **finite language of four complete script
checksums**, from API accepted commit
`d39f4692c13413040439c5e87fed81728e0577f1`, tree
`8da895cc998e5ec43105cfb6fa41a82ea2194f8c`. It preserves original V001/V002,
including V002's real procedural ledger constraints, default-deny RLS,
unavailable ciphertext gates and guarded no-history-deletion reversal. The full
introduced column/type inventory is still required and lineage still checked.
It admits no other function, DO block or data write; any changed script,
identity, direction, checksum or unsupported new routine is refused. This is
not a universal PL/pgSQL/data classifier or an exemption for a future migration.
API SQL is referenced, not copied into an executor or modified.

There was no pre-existing database-extension/package allowlist in accepted
Infra `ecad202c07cd65a5f9250c8041202fcb9b90cc7f`; installed lists therefore
remain empty. The parser recognizes known non-vector extension identifiers,
but only a separate reviewed installation entry can admit one. `pgvector`,
SQL `vector` and every other unlisted extension/package are denied. Static
assets, benign aliases and caller intent cannot extend either list.

## Canonical API installation

`governance/api-database-admission-installation.json` is the canonical input for
two generated API files: `scripts/prepare_database_admission.py` and the committed
resource `src/main/resources/database-admission-installation.json`. Only API gets
these additive artifacts; existing Money preparation, pins, budgets and CI
commands are unchanged. The canonical resource currently has **`binding: null`**:
no real accepted provider or inventory is registered, and every preparation,
verification and managed admission command refuses without creating an output.

The exact generated installation/1 fields are `schema`, `gate`, `runtime`,
`consumer`, `binding` and `launcher`. The canonical input omits the derived
`launcher` record. The consumer is API repository 1394134582 in organization
335295566. A bound installation has exactly `sources` and `payloads`. Its four
source roles are `infra`, `policy`, `inventory` and `evidence`; each binds
`repository`, numeric `repository_id`, immutable `commit`, complete Git `tree`,
and `files` records containing `path`, `mode: "100644"`, `bytes`, `sha256`,
and `git_blob`. Roles bind, respectively, the three Infra Python modules, the
four accepted Docs policy files, the two API inventory provider files, and the
existing API producer/evidence files named by that inventory's source manifest.
The newly accepted inventory publication is **not** claimed to exist at its
older evidence commit. Result `inventory_commit` remains that evidence commit.

`payloads` records contain `path`, `mode: "100644"`, `bytes` and `sha256`. They
bind **exactly five files** under the fixed `build/database-admission` root:

```text
scripts/database_admission.py
scripts/database_sql.py
scripts/database_baseline.py
database/admission-trust.json
inputs.json
```

`inputs.json` contains exactly `{policy, inventory}` in the request envelope
formats above. The trust file and envelopes are deterministically assembled
from the four registered source roles; their resulting bytes must also match
the committed payload pins. The inventory source manifest's original
`inventory` field is the string `database/admission-inventory.json`. Its
repository, commit, tree and complete file bindings must match `evidence`.
There is no output receipt or local acceptance flag to redefine authority.
Extra files/directories (including shadow modules, bytecode and purported
receipts), symlinks, junctions, hardlinks, and incorrect payload modes are
refused. POSIX payload modes are 0644 with directories 0755; Windows verifies
ordinary single-link files/directories using its corresponding mode semantics,
not POSIX permission or ACL attestation.

Use the documented managed Python 3.14 toolchain:

```text
python -I -S -B scripts/prepare_database_admission.py prepare --fetch
python -I -S -B scripts/prepare_database_admission.py prepare
python -I -S -B scripts/prepare_database_admission.py verify
python -I -S -B scripts/prepare_database_admission.py run plan
python -I -S -B scripts/prepare_database_admission.py run admit-apply
```

Only explicit `prepare --fetch` can download. `prepare` without that flag and
`verify` are offline; an existing valid installation is a deterministic no-op.
Invalid existing contents are never silently repaired or overwritten. Fetch
reuses the unchanged, hash-verified managed Money module's bounded read-only
client, immutable Git tree/blob verification and owned-path primitives. It has
no authentication fallback, extra provider enrollment, or increased budgets.
Downloaded gate code is never executed by preparation.

Managed `run` verifies the pinned disk resource, helper and complete payload
inventory. Supplied policy/inventory must equal installed `inputs.json`;
caller executable, source-path and authority overrides do not exist. A
credential-cleared isolated/no-site/no-bytecode child process executes the
three verified module **byte snapshots**, not subsequently reopened paths.
The provider has a seven-second subprocess limit compatible with API's
ten-second outer bound. Only a valid gate result/1 is forwarded to stdout;
installation/process refusals have static stderr JSON and a nonzero exit.
Before starting any launcher, API must match the disk resource to its compiled
committed resource and verify the launcher's own fixed
`{path: "scripts/prepare_database_admission.py", mode: "100644", bytes, sha256}`
record. The generator first hashes canonical authority fields without that
derived record, renders the launcher with that authority hash and the unchanged
Money helper hash, then pins the resulting launcher bytes in the resource.
There is no circular self-hash. The launcher's honest self-check is additional
consistency checking, **not** proof against replacement code that skips it;
the compiled-resource consumer check must happen before execution.
Missing, malformed, timed-out or nonzero responses continue to refuse.

This does not attest a hostile host/interpreter or activate the API adapter.
Root must obtain actual accepted source bindings, regenerate/review the
consumer artifacts and coordinate mandatory consumer/CI activation. An
unbound source-only installation is never operational admission proof.

## Source acceptance, runtime and evidence limits

Root must separately register the genuine protected-accepted Docs commit,
exact policy/schema/ADR bytes and the source's `adr/accepted-records.json`.
The registry's ADR-025 date/SHA/length must match; stale/missing/tampered or
unsupported sources fail closed. The supported accepted files remain the Docs
source of truth; immutable test snapshots are only reproducible test inputs.
The original unaccepted proposal snapshots are retained for refusal regressions,
not relabeled as accepted source. Policy/schema bytes, version, decision date
and prohibition semantics are unchanged by the accepted ADR reconciliation.
The installed trust file is part of the reviewed, immutable consumer
installation, **not** a writable migration input or proof of review identity.

The runtime selection comes from accepted Docs
`9e394961032b50eafb68b37ff3f7c209243127cf`, consequences
`adr-022-ai-egress-consequences@1.1.0` / `2026-10-05.2`
(SHA-256 `44c3b40b8caa01c26c46a6b8103667501bc9e1be2a2cf714dcb84d8a358f476f`,
schema `61f625d370840e9a40e1d7a05355c5504cc8a9d98aafac4814d641d21a021d73`).
It remains FUTURE_NOT_DEPLOYED: Docker Engine Compose, host systemd, separate
prepared namespaces and host-owned nftables. This admission implementation
provisions none of them. India counsel-approved residency, qualified ADR-018
custodian, provider approval, independent review, native CI and operational
gates remain required. Global/custom AI stay OFF; no inference/spend is enabled.
Every result explicitly says `provider_activation: false`, `sql_executed: false`.

Run `python -m unittest discover -s scripts/tests -p "test_database*.py"`.
Normal existing `scripts/tests` discovery includes the gate. Canonical bundle
regressions are in `python -m unittest discover -s governance/tests -p
"test_database_admission_installation.py"`. Synthetic accepted-trust fixtures
exercise real CLI boundaries without changing existing thresholds; they are
not genuine provider acceptance, independent approval, deployed runtime proof
or full original-ticket completion.
