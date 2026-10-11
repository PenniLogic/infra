# Governance: the canonical generator and the generated checker

`generate.py` renders the small public-repository baseline, 20 common files for every repository in
`repository-profiles.json` (`.github/workflows/ci.yml`, `.github/workflows/copilot-setup-steps.yml`,
`AGENTS.md`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CONSTITUTION.md`, `COPILOT_FILES.md`,
`.github/copilot-instructions.md`, `.github/instructions/source.instructions.md`,
`.github/agent-policy.json`, `.github/CODEOWNERS`, `.github/github-app.yml`,
`.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/*` (two files), `.gitattributes`,
`.gitignore`, `scripts/setup.py` and `scripts/check_repository.py`). Consumers never hand-edit those
files: a profile or template change lands here through a reviewed generator PR, then each consumer
regenerates from the merged `main` in its own PR. Additionally, api alone has 25 files, including `scripts/materialize_money_sources.py`,
`scripts/prepare_database_admission.py`, `scripts/qualify_windows.py` and
`src/main/resources/database-admission-installation.json`;
infra alone has 23 files: its report
workflow is `.github/workflows/conformance.yml`, and its additive gate is
`.github/workflows/pr-workflow-integrity.yml`. Both API and Infra render `.nvmrc` to pin
the API client SDK and real governance-fixture Node runtime respectively.
Android alone adds `scripts/check_privacy_components.py` (21 files), a narrow native-inventory
extractor that invokes the Android-owned assertion.
`governance/tests/test_rule_table.py` keeps this per-profile list equal to what `artifacts()` renders.

```text
python governance/generate.py --repository <name> --root <checkout>          # regenerate one consumer
python governance/generate.py --repository infra --check                      # drift check (CI runs this)
python governance/generate.py --root <scratch>                                # render every profile
python -m unittest discover -s governance/tests
```

## Contracts source-test entry point (producer preparation)

The Contracts profile replaces only its final `unittest discover` command with
`python scripts/run_source_tests.py`. Contracts owns that stdlib runner: complete
`scripts/tests/test_*.py` discovery and the exact discovered/executed method-ID union
remain required, with at most two isolated Python process lanes for source-CLI-safe
modules and serialized global-patched, generation and canonical-output work.
Missing/duplicate IDs, discovery, child and receipt failures must fail the command;
this is not a selector or a reduced suite. Conformance recognizes only the exact
entry point and retains both existing source-test defect probes, including the
accepted exit codes and private indexed `TestResult` witness.

Only Contracts' five command-derived artifacts change; all other generated files
remain byte-identical to the accepted base. Setup, lint, breaking checks, real double-generation, all three
target smokes, native `CI` identity/platform and timing limits are unchanged.
This prepares [infra#22](https://github.com/PenniLogic/infra/issues/22) /
[PenniLogic/contracts#1](https://github.com/PenniLogic/contracts/issues/1); it does not
implement or activate the companion runner or prove a sub-600-second native envelope.

## API combined build and coverage (consumer adoption held)

Native API CI now passes the comparison base to its one normal build rather than
starting a second Gradle coverage/Money/PIT graph afterwards:

```text
python scripts\quality.py build --base "<FULL_BASE_SHA>" --money-client-interop-node "<ABSOLUTE_NODE>"
```

**API must implement the combined `build --base` behavior before adopting these
outputs.** Merely accepting the argument is insufficient: the existing build and
`installDist`/`check` graph must run, followed by the existing aggregate and Money
coverage checks against that exact base, then final mutation freshness verification.
Standalone coverage remains available. All assertions, coverage/mutation floors,
elapsed deadlines, unconditional interop/PIT, Node handling and cleanup stay API-owned
and unchanged. The manual profile command remains `python scripts/quality.py build`;
no optional gate, budget or alternate test graph is introduced.

The existing step environment expression
`${{ github.event.pull_request.base.sha || github.sha }}` moves from the removed
coverage step to `Run checks` unchanged: pull requests compare to their base SHA;
push and manual runs retain their reviewed `github.sha` behavior. There is no new
dispatch input, base selector or fallback. The build always passes `--base "$BASE_SHA"`
as one quoted operand, keeping event data out of shell source. Empty/malformed
explicit values must fail in the API-owned validator, not select an unbased build.

In this combined-build unit, Money/database preparation and Python test command order,
actions, permissions, concurrency, timeouts and all non-API workflows/profiles are
unchanged. Its isolated output delta from Infra `26fa29ff` is only API
`.github/workflows/ci.yml`. The Windows extension below additionally changes the
API-only checker and adds its qualification script. That API-only checkpoint leaves
all eight other profiles byte-identical; the separately admitted Infra extension
below preserves those exact API outputs and changes only Infra. Regenerate only the
owning checkout; this source change does not roll out consumer files.

Generator and shell/argv-fixture results do not establish API test parity, real
Postgres execution or the under-five-minute requirement of
[PenniLogic/api#3](https://github.com/PenniLogic/api/issues/3). Independent Core, QA
and Security review, consumer adoption and full local/native qualification remain
required; complete-suite timing under 300 seconds is unverified, and whole-build,
job or workflow timings do not decide that test-suite criterion. Existing Windows
execution/symlink qualification holds are not cleared.

## API Windows owning-suite qualification (native execution held)

API CI has two parallel ordinary jobs: `Linux qualification` retains its complete
combined build, real Postgres, coverage/Money/PIT and Python graph, while
`Windows qualification` runs on standard GitHub-hosted `windows-2025`. The latter
reuses the SHA-pinned checkout/Python/Node/JDK actions and the seven existing
Money/database preparation and verification commands, then runs the existing
input-only `python -I -S -B scripts\money_client_interop.py prepare` before invoking
`python scripts\qualify_windows.py`. All nine ordered PowerShell commands propagate
a nonzero native exit immediately; a preparation failure cannot reach the qualifier.
There is no Windows Postgres, full Windows build,
isolated test selector, new cache, artifact upload, credential, paid/self-hosted
runner, permission or storage-allowance change.

The independent Windows checkout cannot reuse Linux outputs. Ordinary Python
discovery precedes Gradle `test`, and its public-input response fixtures require
all 39 interop inputs. The existing preparer verifies the Money materializer/provider,
reuses ten hash-bound inputs and acquires the other 29 within its existing three-REST-
plus-one-archive bounds. It validates the complete inventory and provenance, reuses
verified state, and refuses corrupt, orphaned or partial state. This command does not
run Node/npm, client generation, JVM/runtime checks, Postgres or PIT; `--node` is
rejected for `prepare` and is not passed. The seven prior commands and ordinary
`quality.py test`/qualifier behavior are unchanged.

The generated stdlib qualifier runs the ordinary `python scripts\quality.py test`
exactly once: complete verbose Python discovery, ordinary Gradle `test`, and the
existing no-skip/no-failure metrics gate. It requires real passing records for:

- `test_money_mutation.ProcessBudgetTest.test_budgeted_quality_admits_only_the_approved_docker_directory`
- `com.pennilogic.migration.AdmissionInstallationTest.a symlinked launcher cannot redirect execution()`

No target assertion, permission requirement or skip condition is changed. A
missing/failed/skipped target refuses qualification. Existing ordinary JUnit results
refuse before execution; absent, cached, up-to-date, no-source, skipped or ambiguous
Gradle task results cannot publish Kotlin positives. A fresh failed task may publish
its individual outcomes, but cannot qualify. The ordinary suite exit and every
ordinary JUnit case must also pass; other genuine Python platform skips remain
explicit outcomes, not fabricated passes.

Only safe JSON events leave the qualifier. Each Python discovery ID is represented
by its exact UTF-8 SHA-256; each JUnit ID hashes `classname`, a NUL separator, and the
exact method display name. Both required targets additionally carry fixed literal
`required_test` labels. Per-test statuses, not aggregate counts, provide the later
parity input. Unique identities and complete case counts are checked, including
JUnit failure/error/skip counters. Only the ASCII unittest protocol is decoded;
arbitrary diagnostics, docstrings, reasons, XML payloads and fixture data are never
printed, including non-UTF-8 child output. Raw streams stay in temporary files that
close after collection. Missing or malformed evidence fails with static codes.
These records are not a trusted-workflow attestation.

The shared unittest parser accepts an outcome only on its case line or the
immediately following docstring line. Interleaved diagnostics, orphaned status
lines and incomplete records refuse the entire outcome stream; they cannot be
searched for a later `ok` or emitted as passing evidence. This also rejects
diagnostic attempts to swap per-ID results while preserving aggregate counts.
Ordinary passing/docstring formatting and explicit platform skips remain supported.

The sole native job named `CI` is a one-minute result aggregator with
`needs: [ci, windows]` and `if: always()`. Only two explicit `success` results pass;
failure, cancellation, skipped or absent results refuse. This is a normal
GitHub-hosted job, not a CheckRun/status publisher or a success-shaped skipped
required job. The shared checker retains its single-job Ubuntu policy and expression
allowlist. An API-only exact-byte CI exception binds the generated compound workflow
and requires the qualifier file; other workflows still use their existing validator.
The exception composes with, but does not enable, optional PR-integrity adoption.

Relative to Infra `26fa29ff`, the API-only checkpoint changes API
`.github/workflows/ci.yml` and `scripts/check_repository.py`, and adds
`scripts/qualify_windows.py`. Its non-API outputs and API setup workflow are unchanged;
the Infra extension below originally retained all three API output bytes. The
shared outcome-parser correction changed only the generated qualifier. The
input-only prerequisite correction changes API CI and its checker digest, leaving
that qualifier, API Linux/setup/manual commands and every other profile unchanged.
The API registry reference still needs the real reviewed source commit through the
separate source/binding sequence; a prebinding history mismatch remains an honest
failure, not a placeholder reference or an acceptance waiver.
Adopt all three atomically with the API-owned combined-build interface, only after
separate producer/consumer review and protected acceptance. Synthetic Infra runner,
parser and shell controls are not execution of the two API tests. Native Windows
qualification, complete-suite timing below 300 seconds, per-test local/CI parity,
and supported full Linux **local** qualification remain unverified. No workflow was
dispatched or published by this source change; the existing Windows holds and
[Infra #22](https://github.com/PenniLogic/infra/issues/22)'s trusted-workflow
identity/mandatory-absence gap remain open.

## Infra Windows/Linux ordinary qualification (owner transition held)

Infra adds the same two parallel standard-hosted qualification jobs and always-running
native `CI` result gate, without changing its canonical manual command list. Linux
keeps every existing command in order, including Compose configuration and all nine
real `StackLifecycleTests`. Windows uses `windows-2025`, the same immutable
GitHub-owned checkout/Python/Node action pins, Python `3.14`, Node `24.14.0` and bundled
npm `11.9.0`. Its uv `0.11.33` Windows x64 wheel is hash-required, binary-only and
dependency-free, pinned to SHA-256
`521229afa69ad5f57127de800120cb2bea1ac729a05a0851aaf920124f8edf66`.
Linux retains its existing uv installer. Every Windows native command has an
immediate exit-code guard, including installation and each repository/generation check.

Both OS jobs execute full governance discovery followed serially by full scripts
discovery. Only those two commands receive the transparent
`python governance/qualify.py -- <canonical discovery command>` wrapper; it executes
the complete ordinary discovery once, using `-v` for per-test outcomes.
It is not a selector, replacement test framework or optional gate.
The child invokes stdlib `unittest.main` discovery with a `TextTestRunner` subclass
that binds only its stream to an exclusively created report inside an owned temporary
directory. `unittest.main` constructs the runner with its normal options, including
the default warning policy or an explicitly selected `PYTHONWARNINGS` policy.
Test stdout and stderr remain separate diagnostic streams, including direct descriptor
writes; neither can impersonate per-ID runner statuses. The complete runner report
must pass the unchanged S1 parser and end with the matching successful terminal
summary. Nonzero exit, a missing/incomplete report or any disallowed outcome refuses.
Cleanup receipts still come only from stdout. The helper is manually maintained Infra
source, not an additional generated consumer file; the shared API parser is unchanged.

The native helper requires a clean, non-shallow checkout matching `GITHUB_SHA`,
records commit/tree and the entire Git file inventory (hashed paths, modes and blobs),
enumerates every discovery ID before execution, then requires the exact same ID set
in the child outcomes. It records actual Python/Node/npm/uv/Git/Bash versions and
runner OS/image build identifiers. `windows-2025`/`ubuntu-24.04` are mutable labels;
`ImageOS`/`ImageVersion` are recorded metadata, not image-byte pins or attestations.
The exact Windows image families are `win25` and `win25-vs2026`; Linux accepts only
`ubuntu24`. The `windows-2025` job in [#74](https://github.com/PenniLogic/infra/pull/74)
reported `windows-2025-vs2026/20260925.250.1`. Its
[published image builder](https://github.com/actions/runner-images/blob/1c7b9f1e082099ad9e2cfa02f257a2e352e753ee/helpers/GenerateResourcesAndImage.ps1#L30-L33)
maps that variant to `ImageOS=win25-vs2026`; this is not an arbitrary image-prefix
allowlist or a waiver of repository, hosted-runner, architecture or tool checks.
Missing tools, import errors, missing historical-object skips, changed source, unknown
skips, setup/teardown failures or nonzero commands cannot qualify.

Nonzero discovery remains the primary failure even if its unittest protocol is
ambiguous. Before refusing, the helper emits diagnostic-only hints: at most 20
failure/error report headings matching the discovered test/class/module identities,
and at most eight source-inventory-bound hashed file/line locations per report.
Truncation and unrecognized headings are explicit. Raw messages, docstrings,
subtest values, tracebacks and external paths are not printed. These untrusted
hints never supply outcomes or authorize a pass; successful commands still use
the unchanged strict S1 parser. The earlier D run's discarded transcript cannot
be reconstructed. Later runs can locate their own failures with these hints,
but cannot retroactively prove D's cause.

F's zero-exit scripts runs emitted no admitted outcomes: their raw stderr was
discarded, so their exact offending text remains unknown. A finite file-only
bootstrap test and tiny real unittest cases reproduce mixed-stderr ambiguity.
Separating the normal runner's report fixes that proven reporting defect without
relaxing S1; it is not retrospective scripts, lifecycle or cleanup qualification.

Canonical-composition fixtures pin the three API/Infra registry references to
source `889c5c35a1677ef33899a2e63bc528d3bac802f9` and prove its historical renderings
match the current workflows; they do not copy candidate references into expectations.
The real CLI/Bash fixtures resolve their owned temporary root before constructing
the runner event path, including Windows case aliases. This fixes the fixture's
canonical-path precondition without relaxing the production event-path guard.
These finite controls are not native qualification or evidence for unseen failures.

The only Windows Docker allowance sets the existing `PENNILOGIC_SKIP_DOCKER_TESTS=1`
inside the Windows scripts-qualification process, for exactly the nine existing
`test_integration_stack.StackLifecycleTests` methods. The existing POSIX-flock-only
method is also inapplicable on Windows. Linux must pass all nine real-stack methods
at that same final source; only its existing exact Windows-only IDs may skip.
Every other discovered test must pass, including native symlinks and the full Windows
process/job/interruption/refusal/pipe/handle/unsafe-result/redaction controls. Their
0.8/5/2.5/4-second bounds and assertions are unchanged. There is no Docker Desktop,
WSL, privilege setup or skip for the harmless process/Docker-command fakes.
`ProcessExitDiagnosticTests` is absent at accepted `26fa29ff`; no frozen runner files
are imported. Later composition must inventory and execute its added methods, and
review any new platform-applicability identities explicitly.

Owning stack cleanup now requires every scoped reset to succeed, queries the four
owned projects for remaining containers/volumes/networks, and refuses query errors,
remaining resources or temporary-tree deletion failures. Reset/inspection failures
retain the owned environment; failed tree deletion does not promise full retention
or removal. Only validated resource counts/project labels and removal receipts are
published, never assertion/fixture payloads. Full per-test evidence uses SHA-256 of
the exact UTF-8 discovery IDs; raw child output closes with its temporary files.
Fixture receipts are not independent resource-absence evidence, and VM disposal or
an aggregate PASS is not verified Docker cleanup.

Only Infra CI, its exact-byte checker exception and the generated PR-integrity
workflow binding change among Infra outputs. Its setup and Conformance workflows,
all API checkpoint outputs and the other seven profiles remain unchanged. Common
checker allowlists stay closed; API and Infra each admit only their own exact CI
bytes. The source/checker/validator change needs the
[owner-maintenance transition](../CI_CONFORMANCE.md#native-os-qualification-owner-maintenance-transition),
real source/registry bindings, separate review and exact-final-source qualification.
The ten-minute OS job bounds remain; actual complete job **and** whole-workflow
times must each be strictly below 600 seconds. Aggregator duration is not a proxy.
Those timings, native qualification and independent cleanup evidence are unverified.

## API Node SDK prerequisite (consumer adoption held)

The API profile now declares the already accepted Node `24.14.0` SDK with bundled
npm `11.9.0`. Native CI and manual Copilot setup reuse the existing
`actions/setup-node@820762786026740c76f36085b0efc47a31fe5020` action and the
generated API `.nvmrc`; there is no new installer, cache selection or action pin.
Only the Linux CI leg adds `Prepare API Node SDK`, before any repository commands. The pinned
action exports no executable path, so that step binds its exact Linux x64 layout:
`$RUNNER_TOOL_CACHE/node/24.14.0/x64/bin/node`, with npm's adjacent
`lib/node_modules/npm/bin/npm-cli.js`. The root comes from trusted runner metadata,
not a workspace executable or PATH search. Missing/non-absolute/multiline roots,
missing files, failed probes and unexpected Node/npm versions refuse before
publishing a path. The step appends only `MONEY_CLIENT_INTEROP_NODE` to the
runner's step environment file after successful checks.

Before either SDK probe, a finite name-based guard rejects inherited `NODE_OPTIONS`,
`NODE_PATH` and npm's `node-options` environment selector, including empty values.
Names are matched case-insensitively; both `npm_config_node_options` and
`npm_config_node-options` spellings are covered. The fixed `/usr/bin/env -0` inventory
preserves entry boundaries, and an inventory error also refuses. Diagnostics are
static: no setting value is printed and the environment file is left byte-identical.
This follows the existing conformance probe's finite name-boundary approach without
changing its credential isolation or banning unrelated Node/npm configuration.
The guard writes no startup setting and does not sanitize away an override silently.
Real benign-preload controls use an owned forwarding layout and the installed pinned
Node/npm: the unchanged emitter runs the preload; the guarded emitter starts neither
probe, and removing the setting restores normal preparation. Test-only reversal of
the probes covers either first invocation; production probe order is unchanged.

The combined normal build passes that value as one quoted
`--money-client-interop-node` argument. The shared helper retains the same handoff
for standalone explicit-base coverage. A missing/empty handoff refuses rather
than selecting an ambient runtime. The same rendering applies to a profile
`gate-self-test` command, but no self-test or other gate is added by this change.
The base expression, Money/database source preparation, task lists, budgets,
permissions, action pins, concurrency and timeouts are unchanged. Combined coverage
is the separate held companion described above. No Gradle
startup variable, runtime allowlist, symlink or global configuration is changed.
Manual profile commands retain the optional/default-None API behavior.

**Do not adopt these generated API outputs until the API-owned parser bridge and
combined coverage behavior are composed in the consumer change.** Its interface is:

```text
python scripts\quality.py build --base "<FULL_BASE_SHA>" --money-client-interop-node "<ABSOLUTE_NODE>"
python scripts\quality.py coverage --base "<FULL_BASE_SHA>" --money-client-interop-node "<ABSOLUTE_NODE>"
python scripts\quality.py gate-self-test --artifact-dir "<OWNED_PARENT>" --money-client-interop-node "<ABSOLUTE_NODE>"
```

API owns validation with `money_client_interop.node_runtime`, one
`-PmoneyClientInteropNode=<absolute>` Gradle argument, and forwarding to the
collector. There is no prepare/verify flag. After the producer is independently
reviewed and accepted, the API owner regenerates from that exact accepted Infra
source in the API owner's exclusive checkout, atomically with the bridge:

```text
python "<ACCEPTED_INFRA_CHECKOUT>\governance\generate.py" --repository api --root "<OWNED_API_CHECKOUT>"
python "<ACCEPTED_INFRA_CHECKOUT>\governance\generate.py" --repository api --root "<OWNED_API_CHECKOUT>" --check
```

The Node-prerequisite API output delta was `.github/workflows/ci.yml`,
`.github/workflows/copilot-setup-steps.yml`, `CONTRIBUTING.md`, and new `.nvmrc`.
The combined-build companion additionally changes only API CI as described above.
The shared checker and its allowlists are unchanged; the API-only Windows exception
is described above. Generator `--check` binds
the exact SDK preparation, base environment and combined CLI handoff.

The documented Ubuntu image default Node `22.23.3`/npm `10.9.9` is unsupported
by the immutable Contracts engines. That missing prerequisite is real, but
the unavailable hosted npm stderr from [PenniLogic/api#102](https://github.com/PenniLogic/api/pull/102)
is not evidence of an `EBADENGINE` cause. Rendering and finite shell/argv fixtures
are not an SDK install run, API application execution or hosted recovery proof.
The Contracts command proposal in [Infra #72](https://github.com/PenniLogic/infra/pull/72)
is not adopted. [Infra #22](https://github.com/PenniLogic/infra/issues/22),
[PenniLogic/api#1](https://github.com/PenniLogic/api/issues/1) and
[PenniLogic/api#22](https://github.com/PenniLogic/api/issues/22) remain open in scope:
independent review, consumer/native acceptance, whole-job and whole-workflow
under-600-second evidence, and the trusted-workflow identity/mandatory-absence
gap are not resolved by this runtime prerequisite.

## API database admission installation (accepted source binding)

`api-database-admission-installation.json` generates the API's fixed launcher and
committed installation resource. The resource binds the launcher plus five exact
build payloads; it is not an output receipt or a caller-controlled acceptance
flag. Its four source roles pin protected-accepted Infra `8939daae`,
Docs `62a627f6`, API inventory publication `b938b31e` and original API evidence
`d39f4692`, each with complete immutable commit/tree/file bindings. Trust and
input envelopes are deterministic projections of those sources, not
caller-provided acceptance flags. Standalone Infra trust remains null/empty;
explicitly unbound installation fixtures still refuse without writes.

Cold preparation requires explicit `prepare --fetch`: 28 public requests,
within the unchanged 32-request/180-second budget. The generated API native
command list adds preparation and offline verification immediately before its
existing build. API owns Gradle preparation/offline consumer wiring; a generated
or locally prepared bundle is not consumer activation or deployment acceptance.
The launcher reuses byte-verified, unchanged Money primitives without altering
Money's catalog, budgets or commands. Full interface and limits are in
[database/README.md](../database/README.md).

## API Money source preparation (local source, acceptance held)

`api-money-sources.json` is the single canonical catalog for the API Money preparation
interface. The API-only profile opt-in renders `templates/materialize_money_sources.py`
as `scripts/materialize_money_sources.py`, embedding that catalog. No other profile,
managed hook, setup workflow, checker rule, action pin, permission or protection changes.
The original opt-in changed five existing API command-derived files and added one
script; it now also changes the API-only checker's exact CI digest. The setup
workflow and the other eight profiles remain byte-identical.

The catalog binds ten Contracts files at
`aa8d90cb98cec9b6dd08c91b3a4d869e47362662` and exactly one Docs file,
`governance/test-strategy.json`, at `a700e639585c61a4610e7b99dbd02b2dab28bdcc`.
Every input has its numeric owning repository identity, full commit, Git blob,
regular-file Git mode, raw size and SHA-256. The registry, accepted renderer,
fixtures and goldens are inputs, not a second codec or currency registry.

The accepted AA8 provider fixes cross-currency equality in unordered collections.
Only its Money source and golden input changed; the other eight Contracts inputs,
registry output and Docs strategy remain exact. The catalogue binds the new Money
output and the freshly reproduced native `provider.json` provenance (2,404 bytes,
SHA-256 `e982e5b7fcd26314cdf7a3fd79e3de5fd782ceac0bc35b6ea5c8e779c55b86a0`).
That receipt was reproduced by the unchanged producer at frozen API source
`35267fcf20a0de02760187e8ff72421a78f722ff`; running only that producer does not
execute, adopt or approve its separately reviewed mutation proposal.

The shared API profile for manual runs and the credential-free Conformance exerciser remains:

```text
python scripts\check_repository.py
python scripts\materialize_money_sources.py
python scripts\money_provider.py --source-root "build\source-materialization\contracts-aa8d90cb98cec9b6dd08c91b3a4d869e47362662" --strategy-file "build\source-materialization\docs-a700e639585c61a4610e7b99dbd02b2dab28bdcc\governance\test-strategy.json"
python scripts\money_provider.py --verify
python scripts\materialize_money_sources.py --verify
python -I -S -B scripts\prepare_database_admission.py prepare --fetch
python -I -S -B scripts\prepare_database_admission.py verify
python scripts\quality.py build
python -m unittest discover -s scripts\tests
```

In native CI, the combined-build companion supplies `--base` and the prepared Node
executable to the normal build; no later coverage graph is started. The proposed
native-only acquisition and prepared-input arrangement below retains these owning
gates but separates their credential-free execution from source acquisition.
The provider and combined build belong to the owning API candidate, which must be
adopted separately. Rendering these commands does not admit or release the currently
unaccepted API Money source.

The AA8 transition changed only the provider command's source-root pin literal,
preserving its seven command identities and their shape/order. The later database
binding adds the two explicit preparation/verification commands shown above,
without changing or removing those Money/build/test commands. The AA8 protected-profile
projection changes from `46f6029b32f77a628a70ae632976a67b0a4e66ba77ba0cbdb0ed113be895423a`
to `2d76a54b2358c2059e8ceddf18cdc51558ad897105c339183e67fb30a95df1a1`.
This explicit source preparation is not an equality waiver or maintenance/native
admission; the accepted validator, permissions, budgets and required checks are unchanged.

Only named snapshots and their deterministic `materialization.json` receipt under
`build/source-materialization` are written by the materializer. The API provider
alone writes `build/contracts-money`. Offline `--verify-inputs` checks only complete
input snapshots and their receipt, without fetching, repairing or running the provider.
Offline `--verify` still checks both complete input
snapshots and all fourteen provider files, including the provider receipt and both
golden Kotlin sources. An existing provider bundle is checked before preparation
so a changed receipt or partial/tampered output cannot be silently overwritten.
Existing snapshots are verified without fetching or rewriting. Missing, partial,
extra, mismatched, linked or hardlinked files refuse explicitly; there is no repair,
floating-main substitute, normalization, threshold fallback or tool installation.
On an ordinary write/publication failure, rollback removes only this attempt's
exclusively created, identity-checked files and empty directories. Existing or
unexpected artifacts are never recursively removed or repaired; unsafe cleanup
refuses explicitly. This is recoverable publication, not atomic visibility or a
hostile-concurrent-filesystem guarantee. A process killed before rollback can leave
a partial snapshot; that retry refuses rather than repairing unknown inputs.

Fetch mechanics reuse the accepted validator's fixed GitHub HTTPS GET, numeric
identity, commit/tree/blob and bounded-read patterns, without changing that validator.
Each fixed source uses one complete, nontruncated recursive Git-tree response.
All paths, explicit ancestors, type/mode pairs and blob sizes are validated; each
subtree and the commit-bound root are recomputed using Git's tree-object encoding.
This replaces sixteen directory-tree reads with two, reducing a fresh fixed-catalogue
fetch from 31 to 17 anonymous GETs (18 with the explicit local user-identity read).
It reduces request pressure, not the possibility of rate limiting or a service denial.
Redirects and proxy selection are disabled. Declared Content-Length must be complete;
chunked reads use the stdlib HTTP parser, and close-delimited responses remain bounded.
Ambiguous/invalid length or transfer framing refuses with a static protocol code.
Limits are 32 requests, a ten-second checked elapsed deadline for each complete GET
(including open/read/JSON completion), a 180-second overall checked deadline, two MiB
per response and four MiB total. Late progress or completed responses are not admitted.
Socket timeouts bound individual waits, not guaranteed whole-GET interruption;
platform DNS/socket blocking still has the native job as its outer bound.
Default/local acquisition and shared Conformance preparation remain anonymous; they
never infer authentication from an ambient token. The native API proposal below is
an explicit, narrow change to the previous anonymous-only consumer CI policy.
Local authenticated reads require explicit `--authenticated-local`, a process-local
`GH_TOKEN`, and verified `basiltt:54134686` identity. That option refuses before
client/provider/cache handling whenever `GITHUB_ACTIONS` is present, regardless of
its value (including empty, false-like, case-variant or malformed markers),
never consults stored auth or falls back, and never records credentials.
HTTP/rate-limit/timeout/decoding failures report static refusal codes.
HTTP 401, 403 and 404 report `source-unauthorized`, `source-forbidden` and
`source-not-found`. A 403 with one exact exhausted-rate header reports
`source-rate-exhausted`; 429 reports `source-rate-limited`, and 5xx reports
`source-http-unavailable`. Transport failures retain `source-unavailable`.
Error bodies and header values are never read into diagnostics, and no HTTP failure
triggers retries, credentials or a fallback. The historical accepted API push failure
reported only `source-denied`, so its exact HTTP cause cannot be recovered or asserted
as quota exhaustion; current local access is not hosted recovery evidence.

### Proposed native API source-preparation exception

This source proposes a reviewed policy change, not an already accepted exception,
owner waiver or runtime activation. Only the exact generated API native CI workflow
may give its two acquisition steps `PENNILOGIC_NATIVE_SOURCE_TOKEN: ${{ github.token }}`
under unchanged `contents: read`. Independent Core/QA/Security review and ordinary
protected integration remain required.

After the credential-free repository check, the first step runs only
`python -I -S -B scripts/materialize_money_sources.py --native-fetch`. The next,
credential-free step verifies the complete Money inputs with `--verify-inputs`,
executes the existing provider, verifies that provider and runs the existing full
Money `--verify`. Only then may the second token-scoped step run
`python -I -S -B scripts/prepare_database_admission.py prepare --fetch --native-fetch`
followed by `python -I -S -B scripts/money_client_interop.py prepare --native-fetch`.
Provider verification remains an interop acquisition prerequisite; it never runs
with this credential. All original gates and their fail-fast order are retained.

The explicit client mode consumes only that one variable, requires the exact API
repository/organization numeric context and an ordinary native event, and validates
the credential before a cached-input short-circuit. It does not inspect PATs,
keyrings, `GH_TOKEN` or `GITHUB_TOKEN`, infer native mode, retry or fall back to
anonymous/local authentication. Missing/invalid credentials or context refuse
statically. The context is a caller restriction, not cryptographic token provenance.
The token stays in process memory only for Authorization headers on the existing
approved `https://api.github.com` pinned public read endpoints. It is removed from
the process environment; no token value enters argv, URLs, output or artifacts.
Redirects/proxies remain disabled, and the separate pinned interop archive reader
retains its own credential-free headers. No acquisition command launches owning
tests, builds, provider execution or tool installation.

Later steps have no token environment. Database preparation omits `--fetch` and
re-verifies its existing complete installation before the unchanged verification
gate. Windows' input-only interop `prepare --require-prepared` and the Linux build
or Windows qualifier's `--require-prepared` forwarding require complete existing
interop inputs plus receipt. API's owning quality/Gradle/isolated worker chain
repeats that requirement at actual use: even disappearance of both artifacts must
refuse, never reacquire. The flag carries no secret. Default/manual/Conformance
commands omit it and preserve their existing behavior.

Request counts remain 17 for Money, 28 for database authority and three interop
metadata GETs plus its one credential-free archive GET. There is no new identity
cache, request reduction, origin, permission, deadline or cap. The ephemeral-token
mode addresses the anonymous-quota availability class, not all rate limits or
cross-repository access failures; the same upstream quota refusal remains valid.
The Actions `GITHUB_TOKEN` limit is 1,000 requests/hour/repository, not the generic
installation-token limit; preparation does not own that entire shared allowance.
First-party [setup-node](https://github.com/actions/setup-node/blob/main/action.yml)
and [pinned tool-cache code](https://github.com/actions/toolkit/blob/fa980c4100e53128102670562e9e293518900112/packages/tool-cache/src/tool-cache.ts#L588)
provide precedent for authenticated public cross-repository tree/blob reads, not
proof that this exact endpoint set or available quota has passed.
Synthetic transport/negative controls are not actual native quota availability.
That requires a later authorized changed-source native run after review/integration.

The check-name registry binds the API workflow to an actual source commit in a
subsequent registry-only commit, not a guessed/self-referential SHA. Local source
and offline transport fixtures are not hosted executions or trusted-CI producer
qualification. [Infra #22](https://github.com/PenniLogic/infra/issues/22), functional
[PenniLogic/api#1](https://github.com/PenniLogic/api/issues/1) /
[PenniLogic/contracts#1](https://github.com/PenniLogic/contracts/issues/1) adoption,
independent review and release acceptance remain held. This catalogue unit neither
measures nor waives the mandatory 90% mutation floor; methodology and executable
qualification remain owned by
[PenniLogic/api#22](https://github.com/PenniLogic/api/issues/22), dependent on
[PenniLogic/api#3](https://github.com/PenniLogic/api/issues/3).

Generated workflows are written in JSON syntax, a valid YAML subset, so the stdlib checker below can
parse them without a second parser. Profile values are validated by `validate_profile` before
rendering (single printable ASCII lines, no `${{`, reviewed `env` keys, narrow `.gitattributes`
shapes, bounded timeouts).

## `templates/check_repository.py`

The template is copied into every consumer as `scripts/check_repository.py` and runs from the
managed pre-commit hook (`--staged`) and as the first owning profile check. One block is rendered during the
copy: `generate.py` replaces the `WORKFLOW_ACTION_PINS` mapping with the `actions` pins of
`repository-profiles.json` (validated as lowercase 40-hex commits, sorted by action name), so the
same source that pins `actions/checkout`, `actions/setup-python`, `actions/setup-node` and
`actions/setup-java` in `ci.yml`, plus `actions/upload-artifact` in infra's conformance workflow,
binds them in the consumer checker, and one pin bump reaches both in the same regeneration.
`WORKFLOW_REPOSITORY` is also rendered from the selected profile, not read from editable policy
metadata: only the infra checker admits the conformance exception, and only at its exact filename.
The template carries the current pins and the infra binding so it can be tested unrendered;
`test_workflow_validation.py` fails when the pins or normalized template differ, and `generate.py`
refuses a template that does not define either rendered field exactly once.

The checker is a **drift tripwire**, not the security boundary: a pull request that can edit a
workflow can edit the checker too, and the workflow token is already `contents: read`. It refuses
anything the generator does not emit so a hand-edit is visible before review, without network
access or third-party dependencies.

Every refusal is a `Refused` (a `ValueError`) whose message is **static rule text**. `check()` prints
`Invalid or unsafe workflow: <file>: <rule>` (or `Invalid JSON in <file>: <rule>`); no key, value or
other content of the refused file is ever echoed, and a non-printable path is shown as
`[non-printable path]`. Input that is not a UTF-8 JSON document of bounded depth, or a shape no rule
anticipated, fails closed with the one line `...: not a parseable UTF-8 JSON-syntax document`
(never a traceback).

The common rules below exclude the exact-byte API CI and opted-in PR-integrity
exceptions. Those use separate path/profile bindings and never widen this template.

The rules, in evaluation order. `validate_workflow` runs its stages one after another and each rule
is an early `raise`, so across stages the first matching rule is the one reported: a token is named
before a placement, a condition or unlisted action before the key allowlists, and a key outside the
allowlists before the per-file trigger and job sets. Within a stage the walk is per element in
document order: rules 7-12 are applied to each mapping before the next mapping is visited (a `uses`
problem in step 1 is reported before an `if` in step 3), rules 15-18 to each job and each of its
steps before the next job, and rules 20-21 to each job in turn. The table order is derived from the
template's source by `governance/tests/test_rule_table.py` (each helper expanded at its call site),
so a rule moved or added in the template fails that test until the row moves with it.

| # | Rule text | Refuses |
|---|-----------|---------|
| 1 | `UTF-8 byte order mark before the JSON document` | a BOM that `json.loads(bytes)` would otherwise skip (UTF-16/32 input instead fails the strict UTF-8 decode and gets the parse fallback line) |
| 2 | `Duplicate JSON key` | a repeated key at any depth, which parsers resolve differently |
| 3 | `workflow document must be one JSON object` | a top-level array, string, number, boolean or `null` |
| 4 | `expected read-only workflow token` | any workflow `permissions` other than `{"contents": "read"}` |
| 5 | `unreviewed workflow expression; public jobs must not receive secrets` | every `${{ ... }}` outside `WORKFLOW_EXPRESSIONS`, at any depth, except the exact, separately path-bound Conformance token value described below |
| 6 | `public candidate jobs must not receive secrets` | the `secrets` context or `github.token` in any key or string outside that same single token leaf, including whitespace-split and whole-context forms (tripwire behind rule 5) |
| 7 | `conditions are not part of the generated workflows` | the key `if` in any mapping (job, step, snapshot or any other depth) |
| 8 | `action must be immutable and one of the generated GitHub-owned actions` | any `uses` that is not one of `WORKFLOW_ACTIONS` followed by `@` and a lowercase 40-hex commit, including reusable-workflow jobs, local and `docker://` actions, tags, branches, short or upper-case commits |
| 9 | `action commit differs from the generated pin; regenerate instead of editing it` | a listed action at any 40-hex commit other than its entry in `WORKFLOW_ACTION_PINS` (compared exactly and case-sensitively), including a listed action at another listed action's pin and a fork's commit reachable by SHA through the upstream repository |
| 10 | `unreviewed action input; only the generated inputs are accepted` | a `with` key outside the per-action input allowlist, or a non-mapping `with` |
| 11 | `checkout must not retain credentials` | `actions/checkout` without `persist-credentials: false` |
| 12 | `artifact upload is reserved for infra conformance` | `actions/upload-artifact` anywhere except the infra profile's exact `.github/workflows/conformance.yml` |
| 13 | `top-level key outside the generated workflow keys name, on, permissions, concurrency, jobs` | a top-level `env`, `defaults`, `run-name`, merge key or any other field |
| 14 | `jobs must be a mapping of job ids with at least one job` | `jobs` missing, empty, a list or a scalar |
| 15 | `job must be a mapping` | a job whose value is a scalar or list |
| 16 | `job-level key outside the generated job keys name, runs-on, timeout-minutes, env, steps` | `container`, `services`, `snapshot`, `environment`, `strategy`, `outputs`, `defaults`, `needs`, `continue-on-error`, `if`, `uses`/`with`/`secrets` of a reusable workflow (with or without `runs-on`), a job-level `permissions` (even read-only) or `concurrency`, differently cased or whitespace-padded keys, and any future field |
| 17 | `steps must be a list of step mappings with at least one step` | `steps` missing, empty, not a list, or containing a non-mapping |
| 18 | `step-level key outside the generated step keys name, uses, with, run, env` | `id`, `shell`, `working-directory`, `timeout-minutes`, `continue-on-error`, `if` and any other step field |
| 19 | `unreviewed workflow trigger` | an `on` that is not a mapping, or an event outside `push`, `pull_request`, `workflow_dispatch`; only infra's exact conformance file additionally admits `schedule` |
| 20 | `only the standard hosted Ubuntu runner is configured` | any `runs-on` other than `ubuntu-24.04` |
| 21 | `writable job credentials are not permitted` | a job-level `permissions` other than read-only; tripwire behind rule 16, which already refuses the key |
| 22 | `CI must run on exactly main pushes, pull requests and manual dispatch` | `ci.yml` whose event set is not exactly `push`, `pull_request`, `workflow_dispatch` (a dropped event as well as an added one) |
| 23 | `CI must contain its documented single job` | `ci.yml` with any job set other than `ci` (an extra plain job, a second copy of the job, a renamed or differently cased id) |
| 24 | `Keep the required native CI job name stable` | `ci.yml` whose `ci` job is not named `CI` |
| 25 | `Copilot setup must run on manual dispatch only` | `copilot-setup-steps.yml` whose event set is not exactly `workflow_dispatch` (a gained `push` or `pull_request` included) |
| 26 | `Copilot setup must contain its documented single job` | `copilot-setup-steps.yml` with any job set other than `copilot-setup-steps` |
| 27 | `Conformance must run on exactly weekly schedule and manual dispatch` | infra conformance whose event set is not exactly `workflow_dispatch`, `schedule`, including a gained `push` or `pull_request` |
| 28 | `Conformance must keep its weekly cron and input-free manual dispatch` | a dispatch value other than `{}` or a schedule other than the single `{"cron": "17 5 * * 1"}` mapping, including unknown fields, malformed values and additional entries |
| 29 | `Conformance must contain its documented single job` | infra conformance with any job set other than `conformance` |
| 30 | `Keep the Conformance workflow and job names stable` | infra conformance whose workflow or job name is not `Conformance` |
| 31 | `Conformance must keep its bounded 60-minute timeout` | infra conformance whose timeout is not the integer `60`, including a missing timeout, a string or a float |
| 32 | `Conformance must keep one authenticated harness step and no other environment` | a missing, duplicate, renamed or action-based harness step, any harness key set other than `name`, `run`, `env`, any environment other than exactly `GH_TOKEN: ${{ github.token }}` on that step, a job environment or another step environment |
| 33 | `workflow file outside the generated pair or infra-only conformance.yml` | every other path under `.github/workflows/`, including a consumer conformance file, `.yaml` twin, differently cased name or subdirectory |

The token expression is **not** in `WORKFLOW_EXPRESSIONS`. Before rules 5-6, the checker computes
one exception only when its generated `WORKFLOW_REPOSITORY` is `infra`, the path is exactly
`.github/workflows/conformance.yml`, the sole job id is `conformance`, and its sole plain run step
named `Run conformance` has keys exactly `name`, `run`, `env`, a string `run`, and `env` exactly
`{"GH_TOKEN": "${{ github.token }}"}`. No job or other step may have an environment. Only that
value leaf is omitted from the expression walk and the independent secret tripwire; mapping keys
have distinct paths and cannot borrow the exception. Other spellings, whole/computed/bracket
contexts, other token variables, extra environments and other workflow/profile paths remain
refused. A malformed placement carrying a token is consequently refused by rules 5-6 before
the later shape rule; rule 32 also catches a missing token or a static environment.

Rules 13-18 accept exactly the keys the generator emits in the common layer across profiles: job-level
and step-level `env` are emitted only by some profiles (web/admin telemetry opt-out, api coverage
base) but accepted for every consumer; only the conformance exception uses the profile binding.
`governance/tests/test_workflow_shape.py` derives the three allowlists from each
profile's standard workflow layer (API/Infra Linux layers are projected to the
single-job shape for common-parser tests only). Full API/Infra compound-workflow
acceptance and drift refusals use the actual rendered checker in separate controls.
Adding a common key fails until the template lists it in the same PR.
Job-level `permissions` is deliberately not allowlisted: no profile emits it and the exact
workflow-level `permissions` is the rule. Step `id`, `shell`, `working-directory` and
`timeout-minutes` are not emitted either.

Rules 8-9 bind each `uses` to one of five names at one commit each; `test_workflow_validation.py`
derives both mappings from the rendered workflows of every profile, so a pin bump or a new action
in `generate.py` fails until the checker carries it. Rule 12 restricts upload to infra conformance;
its only allowlisted inputs are `name`, `path`, `retention-days` and `if-no-files-found`.
Rules 22-33 bind each generated workflow file in the common layer to its own trigger set and single job. CI/setup
event filters (`branches`, `paths`, `types`, dispatch `inputs`) remain unbound (their strings are
still walked by rules 5-6); conformance's dispatch and schedule values are exact. Other action
input values, run text, step order and concurrency still rely on infra's byte-level `--check`
and review, not on this checker. These are disclosed residuals, not security guarantees.

Beyond workflows, `check()` requires the generated file set, refuses tracked symlinks, key material
by file name, obvious token/private-key patterns (content withheld), invalid UTF-8 in text files and
invalid JSON in `*.json` (a top-level JSON array remains valid JSON there; only a workflow must be an
object). Passing the checker is a repository-foundation result, never product acceptance.
The common required-file subset is unchanged; the API exception adds its qualifier
and the PR-integrity exception adds its gate. Infra's generator `--check` detects a
missing conformance file as well as any changed generated byte.

## Opt-in PR workflow integrity bootstrap

Only the Infra profile currently sets `pr_workflow_integrity: true`. The generator can render
the same profile-bound contract for all nine repositories, but the other eight retain their
entire accepted 20-file baselines. All eighteen existing CI/setup workflows, Conformance,
commands, pins, permissions and toolchains are unchanged. Consumer opt-in/adoption is a
separate coordinated delivery; source support does not make an undeployed gate required.

`templates/pr_workflow_integrity_checker.py` is inserted only into an opted-in checker, ahead
of `check()`. It requires the additive file and accepts only its exact generated SHA-256:
`PR workflow integrity must match its generated data-only workflow`. The common template and
its 33 ordered rules above remain unchanged. The new file is not passed through a widened
expression/event/action allowlist: its exact emitted bytes bind the profile, sole job,
trigger, runner, program and single token value leaf together. This checker remains a
candidate-editable tripwire, not the pre-merge trust boundary.

The new boundary is the base-sourced `pull_request_target` workflow, named and reporting
**PR workflow integrity**, not another job named CI. It has one actionless/no-checkout
`ubuntu-24.04` job and one `python3 -I -S` step containing the standalone reviewed
`templates/pr_workflow_integrity.py` program and static rendered expectations. Only that
step's `env.GH_TOKEN` is `${{ github.token }}`; permissions are exactly `contents: read`.
No candidate checkout, imports, eval/exec, shell interpolation, package hooks, reusable jobs,
downloaded programs, artifact execution, personal credential, secret or write grant exists.

The program checks native workflow/event/main provenance and numeric repository/org
identity before candidate Git-object reads. It reads immutable head/base trees/blobs through
fixed github.com HTTPS GET endpoints, with redirects and proxy selection disabled, and
compares actual CI/setup/policy bytes to the canonical rendering. Candidate checker and
validator-workflow bytes must match protected base. Infra source-profile contract fields
are compared as JSON data, not imported; unrelated purpose/state prose is not locked.
Current PR/base metadata is checked again before success. Conditions, echo stubs, command
removal/masking, wrong names, missing/extra workflows and checker/validator tampering fail,
even when the candidate removes its own checker step.

The five-minute job bound remains the outer limit. The validator checks a 180-second
deadline, at most 32 requests, ten-second request/socket timeouts and one-MiB response limits;
blocking platform DNS/socket behavior is still bounded externally by the native job, not
an invented OS sandbox. Only the runner-owned event file is opened. Reports contain fixed
paths/static refusal codes, validated public identity/SHAs, request/timing figures and
`pass|fail|error`, never candidate code/prose, API error bodies, host paths or credentials.
Exit codes are 0/1/2 respectively. Missing tooling/token, denied metadata or exceeded
bounds fail explicitly without anonymous/stored-auth fallback.

The existing registry keeps every primary CI entry/ref. An opted-in entry additionally
has `pr_gate: {check_name, workflow_ref}`. Source A actually renders and commits the native
bytes; subsequent registry-only B binds A's real full SHA. Historical gate rendering
includes its trusted program template and must equal the committed workflow as well as
the current rendering. Scheduled audit counts only actual adopted eligible PR producers,
never Conformance; a missing/unavailable/different new gate binding fails the row.

```text
python -m unittest discover -s governance/tests -p "test*pr_workflow_integrity*.py"
python governance/conformance/registry.py
```

These include actual isolated CLI and emitted Bash-step executions over finite owned
metadata responses; the external fixture driver replaces only HTTP transport, not the
validator or its refusal logic. The native program has no fixture mode. Those are mechanics
proofs, not hosted job-token permissions, duplicate-check aggregation, protection activation,
under-600-second native timing or protected merge-refusal evidence.
GitHub explicitly warns that SHA-like head branch names may suppress `pull_request_target`.
The native matrix must combine that missing trusted producer with a candidate-authored
same-App green context; a validator cannot reject anything when the platform does not
invoke it. Local rejection of a workflow/branch fixture does not resolve this limit.
See [CI_CONFORMANCE.md](../CI_CONFORMANCE.md#infra-only-trusted-pr-command-binding-bootstrap)
for the owner activation request, separate native qualification and rollback.

## Infra-only report workflow (infra#24, PR G and bounded runtime expansion)

The preserved request in `CI_CONFORMANCE.md`, "Preserved generated-setup request: the initial scheduled workflow",
is rendered only for infra. It does not alter any profile's `ci.yml` or Copilot setup workflow,
the required native `CI` context, consumer profiles, rulesets or review restrictions.

`Conformance` has one job id `conformance`, also named `Conformance`, on `ubuntu-24.04` with a
60-minute timeout, `contents: read`, manual dispatch and the weekly UTC cron `17 5 * * 1`.
Its checkout has `persist-credentials: false` and full history for registry commit rendering.
Python, Node `24.14.0` and uv `0.11.33` are set up before the harness runs with
`--github-client gh --exercise python,node,uv`. Node uses the existing pinned setup action and
the infra profile's generated `.nvmrc`. The uv install reuses the ai-service profile's exact
verified, hash-required, binary-only, dependency-free pip line. Infra's native CI and setup
provision the same Node and uv before checks because the governance tests execute real fixtures.
The other sixteen consumer CI/setup workflows and all eight consumer profiles remain byte-identical
to accepted source `e96eb757beeb02b0a802e7545ca781669e85deb8`. The native `CI` name, triggers,
read-only permissions, hosted runner and ten-minute bound are unchanged. Infra's primary registry
language remains Python. Its updated native `CI` source binding is recorded in a separate commit
after the source commit that actually renders the new workflow; no self-referential SHA is used.

Unaccepted head `c9fceee` passed locally with Node `24.14.0`/npm `11.9.0`, but native PR CI
`36795639431` failed real Node fixture lock preparation (`edgesOut`), with 227 tests reported,
one setup error and 13 skips. That run did not provision Node or uv. Its exact runner image
`ubuntu24/20260927.320` documents default Node `22.23.3`/npm `10.9.9`. A clean Linux reproduction
with checksum-verified distributions reproduced npm's Arborist `loadPeerSet` failure on that
pair and succeeded on `24.14.0`/`11.9.0` using the identical manifest/command. This is a toolchain
dependency mismatch, not presumed transient; the native setup fix adds no retry, cache deletion,
peer bypass or suite skip. Missing Node/npm/uv now fails fixture setup before scratch/execution,
and the real suite prints the actual runtime and test-runner versions.

The automatically issued, short-lived Actions `github.token` reaches only the `Run conformance`
step as `GH_TOKEN`. The reused `GhClient` invokes `gh api --hostname github.com -X GET` with a
60-second subprocess bound and captured output, an empty gh config directory and that token.
Other GH/GITHUB/ACTIONS selectors are scrubbed. Actions requires explicit `gh` and a non-empty
step token; no user-endpoint authentication probe, stored credential, personal credential or
anonymous fallback is used there. Missing tooling/token and unreadable metadata fail explicitly.
No actions, id-token or contents write permission is granted, and no repository secret is used.
This replaces the shared anonymous quota path that failed in hosted run `36784511111`; it is not
proof that the job token can read every public cross-repository endpoint. An inaccessible endpoint
still fails its row, and unreadable repository identity still prevents clone/execution.

The existing run step additionally checks the runtime `GITHUB_REF` is `refs/heads/main` and
`GITHUB_REF_PROTECTED` is `true` before invoking the harness. An off-main or unprotected dispatch
prints an explicit error and writes `conformance-report/FAILED` without executing the harness.
Scheduled workflows use the default branch. **Manual dispatch itself is not main-only**: it can
select another ref and checkout runs before this guard. The unmodified generated run step refuses
that ref; a branch that edits away the guard can still execute branch code. Neither the guard nor
the editable checker is a platform security boundary. Read-only permissions, no persisted checkout
credential, no application secrets and the harness's credential-isolated probes remain necessary.
There is no OS sandbox: the trusted infra process and trusted consumer `main` code can open files
and process resources accessible to their OS user. Environment scrubbing is not an in-process,
file-store or OS-level credential boundary. The step token remains short-lived and read-only.
Every scratch git command and consumer command uses the existing isolated `probe_environment()`,
without the metadata token or Actions state selectors; real child/descendant tests assert that.
Exact in-process token values as well as credential shapes are redacted before truncation,
stdout or report publication, and the final scan refuses a surviving credential.
The redactor now runs inside capture, before every initial normal/timeout tail on Windows and
POSIX, not after `Result.output` has already lost a matching prefix. `redacting_runner()` supplies
the report's exact known-path/token scope; direct probes use the same shared redactor with their
own default scope. The retained 3000-character result and 400-character report caps and report
shape remain unchanged. No additional full-output store, altered process ownership or new OS
sandbox claim is added.

Coordinator-confirmed c9 evidence used synthetic output with a credential crossing the first
3000-character cut. Initial plain-padding tests showed a suffix in `Result.output` but not the
later 400-character tail. Further credential/path-padding compression pulled that suffix into
the JSON sink with zero scanner survivors, demonstrating a publication-sanitizer defect.
No real credentials, upload or consumer-environment token exposure was demonstrated. The named
normal/timeout, known-path, credential-shape, unsafe-Windows-result and end-to-end JSON shortening
regressions include opaque/shaped values and unsplit controls; no exploit-severity judgment is
claimed here. The original negative evidence remains preserved.

A harness failure also writes `FAILED` instead of immediately failing the run step. Upload therefore
precedes the final `test ! -f conformance-report/FAILED`, without an `if` key or `if: always()`.
The upload includes only the report directory, never scratch checkouts. On a redaction or startup
error it may contain only the failure marker; no report is fabricated. Upload failure itself is
fatal. Cancellation, the job timeout or a failed checkout/setup can prevent publication; the sentinel
covers ordinary harness exits, not every interruption. The action uses the runner's artifact-service
credential, not an explicit repository token.
Its documented `retention-days: 3` limits storage lifetime and `if-no-files-found: error` prevents
a missing upload directory from passing with a warning; no storage allowance is increased.

Read-only action-source verification: `actions/upload-artifact` is repository id `192625955`,
owned by `actions` (id `44036562`); tag `v7.0.1` resolves to
`043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`, whose tree is
`9eac56dcf4bfeeb308ee3d0d7d49913c3d65b676`. Its pinned `action.yml` documents all four emitted
inputs and runs the Node 24 upload entry point. The canonical pin and template pin must agree;
the tag is verification evidence, never the executable workflow ref.

This is report-only. No required `Conformance` context, ruleset mutation, paid service or deployment
is added. The expanded job exercises actual failing/removed Vitest suites for web/admin and locked pytest
suites for ai-service. JDK/Android fixtures are not added. Kotlin evidence, owner-administered
wiring, opt-out expiry and budget decisions remain under infra#24;
this bounded change references that issue, not closes it. Consumers regenerate only in later
coordinator-scheduled PRs. This runtime unit rolls back by reviewed revert/regeneration to accepted
`e96eb757`, explicitly removing the new `.nvmrc` while retaining the original anonymous/Python-only
Conformance workflow and its known quota limit. The earlier PR-G whole-workflow removal is a
different rollback, preserved in the original request.

`test_generated_conformance_workflow.py` checks the expanded request plus the guard and supported storage
inputs, every profile's artifact count, deterministic all-nine baselines, profile-bound refusals and
the existing expression/action/condition/permission evasions. It executes the Bash run/final steps
with a synthetic harness for successful reports, findings, report-less errors and denied dispatches.
`test_conformance_runtime.py` asserts the leaf-bound exception, GET client, hostile environment,
redaction and unchanged consumer workflow/profile bytes. `test_conformance_native_runtime.py`
checks native infra runtime provisioning and missing-tool/preparation failures.
`test_conformance_runtime_fixtures.py`
executes the real profile commands on temporary minimal consumers with actual Vitest/pytest
dependencies, including a passing baseline and both planted refusals; missing toolchains are
errors, never successful skips. These are mechanics proofs, not hosted token permissions or nine-main
acceptance. Only an accepted, reviewed merge followed by actual hosted verification can prove
that. No workflow activation or manual dispatch is part of this implementation.

## Provenance

PR C (#45) added the whole-context secret guard and `.gitattributes` shape allowlist; PR D (#48)
moved the tripwire to decoded strings and added the `if`, action and input rules; PR E (#50) added
the top-level, job-level and step-level key allowlists (rules 3, 12-17), the surfaced rule messages
and the BOM / non-object / depth hardening of `json_document` and `check()`; PR F (#54) bound each
listed action to its generated pin (rule 9, rendered from `repository-profiles.json`), bound each
workflow file to its trigger set and single job, and made this table's order and the generated-file
list above test-enforced. PR G extends only the infra file/profile exception, scopes upload (rule 12),
and binds its weekly trigger shape, job, names and timeout (rules 27-31); the updated table records
the new evaluation order rather than retaining historical rule numbers as current ones. The runtime
expansion adds the sole step-token exception and rule 32, without widening the global expression
set, action/input channels, consumer CI/setup tokens or permissions. It requires separate
non-author Core, QA, Security, Privacy and Reliability review before integration.
