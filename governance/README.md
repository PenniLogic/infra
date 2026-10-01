# Governance: the canonical generator and the generated checker

`generate.py` renders the small public-repository baseline, 20 common files for every repository in
`repository-profiles.json` (`.github/workflows/ci.yml`, `.github/workflows/copilot-setup-steps.yml`,
`AGENTS.md`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CONSTITUTION.md`, `COPILOT_FILES.md`,
`.github/copilot-instructions.md`, `.github/instructions/source.instructions.md`,
`.github/agent-policy.json`, `.github/CODEOWNERS`, `.github/github-app.yml`,
`.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/*` (two files), `.gitattributes`,
`.gitignore`, `scripts/setup.py` and `scripts/check_repository.py`). Consumers never hand-edit those
files: a profile or template change lands here through a reviewed generator PR, then each consumer
regenerates from the merged `main` in its own PR. Additionally, infra alone has 22 files: its third
workflow is `.github/workflows/conformance.yml`, and `.nvmrc` pins its real governance-fixture Node runtime.
`governance/tests/test_rule_table.py` keeps this per-profile list equal to what `artifacts()` renders.

```text
python governance/generate.py --repository <name> --root <checkout>          # regenerate one consumer
python governance/generate.py --repository infra --check                      # drift check (CI runs this)
python governance/generate.py --root <scratch>                                # render every profile
python -m unittest discover -s governance/tests
```

Generated workflows are written in JSON syntax, a valid YAML subset, so the stdlib checker below can
parse them without a second parser. Profile values are validated by `validate_profile` before
rendering (single printable ASCII lines, no `${{`, reviewed `env` keys, narrow `.gitattributes`
shapes, bounded timeouts).

## `templates/check_repository.py`

The template is copied into every consumer as `scripts/check_repository.py` and runs from the
managed pre-commit hook (`--staged`) and as the first CI command. One block is rendered during the
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

Rules 13-18 accept exactly the keys the generator emits, as the union over all profiles: job-level
and step-level `env` are emitted only by some profiles (web/admin telemetry opt-out, api coverage
base) but accepted for every consumer; only the conformance exception uses the profile binding.
`governance/tests/test_workflow_shape.py` derives the three allowlists from the rendered workflows of
every profile, so adding a key to the generator fails that test until the template lists it in the
same PR. Job-level `permissions` is deliberately not allowlisted: no profile emits it and the exact
workflow-level `permissions` is the rule. Step `id`, `shell`, `working-directory` and
`timeout-minutes` are not emitted either.

Rules 8-9 bind each `uses` to one of five names at one commit each; `test_workflow_validation.py`
derives both mappings from the rendered workflows of every profile, so a pin bump or a new action
in `generate.py` fails until the checker carries it. Rule 12 restricts upload to infra conformance;
its only allowlisted inputs are `name`, `path`, `retention-days` and `if-no-files-found`.
Rules 22-33 bind each generated workflow file to its own trigger set and single job. CI/setup
event filters (`branches`, `paths`, `types`, dispatch `inputs`) remain unbound (their strings are
still walked by rules 5-6); conformance's dispatch and schedule values are exact. Other action
input values, run text, step order and concurrency still rely on infra's byte-level `--check`
and review, not on this checker. These are disclosed residuals, not security guarantees.

Beyond workflows, `check()` requires the generated file set, refuses tracked symlinks, key material
by file name, obvious token/private-key patterns (content withheld), invalid UTF-8 in text files and
invalid JSON in `*.json` (a top-level JSON array remains valid JSON there; only a workflow must be an
object). Passing the checker is a repository-foundation result, never product acceptance.
The existing required-file subset is unchanged; infra's generator `--check` detects a missing
conformance file as well as any changed generated byte.

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
