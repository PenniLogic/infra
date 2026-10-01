# CI conformance across the nine PenniLogic repositories

Owner ticket: [PenniLogic/infra#24](https://github.com/PenniLogic/infra/issues/24) (T-SCA-INF-01) with the
coordinator addendum of 2026-09-30. This document is maintained by hand; nothing in it is generated.

The "one workflow set adopted by all eight repositories" is the governance generator
(`governance/generate.py` + `governance/repository-profiles.json`): every consumer's
`.github/workflows/ci.yml`, `scripts/check_repository.py`, `AGENTS.md` and the rest of the baseline are
rendered from one source and regenerated from a pinned infra commit. Adoption is proven by byte-identical
generation plus the drift tripwire, **not** by `workflow_call` reusable workflows: generator PR D
([#48](https://github.com/PenniLogic/infra/pull/48)) makes the checker refuse `jobs.<id>.uses` because a
reusable workflow reached through `uses:` carries the caller's token into code the caller does not review.
Do not reintroduce reusable-workflow adoption.

## What the conformance job does

`python governance/conformance/run.py` is a standard-library-only, read-only job. For every profile in
`repository-profiles.json` it:

1. clones the repository's `main` shallowly into a scratch directory (or reuses a clean clone of the same
   origin; `--refresh` advances it), sets the clone's push URL to the invalid value `DISABLED`, and
   records the cloned commit;
2. asserts the numeric repository id through the read-only REST API against the profile's `id` **before**
   anything is cloned or executed: a repository whose id does not match, or whose id cannot be read,
   fails its row with `repository identity not verified; nothing from the repository was executed` and
   only the read-only API facts are recorded for it;
3. compares every generated artifact byte for byte with the current generator rendering: a differing
   **workflow** file fails the repository, differing non-workflow files (a consumer that has not
   regenerated since the last generator PR) are a warning listing the stale files;
4. runs the consumer's own `python scripts/check_repository.py` on its `main`;
5. classifies the profile's commands into build, test and lint steps with a reviewed pattern table
   (`conformance/steps.py`); a profile with no recognisable test command fails;
6. plants defects in the scratch tree, runs the profile's real command, restores the tree byte for byte
   and records whether the command refused the defect (`conformance/defects.py`, see the catalogue below);
7. reads the repository's rulesets and the effective rules on `main`, and fails when a required
   status-check context is not produced by a job of the workflow on `main` (or is bound to an integration
   other than GitHub Actions, app id 15368);
8. checks the check-name registry entry (`conformance/check-names.json`) and verifies that the recorded
   `workflow_ref` generator commit renders the workflow currently on the consumer's `main`;
9. records the last completed push run of the `CI` workflow on `main`, its conclusion and wall-clock
   (`run_started_at` to `updated_at`, queue time excluded) against the ten-minute budget;
10. writes `conformance-report.json` (schema `pennilogic.infra.conformance/1`) and
    `conformance-summary.md` with local paths, exact in-process GH/GITHUB token values and
    credential-shaped strings redacted, after a
    fail-closed self-scan: if any local marker survives redaction (a path spelling, the account name as a
    path component, an absolute drive path or a credential) the job names the kind of marker, writes nothing and
    exits 2; otherwise it exits 1 when any repository fails.

It never pushes, comments, or writes to any repository. The harness refuses to plant into a tree that
`git status` does not report clean, and a tree that is not clean again after restoration is an `error`,
which fails the job and stops further planting in that repository. Backup-directory cleanup is checked
separately from restoring consumer files: all filesystem undos are attempted, the first error is
preserved, and a failed backup deletion is an `error` even when the consumer tree is byte-identical and
clean. The record's `cleanup` names the redacted backup location and error; any file whose undo failed
is retained there with a `file` / `restore_to` recovery mapping, never deleted as leftover scratch.
Cleanup failure stops further planting in that repository.

On Windows each probe reuses infra's `scripts/bootstrap.py` Job Object, process-object exit waits and
bounded pipe-release helpers. An isolated trusted Python launcher (`-I -S`) waits for one release byte
on stdin; the parent assigns it to the kill-on-close job **before** releasing any consumer command. The
consumer and all descendants are therefore job members from birth. A timeout terminates the whole job,
then allows at most five seconds for process-object exit confirmation and captured-pipe release.
Successful commands also end and confirm the owned lifetime, including background descendants whose
output was redirected. Probe stdin is closed; the reviewed profile commands are non-interactive.

If ownership cannot be established, no consumer command is released and the idle launcher is stopped.
If tree exit, job membership or pipe release cannot be confirmed, the probe fails explicitly instead of
claiming a bounded successful teardown. Repository inspection stops; a planted fixture records
`restoration_deferred` and retains its backups rather than restoring files a consumer might still hold.
The JSON includes the redacted failure/recovery details. Confirm process exit before recovering or
discarding that scratch checkout. POSIX keeps the existing `subprocess.run` behavior and makes no
Windows process-tree ownership claim.

Every probe, and every git command on a scratch checkout, runs with `probe_environment()`
(`governance/conformance/defects.py`): an explicit deny-list of variable names and prefixes is removed
(`GIT_CONFIG_PARAMETERS` and the whole `GIT_CONFIG_*` family, `GH_*`, `GITHUB_*`, `ACTIONS_*`, `SSH_*`,
`GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_PROXY_COMMAND`, package-manager and
cloud credential variables), a name heuristic (`TOKEN`, `SECRET`, `PASSWORD`, `CREDENTIAL`, `API_KEY`,
`PRIVATE_KEY`, `_KEY`) removes what the list does not name, git reads an empty global config and no
system config (`GIT_CONFIG_GLOBAL` → an empty file, `GIT_CONFIG_NOSYSTEM=1`, so no credential helper,
askpass program or URL rewrite of the operator applies), `gh` reads an empty config directory
(`GH_CONFIG_DIR`), terminal prompts are off, and `NoDefaultCurrentDirectoryInExePath=1` stops cmd.exe from
resolving a bare command name such as `python` or `npm` from the consumer's working directory (a
consumer-committed `python.cmd` would otherwise run first on Windows). Removing `GITHUB_ENV`,
`GITHUB_PATH` and `ACTIONS_RUNTIME_TOKEN` also keeps consumer code from writing state or artifacts into
later steps of the requested workflow.

**Remaining limit:** the scrub covers variables and the git/gh configuration files; it cannot cover
credentials that live in files or stores a consumer command can open by itself — SSH keys in `~/.ssh`,
an OS keyring or Git Credential Manager store, `~/.npmrc`, `~/.pypirc`, `~/.docker/config.json`, or a
credential helper the command configures in its own process. The disabled push URL means those
credentials cannot push through the scratch clone, but a command could still use them elsewhere.
That is why the job is meant for a disposable runner with no application/provider secrets or
personal credential, or for local runs against the organization's own repositories only.
Consumer `main` code is inside the trust boundary. Environment scrubbing is not an OS sandbox:
the trusted infra process and executed trusted-main code can open files and process resources
accessible to their OS user. The step-scoped workflow token is short-lived and read-only;
no stronger in-process or file-credential separation is claimed.

Trust boundary: proving that a consumer's real command refuses a defect means executing that consumer's
code (`scripts/check_repository.py`, `check_docs.py`, `npm ci` lifecycle scripts, `uv sync`, Gradle). Run
the job on a disposable runner with `contents: read` and only the metadata step token described below,
or locally only against the organization's own repositories. The fixtures prove the honest failure modes
(a removed, stubbed or skipped test step, an empty suite, a failing test that is really executed); a
consumer whose maintainers deliberately rewrite their own test runner to fake those outputs is a review
finding, not something a probe can prove from outside. Do not share one scratch directory between
concurrent runs.

### Running it

```text
python governance/conformance/registry.py                       # validate the check-name registry alone
python governance/conformance/run.py --scratch <dir> --output <dir> --github-client anonymous
python governance/conformance/run.py --scratch <dir> --output <dir> --github-client gh --exercise python,node,uv --refresh
python -m unittest discover -s governance/tests -p "test_conformance_*.py"
```

Options: `--repository <profile>` (repeatable) limits the run; `--github-client auto|gh|anonymous`
(`auto` locally uses the `gh` CLI's stored credential when it is installed and authenticated, else anonymous);
`--exercise` names the toolchains whose planted defects run (`python` by default; `node`, `uv`, `java`,
`android` need the matching toolchain on the machine and a network for `npm ci` / `uv sync`);
`--command-timeout`, `--budget-minutes` (the wall-clock budget recorded per row and applied to the last
`main` run; default 10), `--generated-at`. Exit status: 0 pass, 1 at least one repository failed, 2 the
job itself could not run (registry invalid, unknown profile, `gh` requested but absent, missing Actions
step token, wrong Actions client, or the redaction
self-scan found a surviving local marker — nothing is written in that case).

The scheduled job now uses the existing `GhClient` with only the automatically issued Actions
`github.token`, passed as `GH_TOKEN` on `Run conformance`, never job/global env or a repository secret.
On Actions, explicit `--github-client gh` and a non-empty `GH_TOKEN` are mandatory: no `/user` probe,
personal/stored credential or anonymous fallback is used. Every metadata subprocess is
`gh api --hostname github.com -X GET`, captured and bounded to 60 seconds, with other GH/GITHUB/ACTIONS
selectors removed and an empty gh configuration directory. Every scratch git and consumer command
instead receives `probe_environment()` without that token or Actions selectors. The workflow's only
grant stays `contents: read`; actions/id-token/contents write grants are not added.

The public anonymous client remains an explicit local option. A normal run needs five GETs per
repository (identity, ruleset list, ruleset detail, branch rules, runs), 45 for nine repositories,
against its shared 60/hour/address quota. Hosted run
[36784511111](https://github.com/PenniLogic/infra/actions/runs/36784511111) at accepted generator commit
`e96eb757beeb02b0a802e7545ca781669e85deb8` made 19 anonymous reads and reported
`api_rate_limit_remaining: 0`: .github/docs passed, the contracts ruleset GET returned 403,
and six remaining identity GETs returned 403 and prevented any clone/execution. Its real
[failure artifact 11128554489](https://github.com/PenniLogic/infra/actions/runs/36784511111/artifacts/11128554489)
contains JSON, Markdown and `FAILED`, uploaded before the final job failure with three-day retention.
That report is preserved, not retried into a passing result or replaced by local fixtures.
Quota exhaustion is observed there; a future authenticated 403 is not automatically classified
as quota exhaustion. Inaccessible metadata still fails explicitly, with no grant escalation.

A run that is killed while a defect is planted cannot restore the tree (the process never reaches its
restore step); the next run refuses to plant into that clone (`scratch checkout is not clean`) and fails
that repository. Delete the scratch directory, or the clone, and run again. The scheduled job always
starts from an empty scratch directory.

### Reading the report

Per repository the JSON carries `identity`, `main_sha`, `generated_baseline` (`workflow_files_identical`,
`workflow_differences`, `stale_files`, the generator's own `--check` exit code), `repository_check`,
`detected_steps` (`build`, `test`, `lint`, `checker`, `install`, `other`, `consumer_self_tests`),
`required_checks` (`produced`, `required`, `missing`, `strict_up_to_date`, `branch_rules`, `rulesets` with
bypass actors), `registry`, `last_main_run` (`wall_clock_seconds`, `within_budget`, `head_sha`),
`planted_defects`, `language_coverage`, then `failures`, `warnings` and `result`.
Probe `error` details, fixture `cleanup` locations/recovery mappings and `restoration_deferred` are
included when applicable; all strings pass the same whole-document redaction and final self-scan.

Failures (any one fails the repository and the job): repository id mismatch or unreadable API; scratch
checkout unavailable; a generated workflow file that differs from the generator; the consumer's own
checker failing; no test step detected; no required status check on `main`; a required context without a
producing workflow job; no registry entry, a registry check name the workflow does not produce, or a
`workflow_ref` that does not render the workflow on `main`; a planted defect `not_proved` or `error`; a
red last `main` CI run; a run over the ten-minute budget for a profile whose reviewed timeout is the
default ten minutes. Failed backup cleanup and unconfirmed Windows probe teardown fail the row too;
a restored consumer tree alone is not enough to prove cleanup succeeded.

Warnings (recorded, not failing): stale non-workflow generated files; a ruleset that does not require an
up-to-date branch; planted defects of a toolchain not exercised in this run; no completed `main` run
found; a run over ten minutes for a profile with a larger reviewed `timeout_minutes` (contracts, api,
android run with 30); `main` moved since the last completed run; a registry `workflow_ref` that could
not be verified in this run (no local history for the commit, or no scratch checkout to compare with).

Budget decision (Q5 of the QA review): the ten-minute budget of addendum item 3 fails a repository only
when its profile runs with the default ten-minute `timeout-minutes`; for the three heavy profiles whose
reviewed timeout is 30 minutes an overrun is a warning naming both figures, because the reviewed
timeout is the current per-profile decision. Making the budget per profile (or failing the heavy
profiles too) is the enforcement decision of [PenniLogic/infra#22](https://github.com/PenniLogic/infra/issues/22),
not of this report-only job.

Planted-defect outcomes: `proved` (every probe this job planted for behaved as required), `not_proved`,
`recorded` (observation-only fixture), `consumer_evidence` (a consumer-owned self-test exited 0 — the
consumer's own claim, presented separately and never counted as proved by this job; a non-zero exit is
`not_proved`), `not_exercised` (toolchain excluded from the run), `error` (timeout, could not start,
tree not clean or not restored). Probe outcomes: `as_expected` / `unexpected` for required probes,
`detected` / `not_detected` for observations; `detail_surfaced` records whether the consumer's checker
printed its rule text (only checkers regenerated after PR E, [#50](https://github.com/PenniLogic/infra/pull/50),
do; older ones refuse with the same exit code and the line `Invalid or unsafe workflow: <file>`).

A passing report is a repository-foundation result. It is not product, release, accessibility, load or
security acceptance.

## Planted-defect catalogue

| Fixture | Language | Toolchain | Applies to | Required probe(s) |
| --- | --- | --- | --- | --- |
| `workflow-test-step-removed` | workflow | python | every profile | generator drift check names `ci.yml`; the consumer checker is observed (it validates shape, not which commands run) |
| `workflow-test-step-stubbed` | workflow | python | every profile | drift check names `ci.yml` after the Run checks step becomes `echo tests skipped` |
| `workflow-step-skipped-by-condition` | workflow | python | every profile | drift check; consumer checker refuses (`if` rule) |
| `workflow-unpinned-action` | workflow | python | every profile | drift check; consumer checker refuses `actions/checkout@v4` (pinned-action rule) |
| `workflow-reusable-workflow-job` | workflow | python | every profile | drift check; consumer checker refuses `jobs.reuse.uses` |
| `workflow-step-continue-on-error` | workflow | python | every profile | drift check; the current infra template copied over the scratch checker refuses (step-key rule from PR E, rule 17 of the ordered table) |
| `python-tests-removed` | python | python | profiles with `unittest discover` | the exact profile command exits 5, `NO TESTS RAN` |
| `python-test-failing` | python | python | profiles with `unittest discover` | the exact profile command exits 1 naming `test_planted_defect_must_fail` |
| `python-pytest-failing` / `python-pytest-removed` | python | uv | ai-service | `uv sync --locked` then `uv run --locked pytest` exits 1 / 5 |
| `documentation-index-link-broken` | documentation | python | docs | `check_docs.py` fails: `generated slot ADR-001 differs` |
| `documentation-dangling-supersedes` | documentation | python | docs | `check_docs.py` fails: `supersedes ADR-099, which has no source record` |
| `documentation-body-link-broken` | documentation | python | docs | observation: a broken relative link outside the ADR graph is **not** detected (see limitations) |
| `typescript-test-failing` / `typescript-tests-removed` | typescript | node | web, admin | `npm ci` then `npm test` exits non-zero (`planted defect` / `No test files found`) |
| `kotlin-test-failing` | kotlin | java | api | `python scripts/quality.py test` must fail on a planted JUnit 5 test |
| `kotlin-android-self-test` | kotlin | android | android | consumer evidence, not a defect this job plants: the consumer-owned `quality_gates.py self-test` (a failing test, spotless and lint defects, UP-TO-DATE and FROM-CACHE results) must exit 0; recorded as `consumer_evidence`, never as `proved`; needs the Android SDK |

Kotlin fixtures are not exercised by the expanded Python/Node/uv job; their evidence is the consumer's last `main`
CI run (api runs `quality.py build`, android runs its own `self-test` on every run) recorded in the
report, and the warning says so explicitly. The python fixtures still run for api and android
(`scripts/tests`). Consumer-owned planted-defect commands present in the profiles are listed under
`detected_steps.consumer_self_tests` (android `quality_gates.py self-test`, web `check:bundle:planted`).

## Check-name registry

`governance/conformance/check-names.json` (schema `governance/conformance/check-names.schema.json`) has
one entry per repository: `repo` (`PenniLogic/<name>`), `check_name` (the context the workflow produces and
the ruleset requires; `CI` everywhere), `workflow_ref` (a full `PenniLogic/infra` commit whose generator
renders the workflow on the repository's `main` byte for byte — by convention the commit that last changed
that rendering, so a consumer regenerating for a non-workflow change keeps its entry) and `language`
(`kotlin`, `typescript`, `python`, `documentation`, `openapi`). `registry.py` validates it with the stdlib
schema validator (`conformance/schema.py`, a reviewed subset that refuses unknown keywords) and
cross-checks it against the profiles: exactly one entry per profile, the check name produced by the
rendered `ci.yml` and equal to the policy's `required_native_check`, the language derived from the
profile toolchain. The tests reject an entry missing any required field, an unknown field, a short
`workflow_ref`, an unknown language and a duplicate repository, and verify that every `workflow_ref`
renders the current workflow from Git history; the job verifies the same against each consumer's `main`.

Update the registry in the same PR as a profile change that alters a workflow: set `workflow_ref` to the
merged generator commit the consumer regenerates from (the eight consumers record
`4e6e749fd849ae58f2b13c21215022c1bc410b9f`, the last commit that changed their rendered `ci.yml`; infra
records the full source commit that renders its current `ci.yml`. When source changes that workflow,
an ordinary source commit is followed by a registry-only binding commit pointing to the source commit;
never try to embed a commit's own unknown SHA in its contents).

## Onboarding a new repository

A repository adopts the baseline by adding a generator profile, never by copying steps:

1. Add the repository to `governance/repository-profiles.json` with its numeric `id`, `purpose`, `state`,
   toolchain fields (`node`, `java`, `android_sdk`, ...), `install` and `commands` (the first command is
   always `python scripts/check_repository.py`; every command is one printable line without `${{`), as a
   reviewed generator PR. Precedent: the contracts profile from the contracts#2 generated-setup request,
   [PenniLogic/infra#49](https://github.com/PenniLogic/infra/pull/49) (merged as `4e6e749f`).
2. Add the registry entry (`repo`, `check_name` = `CI`, `workflow_ref` = the merged generator commit,
   `language`) in the same PR; `test_conformance_registry.py` fails until every profile has exactly one.
3. After the merge, regenerate in the consumer's own PR
   (`python <infra>/governance/generate.py --repository <name> --root .`), commit the generated files
   unchanged, and let the native `CI` job run.
4. Ask the owner to apply the `Protect main` ruleset (PR-only squash, required `CI` from app 15368,
   up-to-date branch, resolved threads, linear history, empty bypass) — rulesets are owner-administered.
5. Run the conformance job; the new row must pass, including its planted defects.

## Ruleset state (read-only, live run of 2026-09-30) and proposals

The live run's redacted output is committed as evidence in `governance/conformance/evidence/`
(`conformance-report-2026-09-30.json`, `conformance-summary-2026-09-30.md`): produced locally by the
implementer at generator commit `66b0fc12` with `--github-client anonymous --exercise python,node,uv
--refresh` (45 anonymous reads, about 20 minutes including `npm ci` and `uv sync`), so it is a reproducible
claim, not a workflow artifact; once the generated workflow exists, its uploaded artifact supersedes it.
An earlier attempt during a network outage is not committed: the job failed closed on the two reads that
raised `URLError` and on the one scratch refresh that failed, and still wrote the complete report for the
other seven repositories.

Every one of the nine repositories has exactly one ruleset, `Protect main` (active, target `branch`,
`~DEFAULT_BRANCH`), with rule types `deletion`, `non_fast_forward`, `required_linear_history`,
`pull_request` (required approving reviews 0, thread resolution required, squash merges) and
`required_status_checks` requiring `CI` from integration 15368 with `strict_required_status_checks_policy`
true, and an empty bypass-actor list. The registry, the rendered workflows and the rulesets agree: the
required context `CI` is produced by the single generated job on every repository. Direct pushes to `main`
are refused by the `pull_request` rule with an empty bypass list; the merge history consists of squash
merges of reviewed PRs. This was read, not tested by pushing.

Proposed changes (text only; an agent session does not apply ruleset changes):

- **Make the conformance job a required check?** Not yet. It runs against the other repositories'
  `main`, not against the PR under review, so it cannot gate a PR on its own content; it stays a
  scheduled, report-only job whose failure is a finding for the coordinator. If the owner wants a
  blocking signal, the honest option is a required `CI` step in infra that validates the registry
  (`python governance/conformance/registry.py`) — a generator profile change for infra.
- **Stack check names.** The original specification asked for per-stack contexts. With one generated
  job per repository the standardised context is `CI` everywhere; splitting into `build`/`test`/`lint`
  jobs would add contexts to require but also three checkouts per run. No change proposed now; if a
  profile later renders more than one job, add each job name to the registry and to the ruleset.
- **Rulesets keep requiring `CI` from integration 15368 only**; the report fails if a context appears that
  no workflow produces, which protects against a stale required context after a rename.

## Preserved generated-setup request: the initial scheduled workflow

This is the original request from the harness PR, retained as historical scope. The infra-only
workflow was subsequently accepted in [#58](https://github.com/PenniLogic/infra/pull/58) at `e96eb757`.
Its anonymous/Python-only preference and refusal-table numbers below describe that earlier
request, not the current runtime expansion. The successor request and remaining proof are below.

`.github/workflows/conformance.yml` cannot be added by this PR. Every workflow file is validated by the
generated `scripts/check_repository.py`, which runs first in CI, and its rules refuse the file regardless of
content (verified with the template's `validate_workflow` on 2026-09-30, after PR F
[#54](https://github.com/PenniLogic/infra/pull/54); rule numbers follow the ordered table in
`governance/README.md`):

| Candidate | Refusing rule |
| --- | --- |
| any third workflow file, whatever its job id | 26 `workflow file outside the generated pair ci.yml and copilot-setup-steps.yml` |
| `on.schedule` | 18 `unreviewed workflow trigger` |
| `actions/upload-artifact@<sha>` | 8 `action must be immutable and one of the generated GitHub-owned actions` (and 9, the generated-pin rule, once listed) |
| `env: GH_TOKEN: ${{ github.token }}` | 5 `unreviewed workflow expression; public jobs must not receive secrets` (rule 6 behind it) |

The checker is not weakened here and no generated file is hand-edited. The request to the generator
owner (a successor of PR F, [#54](https://github.com/PenniLogic/infra/pull/54)) is:

1. **A third generated workflow for the infra profile only**, `.github/workflows/conformance.yml`, rendered
   by `generate.py` in JSON syntax exactly as below (action SHAs are the generator's `actions` table; the
   upload-artifact SHA is `v7.0.1`, resolved read-only on 2026-09-30, to be reviewed before adoption):

   ```json
   {
     "name": "Conformance",
     "on": {
       "workflow_dispatch": {},
       "schedule": [{"cron": "17 5 * * 1"}]
     },
     "permissions": {"contents": "read"},
     "concurrency": {"group": "${{ github.workflow }}", "cancel-in-progress": true},
     "jobs": {
       "conformance": {
         "name": "Conformance",
         "runs-on": "ubuntu-24.04",
         "timeout-minutes": 60,
         "steps": [
           {"name": "Checkout", "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "with": {"persist-credentials": false, "fetch-depth": 0}},
           {"name": "Python", "uses": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "with": {"python-version": "3.14"}},
           {"name": "Run conformance",
            "run": "mkdir -p conformance-report\npython governance/conformance/run.py --scratch \"$RUNNER_TEMP/conformance-scratch\" --output conformance-report --github-client anonymous --exercise python || touch conformance-report/FAILED"},
           {"name": "Upload report", "uses": "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "with": {"name": "conformance-report", "path": "conformance-report"}},
           {"name": "Fail on findings", "run": "test ! -f conformance-report/FAILED"}
         ]
       }
     }
   }
   ```

   The report is uploaded before the job fails, without an `if: always()` condition (rule 7 refuses `if`),
   by recording the failure in a file and failing in the last step. `fetch-depth: 0` is needed so the
   registry's `workflow_ref` commits can be rendered from history.
2. **Rule 26**: accept `conformance.yml` for the infra profile with a job set of exactly `{"conformance"}`
   named `Conformance` and an event set of exactly `workflow_dispatch` + `schedule` (a name-scoped
   per-file job and trigger set, like the `ci.yml` / `copilot-setup-steps.yml` rules PR F introduced), so
   no consumer surface changes; a third file stays refused everywhere else.
3. **Rule 18**: accept `schedule` only in `conformance.yml`, as a list of `{"cron": "<string>"}` mappings;
   `push`/`pull_request` stay refused there so the job never runs on PR content it did not review.
4. **Rules 8/9/10**: add `actions/upload-artifact` with inputs `name` and `path` to `WORKFLOW_ACTIONS`, and its
   reviewed commit to the `actions` pins of `repository-profiles.json`, from which `generate.py` renders
   `WORKFLOW_ACTION_PINS` into every consumer's checker; `test_workflow_shape.py` derives the allowlists
   from the rendered profiles, so the template and the generator change land in the same PR.
   `contents: read` suffices; upload-artifact uses the runtime artifact token, not the repository token.
5. **No token channel** (preferred): the job reads with the anonymous client and public clones. Consequence:
   60 requests per hour per runner address, of which the job uses 45; a manual dispatch within an hour of
   the scheduled run from the same address may fail closed. If a token ever becomes unavoidable, it would
   need a reviewed exception to rules 5 and 6 for exactly `GH_TOKEN: ${{ github.token }}` on the run
   step; this document does not request it.
6. **Phase 2 (separate request, after the workflow exists)**: exercise the TypeScript and pytest fixtures
   on the runner as well, with `actions/setup-node` (needs an `.nvmrc` with `24.14.0` in infra, a profile
   `node` field) and the ai-service `uv` install line, then `--exercise python,node,uv`. Until then the
   scheduled job proves refusal for the workflow, python and documentation fixtures, and the TypeScript
   and pytest refusals rest on the local live run recorded in the PR plus the consumers' own `main` runs.

Rollout: report-only (this PR provides the job, the registry and the local evidence; the workflow lands
through the generator). Making it blocking is an owner decision recorded above. Rollback: remove the
generated workflow from the infra profile and regenerate; the registry and the job code are inert
without it.

## Bounded runtime expansion after accepted PR 58

The hosted quota failure makes dependable authenticated read-only metadata necessary. The canonical
generator now emits one intentional exception: only the infra profile's exact
`.github/workflows/conformance.yml`, sole `conformance` job and unique plain `Run conformance` step
may receive `env` exactly `{"GH_TOKEN": "${{ github.token }}"}`. The expression is not added to
the global allowlist. Keys and every other string still pass the expression and secret tripwires;
whole/computed/bracket contexts, renamed/duplicate/action harnesses, other token variables, extra
environments, consumer CI/setup workflows and reusable/default-input action channels remain refused.
The source-bound ordered refusal table and generated artifact-count/shape assertions are updated
with it (`governance/README.md`, 33 rules, 22 infra files versus 20 per consumer).

Before the guarded harness step, Conformance sets up Node `24.14.0` from infra's new canonical
profile pin and generated `.nvmrc`, using the existing setup-node SHA, and installs uv `0.11.33`
using the existing ai-service hash-required, binary-only, no-dependency install line. Its arguments
are `--github-client gh --exercise python,node,uv`: web/admin Vitest and ai-service locked pytest
failing/removed-suite fixtures run, not `not_exercised`. JDK/Android fixtures and consumer profiles
are unchanged. The other sixteen native consumer CI/setup workflow bytes and all eight consumer
profiles are preserved. Infra CI/setup also provisions these runtimes for the real governance
fixtures, as the native failure and repair below require. Infra's primary registry language remains
Python; its native `CI` workflow source reference binds the preceding source commit.

The protected-default-main guard, weekly schedule, input-free dispatch, concurrency, standard
runner, 60-minute job bound, ten-minute reporting budget, sentinel-before-failure upload, three-day
retention and missing-file error remain. Report schema `/1` and all eight consumer registry references
are unchanged; only infra's native workflow source binding changes with its runtime provisioning.
No ruleset, entitlement, purchase, deployment, reviewer mechanism or required Conformance context
is added. No unreviewed workflow is activated or manually dispatched by this unit.

Named regressions were RED against unchanged accepted source `e96eb757`: the intended token
leaf was refused, missing/static harness env was unbound, historical/support git inherited
selectors, a synthetic unshaped token survived publication, and all six Node/uv refusals were
`not_exercised`. The new runtime tests cover those boundaries, actual consumer/child environment
scrubbing and fail-closed credential scanning. Real minimal fake web/admin/AI consumers run their
unchanged `npm ci`/`npm test` and `uv sync --locked`/`uv run --locked pytest` commands against actual
Vitest/pytest, with passing baselines, executed failures and removed-suite refusals. Dependencies
stay in temporary fixture trees; missing toolchains now fail before setup, not skip as proof.
This proves mechanics only, not nine current-main rows or hosted job-token read permissions.

Separate non-author Core, QA, Security, Privacy and Reliability review is required for this
intentional credential-channel change before merge. Actual hosted verification is allowed only
after the reviewed merge. If cross-repository job-token reads fail, preserve the failure and
request a reviewed decision; do not add personal credentials, permissions or silent fallback.
Rollback is a reviewed revert/regeneration to accepted `e96eb757` (remove the new generated
`.nvmrc` explicitly), restoring the anonymous/Python-only workflow and its known quota limit.
The original failure artifact remains evidence either way.

### Native PR CI failure and required runtime repair

The local results on unaccepted `c9fceee` were not native acceptance.
[PR CI run 36795639431](https://github.com/PenniLogic/infra/actions/runs/36795639431)
([job 110158325561](https://github.com/PenniLogic/infra/actions/runs/36795639431/job/110158325561))
failed `RealNodeFixtureTests.setUpClass` at `npm install --package-lock-only --ignore-scripts
--no-audit --no-fund`, with `Cannot read properties of null (reading 'edgesOut')`. It reported
227 tests, one error and 13 skips; uv had not been provisioned. Its immutable image
`ubuntu24/20260927.320` documents default Node `22.23.3`/npm `10.9.9`, while that native infra
workflow had deliberately remained Python-only.

A Linux reproduction downloaded checksum-verified Node distributions, recorded actual
`node --version`/`npm --version`, and ran the same minimal Vitest `5.0.2` manifest and preparation
command. `22.23.3`/`10.9.9` reproduced the exact `edgesOut` error with no lock file; its debug
stack is npm Arborist's `loadPeerSet`. `24.14.0`/`11.9.0` completed the same command with a lock
file. No retry, cache deletion, `--legacy-peer-deps`, altered fixture dependency or successful
fallback was used. The original native log, declared image metadata and reproduction stderr/debug
logs are preserved as evidence rather than calling the failure transient.

The precise canonical fix provisions the existing pinned Node action and hash-verified uv
installer in infra's native CI/setup before checks, reusing the same source as Conformance.
This changes only those two infra workflow bytes; no consumer profile or workflow changes.
Missing Node/npm/uv in the real suite is an explicit setup error before scratch or commands;
real executions print their actual Node/npm/Vitest and uv/pytest versions. The existing native
`CI` name, triggers, permissions, action pins, runner and ten-minute bound are preserved.
A source commit followed by a registry-only commit binds infra's entry to a full source SHA
that actually renders the changed workflow. The eight other entries stay unchanged.
Fresh native CI on the final bound head is required; old local success or a skipped uv suite
cannot replace it. Conformance dispatch remains prohibited until separately accepted integration.

Pinned Linux validation also exposed why the real fixture assertion must inspect the full probe
output used by the harness's matcher, not the intentionally truncated 400-character report tail:
Vitest's colored summary can push the actual failing-test marker outside that tail. The fixtures
were already `proved` from the real exit/text match; the corrected tests retain and assert that
executed output directly, without changing report truncation or refusal semantics. The missing-token
unit test independently supplies the synthetic installed-gh seam so it tests missing authentication,
not availability of a CLI it never executes.

### Redaction before the first capture tail

The c9 implementation applied exact-token redaction in `run.redacting_runner()` after
`defects.subprocess_runner()` had already kept only 3000 characters. Synthetic 3001-character
normal and timeout output on Windows/POSIX showed a credential suffix surviving when the first
cut destroyed the full-value/shape prefix. Plain padding initially kept the fragment outside
the later 400-character tail, but further credential/path-padding compression pulled it into the
actual JSON sink while the scanner reported zero survivors. This demonstrates a publication
sanitizer defect with synthetic fragments, not real-token, upload or consumer-environment exposure.
Original coordinator evidence and new RED output are retained; no exploit-severity judgment is
claimed by the author.

Capture now applies the shared exact-value, credential-shape and known-path redactor before
every initial normal/timeout slice, including the Windows unsafe-result branch.
`run.redacting_runner()` supplies its exact report scope to capture; direct probes use the same
redactor with their own scope. The first retained result still has at most 3000 characters,
report probes at most 400, and the report schema/shape is unchanged. No new full-output store,
weaker final privacy scan, altered Windows lifetime/ownership rules, sandbox or confidentiality
boundary is claimed. Synthetic cut-boundary tests cover real normal/timeout subprocesses on
each native platform and preserve the unsafe Windows flag. End-to-end `run.main` tests exercise
the real report redaction, self-scan and JSON/Markdown writing with opaque/shaped tokens,
credential/path compression and unsplit controls.

## Remaining for infra#24

- Reviewed integration and actual hosted verification of the authenticated Python/Node/uv runtime:
  the nine real consumer-main rows and job-token metadata permissions are not proved by local tests.
- Ruleset wiring decisions and any change to the `Protect main` rulesets (owner; proposals above).
- Kotlin evidence on the runner: `java` and `android` are never exercised by the Python/Node/uv scheduled
  job; the api `kotlin-test-failing` fixture has been proved only in local runs, and the android
  self-test remains consumer evidence. A JDK/Android SDK setup in the conformance workflow is a later
  generator request with a real cost in runner minutes.
- The opt-out-with-recorded-expiry mechanism of the original rollout note: not implemented; if the owner
  wants it, the natural place is an optional `opt_out_until` (ISO date) field per registry entry that the
  job honours only while the date is in the future and reports as a warning.
- A general Markdown link checker for docs (docs decision; `check_docs.py` covers the ADR graph only).
- Per-profile budgets or failing the heavy profiles on the ten-minute budget (infra#22 decision).

## Limitations recorded honestly

- A test body that is trivially passing but keeps the count above zero is not detectable by this job:
  the runner reports success. The job proves that removed tests (`NO TESTS RAN` / `no tests ran` /
  `No test files found`), a removed or stubbed test step (drift) and an executed failing test are all
  refused. Semantic emptiness is left to review and to the consumers' own coverage/mutation gates
  (admin's 100 % thresholds, the docs test strategy).
- `check_docs.py` detects a broken ADR index link and a dangling `supersedes` reference; it does not check
  arbitrary Markdown links (`documentation-body-link-broken` records `not_detected`). A general link
  checker is a docs decision, not added here (the addendum asked for no second checker).
- A consumer whose checker predates the current template refuses the planted workflow defects with the
  same exit code but may lack a newer rule (before PR E: no rule text and no step-level
  `continue-on-error` refusal). The harness therefore requires only the refusal line from the consumer's
  checker, records `detail_surfaced`, and proves the newest rule by copying the current template over the
  scratch checkout; the drift check catches every planted workflow defect regardless. In the committed
  evidence all nine consumers run the PR E checker (rule text surfaced) and eight still carry the pre-PR F
  `scripts/check_repository.py` — the stale-file warning is that regeneration wave.
- The wall-clock figure is the run's own duration; queue time is excluded. android's last `main` runs took
  9 min 28 s and 9 min 33 s in the two live runs, inside the ten-minute budget but close; its reviewed
  profile timeout is 30 minutes, so an overrun would be a warning, not a failure, until the budget is
  reviewed.
- Kotlin planted defects are not exercised by the Python/Node/uv job (evidence: last `main` runs).
  The old accepted Python-only hosted job did not catch a consumer stubbing `npm test` or pytest.
  The expanded runtime invokes their existing failing/removed-suite fixtures; hosted effectiveness
  still needs actual post-merge evidence, not a local fake-consumer success.
- The job reads consumers' `main`, never the pull request under review, so it cannot gate a consumer PR;
  it reports the state of what was merged.
- The registry `workflow_ref` verification needs the commit in local history; a shallow infra checkout
  records `unverifiable` and the row carries a warning instead of failing.
- Redaction covers the scratch, infra, temp and home paths in every spelling the code knows (native,
  POSIX, resolved, Windows 8.3 short form, repr/JSON-escaped doubled backslashes; matched
  case-insensitively) plus the account name as a path component and token/private-key shapes. The
  fail-closed self-scan refuses to write a report in which any of those markers or an absolute drive path
  survives — an unknown spelling therefore costs a run, never a leak. A local path that is neither under
  those roots nor spelled with a drive letter (a POSIX path outside home and temp, for example) is not a
  marker the scan knows.
