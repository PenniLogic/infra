# QA gates: flake quarantine and retry limit (E25-F01)

Status: **proposed, not yet wired into CI and not yet blocking.** This guide belongs to
[PenniLogic/infra#28](https://github.com/PenniLogic/infra/issues/28) (T-QA-04), first pull request: the vendored flake
policy, the quarantine gate and the retry-limit configuration check. Nothing here claims an acceptance criterion
of that issue as met; the open items are listed under [Still unmet](#still-unmet).

## Entry point and exit codes

All gates run with the standard library of the repository's pinned Python, offline, from the repository root:

```text
python scripts/qa_gates.py policy
python scripts/qa_gates.py retry --root DIR --manifest PATH [--workflow .github/workflows/NAME.yml ...]
                                 [--runner-config RELATIVE/PATH.json ...]
python scripts/qa_gates.py quarantine --job JOB --run-id RUN --attempt FIRST.xml [--attempt RETRY.xml]
                                      --ledger PATH --manifest PATH --base-ledger PATH --base-manifest PATH
python scripts/qa_gates.py rate --attempt JOB=FIRST.xml [--attempt JOB=RETRY.xml ...] --ledger PATH --manifest PATH
                                --base-ledger PATH [--fix-only PenniLogic/<repo>#N]
```

`--ledger`, `--manifest` and `--root` name the candidate (head) inputs and have no default (review round 3,
ADVSEC-R3-03): a default relative to the script would name the base checkout's own files when CI runs the gate
code from a base checkout, and the head ledger, manifest and workflows would never be read. Locally, pass the
committed files (`scripts/qa-gates/quarantine-ledger.json`, `scripts/qa-gates/protected-tests.json`, `--root .`).
A help token is accepted only alone; any other argument starting with `-h` or `--help` in a gate command is
refused (`USAGE`).

In CI the gate code and the vendored policy must also come from the protected base revision (see the wiring
precondition under [Known limits](#known-limits)); otherwise a change can edit the checks it is judged by.

`--base-ledger` and `--base-manifest` name the ledger and manifest of the protected base revision (in CI: the
files from the pull request's base commit; locally: the committed files). Without them the quarantine gate fails
(`QG-LEDGER-BASE-MISSING`, `QG-MANIFEST-BASE-MISSING`), so the append-only and no-relaxation checks are never
silently skipped; the `rate` step likewise fails without `--base-ledger` (`QG-LEDGER-BASE-MISSING`).

`scripts/qa_gates_retry.py`, `scripts/qa_gates_quarantine.py` and `scripts/qa_gates_rate.py` can also be run directly with the same arguments.
Run them as `python scripts/<name>.py`; isolated mode (`python -I`) leaves `scripts/` off the import path, like the
other flat scripts of this repository.

| Exit | Meaning |
|------|---------|
| 0 | Pass. |
| 1 | Gate failure: at least one finding with effect `fail`. |
| 2 | Refused: usage error, missing or unknown subcommand, missing or unreadable input, input that breaks its format. |

Every run prints exactly one ASCII JSON line on stdout. Reports carry static rule codes, validated input paths,
job keys and grammar-validated test identities only; they never echo messages, captured output, key names, values
or other file content. `--help` (or `-h`) alone prints usage and exits 0; combined with any other argument it is
refused as `USAGE` (exit 2), so a stray help token never turns a gate run into a pass.

## Policy pin and re-pin trigger

The numbers come only from `scripts/qa-gates/flake-policy.json`, the `flake_policy` object copied verbatim from
`PenniLogic/docs` `governance/test-strategy.json` at commit `1722fc79ab2abee15d3adc2ed2f3baaad4bd6ed4`
(strategy 1.1.1, JSON pointer `/flake_policy`). The pin records repository, commit, path, JSON pointer, strategy
version, canonicalization (`sorted-keys-compact-ascii-json-sha256`) and the canonical SHA-256
`ed5626f8c95b2c1919c5ebbdd039a966fc7e4494077f2a786fd1ae29ecf6db2c`; the same pin is a constant in
`scripts/qa_gates_policy.py`. A digest mismatch, a pin mismatch, or a missing or extra key refuses every gate
(exit 2). `python scripts/qa_gates.py policy` validates the copy and prints the provenance and numbers:

| Policy field | Value | Used by |
|--------------|-------|---------|
| `retry_limit` | 1 | retry check; quarantine gate (re-executions of a failed case) |
| `money_path_retry_limit` | 0 | jobs the manifest maps to a money-path package |
| `quarantine_after_flakes` | 2 | flake events inside the window that propose a quarantine |
| `flake_window_days` | 14 | window for counting flake events |
| `quarantine_max_age_days` | 14 | maximum quarantine age and proposed expiry |
| `quarantine_rate_ceiling_percent` | 2 | maximum share of a repository's tests that is quarantined (`rate` step) |

**Re-pin trigger:** re-pin when PenniLogic/docs changes `/flake_policy` or `strategy_version` in
`governance/test-strategy.json` on its main branch: copy the object verbatim, update commit, strategy version and
canonical SHA-256 in the vendored file and the `PIN` constant in the same reviewed change, and update every number
this guide restates (the table above and the quarantine-gate section) in that change. The values printed by
`python scripts/qa_gates.py policy` are authoritative; where this guide differs, the guide is stale.
**Offline limitation:** infra CI cannot read PenniLogic/docs, so the digest detects only edits to the vendored copy;
it cannot notice that the docs strategy moved on. Only the re-pin trigger finds a newer version.

## Retry-limit configuration check

Docs test-strategy 1.1.1, "Automatic retry limit": a pipeline step configured to retry beyond the limit fails the
pipeline configuration check. `retry` reads JSON-syntax workflow files (every workflow of this repository is JSON
syntax) and JSON runner configurations such as `package.json`, named relative to `--root` (required; the head checkout). It looks only at object keys, `uses` action names and command-line flag or `name=value` tokens of string
values; it never matches substrings of free text.

- Counted constructs: flags `--reruns`, `--retry`, `--retries`, `--max-retries`, `--retry-count`, `--max-attempts`,
  `--max-runs`, `-D...rerunFailingTestsCount=N`, Gradle `-PmaxRetries=N`; keys with the same names (any case or separator, for example
  `max_attempts`, `retryTimes`, `test.retry`); a retry-shaped action such as `nick-fields/retry` with its
  `max_attempts` input. Attempt counts become re-executions (attempts minus one); `false` counts as 0.
- Constructs compound only where a known wrapper re-runs what it wraps: a retry action multiplies the rest of
  its step, so a retry action with two attempts around `pytest --reruns 1` is three re-executions. Everything else
  is an alternative and the largest applies: independent steps of a job, scripts of a `package.json`, commands of
  one shell string (separated by newlines, `;`, `&&`, `||` or `|`), several retry flags or keys of one command (the
  runner applies one of them, for example surefire and failsafe each re-run their own tests once), and
  workflow-level or job-level keys (for example `env`) against the commands of unwrapped steps. A wrapped command
  inherits the environment, so its wrapper also multiplies workflow `env`, job `env`, the commands of steps of the
  same job that write `$GITHUB_ENV` (wherever they stand in the job) and, when runner configurations are inputs of
  the same check, the largest count among them (the wrapped command may start that runner, for example `npm test`;
  this can over-count a wrapper around an unrelated command, which fails closed). A retry action with two attempts
  around `pytest` under a job `env` of `PYTEST_ADDOPTS: --reruns 1` is three re-executions.
- Flags inside the value of a `NAME=value` token are read (`PYTEST_ADDOPTS=--reruns=5`, `export ...`,
  `echo "PYTEST_ADDOPTS=--reruns 5" >> "$GITHUB_ENV"`, `MAVEN_ARGS=-D...rerunFailingTestsCount=3`,
  `pytest -o addopts=--reruns=5`), and an empty quote pair inside a word (`--re''runs`, `--re$''runs`,
  `--re$""runs`) is joined as the shell does.
- A `${{ ... }}` expression is evaluated by GitHub before the shell runs, so a value is read twice: once with each
  expression as one opaque word (a known flag whose value is an expression fails closed), and once with each
  expression replaced by the text of its string literals (`pytest ${{ runner.os == 'Linux' && '--reruns 3' || '' }}`
  is read as `--reruns 3`; `${{ format('--reruns={0}', 5) }}` fails closed). A construct of either reading applies.
  An unclosed `${{` fails closed.
- **Re-execution model (proposed, pending a QA/Reliability decision).** The quarantine gate can record a flake
  only when the failing first run and the re-execution arrive as separate JUnit reports. A retry inside the test
  runner (`--reruns`, `--retry`, `rerunFailingTestsCount`, ...) or a whole-step retry action re-runs inside one
  reported attempt: the report then shows a clean pass, or a rerun element the gate refuses, and an in-runner
  retry plus a separate re-execution attempt can exceed one re-execution while both gates pass. The proposed model
  is: in-runner and whole-step retries 0, and the one permitted re-execution is a separate CI step that re-runs
  only the failed cases into its own report. The brief keeps "fail above 1", so every counted construct of at
  least one re-execution is reported as `RETRY-ATTEMPT-HIDDEN` (effect `report`) for that decision; making it
  fail is the decision's to take. Until then such a configuration can turn a flake into a clean pass.
- Limits: `money_path_retry_limit` (0) for a job that `scripts/qa-gates/protected-tests.json` maps (workflow file
  and job key) to a money-path package, `retry_limit` (1) for every other mapped job. A job the manifest does not
  map, and a runner configuration (which cannot be mapped to one job), get the strictest limit of any job in the
  manifest; an unmapped job is listed as `RETRY-JOB-UNMAPPED` when that limit is the money-path one, and a
  manifest job missing from a checked workflow file is listed as `RETRY-MANIFEST-JOB-UNCHECKED`.
- Fail closed: a retry-shaped key, flag or action whose count cannot be read (a non-number, an expression, a
  retry action without an attempt input, an unknown retry flag) is `RETRY-UNKNOWN`, and so are a request to re-run
  a workflow run or job (`gh run rerun`, also after gh global flags such as `--repo`; the
  `.../actions/runs/<id>/rerun`, `rerun-failed-jobs` and `.../actions/jobs/<id>/rerun` endpoints, with a literal,
  a shell variable or a `${{ ... }}` expression as the id) and a retry-shaped command word of a command line (a
  workflow `run` or `shell` value, the `command`, `on_retry_command` or `new_command_on_retry` input of a retry
  action, or a `scripts` entry, for example `retry --times 3 -- pytest` or `./retry.sh pytest`). The `gh` word is
  matched with any directory and as `gh.exe`. Gradle's `--rerun-tasks` and `--rerun` force a task to run again and are not retries of a
  failure. Known non-count modifiers of the named mechanisms (`--reruns-delay`, `--only-rerun`, and nick-fields/retry
  `retry_on`, `retry_wait_seconds`, `retry_on_exit_code`, `on_retry_command`, `new_command_on_retry`,
  `warning_on_retry`) are not retry counts; a command they carry is still read.
- Reported only: a retry-shaped name inside a top-level dependency map of a runner configuration
  (`dependencies`, `devDependencies`, `overrides`, ...). In workflows and `env`, such keys are read like any other.
- Script names in a `scripts` map (for example `test:flaky`) are labels: only the commands are read.

| Rule | Effect | Meaning |
|------|--------|---------|
| `RETRY-LIMIT-EXCEEDED` | fail | A job or runner configuration re-executes more than `retry_limit`. |
| `RETRY-MONEY-PATH` | fail | A money-path job (or a runner configuration under the strictest limit) re-executes more than 0. |
| `RETRY-UNKNOWN` | fail | A retry-shaped construct whose count cannot be read. |
| `RETRY-DEPENDENCY` | report | A retry-shaped dependency name; not a configuration, listed for review. |
| `RETRY-ATTEMPT-HIDDEN` | report | An in-runner or whole-step retry the quarantine gate cannot observe (see the re-execution model). |
| `RETRY-JOB-UNMAPPED` | report | A job the manifest does not map, checked under the money-path limit. |
| `RETRY-MANIFEST-JOB-UNCHECKED` | report | A manifest job missing from its checked workflow file. |

Refusals (exit 2): `USAGE`, `INPUT-NONE` (no input named), `INPUT-WORKFLOWS-MISSING` (a workflow file the manifest
maps is not among the `--workflow` inputs: an unchecked workflow is never a passing one), `INPUT-PATHS` (duplicate or
more than 64 inputs),
`INPUT-PATH` (absolute, `..` or non-workflow path), `INPUT-UNREADABLE`, `CONFIG-SIZE`, `CONFIG-JSON` (not strict
JSON, duplicate key, NaN), `CONFIG-DEPTH` (also a `NAME=value` chain nested deeper than 64),
`CONFIG-SHAPE` (no `jobs` object), `CONFIG-JOB-KEY`, and the policy and
manifest refusals.

## Quarantine gate

Inputs: one JUnit XML report per attempt (the first run, then at most the allowed re-executions of the cases that
failed), the committed ledger `scripts/qa-gates/quarantine-ledger.json` and the committed protected-tag manifest
`scripts/qa-gates/protected-tests.json`. The date is the real UTC date. A test is identified as
`suite::classname::name`; JUnit input is bounded (size, depth, counts) and refuses DTDs, entities, processing
instructions, duplicate cases and rerun elements.

- **A flake is a failing outcome (proposed design, pending a QA/Reliability decision).** A case that fails and
  then passes on its one allowed re-execution is a flake event, never a clean pass: the run fails with
  `QG-FLAKE-EVENT` and the report's `ledger_delta` carries the exact event. CI cannot write the committed ledger,
  so events and proposed quarantines persist **only** when someone copies `ledger_delta` into the ledger through a
  reviewed pull request. An uncopied delta is lost, and a job re-run in which the test passes first time passes
  without any record; the 2-in-14-days trigger then never sees that event. Recording events and quarantining are
  therefore not automatic in this change (see [Still unmet](#still-unmet)). The gate only refuses to count a flake
  it can see as a clean pass; it cannot see a retry inside the test runner or a whole-step retry (see the retry
  check's re-execution model). A case that still fails is `QG-REAL-FAILURE`. A re-execution beyond the policy
  (or any on a money-path job) is `QG-RETRY-LIMIT`.
- When the recorded events of a test inside the 14-day window plus this one reach 2, the report proposes a
  quarantine. The gate and the ledger use one trigger definition: after a release or deletion of the test (in any
  job), only events dated strictly after its last closure count, so a proposal copied into the ledger always
  parses. That post-closure exclusion is a **proposed rule beyond `flake_policy`** (pending QA/Reliability): the
  policy itself counts every flake event of the window. The proposal (`QG-QUARANTINE-PROPOSED`) carries the
  package owner from the manifest, a ticket requested through the `TicketPort` and an expiry at 14 days. Real ticket creation is held: the default port creates nothing and the
  report says `ticket_creation: held`, so a proposal without a ticket fails with `QG-QUARANTINE-TICKET-MISSING`.
- Security, privacy and money tests are never quarantined (`QG-QUARANTINE-REFUSED-PROTECTED`,
  `QG-QUARANTINE-PROTECTED`), as classified by the head manifest; a change that removes a tag from a known test,
  relaxes a money-path job, or removes a protecting rule, drops tags from a rule or takes `money_path` from its
  package (rules compared by id, whatever tests ran, so a renamed module whose rule loses its tags is seen) compared
  with `--base-manifest` fails (`QG-MANIFEST-RELAXED`); a new rule without tags is listed for review
  (`QG-MANIFEST-RULE-UNPROTECTED`, effect `report`). This holds only when CI passes the base revision's manifest,
  which is a wiring precondition; a test the manifest cannot classify, or
  classifies into two packages, fails closed
  (`QG-CLASSIFICATION-UNKNOWN`, `QG-CLASSIFICATION-AMBIGUOUS`), and so does a test whose package the job does not
  list (`QG-JOB-PACKAGE-UNMAPPED`).
- Active quarantines still run and are reported (`QG-QUARANTINED-FAILURE`, `QG-QUARANTINED-FLAKE`, effect
  `report`). The run fails when a quarantine is older than 14 days or past its expiry (`QG-QUARANTINE-AGE`,
  `QG-QUARANTINE-EXPIRED`), when a quarantined test is skipped or not run (`QG-QUARANTINED-NOT-RUN`) or disappears
  without an approved deletion record (`QG-QUARANTINED-TEST-MISSING`); only an approved deletion lets a
  quarantined test go. A release closes a quarantine without reviewer approval, so the change that appends a
  release must still run the released test (`QG-RELEASED-TEST-MISSING` when it is missing or skipped); a later
  change may rename or remove it like any other test. A release or deletion appended in the change (compared with
  `--base-ledger`) may not be dated before the latest fact the base ledger records for its test (a flake event,
  quarantine start or closure; `QG-CLOSURE-BACKDATED`), so a backdated closure cannot move the post-closure
  trigger back over recorded evidence. The release or approval date is not bounded against the run date: a truthful
  approval does not expire when CI re-runs later (review round 3, PS-4; this replaces the earlier 3-day
  tolerance). A quarantine appended in the change must start strictly after every closure of its test in the head
  ledger (any job) other than its own (`QG-QUARANTINE-BACKDATED`), so it cannot reuse a closed quarantine's events.
  These rules are **proposed controls beyond `flake_policy`** (pending QA/Reliability).
  A first attempt in which no case outside the active quarantines ran (every other case skipped) fails
  (`QG-NOTHING-RAN`). A ledger change that is not append-only
  against `--base-ledger` fails (`QG-LEDGER-NOT-APPEND-ONLY`).
- **Quarantine rate ceiling (repository level).** The policy's ceiling is 2 % of a repository's tests, so it is
  judged once per pipeline by `qa_gates.py rate`, not per job: the denominator is the distinct test identities
  reported by every job of the manifest (plus quarantined tests no job reported), the numerator the distinct
  actively quarantined tests of the whole ledger. A share above the ceiling fails (`QG-QUARANTINE-RATE`) unless
  `--fix-only` names the ticket of a quarantine active in the **base** revision's ledger (effect `report`;
  `QG-FIX-ONLY-UNBOUND` otherwise). Binding to the base keeps a change that fixes a quarantined test and appends
  its release (or approved deletion) in the same change exempt, also when that quarantine is past its maximum age.
  A ledger-only change that releases a fixed test counts as a fix of that test. A change that adds an active
  quarantine (a job and test active in the head ledger but not in the base ledger) is not a fix of a quarantined
  test: the exemption is withheld (`QG-QUARANTINE-RATE` and `QG-FIX-ONLY-ADDS-QUARANTINE`, both `fail`), and the
  report publishes `added_quarantines`. `--fix-only` is a declaration:
  the gate checks only that its ticket owns a base quarantine, so reviewers must check that the change really
  fixes that test (an unrelated change citing an active ticket is not detected). A
  manifest job without a report refuses the step (`INPUT-JOBS-MISSING`, exit 2). The per-job report publishes the
  job's own rates with `scope: job` for information only.

**Ledger workflow:** copy `ledger_delta` from the failing run's report into the ledger in a pull request; a
quarantine needs owner, ticket, start and expiry, and two flake events dated after the last closure of the same
test in any job (the proposed post-closure rule above), the last of which counts closures dated on the quarantine's
first day too; a release or a deletion closes it, and a deletion needs an approval comment URL on the owning
ticket. **Approver distinctness is a proposed control beyond `flake_policy`** (pending QA/Reliability): the policy
asks only for "recorded reviewer approval on its owning ticket", while the ledger refuses an `approved_by` equal to
the quarantine owner or to the head manifest's package owner of the test (`LEDGER-SELF-APPROVAL`), and the gate
also fails one equal to the base manifest's package owner (`QG-SELF-APPROVAL`) and lists a package owner change
(`QG-MANIFEST-OWNER-CHANGED`, effect `report`). The ledger records no author, so the gate cannot compare with the
author of the change. **Consequence in infra today:** every package of the committed manifest is owned by
`@basiltt`, the organization's only GitHub user (reviewer sessions also post as `basiltt`), so no deletion record
can be accepted and the policy's "deleted with recorded reviewer approval" exit is unavailable; an expired
quarantine can only be fixed and released (and the test removed in a later change). This is listed under
[Still unmet](#still-unmet). Reviewers must check every reference-shaped value by hand: run ids in flake
events, `fix_ref`, `approval_ref` URLs and `approved_by` handles are grammar-checked only and cannot be verified
offline.

**Protected-tag manifest:** status `proposed` (pending separate review; `confirmation_ref` is null). Criterion:
`security` = credential, token or secret protection, untrusted-input refusal or check-bypass prevention;
`privacy` = redaction or privacy inventories; `money` = money-path sources or arithmetic, or any test of a
money-path package. Each committed test module of `scripts/tests` and `governance/tests` has one rule; a new test
module needs a new rule, or its tests fail closed as unclassified. Rules are per module, so a module takes the
union of its tests' tags. Every rule's `reason` records the basis of its tags; after review round 3 (ADVSEC-R3-02)
only `test_capability_paragraph` and `test_rule_table` stay untagged (text rendering and documentation order).

## Observability

Every report is one JSON line, suitable for publishing as a CI artifact:

- rate step: the per-repository `flake_rate` and `quarantine_rate` (`count`, `tests`, and `basis_points` rounded
  down; the exact share is `count`/`tests`, and `exceeded` is decided on the exact fraction). A flake is counted
  with each job's re-execution allowance, as the per-job gate does: a pass on a re-execution the policy does not
  permit (any re-execution on a money-path job) is a real failure there and no flake here;
- quarantine gate: `counts` (tests, passed, failed, flaky, skipped), job-scope `flake_rate` and `quarantine_rate`
  (basis points rounded down), `quarantined_tests` (the quarantine population with owner, ticket, start and expiry),
  `retry` (allowed and observed re-executions), `ledger_delta`, and input digests;
- retry check: `counts` (inputs, jobs, failing, reported) and per job or configuration `checked` (limit,
  compounded re-executions, counted and unknown constructs);
- both: the policy provenance (`policy`) and manifest status and digest.

Severity counts and exception counts with expiry dates (also listed under Observability in infra#28) belong to the
SAST/DAST and infra#23 parts and are not produced here.

## Rollout and rollback

As infra#28 describes: the gates are introduced **warning-only for one week** to measure noise, then made blocking.
Rollback returns one specific rule (one rule code above) to warning with a recorded expiry; it is never a blanket
disable. Neither step has happened: CI wiring belongs to the generator owner (the standard workflows are generated
and hash-pinned), so the warning week, its noise measurement and the switch to blocking are still to come. The
per-rule warning switch with expiry is to be implemented with that wiring; it does not exist in this change.

## Known limits

- The retry check reads JSON only. Retries configured in YAML-syntax files, in `vitest.config.*`, `build.gradle*`,
  `gradle.properties`, `pyproject.toml` or implemented inside scripts (for example `npm test` or
  `python scripts/quality.py`) are not seen; such files must be added as JSON inputs or checked by their owners.
- A reusable workflow called by a job (`jobs.<id>.uses`) is not followed; pass the called workflow as its own input.
- Token matching cannot tell a test retry from a network retry: `curl --retry 3` fails as a retry above the limit.
- Only `-flag`, `--flag` and `name=value` tokens are read: Windows-style `/retry:3` switches, composite actions
  (`action.yml`) and expressions that compute a count at run time are not evaluated (an expression as the value of
  a known flag fails closed; string literals inside an expression are read, other computed text is not).
  Compounded re-executions are reported up to a cap of 1000000.
- Retry mechanisms the token check does not see (criterion 6 depends on them being reviewed by hand): flag names
  spliced from shell variables (`R=runs; pytest --re$R 5`) or from non-empty quoted fragments; shell-level
  repetition (`pytest || pytest`, a `for` loop around a test command); a `continue-on-error` test step followed by
  a conditional re-run step; a `workflow_run` workflow that re-runs failed runs through an action or script other
  than `gh run rerun` and the rerun endpoints; `npm run` scripts that call each other (each script is read on its
  own); a retry inside the reusable workflows, composite actions and non-JSON files listed above; a retry wrapper
  started through a launcher (`npx retry-cli ...`, `uvx ...`, `python -m ...`: only the command word is read);
  runner options read from a file (pytest `@args.txt` arguments, `pytest.ini`, `setup.cfg`) or injected from a
  repository or organization variable (`PYTEST_ADDOPTS: ${{ vars.X }}`), whose value is not in the repository;
  a `$GITHUB_ENV` write made by an action (not a command line) of an earlier step.
- Renaming or moving a protected test into a module that an existing untagged rule covers (for example a class
  moved into an untagged test module) changes no rule, so the gate cannot see it; only review of the test diff
  can. New untagged rules are reported (`QG-MANIFEST-RULE-UNPROTECTED`) for that review.
- **Wiring precondition: run the gates from the protected base.** The append-only check, `QG-MANIFEST-RELAXED`,
  `QG-CLOSURE-BACKDATED`, the policy pin and every other same-change protection hold only if the code and data
  that enforce them are not the candidate's: CI must run `scripts/qa_gates*.py`, `scripts/qa-gates/flake-policy.json`
  and the base ledger and manifest from the pull request's base revision (for example a separate base checkout), or
  bind those files to the base the way the `pr-workflow-integrity` workflow binds `scripts/check_repository.py`.
  With a base checkout, the head checkout's ledger, manifest and root must be passed explicitly (`--ledger`,
  `--manifest`, `--root`; required arguments since review round 3).
  A step that runs the checked-out head code can re-pin the policy (for example `retry_limit` 5 with a recomputed
  digest and `PIN`) or drop a check in the same change, and then none of these protections hold.
- The quarantine gate relies on CI passing the base revision's ledger and manifest (`--base-ledger`,
  `--base-manifest`; `--base-ledger` also for `rate`) and running the `rate` step after every manifest job; both
  are wiring preconditions.
- The ticket idempotency key includes the run id, so a real `TicketPort` must also deduplicate open tickets per
  job and test; a real port that raises is not caught by the gate (traceback, exit 1: fails closed without a
  refusal report). Decide both at integration.

## Still unmet

Each item below stays open; none is claimed by this change.

- Criteria 3 and 4 (dependency advisory with exceptions; planted secret with rotation ticket): require the
  infra#23 shared secret, dependency and exception mechanism to be integrated and verified.
- Criteria 1 and 6 (planted SAST pattern fails the pull request; no pipeline step retries beyond the policy):
  require CI wiring through the generator owner; the retry check exists but no workflow runs it yet. Criterion 6
  also depends on the re-execution model decision (`RETRY-ATTEMPT-HIDDEN` is report-only) and on the mechanisms
  listed under Known limits.
- Criterion 5 (quarantine creates a ticket): real ticket creation is held; tests use a fake `TicketPort`.
- Quarantined-test deletion: the approver-distinctness rule (proposed, above) makes the policy's approved-deletion
  exit unavailable while every manifest package owner is `@basiltt`. Owner of the decision: QA/Reliability with the
  coordinator (keep the rule, or record distinctness on a basis this organization can record truthfully, for
  example the reviewer session named in the approval comment). Not decided here.
- Criterion 5 and the Scope item "automatic quarantine after a defined number of flakes": flake events are not
  recorded automatically and quarantines are not applied automatically. Events persist only through a manual
  ledger pull request that copies `ledger_delta`; they are lost on a job re-run or when the delta is not copied.
  Persisting them needs CI wiring (generator owner) or an event store, owner to be decided with QA/Reliability.
  The blocking-flake and manual-ledger design is a proposal pending that decision.
- Criterion 2 and SAST/DAST ingestion, severity policy and scan-report publication: the second pull request.
- A real authenticated dynamic scan against an ephemeral deployed build: not performed.
- The infra#22 conformance hold is preserved; the warning week, the definition-of-done items and the Core, Security,
  QA and Reliability reviews are outstanding.
