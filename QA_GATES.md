# QA gates: flake quarantine and retry limit (E25-F01)

Status: **proposed, not yet wired into CI and not yet blocking.** This guide belongs to
[PenniLogic/infra#28](https://github.com/PenniLogic/infra/issues/28) (T-QA-04), first pull request: the vendored flake
policy, the quarantine gate and the retry-limit configuration check. Nothing here claims an acceptance criterion
of that issue as met; the open items are listed under [Still unmet](#still-unmet).

## Entry point and exit codes

All gates run with the standard library of the repository's pinned Python, offline, from the repository root:

```text
python scripts/qa_gates.py policy
python scripts/qa_gates.py retry [--root DIR] [--workflow .github/workflows/NAME.yml ...]
                                 [--runner-config RELATIVE/PATH.json ...] [--manifest PATH]
python scripts/qa_gates.py quarantine --job JOB --run-id RUN --attempt FIRST.xml [--attempt RETRY.xml]
                                      [--ledger PATH] [--manifest PATH] [--base-ledger PATH]
                                      [--fix-only PenniLogic/<repo>#N]
```

`scripts/qa_gates_retry.py` and `scripts/qa_gates_quarantine.py` can also be run directly with the same arguments.
Run them as `python scripts/<name>.py`; isolated mode (`python -I`) leaves `scripts/` off the import path, like the
other flat scripts of this repository.

| Exit | Meaning |
|------|---------|
| 0 | Pass. |
| 1 | Gate failure: at least one finding with effect `fail`. |
| 2 | Refused: usage error, missing or unknown subcommand, missing or unreadable input, input that breaks its format. |

Every run prints exactly one ASCII JSON line on stdout. Reports carry static rule codes, validated input paths,
job keys and grammar-validated test identities only; they never echo messages, captured output, key names, values
or other file content. `--help` prints usage and exits 0.

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
| `quarantine_rate_ceiling_percent` | 2 | maximum share of quarantined tests in a job |

**Re-pin trigger:** re-pin when PenniLogic/docs changes `/flake_policy` or `strategy_version` in
`governance/test-strategy.json` on its main branch: copy the object verbatim, update commit, strategy version and
canonical SHA-256 in the vendored file and the `PIN` constant in the same reviewed change.
**Offline limitation:** infra CI cannot read PenniLogic/docs, so the digest detects only edits to the vendored copy;
it cannot notice that the docs strategy moved on. Only the re-pin trigger finds a newer version.

## Retry-limit configuration check

Docs test-strategy 1.1.1, "Automatic retry limit": a pipeline step configured to retry beyond the limit fails the
pipeline configuration check. `retry` reads JSON-syntax workflow files (every workflow of this repository is JSON
syntax) and JSON runner configurations such as `package.json`, named relative to `--root` (default: the repository
root). It looks only at object keys, `uses` action names and command-line flag or `name=value` tokens of string
values; it never matches substrings of free text.

- Counted constructs: flags `--reruns`, `--retry`, `--retries`, `--max-retries`, `--retry-count`, `--max-attempts`,
  `--max-runs`, `-D...rerunFailingTestsCount=N`; keys with the same names (any case or separator, for example
  `max_attempts`, `retryTimes`, `test.retry`); a retry-shaped action such as `nick-fields/retry` with its
  `max_attempts` input. Attempt counts become re-executions (attempts minus one); `false` counts as 0.
- Several constructs in one job compound: executions multiply, so a retry action with two attempts around
  `pytest --reruns 1` is three re-executions. Workflow-level keys (for example top-level `env`) count for every job.
- Limits: `money_path_retry_limit` (0) for a job that `scripts/qa-gates/protected-tests.json` maps (workflow file
  and job key) to a money-path package, `retry_limit` (1) for every other job. A runner configuration cannot be
  mapped to one job, so it gets the strictest limit of any job in the manifest.
- Fail closed: a retry-shaped key, flag or action whose count cannot be read (a non-number, an expression, a
  retry action without an attempt input, an unknown retry flag) is `RETRY-UNKNOWN`. Gradle's `--rerun-tasks` and
  `--rerun` force a task to run again and are not retries of a failure.
- Reported only: a retry-shaped name inside a dependency map (`dependencies`, `devDependencies`, `overrides`, ...).

| Rule | Effect | Meaning |
|------|--------|---------|
| `RETRY-LIMIT-EXCEEDED` | fail | A job or runner configuration re-executes more than `retry_limit`. |
| `RETRY-MONEY-PATH` | fail | A money-path job (or a runner configuration under the strictest limit) re-executes more than 0. |
| `RETRY-UNKNOWN` | fail | A retry-shaped construct whose count cannot be read. |
| `RETRY-DEPENDENCY` | report | A retry-shaped dependency name; not a configuration, listed for review. |

Refusals (exit 2): `USAGE`, `INPUT-NONE` (no input named), `INPUT-PATHS` (duplicate or more than 64 inputs),
`INPUT-PATH` (absolute, `..` or non-workflow path), `INPUT-UNREADABLE`, `CONFIG-SIZE`, `CONFIG-JSON` (not strict
JSON, duplicate key, NaN), `CONFIG-DEPTH`, `CONFIG-SHAPE` (no `jobs` object), `CONFIG-JOB-KEY`, and the policy and
manifest refusals.

## Quarantine gate

Inputs: one JUnit XML report per attempt (the first run, then at most the allowed re-executions of the cases that
failed), the committed ledger `scripts/qa-gates/quarantine-ledger.json` and the committed protected-tag manifest
`scripts/qa-gates/protected-tests.json`. The date is the real UTC date. A test is identified as
`suite::classname::name`; JUnit input is bounded (size, depth, counts) and refuses DTDs, entities, processing
instructions, duplicate cases and rerun elements.

- **A flake is a failing outcome.** A case that fails and then passes on its one allowed re-execution is a flake
  event, never a clean pass: the run fails with `QG-FLAKE-EVENT` and the report's `ledger_delta` carries the exact
  event. CI cannot write the committed ledger, so the event (and any proposed quarantine) is appended to the ledger
  through a reviewed pull request; muting a flake silently is not possible. A case that still fails is
  `QG-REAL-FAILURE`. A re-execution beyond the policy (or any on a money-path job) is `QG-RETRY-LIMIT`.
- When the recorded events of a test inside the 14-day window plus this one reach 2, the report proposes a
  quarantine (`QG-QUARANTINE-PROPOSED`) with the package owner from the manifest, a ticket requested through the
  `TicketPort` and an expiry at 14 days. Real ticket creation is held: the default port creates nothing and the
  report says `ticket_creation: held`, so a proposal without a ticket fails with `QG-QUARANTINE-TICKET-MISSING`.
- Security, privacy and money tests are never quarantined (`QG-QUARANTINE-REFUSED-PROTECTED`,
  `QG-QUARANTINE-PROTECTED`); a test the manifest cannot classify, or classifies into two packages, fails closed
  (`QG-CLASSIFICATION-UNKNOWN`, `QG-CLASSIFICATION-AMBIGUOUS`), and so does a test whose package the job does not
  list (`QG-JOB-PACKAGE-UNMAPPED`).
- Active quarantines still run and are reported (`QG-QUARANTINED-FAILURE`, `QG-QUARANTINED-FLAKE`, effect
  `report`). The run fails when a quarantine is older than 14 days or past its expiry (`QG-QUARANTINE-AGE`,
  `QG-QUARANTINE-EXPIRED`), when a quarantined test is skipped or not run (`QG-QUARANTINED-NOT-RUN`) or disappears
  without an approved deletion record (`QG-QUARANTINED-TEST-MISSING`), and when more than 2 % of the job's tests are
  quarantined (`QG-QUARANTINE-RATE`), unless `--fix-only` names the ticket of an active quarantine
  (`QG-FIX-ONLY-UNBOUND` otherwise). With `--base-ledger`, a ledger change that is not append-only fails
  (`QG-LEDGER-NOT-APPEND-ONLY`).

**Ledger workflow:** copy `ledger_delta` from the failing run's report into the ledger in a pull request; a
quarantine needs owner, ticket, start and expiry; a release or a deletion closes it, and a deletion needs an
approval comment URL by someone other than the author. Reviewers must check that the run ids in flake events name
real runs: they are reference-shaped only and cannot be verified offline.

**Protected-tag manifest:** status `proposed` (pending separate review; `confirmation_ref` is null). Criterion:
`security` = credential, token or secret protection, untrusted-input refusal or check-bypass prevention;
`privacy` = redaction or privacy inventories; `money` = money-path sources or arithmetic, or any test of a
money-path package. Each committed test module of `scripts/tests` and `governance/tests` has one rule; a new test
module needs a new rule, or its tests fail closed as unclassified.

## Observability

Every report is one JSON line, suitable for publishing as a CI artifact:

- quarantine gate: `counts` (tests, passed, failed, flaky, skipped), `flake_rate` and `quarantine_rate` (exact
  basis points), `quarantined_tests` (the quarantine population with owner, ticket, start and expiry),
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
- The ticket idempotency key includes the run id, so a real `TicketPort` must also deduplicate open tickets per
  job and test; a real port that raises is not caught by the gate (traceback, exit 1: fails closed without a
  refusal report). Decide both at integration.

## Still unmet

Each item below stays open; none is claimed by this change.

- Criteria 3 and 4 (dependency advisory with exceptions; planted secret with rotation ticket): require the
  infra#23 shared secret, dependency and exception mechanism to be integrated and verified.
- Criteria 1 and 6 (planted SAST pattern fails the pull request; no pipeline step retries beyond the policy):
  require CI wiring through the generator owner; the retry check exists but no workflow runs it yet.
- Criterion 5 (quarantine creates a ticket): real ticket creation is held; tests use a fake `TicketPort`.
- Criterion 2 and SAST/DAST ingestion, severity policy and scan-report publication: the second pull request.
- A real authenticated dynamic scan against an ephemeral deployed build: not performed.
- The infra#22 conformance hold is preserved; the warning week, the definition-of-done items and the Core, Security,
  QA and Reliability reviews are outstanding.
