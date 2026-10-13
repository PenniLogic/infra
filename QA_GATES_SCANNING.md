# QA gates: SAST and DAST report ingestion (PenniLogic/infra#28, slice 2)

This guide covers the scan-report gates of [infra#28](https://github.com/PenniLogic/infra/issues/28) (T-QA-04).
The flake, quarantine and retry gates of the same ticket are a separate change with their own guide.
Nothing here is wired into CI yet, and no acceptance criterion of infra#28 is met by this source alone
(see [Held and not claimed](#held-and-not-claimed)).

## SAST: Semgrep report gate

```text
python scripts/qa_gates_sast.py --report SEMGREP.json --root SOURCE_ROOT [--policy POLICY.json]
```

`--report` is one Semgrep JSON report. `--root` is the checkout the report was produced from: the gate reads the
matched byte span of every finding from it. `--policy` defaults to `scripts/qa-gates/rules/sast-policy.json`.
Exit 0 means pass, 1 means gate failure (including an incomplete report) and 2 means refused input or usage,
including a missing report. stdout carries one ASCII JSON report (`pennilogic.qa-gates.sast-report/1`).

### Decision order

1. The report must be one strict JSON document (UTF-8, no BOM, no duplicate key) with `version`, `results`,
   `errors`, `paths.scanned` and `skipped_rules`. A malformed report is refused (exit 2).
2. **Incomplete fails.** A non-empty `errors` list (`SAST-INCOMPLETE-ERRORS`), a skipped rule
   (`SAST-INCOMPLETE-SKIPPED-RULES`) or zero scanned paths (`SAST-INCOMPLETE-NO-PATHS`) fails the gate, even when
   no finding is reported.
3. **Everything blocks** (`SAST-BLOCKING-FINDINGS`), as the accepted test strategy states for
   `static_dependency_secret_gates` ("all blocking"). The only relaxation is a per-rule `warn` mode with a
   recorded window (below). A finding from a rule this repository does not define always blocks.

Every finding must name a path listed in `paths.scanned`, a known Semgrep severity and a non-empty byte span inside
the source file; otherwise the report is refused. Static rule codes are the only refusal text: no message,
snippet, metadata or unvalidated value is ever printed.

### Finding record (proposed vocabulary)

| Field | Meaning |
| --- | --- |
| `rule_id` | The rule ID (the Semgrep config-path prefix is removed only for this repository's rule IDs). |
| `scanner_severity` | Semgrep's own level, unmapped. No severity threshold is defined: every level blocks. |
| `path`, `line` | Normalized repository-relative POSIX path (a Windows separator becomes `/`) and start line. |
| `fingerprint` | `sha256:` over the canonical JSON of `[rule_id, path, sha256(matched byte span)]`. |
| `mode` | `block` or `warn`, judged against the evaluation date. |

Semgrep OSS writes `requires login` in place of `extra.fingerprint` and `extra.lines`, so neither is used. The
fingerprint does not depend on the line number: moving unrelated code keeps it stable, editing the matched code
changes it. The report vocabulary is *proposed, pending infra#23 owner alignment*.

### Rule set (proposed, not agreed)

Rules live in `scripts/qa-gates/rules/{python,typescript,kotlin}.yml`, written in JSON syntax (valid YAML) so the
stdlib can verify them. Every rule carries `metadata.status: "proposed, not agreed"`; the gate refuses a rule file
without it.

| Rule ID | Pattern family |
| --- | --- |
| `pennilogic-python-sql-built-string` | f-string, `%`, `.format` or `+` SQL passed to `execute`/`executemany` (CWE-89) |
| `pennilogic-python-shell-command` | `subprocess.*(..., shell=True)`, non-literal `os.system`/`os.popen` (CWE-78) |
| `pennilogic-python-dynamic-eval` | non-literal `eval`/`exec` (CWE-95) |
| `pennilogic-typescript-sql-built-string` | template literal or concatenation passed to `query`/`execute`/`raw` calls (CWE-89) |
| `pennilogic-typescript-shell-command` | non-literal `exec`/`execSync` of `child_process` (CWE-78) |
| `pennilogic-typescript-dynamic-eval` | non-literal `eval`, `new Function` (CWE-95) |
| `pennilogic-kotlin-sql-built-string` | string template or concatenation passed to JDBC/Android SQL calls (CWE-89) |
| `pennilogic-kotlin-runtime-exec` | non-literal `Runtime.getRuntime().exec` (CWE-78) |

The rules are syntactic: SQL text assembled in an earlier statement and passed by variable is not caught. Agreeing
the per-language rule set is an owner decision that is not recorded (`decision_ref` stays `null`).

### Per-rule warn mode, rollout and rollback

`sast-policy.json` names every rule exactly once (a missing or extra rule is refused). The committed policy sets
every rule to `block`. A rule may instead be `{"mode": "warn", "warn_from": "YYYY-MM-DD", "warn_until":
"YYYY-MM-DD"}` with `warn_from` < `warn_until` at most seven days apart: the ticket's one-week warning window, and
its rollback ("return a specific rule to warning with a recorded expiry"). The rule warns only on dates inside the
window; before it and after it the rule blocks, and an ended window is listed under `expired_warnings`. Changing a
mode is a reviewed edit of this file; the one-week warning-only rollout itself has not happened.

### Exceptions

None. The exception mechanism belongs to infra#23 (draft infra PR #88), which is not integrated, so every report
says `exceptions: {"status": "unavailable: infra#23 not integrated", "count": 0}`. The planned binding is
`security_exceptions.Exceptions.suppression`; it is named only, never copied or re-implemented.

### Observability fields

`counts.blocking`, `counts.warning`, `counts.by_scanner_severity`, `expired_warnings`, `exceptions.count`,
`scanned_path_count`, `error_count`, `skipped_rule_count`, `complete` and `evaluated_on`.
Publishing them from CI is held with the CI wiring.

### Planted sources and the canned report

Planted positives and clean controls are in `scripts/qa-gates/fixtures/planted/{python,typescript,kotlin}/`. They
are never imported, compiled or run, and they sit outside every `tests/` path because Semgrep ignores test paths by
default. The tests use `scripts/tests/fixtures/qa_gates_sast/semgrep-planted.json`, a report from a **local**
Semgrep 1.178.0 run (user-local install, not pinned by infra), with
`semgrep-planted.provenance.json`. The provenance records the command (`--metrics=off --disable-version-check`,
local rules only, never a registry config), the Semgrep version, the SHA-256 of the rule files, of the planted
tree and of the committed report, and the scanned path list. A unit test recomputes the bindings: editing a rule
file or a planted source without regenerating the report fails it. The canned report is a `local-fixture` input
and **never acceptance evidence** (`acceptance_evidence: false`).

To regenerate after a rule or planted-source change, run from the repository root, then re-serialize the output with
`json.dumps(indent=2, ensure_ascii=True)` plus a final LF and update every digest in the provenance file:

```text
semgrep scan --metrics=off --disable-version-check --json --output <tmp>/semgrep-planted.raw.json \
    --config scripts/qa-gates/rules scripts/qa-gates/fixtures/planted
```

## Held and not claimed

- Criterion 1 ("fails the pull request") needs a Semgrep CI step with a pinned, trusted Semgrep binary, wired
  through the generator owner. Scanner execution, timeouts and process cleanup wait for infra#23's process
  controls.
- The rule set and the report vocabulary are proposals; no owner decision is recorded.
- The one-week warning window has not run.
- infra#23 (exceptions) and the infra#22 conformance hold are unresolved.
- The Windows test leg was not run locally; the tests are written to pass on Linux and Windows without skips.
- Independent Core, Security, QA, Privacy and Reliability reviews are required and not done.
