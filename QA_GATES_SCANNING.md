# QA gates: SAST and DAST report ingestion (PenniLogic/infra#28, slice 2)

This guide covers the scan-report gates of [infra#28](https://github.com/PenniLogic/infra/issues/28) (T-QA-04).
The flake, quarantine and retry gates of the same ticket are a separate change with their own guide.
Nothing here is wired into CI yet, and no acceptance criterion of infra#28 is met by this source alone
(see [Held and not claimed](#held-and-not-claimed)).

Entry points (stdlib Python, no network, run from the repository root; `--help` prints the usage):

- `python scripts/qa_gates_sast.py` gates one Semgrep JSON report ([SAST](#sast-semgrep-report-gate)).
- `python scripts/qa_gates_dast.py` gates one ZAP alerts report bound to its scan manifest
  ([DAST](#dast-zap-alerts-and-scan-manifest-gate)).

Both print one ASCII JSON report on stdout and exit 0 (pass), 1 (gate failure, including incomplete input) or 2
(refused input or usage, including a missing file). Refusals print a static rule code only.

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
   (`SAST-INCOMPLETE-SKIPPED-RULES`), a rule file's ID missing from a non-empty `time.rules` (`--time` lists every
   rule Semgrep ran, so a rule dropped by `--exclude-rule` shows there; `SAST-INCOMPLETE-RULES`, listed under
   `rule_binding.missing_rules`) or zero scanned paths (`SAST-INCOMPLETE-NO-PATHS`) fails the gate, even when no
   finding is reported. Without `--time` Semgrep 1.178.0 writes an empty `time.rules`; the report then says
   `rule_binding.status: "unbound: time.rules empty or absent"` (see Held).
3. **Semgrep's own suppression is an incomplete scan.** Semgrep drops a match on a line carrying its inline
   suppression comment and skips files named in a `.semgrepignore`, without any error entry, unless it runs with
   `--disable-nosem` and `--x-ignore-semgrepignore-files`. Semgrep 1.178.0 recognizes the comment (`nosem`,
   optionally followed by `grep`) inline after a space, or on the line above after only non-alphanumeric characters
   and spaces (so `#nosemgrep` and a tab before it count), case-insensitively with Unicode case folding (U+017F
   long s counts as `s`). Either channel would be an unrecorded exception without expiry, so the gate decodes every
   scanned source as UTF-8 (invalid bytes replaced), mirrors both patterns anywhere in it, comment or not, and fails
   when one matches (`SAST-INCOMPLETE-INLINE-SUPPRESSION`, listing the paths) or when the checkout holds any `.semgrepignore`
   outside `.git` (`SAST-INCOMPLETE-IGNORE-FILE`). It does this whatever flags the run used, because a report does
   not record them. A scanned path missing from `--root` is refused (`SAST-SOURCE-UNREADABLE`).
4. **Everything blocks** (`SAST-BLOCKING-FINDINGS`), as the accepted test strategy states for
   `static_dependency_secret_gates` ("all blocking"). The only relaxation is a per-rule `warn` mode with a
   recorded window (below). A finding from a rule this repository does not define always blocks.

Every finding must name a path listed in `paths.scanned`, a known Semgrep severity and a non-empty byte span inside
the source file; otherwise the report is refused. Static rule codes are the only refusal text: no message,
snippet, metadata or unvalidated value is ever printed. A source path whose resolved location leaves the resolved
`--root` (a symbolic link out of the checkout) is refused (`SAST-SOURCE-OUTSIDE-ROOT`), because even a hash of a
short span would reveal bytes of the outside file.

### Finding record (proposed vocabulary)

| Field | Meaning |
| --- | --- |
| `rule_id` | The rule ID (the Semgrep config-path prefix is removed only for this repository's rule IDs). |
| `scanner_severity` | Semgrep's own level, unmapped. No severity threshold is defined: every level blocks. |
| `path`, `line` | Normalized repository-relative POSIX path (a Windows separator becomes `/`; segments of letters, digits and `._@+-()[]`, so Next.js segments such as `(customer)` and `[[...path]]` are accepted; no root, drive, empty, `.` or `..` segment) and start line. |
| `fingerprint` | `sha256:` over the canonical JSON of `[rule_id, path, sha256(matched byte span)]`. |
| `mode` | `block` or `warn`, judged against the evaluation date. |

Semgrep OSS writes `requires login` in place of `extra.fingerprint` and `extra.lines`, so neither is used. The
fingerprint does not depend on the line number: moving unrelated code keeps it stable, editing the matched code
changes it. The report vocabulary is *proposed, pending infra#23 owner alignment*. A rule ID is recognized by
suffix (`<config path>.<rule id>`), so a foreign rule whose ID ends with `.<rule id>` would be treated as that
rule; the held CI step must therefore pass only this repository's rule directory to Semgrep.

### Rule set (proposed, not agreed)

Rules live in `scripts/qa-gates/rules/{python,typescript,kotlin}.yml`, written in JSON syntax (valid YAML) so the
stdlib can verify them. Every rule carries `metadata.status: "proposed, not agreed"`; the gate refuses a rule file
without it. Semgrep loads every `.yml` and `.yaml` file under a `--config` directory recursively but skips
`*.test.yml` and `*.fixed.*`, so the gate accepts only top-level `<name>.yml` rule files (lowercase, digits and
hyphens) and the two policy files in that directory, and refuses anything else (`SAST-RULES-ENTRY`): its rule set
and the canned-report binding then cover exactly what Semgrep runs.

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
"YYYY-MM-DD"}` with `warn_from` < `warn_until`: the ticket's one-week warning window, and its rollback ("return a
specific rule to warning with a recorded expiry"). The gate also caps every window at seven days; the ticket
gives no duration for a rollback window, so that cap is this slice's proposal pending owner confirmation, not
ticket text. The rule warns only on dates inside the
window; before it and after it the rule blocks, and an ended window is listed under `expired_warnings`. Changing a
mode is a reviewed edit of this file; the one-week warning-only rollout itself has not happened.

### Exceptions

None. The exception mechanism belongs to infra#23 (draft infra PR #88), which is not integrated, so every report
says `exceptions: {"status": "unavailable: infra#23 not integrated", "count": 0}`. Semgrep's inline and path
suppression are exception channels too and are refused until then (decision step 3). The planned binding is
`security_exceptions.Exceptions.suppression`; it is named only, never copied or re-implemented. In draft infra PR
#88 that binding accepts only the `secret` and `advisory` kinds, so SAST and DAST exceptions need an infra#23
interface decision at integration.

### Observability fields

`counts.blocking`, `counts.warning`, `counts.by_scanner_severity`, `expired_warnings`, `exceptions.count`,
`suppression.{inline_marker_paths, ignore_files}`, `rule_binding.{status, missing_rules}`,
`scanned_path_count`, `error_count`, `skipped_rule_count`, `complete` and `evaluated_on`.
Publishing them from CI is held with the CI wiring.

### Planted sources and the canned report

Planted positives and clean controls are in `scripts/qa-gates/fixtures/planted/{python,typescript,kotlin}/`. They
are never imported, compiled or run, and they sit outside every `tests/` path because Semgrep ignores test paths by
default. The tests use `scripts/tests/fixtures/qa_gates_sast/semgrep-planted.json`, a report from a **local**
Semgrep 1.178.0 run (user-local install, not pinned by infra), with
`semgrep-planted.provenance.json`. The provenance records the command (`--metrics=off --disable-version-check
--disable-nosem --x-ignore-semgrepignore-files`, local rules only, never a registry config; the binding check is
an allowlist: `semgrep scan`, each of these flags once, optionally `--time`, one `--output` and a final `--config
<rules> <planted dir>`, so a short `-c`, a second config or a rule, severity or path filter is refused), the Semgrep version, the SHA-256 of the rule files, of the planted
tree and of the committed report, and the scanned path list. A unit test recomputes the bindings: editing a rule
file or a planted source without regenerating the report fails it. The canned report is a `local-fixture` input
and **never acceptance evidence** (`acceptance_evidence: false`).

To regenerate after a rule or planted-source change, run from the repository root, then re-serialize the output with
`json.dumps(indent=2, ensure_ascii=True)` plus a final LF and update every digest in the provenance file:

```text
semgrep scan --metrics=off --disable-version-check --disable-nosem --x-ignore-semgrepignore-files --json \
    --output <tmp>/semgrep-planted.raw.json --config scripts/qa-gates/rules scripts/qa-gates/fixtures/planted
```

## DAST: ZAP alerts and scan manifest gate

```text
python scripts/qa_gates_dast.py --alerts ZAP.json --manifest SCAN-MANIFEST.json --surface SURFACE.json \
    [--policy POLICY.json]
```

No ZAP or scan executor exists in this repository yet. The gate reads what a held executor will produce:

- `--alerts`: one ZAP **traditional JSON** report (`@version`, `site[].@name`, `site[].alerts[]` with `pluginid`,
  optional `alertRef`, `riskcode`, `confidence`, `cweid` and `instances[]` with `uri`, `method`, `param`). Other
  keys are ignored and never echoed. **Parser fidelity is unverified**: every report used in the tests is
  synthetic, built from ZAP's documented shape, and the report says `parser_fidelity: "unverified: no real ZAP
  sample exists"` until a real sample is checked in.
- `--manifest`: the executor's scan manifest (`pennilogic.qa-gates.dast-scan-manifest/1`, proposed): `target`
  origin, `zap_version`, `synthetic_data: true`, `contexts[]` (`name`, `authenticated`, and for an authenticated
  context a `user` with `name` and `credential_env`, the **name** of the environment variable that holds a
  short-lived credential, never the value), `scanned_urls[]` (`context`, `method`, `url`), and the SHA-256 of the
  exact alerts report bytes (`alerts_sha256`) and expected-surface bytes (`surface_sha256`).
- `--surface`: the expected-surface manifest (`pennilogic.qa-gates.dast-surface/1`, proposed): entries `{id, auth,
  method, path}` where `auth` is `authenticated` or `unauthenticated` and `path` is a template such as
  `/accounts/{account_id}`. No surface for the real api or web build is committed: the routes belong to their
  owning repositories and the deployed build does not exist yet.
- `--policy` defaults to `scripts/qa-gates/rules/dast-policy.json`.

Exit codes and stdout follow the SAST gate (`pennilogic.qa-gates.dast-report/1`).

### Decision order

1. **Refused (exit 2)** when an input is malformed or the binding breaks: the alerts or surface digest differs
   from the manifest (`DAST-MANIFEST-ALERTS-DIGEST`, `DAST-MANIFEST-SURFACE-DIGEST`), the ZAP versions differ
   (`DAST-ALERTS-VERSION-MISMATCH`), `synthetic_data` is not `true`, the target fails `preflight_target`
   (`DAST-TARGET-NOT-ALLOWLISTED`), a report site is not the target (`DAST-SITE-NOT-ALLOWLISTED`,
   `DAST-SITE-OFF-TARGET`), or an alert instance or scanned URL is on another origin (`...-OFF-TARGET`). An alert
   without instances is refused rather than dropped.
2. **Incomplete fails (exit 1)**: no authenticated context (`DAST-INCOMPLETE-NO-AUTHENTICATED-CONTEXT`), no
   unauthenticated context (`DAST-INCOMPLETE-NO-UNAUTHENTICATED-CONTEXT`), a declared context without any scanned
   URL (`DAST-INCOMPLETE-EMPTY-CONTEXT`), or an expected-surface entry that no scanned URL of the same auth kind and
   method covers (`DAST-INCOMPLETE-SURFACE`, with the missing surface IDs).
3. **Every alert blocks** (`DAST-BLOCKING-FINDINGS`), whatever its risk. The accepted test strategy's
   `security_regression_smoke` evidence says "a high-severity finding or an unsigned or tampered artifact fails the
   deploy gate"; no accepted source or recorded decision makes `medium`, `low` or `info` alerts report-only, so
   this gate does not invent that relaxation. The only relaxation is a per-plugin `warn` window (below). The
   policy refuses a `blocking_risks` list that does not name all four risks (`DAST-POLICY-RISK`); narrowing it
   needs a recorded owner or Security decision, and `decision_ref` stays `null`.

The scan manifest's contexts are declared by the executor; this gate checks that both kinds exist and were
exercised, not that a login really succeeded. Proving that is part of the held real authenticated scan.

### Target allowlist and `preflight_target`

`preflight_target(url, policy)` is pure (no DNS, no socket) and returns `{origin, class}` or refuses. It accepts an
`http`/`https` origin (lowercase, no user info, path, query or fragment) whose host is a loopback IP literal
(`127.0.0.0/8` or `[::1]`) or a DNS name under a declared ephemeral suffix (`targets.ephemeral_host_suffixes`;
the suffix itself is not a valid target). `localhost`, other names, private and public addresses, integer or
zero-padded IPv4 forms and IPv4-mapped IPv6 are refused. The committed policy declares **no** ephemeral suffix
because no ephemeral environment exists; adding one is a reviewed edit of `dast-policy.json`. DNS resolution,
rebinding protection and "fails before the first request" (E25-F04) are execution-time controls of the held
executor, which must call `preflight_target` before it starts ZAP.

### Finding record (proposed vocabulary)

| Field | Meaning |
| --- | --- |
| `plugin_id`, `alert_ref` | ZAP scan rule ID and alert reference (digits; `alertRef` must start with the plugin ID). |
| `risk`, `confidence` | `riskcode` 3/2/1/0 as `high`/`medium`/`low`/`info`; confidence 4..0 as `confirmed`..`false-positive`. |
| `cwe_id`, `method` | CWE number (`-1` when ZAP has none) and HTTP method. |
| `fingerprint` | `sha256:` over the canonical JSON of `[alert_ref, method, URL path, parameter name]`; the query is excluded. |
| `mode` | `block`, or `warn` inside a recorded window. There is no report-only mode. |

The report never carries URIs, hosts, query values, parameter names, attack strings, evidence, alert text,
context or user names, environment variable names or credential values. It reports `target_class`,
context counts, `scanned_url_count`, `surface.{expected, covered, missing}` (validated surface IDs only),
`counts.{blocking, warning, by_risk}`, `expired_warnings` and the same `exceptions` block as SAST.

### Per-plugin warn mode, rollout and rollback

`dast-policy.json` `rules` maps a ZAP plugin ID to `{"mode": "warn", "warn_from", "warn_until"}` with the same
seven-day cap as SAST (proposed, not ticket text). Inside the window an alert of that plugin is `warn`; outside it blocks again
and an ended window is listed in `expired_warnings`. The committed policy has no warn entry.

## Finding vocabulary alignment (infra#31)

The supply-chain gates of infra#31 are to align their finding vocabulary by value with this one. As committed here,
there is **no shared severity field**: SAST findings carry `scanner_severity`, Semgrep's own level unmapped
(`ERROR`, `WARNING`, `INFO`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), and DAST findings carry `risk`, ZAP's
`high`/`medium`/`low`/`info` (ZAP has no `critical`). The common parts are the `fingerprint` form
(`sha256:<64 hex>` over canonical JSON), `mode` (`block`/`warn`), `counts`, `expired_warnings` and the `exceptions`
block. No Semgrep-to-severity mapping and no `critical`..`info` enum is defined here; agreeing a common severity
field is an infra#23/owner decision that is not recorded, so a statement that infra#31 copies such an enum from
infra#28 does not match this slice.

## Rollout and rollback (both gates)

The ticket introduces the gates as **warning-only for one week** to measure noise, then blocking. Once the CI
steps exist, the warning week is recorded the same way as a per-rule rollback: each rule (SAST) or plugin (DAST)
gets a `warn` entry whose `warn_from`..`warn_until` covers at most seven days (the proposed cap), in a reviewed policy edit. Findings
in that window are counted under `counts.warning`; when the window ends they block again without another change,
and `expired_warnings` lists the rules so the entries can be removed. Rolling back one noisy rule later uses the
same entry with a new recorded window; there is no open-ended warning and no global switch. The committed
policies are all-blocking, and the warning week itself has not run.

## Held and not claimed

- **CI wiring.** Criterion 1 ("fails the pull request") needs a Semgrep CI step with a pinned, trusted Semgrep
  binary run with `--metrics=off --disable-version-check --disable-nosem --x-ignore-semgrepignore-files --time`,
  only this repository's rule directory as `--config` and no rule or severity filter (`--exclude-rule`,
  `--severity`, a second `--config` or `-c`); the step must also fail unless `rule_binding.status` is
  `bound: time.rules`, because the gate accepts an unbound report (the committed canned report has none), and criterion 2 needs a deploy-pipeline DAST step; both are wired through the generator owner (the
  workflows are generated files). Scanner execution, timeouts and process cleanup wait for infra#23's process
  controls. Publishing the counts to the release checklist is held with the wiring.
- **Scanned-target binding.** A live report is not yet bound to the target list expected from the trusted
  checkout, so a CI step that passes `--exclude`, `--include` or a narrower target path could drop files without
  the gate noticing. The held CI step must take that list from the trusted checkout and fail when `paths.scanned`
  omits a target. Infra's own repository scan must exclude `scripts/qa-gates/fixtures/planted` only through an
  explicit, recorded `--exclude` (never an inline marker or `.semgrepignore`, which this gate fails), and must scan
  that directory separately as a positive control that is expected to fail with the 13 planted findings.
- **Policy and surface from the protected base.** `--policy` (both gates) and `--surface` (DAST) default to or are
  read from the checkout under test, so a change that introduces a finding could add its own warn window, widen
  the DAST target allowlist or shrink the expected surface in the same change. The gates do not compare these
  inputs with a base revision. The held CI steps must read the policies and the expected surface from the
  protected base revision, never from the head under test; a code-level base comparison (as the quarantine gate
  does for its manifest) is not implemented.
- **Merge dependency on the first slice.** The quarantine and retry slice of infra#28 (branch
  `claude-infra-28-quarantine-retry-gates`) copies every entry of `scripts/qa-gates` as a file in its CLI tests and
  classifies test modules through its protected-tests manifest. Combined with this slice, its tests fail with
  `IsADirectoryError` on `scripts/qa-gates/rules`, and `test_qa_gates_sast` and `test_qa_gates_dast` classify as
  unknown. The fix belongs to the first slice (copy regular files only; add protected-tests rules for both
  modules); this slice does not edit those files. Merge order: the first slice, with that fix, before this one.
- **Real authenticated scan.** Criterion 2 ("a dynamic scan of the running build reports and fails on a high
  severity finding") needs an ephemeral deployed build with synthetic data, a ZAP executor that calls
  `preflight_target` before the first request, short-lived credentials scoped to that environment, a committed
  expected surface from the owning repositories, and a real ZAP report to verify this parser. None exists;
  the DAST tests use synthetic reports only.
- The rule sets, the manifest and surface schemas and the report vocabulary are
  proposals; no owner decision is recorded (`decision_ref` stays `null`).
- The one-week warning window has not run.
- infra#23 (exceptions, process controls; draft infra PR #88) and the infra#22 conformance hold are unresolved.
- The Windows test leg was not run locally; the tests are written to pass on Linux and Windows without skips.
- Independent Core, Security, QA, Privacy and Reliability reviews are required and not done.
