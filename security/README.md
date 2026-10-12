# Secret and dependency controls

Independent source slice of [infra#23](https://github.com/PenniLogic/infra/issues/23).
These commands implement scanning, reconciliation, exception expiry and redacted
rotation requests. They **do not activate workflows, publish issues, establish
trusted report provenance, or prove hosted acceptance**. The QA-I1 Source A below
adds canonical tool preparation for Infra's ordinary qualification, not production
scan activation. Source binding, protected integration and hosted acceptance
remain with the coordinating Infra owner.

## Run locally

Use Python 3.14, trusted Git, and Gitleaks **8.30.1**. There are no new Python
packages. Gitleaks is required: the real-scanner tests fail, rather than skip,
when its explicit tool binding is missing or its digest/version differs. Do not
install dependencies unless the normal missing-tool or manifest-change
condition applies.

The official [8.30.1 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
archives are pinned by SHA-256:

| Archive | SHA-256 |
| --- | --- |
| `gitleaks_8.30.1_linux_x64.tar.gz` | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
| `gitleaks_8.30.1_windows_x64.zip` | `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e` |

Verify the archive before extracting it into an owned tool directory; do not
replace a shared installation. This pin is not an SBOM or signed provenance.
The verified Windows executable's SHA-256 is
`17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c`.
For each platform, obtain the executable digest from the independently verified
archive, not from a candidate-provided binary. The generated Infra CI preparation
implements that verification on both supported hosted platforms; its actual
download and native qualification remain unverified by local mocked controls.

The scanner requires `--git` and `--gitleaks` absolute executable paths outside
the candidate checkout, plus `--gitleaks-sha256` from trusted provisioning.
It does not discover tools from ambient `PATH` or the current directory.
Gitleaks' own child Git lookup receives only the selected Git directory in
`PATH`, `.EXE` on Windows, and disabled current-directory lookup. The executable
digest is checked before execution and around each scanner pass. The caller
must own the selected installation and supply these arguments independently of
candidate files, environment changes and PR text. This is not isolation from
another hostile process that can mutate the same user's trusted installation.

For the focused tests, set these process-local bindings from that same trusted
provisioning; they are test inputs, not production CLI fallbacks:

| Variable | Value |
| --- | --- |
| `PENNILOGIC_TEST_GIT` | Absolute path to the trusted `git` / `git.exe`. |
| `PENNILOGIC_TEST_GITLEAKS` | Absolute path to the verified Gitleaks executable. |
| `PENNILOGIC_TEST_GITLEAKS_SHA256` | Executable digest from the verified release archive. |

```text
python -m unittest discover -s scripts\tests -p test_security_controls.py -v
python scripts\security_exceptions.py
python scripts\scan_secrets.py --repository PenniLogic/infra --git <absolute-trusted-git> --gitleaks <absolute-verified-gitleaks> --gitleaks-sha256 <verified-executable-digest>
```

Commands print one machine-readable JSON document. Exit 0 means the requested
local check passed (or explicitly reported Android `warn` mode), 1 means findings
or an age/closed-ticket alert, and 2 means a refused/unavailable input or tool.
Do not turn an exit 1/2 into a green pipeline while publishing the report.
Malformed input, scanner failure, incomplete history and unavailable advisory
data are not empty successful scans.

## Hosted qualification preparation (QA-I1 Source A)

Only Infra CI gets the generated `Prepare security tools` step, before the existing
complete governance/scripts discoveries. Setup workflows, Conformance and the other
repositories are unchanged. The embedded stdlib program uses the existing pinned
setup-python action's absolute `pythonLocation`, not an interpreter in the checkout.
It checks hosted repository/org/platform identity; downloads the fixed public release
without credentials or proxy inheritance; verifies the entire bounded archive's
SHA-256 **before parsing or extraction**; and requires exactly the regular
`LICENSE`, `README.md` and platform executable entries. Links, alternate paths,
duplicates, extras, malformed/truncated payloads and oversized files refuse.
Only the executable is written to a fresh private directory under `RUNNER_TEMP`,
outside the candidate checkout. There is no global installation or automatic retry.

Git is bound to the hosted image's `/usr/bin/git` on Linux or
`C:\Program Files\Git\cmd\git.exe` on Windows. A missing/linked/different image
installation refuses rather than falling back to `PATH`. Both tools run only
version probes during preparation, with scrubbed environments, external working
directories and private bounded captures. Their digests are checked immediately
before and after invocation. A 180-second preparation deadline and at-most-15-second
network/probe waits supplement, not replace, the unchanged ten-minute OS job limit.
This is not OS isolation against another process with write access to the same
user's installation; DNS/platform stalls still have the native job as an outer bound.

Only successful preparation appends the three existing test bindings plus
`PENNILOGIC_TEST_GIT_SHA256` to the runner's environment file. That fourth binding
is required by the hosted qualifier, not by the unchanged focused local scanner
suite. Failure returns nonzero with a fixed-field refusal, without child output,
URLs or local paths. A failed/interrupted preparation does not claim cleanup;
any tool-only directory already created is retained. It contains binaries, not
scanned history, and is distinct from the sensitive scanner scratch described below.
Do not forge hosted metadata to use this bootstrap as a local installer.

The qualifier checks the prepared locations/digests and records safe version/digest
evidence. It retains the **whole native checkout** commit/tree/blob inventory before
and after each ordinary discovery, and requires the scanner, dependency/rotation
code, exception/config/schema/profile files, `conformance` imports and dynamic
Windows `bootstrap.py` -> `smoke_infra.py` closure within that inventory. This is
not a four-file receipt and does not authenticate candidate-generated scan evidence.
Exactly the three Windows-only security methods are required in both inventories:
they must pass on Windows and be skipped on Linux. Missing IDs, a skip on Windows,
a pass in place of the declared Linux skip or any unrelated skip refuses.

This source does not run a production repository-history gate, collect PR advisories,
publish rotation tickets or schedule rescans. The Infra native/PR-gate registry
references intentionally remain at their old accepted source until a separately
reviewed real Source A commit can be bound by registry-only B. The protected-base
validator rejects the changed CI/checker/gate bytes; local checker success is not
permission to suppress that negative. Both complete native OS jobs **and the whole
workflow** still need times strictly below 600 seconds. Neither the old Windows
65-test results nor a static Linux 62-pass/3-skip expectation establish this.

## Full-history secrets

`scan_secrets.py --root <checkout> --repository PenniLogic/<name>` resolves
repository IDs from the existing canonical profiles. It refuses shallow,
replacement and grafted history; takes a temporary bare mirror of every locally
available ref; checks its HEAD and reachable-commit set against the original;
and verifies that the original did not move during scanning. Network protocols
and lazy object fetching are disabled in child Git processes.

The pinned scanner runs twice over full history, including root commits, merges
and noncurrent branches. One pass uses the small mandatory rules in
`gitleaks.toml`, without path/entropy/inline exemptions; the other uses upstream
provider rules and their pinned upstream false-positive rules. Mandatory rules
detect GitHub token-shaped strings (20+ suffix characters), provider `sk-` keys
(16+ suffix characters), private-key headers and quoted hardcoded database
passwords (8+ characters). Documentation fragments alone are not credentials.

This separation matters: upstream global allowlists omit certain filenames, and
Gitleaks 8.30.1 **always** reads `source/.gitleaksignore` even when an explicit
ignore path is supplied. The bare mirror excludes the candidate's working-tree
ignore file. The explicit trusted config, empty ignore input and
`--ignore-gitleaks-allow` reject candidate-config, ignore-file and inline-comment
suppression. Forced-text Git diffs with external diffs/textconv disabled prevent
binary attributes and suffixes such as `.svg` from hiding mandatory patterns.
Real-scanner fixtures include a credential only in the initial commit, removed
later, and one introduced only by a merge resolution between clean parents,
also removed later. Findings must identify the original root/merge commit.
The tests exercise these actual scanner paths, not substitutes for Gitleaks.

Coverage is reported as `all-local-refs`, not "all history ever hosted." The
integration must fetch full branch/tag/PR history; deleted/unfetched remote refs,
other repositories, archives beyond Gitleaks' supported decoding, Git LFS
payloads and deployed secrets are not proved covered.

### Completion and process lifetime

Gitleaks 8.30.1 can silently finish with partial findings when an internal
deadline expires while workers drain; it also logs some Git errors without
propagating a failing exit code. The wrapper explicitly uses `--timeout=0` and
enforces a **180-second external deadline per scanner pass**. Any scanner output
at the configured error log level, unexpected exit, missing/mismatched report,
timeout, failed mirror or oversized input refuses. Exit 0/10 and a parseable
report alone are not completion evidence. Regressions exercise an actual
swallowed Git error, accepted-code partial/error reports, a late-fragment
detection and cancellation of the real scanner while it is running.

The wrapper reuses the unchanged `governance/conformance/defects.py` owned-process
runners and `scripts/bootstrap.py` lifetime primitives; it does not run the
Conformance suite, Docker or a service. The trusted source binding must include
those helpers and their existing local imports. On Windows a trusted isolated
Python gate waits for Job Object ownership before releasing the command.
Timeout cleanup terminates that job's descendants and bounds pipe/process
draining to the helper's existing five-second teardown reserve. A synthetic
descendant-held-pipe/file test checks actual exit and file release.

POSIX reuses the existing separate process group and bounded termination.
Its timeout path deliberately does **not** claim detached-descendant exit;
the scan refuses and retains scratch when cleanup is unconfirmed. No Windows
result is Linux qualification. Process cleanup status remains explicit, and a
scratch-deletion failure cannot replace the primary timeout/error. Neither
condition is an empty successful scan. Explicit cancellation becomes a
fixed-field `scanner-process-interrupted` refusal, not a Python traceback.
A raw `KeyboardInterrupt` may also originate during the helper's teardown,
so it is **not a typed cleanup witness**: the public boundary always reports
`process_cleanup: unconfirmed`, returns 2 and retains any scan scratch still
under its ownership. It does not retry cleanup against a possibly live tree.
A synthetic control can verify that its particular helper invocation stopped
its processes, but cannot upgrade that public cancellation status. Separate
controls exercise confirmed helper cleanup and interruption during teardown.

Retained scratch may contain full source history, including exposed values;
report redaction does not sanitize it. Operator follow-up must privately locate
the owned scratch, establish that all owning processes have exited and arrange
its controlled cleanup. The public report does not disclose its path. Eventual
cleanup, secure erasure and a precise typed cancellation witness are not
established by this source correction; no automatic retry or cleanup approval
is implied.

Only `pennilogic.secret-scan/1` leaves the command. Raw scanner reports and
stdout/stderr stay private; temporary reports are removed after confirmed
process exit. Unconfirmed cleanup retains scratch and fails explicitly.
Findings contain a rule,
credential class/severity, commit, line/column span, hashed artifact identifier,
and a stable finding ID. They contain no match, credential, filename, author,
email, commit message or secret-derived hash. Separate secrets on the same line
have separate exception targets. Duplicate detector rules may report the same
exposure separately; repeated occurrences of one exact finding are deduplicated.

### Incomplete incident handoff

A refusal is not permission to discard already established detections. Each
pass must finish with the pinned executable intact, confirmed process cleanup,
an accepted exit, no diagnostics and a wholly valid report before its findings
are minimized and retained. Invalid, errored or cancelled passes contribute
**nothing**, including any apparently valid prefix of their report. A later
pass, scratch cleanup or history-stability failure still refuses coverage and
returns exit 2, but preserves earlier completed-pass detections in
`incident_handoff`, separately from a normal scan's `findings`.

The outer `pennilogic.secret-scan/1` stays `status: refused`, with a static
`code` and `coverage: {"scope":"all-local-refs","complete":false}`. If validated
detections exist, `incident_handoff` contains exactly:

- `schema: pennilogic.secret-incident/1`, `status: incomplete`;
- the known `repository`, numeric `repository_id` and original snapshot `head`;
- ordered `completed_passes`: `["mandatory"]` or `["mandatory","provider"]`;
- nonempty `findings`, with only the same minimized finding fields as a complete scan.

There is no completed-coverage or commit-count claim in this handoff. The
original head identifies the scanned snapshot even when a later stability
check discovers movement. With no valid completed-pass detections there is no
incident handoff; a generic refusal cannot be reinterpreted as a clean scan.
Successful scan reports additionally state `coverage.complete: true`, still
limited to locally available refs.

The rotation command accepts this strict incomplete envelope while retaining
repository, finding-identity, severity, current-exception and deduplication
validation. It rejects raw/extra incident fields, inconsistent coverage,
invalid pass sequences and provider findings attributed only to the mandatory
pass. Its output records `scan_status: refused`, `scan_coverage: incomplete`,
and **always returns 2**, even if separate age evaluation succeeds. It may
still contain immediate rotation requests. Schema, hashes, a claimed pass name
and a valid finding ID are **not provenance or authentication**: the eventual
trusted collector must bind the actual trusted producer and preserve its
nonzero exit; candidate-supplied JSON cannot establish that a pass executed.

Synthetic regressions run the real mandatory scanner pass before later
diagnostic, timeout, invalid-report, cleanup and history-movement failures,
then feed the resulting non-green handoff into the rotation CLI. These prove
source data flow and minimization, not live publication or native acceptance.

## One exception contract, no blanket baselines

`exceptions.json` starts empty. `exceptions.schema.json` defines each record:
`id`, `kind`, `repository`, `pattern`, `artifact`, `reason`, `owner`, `expires_at`.
Both secret and advisory gates use `security_exceptions.py`; its CLI publishes
the same audit with active/expired records and returns 1 for any expired record.
The runtime additionally rejects duplicate IDs/targets and invalid calendar
dates. Boolean schema versions, duplicate JSON keys, nonfinite JSON numbers,
linked input files/ancestors, nonregular files and malformed records refuse.

`pattern` is an **exact** scanner rule or GHSA identifier, not a regular
expression. `artifact` is the complete 64-character finding ID, not a glob, raw
secret or digest of a secret. The repository, kind, rule and finding must all
match. `expires_at` is an explicit UTC `YYYY-MM-DDTHH:MM:SSZ`; at equality or
later the original finding blocks again. There is no CLI clock override.
An exception never suppresses missing client inventory or an unlisted SDK.

For a genuine false positive, the owner proposes this exact record with a
non-sensitive justification and finite expiry in a normal PR. Core and
Security/Privacy review examine the original finding privately; do not paste
its value into the PR or issue. The coordinator records the review and source
commit before admitting the policy change. No self-approved baseline,
`gitleaks:allow`, candidate `.gitleaksignore`, wildcard exception or permanent
suppression is an approval. Audit reports omit the free-form reason and owner.
Expiration requires a new reviewed decision, not automatic renewal.

## Client inventory and the Android allowlist

Do not copy Android's list into Infra. The already accepted Android
`scripts/privacy_traffic/components.init.gradle` task emits
`{"schema_version":1,"variants":{"debug":[...],"release":[...]}}` from the
resolved Gradle runtime classpaths. Its existing
`app/src/main/res/raw/privacy_traffic_policy.json` owns the reviewed exact
`group:artifact:version` entries under `components`. The new reconciler consumes
those inputs directly:

```text
python scripts\check_dependencies.py android --resolved <fresh-inventory.json> --policy <privacy_traffic_policy.json> --head <40-character-head>
python scripts\check_dependencies.py android --resolved <fresh-inventory.json> --policy <privacy_traffic_policy.json> --head <40-character-head> --mode warn
```

Every unlisted resolved coordinate (including transitives and version changes)
is named under `missing`. `unused` flags reviewed entries absent from resolution.
Both variants, resolved versions, sorting and uniqueness are required.
Default `enforce` fails on missing entries. The issue's initial rollout must
explicitly select `warn`, review the complete drift, then promote through a
reviewed generator change; rollback only this added check to explicit `warn`.
Warn does not forgive malformed or missing inputs and does not weaken Android's
existing stricter privacy-component gate. No ad/analytics SDK or access to
SMS-derived data is authorized by being syntactically present in a list; review
must enforce the existing data policy.

Web and Admin use npm lockfile v2/v3, including transitive and development
packages, against a consumer-owned reviewed inventory:

```text
python scripts\check_dependencies.py npm --repository PenniLogic/web --lockfile <package-lock.json> --inventory <reviewed-components.json> --head <40-character-head>
```

The npm inventory has exactly `{"schema_version":1,"components":[{"name":"example","version":"1.0.0"}]}`.
Aliases use the resolved package name, multiple install locations are
deduplicated, and exact versions are required. Links, local/workspace packages,
local/Git tarball resolutions, credential-bearing URLs and unsupported lockfile
formats refuse rather than disappear. Native
`npm ci`/manifest-lock consistency remains required; this parser is not a
package resolver. Consumer inventory adoption is outstanding; no existing
package is silently approved here.

`pennilogic.dependency-inventory/1` includes repository ID, requested head,
normalized input/policy SHA-256 values, coordinates/scopes, missing/unused
entries, mode, status and counts. Android's **unchanged native envelope** is
also carried as `android_inventory`: T-CMP-03 can pass it directly to the
existing Android component assertion without re-collection. The integration
must capture it once from a fresh successful native task, bind it to the actual
head and publish only this scrubbed report. A caller-supplied head/hash is not
independent evidence of freshness or provenance.

## Known-vulnerable additions

```text
python scripts\check_dependencies.py review --repository PenniLogic/android --comparison <complete-comparison.json> --base <40-character-base> --head <40-character-head>
```

The input envelope has exactly `schema_version: 1`, `repository`,
`repository_id`, `base`, `head`, `complete: true`, and `changes`. `changes` is
the complete GitHub dependency-review comparison result, preserving each
entry's `change_type`, `ecosystem`, `name`, `version`, `vulnerabilities` and
optional API metadata. Every added vulnerability blocks, including low severity;
removed vulnerable versions do not. Unsupported/malformed advisories or absent
vulnerability arrays refuse. Exceptions use the same expiring contract.
Only package identity, GHSA, severity and counts enter the public report;
advisory prose, manifest paths and arbitrary API fields do not.

The protected integration must collect **every page** for the exact repository
and immutable base/head pair and establish dependency-graph ecosystem support.
An unsupported graph, permission failure, truncated result or unevaluated
manifest must never become `changes: []`. This source slice validates a supplied
comparison; `complete: true` is an input contract, not authentication. Actual
GitHub collection, dependency-review PR execution and a hosted vulnerable-
addition negative remain unimplemented/unverified here.

## Rotation requests and aging

```text
python scripts\secret_rotation.py --scan <redacted-secret-scan.json> --existing <complete-ticket-list.json>
```

The complete ticket-list envelope is exactly `repository`, `repository_id`,
`complete: true`, `issues`. Each GitHub issue record supplies `number`, `state`,
`created_at`, `labels` (objects with `name`) and `body`. The eventual trusted
collector must enumerate all relevant open **and closed** rotation issues.
Only fixed fields and classifications are emitted; raw issue bodies and labels
are never copied into requests.

`pennilogic.secret-rotation/1` emits deterministic create-request payloads, each
with its repository ID, full finding deduplication key, redacted title/body and
`secret-rotation` plus a derived severity label. Database passwords/private keys
are `critical`; source-control/provider tokens and unclassified credentials are
`high` (unknown privilege never lowers severity). It rechecks current exceptions
and their expiry rather than trusting a scan's claimed suppression. It rejects
severity drift, wrong repositories, inconsistent findings and duplicate markers.
Existing open tickets deduplicate requests. A closed ticket for a still-active
finding is flagged for review and keeps the check failed, without opening an endless sequence
of tickets or treating closure as proof of revocation.

Every new, untracked and unsuppressed finding produces a request in that invocation.
There is no waiting period for the initial alert, rotation or incident path.
The report includes per-repository open count, individual ages and oldest age.
Empty inventories have an absent (`null`) oldest age, never a fabricated zero.
Incomplete ticket inventories, repository/identity errors, ambiguous markers
and severity drift still refuse request planning. Age evaluation is separate:
invalid/future creation times or an invalid escalation window set
`age_alert_status: failed` and a static `age_alert_code`, keep counts and
validated requests/deduplication, leave ages and stale flags/counts `null`,
and return 2. A failing age calculation must not suppress an immediate request
or bypass duplicate-ticket controls.

No accepted incident-aging threshold was found in the current policies:
Docs `architecture/02-security-architecture.md` section 6.6 requires immediate
rotation and incident handling, and Infra `ACCOUNT_SECURITY.md` C5/C6 requires
immediate suspected-exposure action. Its proposed seven-day PAT *pre-expiry*
lead is not a rotation-incident escalation window. Accordingly there is **no
default window**. Without one, requests and observed ages are still produced,
but `age_alert_status` is `policy-required`, stale counts/flags are `null`, and
the CLI returns 2. The trusted publisher must not discard new requests because
the separate aging policy is unresolved or failed, or because the incident
handoff reports incomplete scan coverage.

After an explicit accepted decision, the trusted workflow may supply its fixed
positive `--stale-after-seconds` value. Equality triggers escalation of an
already-open incident, measured from issue `created_at`, never a detection grace
period, scan-receipt lifetime or acceptable dependency-evidence age. This value
must not come from candidate arguments or PR text. Synthetic boundary tests
exercise the arithmetic without adopting an operational threshold.

**No command posts a ticket or sends an alert.** Publication must be an
owner-approved, trusted integration with least privilege, serialized per
repository, a fresh deduplication read immediately before creation and
read-back of the returned issue/labels. Candidate code/reports must not gain
issue-write credentials. A failed scan must still trigger this trusted path;
it consumes validated `incident_handoff` evidence without salvaging an errored
pass or making the scan green. Failure to publish must remain visible. The required planted-secret ticket and
independent severity-label confirmation cannot be claimed from a payload test.

## Acceptance ledger and integration handoff

| Issue requirement | Available source / remaining acceptance |
| --- | --- |
| Secret scanning and push protection on all eight repos | Guarded owner readback on 2026-10-12 showed both enabled on all eight, plus `.github`; no settings were changed. Actual rejection remains untested. |
| Deliberately planted credential blocked on push, then removed | Only nonfunctional local Git fixtures are used. No push attempt or public planted credential is authorized/performed. |
| Dependency review fails vulnerable PR additions | All-severity comparison gate and synthetic positive/negative tests; hosted collection, graph coverage and PR execution pending. |
| Android third-party allowlist blocks and names the coordinate | Reuses the existing native inventory and privacy policy; native producer/report wiring and warn-to-enforce rollout pending. |
| Hardcoded GitHub/provider keys and private-key headers fail CI | Actual Gitleaks mandatory-rule tests; generator/CI activation pending. |
| Documented genuine-false-positive exceptions with expiry | Shared schema, gate consumption, audit and expiry re-trigger implemented; no exceptions granted. |
| A client component without inventory fails the pipeline | Android and npm source gates; Web/Admin reviewed inventory adoption and hosted negatives pending. |
| Full-history scan and scheduled rescan | Deleted/noncurrent-branch history, root/binary-path and suppression negatives implemented; full remote-ref acquisition and scheduled workflow pending. |
| Detection automatically opens a severity-labeled rotation ticket | Redacted request/deduplication/age source implemented; automatic publication and reviewer confirmation pending. |
| Inventory published for T-CMP-03 without re-collection | Stable machine-readable output and unchanged Android envelope; artifact publication and actual consumer use pending. |
| Reconciliation report and warn-only rollback | Named missing/unused coordinates and explicit modes implemented; rollout decision/native checks pending. |
| Open-ticket count, age and fixed-window alerts | Deterministic ages, explicit missing-policy status and tested configurable boundary; an accepted fixed window and live collection/alert delivery remain pending. |
| Violation tests and Definition of Done | Focused actual-scanner/source tests only. Separate Core/QA/Security/Privacy review, current-head native CI, protected integration and infra#22 acceptance remain required. |

The actual local Infra history observations on **2026-10-12** remain **RED**:
the initial receipt recorded 56 findings / 957 reachable commits; the later
`f96739cf027a8499825bc97826d4ba4a8e9956bd` receipt recorded 56 / 961, with none
attributed to that commit. Both predate the executable/completion/lifetime
corrections and are preserved as dated results, not completeness witnesses or
claims that the historical findings are false positives. No actual repository
history was rescanned for those corrections. Findings were retained only as
redacted metadata; validity, privilege and revocation remain untriaged. Do not
suppress them wholesale, rewrite history or describe the control as green.
