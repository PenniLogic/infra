# Secret and dependency controls

Independent source slice of [infra#23](https://github.com/PenniLogic/infra/issues/23).
These commands implement scanning, reconciliation, exception expiry and redacted
rotation requests. They **do not activate workflows, publish issues, establish
trusted report provenance, or prove hosted acceptance**. Canonical workflow,
checker and source-binding integration remains with the coordinating Infra owner.

## Run locally

Use Python 3.14, Git, and Gitleaks **8.30.1** on `PATH`. There are no new Python
packages. Gitleaks is required: the real-scanner tests fail, rather than skip,
when it is missing or its version differs. Do not install dependencies unless
the normal missing-tool or manifest-change condition applies.

The official [8.30.1 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
archives are pinned by SHA-256:

| Archive | SHA-256 |
| --- | --- |
| `gitleaks_8.30.1_linux_x64.tar.gz` | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
| `gitleaks_8.30.1_windows_x64.zip` | `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e` |

Verify the archive before extracting it into an owned tool directory; do not
replace a shared installation. This pin is not an SBOM or signed provenance.
Linux/Windows provisioning in generated CI has not been added by this slice.

```text
python -m unittest discover -s scripts\tests -p test_security_controls.py -v
python scripts\security_exceptions.py
python scripts\scan_secrets.py --repository PenniLogic/infra
```

Commands print one machine-readable JSON document. Exit 0 means the requested
local check passed (or explicitly reported Android `warn` mode), 1 means findings
or an age/closed-ticket alert, and 2 means a refused/unavailable input or tool.
Do not turn an exit 1/2 into a green pipeline while publishing the report.
Malformed input, scanner failure, incomplete history and unavailable advisory
data are not empty successful scans.

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
The tests exercise these actual scanner paths, not substitutes for Gitleaks.

Coverage is reported as `all-local-refs`, not "all history ever hosted." The
integration must fetch full branch/tag/PR history; deleted/unfetched remote refs,
other repositories, archives beyond Gitleaks' supported decoding, Git LFS
payloads and deployed secrets are not proved covered. Gitleaks has a 180-second
deadline per pass; timeout, failed mirror, missing objects or oversized reports
refuse, never silently reduce scope.

Only `pennilogic.secret-scan/1` leaves the command. Raw scanner reports and
stdout/stderr remain temporary and are removed. Findings contain a rule,
credential class/severity, commit, line/column span, hashed artifact identifier,
and a stable finding ID. They contain no match, credential, filename, author,
email, commit message or secret-derived hash. Separate secrets on the same line
have separate exception targets. Duplicate detector rules may report the same
exposure separately; repeated occurrences of one exact finding are deduplicated.

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
Future creation times and incomplete ticket inventories refuse.

No accepted incident-aging threshold was found in the current policies:
Docs `architecture/02-security-architecture.md` section 6.6 requires immediate
rotation and incident handling, and Infra `ACCOUNT_SECURITY.md` C5/C6 requires
immediate suspected-exposure action. Its proposed seven-day PAT *pre-expiry*
lead is not a rotation-incident escalation window. Accordingly there is **no
default window**. Without one, requests and observed ages are still produced,
but `age_alert_status` is `policy-required`, stale counts/flags are `null`, and
the CLI returns 2. The trusted publisher must not discard new requests because
the separate aging policy is unresolved.

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
failure to publish must remain visible. The required planted-secret ticket and
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

The initial actual local Infra full-history scan was **RED**, with 56 findings
across 957 reachable commits. Findings were retained only as redacted metadata;
their validity/credential state was not inferred. Do not suppress them wholesale,
rewrite history or describe the control as green. Historical triage belongs to
the owner before activation. Later local histories can contain more refs/commits,
so this initial observation is not a permanent expected count.
