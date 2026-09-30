# Governance: the canonical generator and the generated checker

`generate.py` renders the small public-repository baseline, 20 files for every repository in
`repository-profiles.json` (`.github/workflows/ci.yml`, `.github/workflows/copilot-setup-steps.yml`,
`AGENTS.md`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CONSTITUTION.md`, `COPILOT_FILES.md`,
`.github/copilot-instructions.md`, `.github/instructions/source.instructions.md`,
`.github/agent-policy.json`, `.github/CODEOWNERS`, `.github/github-app.yml`,
`.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/*` (two files), `.gitattributes`,
`.gitignore`, `scripts/setup.py` and `scripts/check_repository.py`). Consumers never hand-edit those
files: a profile or template change lands here through a reviewed generator PR, then each consumer
regenerates from the merged `main` in its own PR. `governance/tests/test_rule_table.py` keeps this
list equal to what `artifacts()` renders.

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
`actions/setup-java` in `ci.yml` binds them in the consumer checker, and one pin bump reaches both
in the same regeneration. The template carries the current pins too, so it can be imported and
tested unrendered; `test_workflow_validation.py` fails when the template and the rendered copy
differ, and `generate.py` refuses a template that does not define the block exactly once.

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
document order: rules 7-11 are applied to each mapping before the next mapping is visited (a `uses`
problem in step 1 is reported before an `if` in step 3), rules 14-17 to each job and each of its
steps before the next job, and rules 19-20 to each job in turn. The table order is derived from the
template's source by `governance/tests/test_rule_table.py` (each helper expanded at its call site),
so a rule moved or added in the template fails that test until the row moves with it.

| # | Rule text | Refuses |
|---|-----------|---------|
| 1 | `UTF-8 byte order mark before the JSON document` | a BOM that `json.loads(bytes)` would otherwise skip (UTF-16/32 input instead fails the strict UTF-8 decode and gets the parse fallback line) |
| 2 | `Duplicate JSON key` | a repeated key at any depth, which parsers resolve differently |
| 3 | `workflow document must be one JSON object` | a top-level array, string, number, boolean or `null` |
| 4 | `expected read-only workflow token` | any workflow `permissions` other than `{"contents": "read"}` |
| 5 | `unreviewed workflow expression; public jobs must not receive secrets` | every `${{ ... }}` outside `WORKFLOW_EXPRESSIONS`, at any depth |
| 6 | `public candidate jobs must not receive secrets` | the `secrets` context or `github.token` in any key or string, including whitespace-split and whole-context forms (tripwire behind rule 5) |
| 7 | `conditions are not part of the generated workflows` | the key `if` in any mapping (job, step, snapshot or any other depth) |
| 8 | `action must be immutable and one of the generated GitHub-owned actions` | any `uses` that is not one of `WORKFLOW_ACTIONS` followed by `@` and a lowercase 40-hex commit, including reusable-workflow jobs, local and `docker://` actions, tags, branches, short or upper-case commits |
| 9 | `action commit differs from the generated pin; regenerate instead of editing it` | a listed action at any 40-hex commit other than its entry in `WORKFLOW_ACTION_PINS` (compared exactly and case-sensitively), including a listed action at another listed action's pin and a fork's commit reachable by SHA through the upstream repository |
| 10 | `unreviewed action input; only the generated inputs are accepted` | a `with` key outside the per-action input allowlist, or a non-mapping `with` |
| 11 | `checkout must not retain credentials` | `actions/checkout` without `persist-credentials: false` |
| 12 | `top-level key outside the generated workflow keys name, on, permissions, concurrency, jobs` | a top-level `env`, `defaults`, `run-name`, merge key or any other field |
| 13 | `jobs must be a mapping of job ids with at least one job` | `jobs` missing, empty, a list or a scalar |
| 14 | `job must be a mapping` | a job whose value is a scalar or list |
| 15 | `job-level key outside the generated job keys name, runs-on, timeout-minutes, env, steps` | `container`, `services`, `snapshot`, `environment`, `strategy`, `outputs`, `defaults`, `needs`, `continue-on-error`, `if`, `uses`/`with`/`secrets` of a reusable workflow (with or without `runs-on`), a job-level `permissions` (even read-only) or `concurrency`, differently cased or whitespace-padded keys, and any future field |
| 16 | `steps must be a list of step mappings with at least one step` | `steps` missing, empty, not a list, or containing a non-mapping |
| 17 | `step-level key outside the generated step keys name, uses, with, run, env` | `id`, `shell`, `working-directory`, `timeout-minutes`, `continue-on-error`, `if` and any other step field |
| 18 | `unreviewed workflow trigger` | an `on` that is not a mapping (a list or string shorthand included), or one with an event other than `push`, `pull_request`, `workflow_dispatch` |
| 19 | `only the standard hosted Ubuntu runner is configured` | any `runs-on` other than `ubuntu-24.04` |
| 20 | `writable job credentials are not permitted` | a job-level `permissions` other than read-only; tripwire behind rule 15, which already refuses the key |
| 21 | `CI must run on exactly main pushes, pull requests and manual dispatch` | `ci.yml` whose event set is not exactly `push`, `pull_request`, `workflow_dispatch` (a dropped event as well as an added one) |
| 22 | `CI must contain its documented single job` | `ci.yml` with any job set other than `ci` (an extra plain job, a second copy of the job, a renamed or differently cased id) |
| 23 | `Keep the required native CI job name stable` | `ci.yml` whose `ci` job is not named `CI` |
| 24 | `Copilot setup must run on manual dispatch only` | `copilot-setup-steps.yml` whose event set is not exactly `workflow_dispatch` (a gained `push` or `pull_request` included) |
| 25 | `Copilot setup must contain its documented single job` | `copilot-setup-steps.yml` with any job set other than `copilot-setup-steps` |
| 26 | `workflow file outside the generated pair ci.yml and copilot-setup-steps.yml` | any other path under `.github/workflows/` that reaches this stage, whatever its content (a `.yaml` twin, a differently cased name, a subdirectory or a third workflow) |

Rules 12-17 accept exactly the keys the generator emits, as the union over all profiles: job-level
and step-level `env` are emitted only by some profiles (web/admin telemetry opt-out, api coverage
base) but accepted for every consumer, because the checker does not know which profile it runs in.
`governance/tests/test_workflow_shape.py` derives the three allowlists from the rendered workflows of
every profile, so adding a key to the generator fails that test until the template lists it in the
same PR. Job-level `permissions` is deliberately not allowlisted: no profile emits it and the exact
workflow-level `permissions` is the rule. Step `id`, `shell`, `working-directory` and
`timeout-minutes` are not emitted either.

Rules 8-9 bind each `uses` to one of four names at one commit each; `test_workflow_validation.py`
derives both mappings from the rendered workflows of every profile, so a pin bump or a new action
in `generate.py` fails until the checker carries it. Rules 21-26 bind each generated workflow file
to its own trigger set and single job; the filters under an event (`branches`, `paths`, `types`,
dispatch `inputs`) are not bound by them (their strings are still walked by rules 5-6), which is a
disclosed residual, not a guarantee.

Beyond workflows, `check()` requires the generated file set, refuses tracked symlinks, key material
by file name, obvious token/private-key patterns (content withheld), invalid UTF-8 in text files and
invalid JSON in `*.json` (a top-level JSON array remains valid JSON there; only a workflow must be an
object). Passing the checker is a repository-foundation result, never product acceptance.

## Provenance

PR C (#45) added the whole-context secret guard and `.gitattributes` shape allowlist; PR D (#48)
moved the tripwire to decoded strings and added the `if`, action and input rules; PR E (#50) added
the top-level, job-level and step-level key allowlists (rules 3, 12-17), the surfaced rule messages
and the BOM / non-object / depth hardening of `json_document` and `check()`; PR F (#54) bound each
listed action to its generated pin (rule 9, rendered from `repository-profiles.json`), bound each
workflow file to its trigger set and single job (rules 21-22, 24, 26), and made this table's order
and the generated-file list above test-enforced.
