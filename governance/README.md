# Governance: the canonical generator and the generated checker

`generate.py` renders the small public-repository baseline for every repository in
`repository-profiles.json` (`.github/workflows/ci.yml`, `.github/workflows/copilot-setup-steps.yml`,
`AGENTS.md`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CONSTITUTION.md`, `COPILOT_FILES.md`,
`.github/copilot-instructions.md`, `.github/agent-policy.json`, `.github/CODEOWNERS`,
`.github/github-app.yml`, `.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/*`,
`.gitattributes`, `.gitignore`, `scripts/setup.py` and `scripts/check_repository.py`). Consumers never
hand-edit those files: a profile or template change lands here through a reviewed generator PR, then
each consumer regenerates from the merged `main` in its own PR.

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

The template is copied verbatim into every consumer as `scripts/check_repository.py` and runs from the
managed pre-commit hook (`--staged`) and as the first CI command. It is a **drift tripwire**, not the
security boundary: a pull request that can edit a workflow can edit the checker too, and the
workflow token is already `contents: read`. It refuses anything the generator does not emit so a
hand-edit is visible before review, without network access or third-party dependencies.

Every refusal is a `Refused` (a `ValueError`) whose message is **static rule text**. `check()` prints
`Invalid or unsafe workflow: <file>: <rule>` (or `Invalid JSON in <file>: <rule>`); no key, value or
other content of the refused file is ever echoed, and a non-printable path is shown as
`[non-printable path]`. Input that is not a UTF-8 JSON document of bounded depth, or a shape no rule
anticipated, fails closed with the one line `...: not a parseable UTF-8 JSON-syntax document`
(never a traceback).

Rules, in evaluation order (the first matching rule is the one reported, so a token is always named
before a placement, and a condition or unlisted action before the key allowlists):

| # | Rule text | Refuses |
|---|-----------|---------|
| 1 | `UTF-8 byte order mark before the JSON document` | a BOM that `json.loads(bytes)` would otherwise skip (UTF-16/32 input instead fails the strict UTF-8 decode and gets the parse fallback line) |
| 2 | `Duplicate JSON key` | a repeated key at any depth, which parsers resolve differently |
| 3 | `workflow document must be one JSON object` | a top-level array, string, number, boolean or `null` |
| 4 | `expected read-only workflow token` | any workflow `permissions` other than `{"contents": "read"}` |
| 5 | `unreviewed workflow expression; public jobs must not receive secrets` | every `${{ ... }}` outside `WORKFLOW_EXPRESSIONS`, at any depth |
| 6 | `public candidate jobs must not receive secrets` | the `secrets` context or `github.token` in any key or string, including whitespace-split and whole-context forms (tripwire behind rule 5) |
| 7 | `conditions are not part of the generated workflows` | the key `if` in any mapping (job, step, snapshot or any other depth) |
| 8 | `action must be immutable and one of the generated GitHub-owned actions` | any `uses` that is not one of `WORKFLOW_ACTIONS` pinned to a 40-hex commit, including reusable-workflow jobs, local and `docker://` actions |
| 9 | `unreviewed action input; only the generated inputs are accepted` | a `with` key outside the per-action input allowlist, or a non-mapping `with` |
| 10 | `checkout must not retain credentials` | `actions/checkout` without `persist-credentials: false` |
| 11 | `top-level key outside the generated workflow keys name, on, permissions, concurrency, jobs` | a top-level `env`, `defaults`, `run-name`, merge key or any other field |
| 12 | `jobs must be a mapping of job ids with at least one job` | `jobs` missing, empty, a list or a scalar |
| 13 | `job must be a mapping` | a job whose value is a scalar or list |
| 14 | `job-level key outside the generated job keys name, runs-on, timeout-minutes, env, steps` | `container`, `services`, `snapshot`, `environment`, `strategy`, `outputs`, `defaults`, `needs`, `continue-on-error`, `if`, `uses`/`with`/`secrets` of a reusable workflow, a job-level `permissions` (even read-only) or `concurrency`, differently cased or whitespace-padded keys, and any future field |
| 15 | `steps must be a list of step mappings with at least one step` | `steps` missing, empty, not a list, or containing a non-mapping |
| 16 | `step-level key outside the generated step keys name, uses, with, run, env` | `id`, `shell`, `working-directory`, `timeout-minutes`, `continue-on-error`, `if` and any other step field |
| 17 | `unreviewed workflow trigger` | an `on` that is not a mapping, or one with an event other than `push`, `pull_request`, `workflow_dispatch` |
| 18 | `only the standard hosted Ubuntu runner is configured` | any `runs-on` other than `ubuntu-24.04` |
| 19 | `writable job credentials are not permitted` | a job-level `permissions` other than read-only; tripwire behind rule 14, which already refuses the key |
| 20 | `CI must run on both main pushes and pull requests` | `ci.yml` without both triggers |
| 21 | `Keep the required native CI job name stable` | `ci.yml` whose `ci` job is not named `CI` |
| 22 | `Copilot setup must contain its documented single job` | `copilot-setup-steps.yml` with any job set other than `copilot-setup-steps` |

Rules 11-16 accept exactly the keys the generator emits, as the union over all profiles: job-level
and step-level `env` are emitted only by some profiles (web/admin telemetry opt-out, api coverage
base) but accepted for every consumer, because the checker does not know which profile it runs in.
`governance/tests/test_workflow_shape.py` derives the three allowlists from the rendered workflows of
every profile, so adding a key to the generator fails that test until the template lists it in the
same PR. Job-level `permissions` is deliberately not allowlisted: no profile emits it and the exact
workflow-level `permissions` is the rule. Step `id`, `shell`, `working-directory` and
`timeout-minutes` are not emitted either.

Beyond workflows, `check()` requires the generated file set, refuses tracked symlinks, key material
by file name, obvious token/private-key patterns (content withheld), invalid UTF-8 in text files and
invalid JSON in `*.json` (a top-level JSON array remains valid JSON there; only a workflow must be an
object). Passing the checker is a repository-foundation result, never product acceptance.

## Provenance

PR C (#45) added the whole-context secret guard and `.gitattributes` shape allowlist; PR D (#48)
moved the tripwire to decoded strings and added the `if`, action and input rules; PR E (#50) added
the top-level, job-level and step-level key allowlists (rules 3, 11-16), the surfaced rule messages
and the BOM / non-object / depth hardening of `json_document` and `check()`.
