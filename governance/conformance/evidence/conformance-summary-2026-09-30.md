# CI conformance report

- Result: **PASS** across 9 repositories
- Generator commit (PenniLogic/infra): `66b0fc12cdc62fed1b34ad139522b7443c5859ba`
- GitHub reads: `anonymous` client, 45 requests, 15 anonymous requests remaining
- Planted-defect toolchains exercised: node, python, uv
- Wall-clock budget: 10 minutes per main CI run
- Generated at: 2026-09-30T14:53:28+00:00

A passing row is a repository-foundation result; it is not product, release or security acceptance.

| Repository | main | Generated workflow | Own checker | Required check | Last main CI | Wall-clock | Planted defects | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PenniLogic/.github | `58972bab7f25` | identical (1 stale non-workflow files) | passed | `CI` | success | 0 min 16 s | 8/8 proved, 0 not exercised | **PASS** |
| PenniLogic/docs | `c2726e6322a7` | identical (1 stale non-workflow files) | passed | `CI` | success | 0 min 19 s | 10/11 proved, 0 not exercised | **PASS** |
| PenniLogic/contracts | `cff371179a70` | identical (1 stale non-workflow files) | passed | `CI` | success | 1 min 50 s | 8/8 proved, 0 not exercised | **PASS** |
| PenniLogic/api | `68341c0a9246` | identical (1 stale non-workflow files) | passed | `CI` | success | 1 min 43 s | 8/8 proved, 1 not exercised | **PASS** |
| PenniLogic/ai-service | `1c3d5aa3c914` | identical (1 stale non-workflow files) | passed | `CI` | success | 0 min 27 s | 8/8 proved, 0 not exercised | **PASS** |
| PenniLogic/android | `14394cf966bf` | identical (1 stale non-workflow files) | passed | `CI` | success | 9 min 28 s | 8/8 proved, 1 not exercised | **PASS** |
| PenniLogic/web | `4b63423a8762` | identical (1 stale non-workflow files) | passed | `CI` | success | 0 min 38 s | 8/8 proved, 0 not exercised | **PASS** |
| PenniLogic/admin | `302c7b593600` | identical (1 stale non-workflow files) | passed | `CI` | success | 0 min 56 s | 8/8 proved, 0 not exercised | **PASS** |
| PenniLogic/infra | `8f605422f668` | identical | passed | `CI` | success | 1 min 28 s | 8/8 proved, 0 not exercised | **PASS** |

## Findings

No failures.

- warning PenniLogic/.github: generated non-workflow files predate the current generator: scripts/check_repository.py
- warning PenniLogic/docs: generated non-workflow files predate the current generator: scripts/check_repository.py
- warning PenniLogic/docs: main moved since the last completed CI run; results describe the cloned commit
- warning PenniLogic/contracts: generated non-workflow files predate the current generator: scripts/check_repository.py
- warning PenniLogic/api: generated non-workflow files predate the current generator: scripts/check_repository.py
- warning PenniLogic/api: kotlin planted defects not exercised in this run; evidence is the consumer's last main CI run
- warning PenniLogic/ai-service: generated non-workflow files predate the current generator: scripts/check_repository.py
- warning PenniLogic/android: generated non-workflow files predate the current generator: scripts/check_repository.py
- warning PenniLogic/android: kotlin planted defects not exercised in this run; evidence is the consumer's last main CI run
- warning PenniLogic/web: generated non-workflow files predate the current generator: scripts/check_repository.py
- warning PenniLogic/admin: generated non-workflow files predate the current generator: scripts/check_repository.py

## Branch rulesets on main (read-only)

| Repository | Rulesets | Required checks (integration) | Up to date | PR only | Approvals | Threads resolved | Linear | Force push | Deletion | Bypass actors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PenniLogic/.github | Protect main (active) | `CI` (15368) | True | True | 0 | True | True | blocked | blocked | 0 |
| PenniLogic/docs | Protect main (active) | `CI` (15368) | True | True | 0 | True | True | blocked | blocked | 0 |
| PenniLogic/contracts | Protect main (active) | `CI` (15368) | True | True | 0 | True | True | blocked | blocked | 0 |
| PenniLogic/api | Protect main (active) | `CI` (15368) | True | True | 0 | True | True | blocked | blocked | 0 |
| PenniLogic/ai-service | Protect main (active) | `CI` (15368) | True | True | 0 | True | True | blocked | blocked | 0 |
| PenniLogic/android | Protect main (active) | `CI` (15368) | True | True | 0 | True | True | blocked | blocked | 0 |
| PenniLogic/web | Protect main (active) | `CI` (15368) | True | True | 0 | True | True | blocked | blocked | 0 |
| PenniLogic/admin | Protect main (active) | `CI` (15368) | True | True | 0 | True | True | blocked | blocked | 0 |
| PenniLogic/infra | Protect main (active) | `CI` (15368) | True | True | 0 | True | True | blocked | blocked | 0 |

## Planted defects

### PenniLogic/.github

| Fixture | Language | Toolchain | Outcome | Probes |
| --- | --- | --- | --- | --- |
| `workflow-test-step-removed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-test-step-stubbed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-step-skipped-by-condition` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-unpinned-action` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-reusable-workflow-job` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-step-continue-on-error` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); current infra template check_repository.py over the scratch tree -> exit 1 (as_expected) |
| `python-tests-removed` | python | python | proved | profile command: python -m unittest discover -s scripts/tests -> exit 5 (as_expected) |
| `python-test-failing` | python | python | proved | profile command: python -m unittest discover -s scripts/tests -> exit 1 (as_expected) |

Detected steps - build: 0, test: 1, lint: 1, consumer self-tests: 0.

### PenniLogic/docs

| Fixture | Language | Toolchain | Outcome | Probes |
| --- | --- | --- | --- | --- |
| `workflow-test-step-removed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-test-step-stubbed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-step-skipped-by-condition` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-unpinned-action` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-reusable-workflow-job` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-step-continue-on-error` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); current infra template check_repository.py over the scratch tree -> exit 1 (as_expected) |
| `python-tests-removed` | python | python | proved | profile command: python -m unittest discover -s scripts/tests -> exit 5 (as_expected) |
| `python-test-failing` | python | python | proved | profile command: python -m unittest discover -s scripts/tests -> exit 1 (as_expected) |
| `documentation-index-link-broken` | documentation | python | proved | profile command: python scripts/check_docs.py -> exit 1 (as_expected) |
| `documentation-dangling-supersedes` | documentation | python | proved | profile command: python scripts/check_docs.py -> exit 1 (as_expected) |
| `documentation-body-link-broken` | documentation | python | recorded | profile command: python scripts/check_docs.py -> exit 0 (not_detected) |

Detected steps - build: 0, test: 1, lint: 2, consumer self-tests: 0.

### PenniLogic/contracts

| Fixture | Language | Toolchain | Outcome | Probes |
| --- | --- | --- | --- | --- |
| `workflow-test-step-removed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-test-step-stubbed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-step-skipped-by-condition` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-unpinned-action` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-reusable-workflow-job` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-step-continue-on-error` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); current infra template check_repository.py over the scratch tree -> exit 1 (as_expected) |
| `python-tests-removed` | python | python | proved | profile command: python -m unittest discover -s scripts/tests -p "test_*.py" -> exit 5 (as_expected) |
| `python-test-failing` | python | python | proved | profile command: python -m unittest discover -s scripts/tests -p "test_*.py" -> exit 1 (as_expected) |

Detected steps - build: 1, test: 4, lint: 2, consumer self-tests: 0.

### PenniLogic/api

| Fixture | Language | Toolchain | Outcome | Probes |
| --- | --- | --- | --- | --- |
| `workflow-test-step-removed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-test-step-stubbed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-step-skipped-by-condition` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-unpinned-action` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-reusable-workflow-job` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-step-continue-on-error` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); current infra template check_repository.py over the scratch tree -> exit 1 (as_expected) |
| `python-tests-removed` | python | python | proved | profile command: python -m unittest discover -s scripts/tests -> exit 5 (as_expected) |
| `python-test-failing` | python | python | proved | profile command: python -m unittest discover -s scripts/tests -> exit 1 (as_expected) |
| `kotlin-test-failing` | kotlin | java | not exercised | toolchain java not exercised in this run |

Detected steps - build: 1, test: 2, lint: 1, consumer self-tests: 0.

### PenniLogic/ai-service

| Fixture | Language | Toolchain | Outcome | Probes |
| --- | --- | --- | --- | --- |
| `workflow-test-step-removed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-test-step-stubbed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-step-skipped-by-condition` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-unpinned-action` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-reusable-workflow-job` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-step-continue-on-error` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); current infra template check_repository.py over the scratch tree -> exit 1 (as_expected) |
| `python-pytest-failing` | python | uv | proved | prepare: uv sync --locked -> exit 0 (as_expected); profile command: uv run --locked pytest -> exit 1 (as_expected) |
| `python-pytest-removed` | python | uv | proved | prepare: uv sync --locked -> exit 0 (as_expected); profile command: uv run --locked pytest -> exit 5 (as_expected) |

Detected steps - build: 0, test: 1, lint: 3, consumer self-tests: 0.

### PenniLogic/android

| Fixture | Language | Toolchain | Outcome | Probes |
| --- | --- | --- | --- | --- |
| `workflow-test-step-removed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-test-step-stubbed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-step-skipped-by-condition` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-unpinned-action` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-reusable-workflow-job` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-step-continue-on-error` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); current infra template check_repository.py over the scratch tree -> exit 1 (as_expected) |
| `python-tests-removed` | python | python | proved | profile command: python -m unittest discover -s scripts/tests -p "test_*.py" -> exit 5 (as_expected) |
| `python-test-failing` | python | python | proved | profile command: python -m unittest discover -s scripts/tests -p "test_*.py" -> exit 1 (as_expected) |
| `kotlin-android-self-test` | kotlin | android | not exercised | toolchain android not exercised in this run |

Detected steps - build: 1, test: 4, lint: 1, consumer self-tests: 1.

### PenniLogic/web

| Fixture | Language | Toolchain | Outcome | Probes |
| --- | --- | --- | --- | --- |
| `workflow-test-step-removed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-test-step-stubbed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-step-skipped-by-condition` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-unpinned-action` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-reusable-workflow-job` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-step-continue-on-error` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); current infra template check_repository.py over the scratch tree -> exit 1 (as_expected) |
| `typescript-test-failing` | typescript | node | proved | prepare: npm ci -> exit 0 (as_expected); profile command: npm test -> exit 1 (as_expected) |
| `typescript-tests-removed` | typescript | node | proved | prepare: npm ci -> exit 0 (as_expected); profile command: npm test -> exit 1 (as_expected) |

Detected steps - build: 1, test: 2, lint: 5, consumer self-tests: 1.

### PenniLogic/admin

| Fixture | Language | Toolchain | Outcome | Probes |
| --- | --- | --- | --- | --- |
| `workflow-test-step-removed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-test-step-stubbed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-step-skipped-by-condition` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-unpinned-action` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-reusable-workflow-job` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-step-continue-on-error` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); current infra template check_repository.py over the scratch tree -> exit 1 (as_expected) |
| `typescript-test-failing` | typescript | node | proved | prepare: npm ci --no-audit --no-fund -> exit 0 (as_expected); profile command: npm test -> exit 1 (as_expected) |
| `typescript-tests-removed` | typescript | node | proved | prepare: npm ci --no-audit --no-fund -> exit 0 (as_expected); profile command: npm test -> exit 1 (as_expected) |

Detected steps - build: 1, test: 2, lint: 3, consumer self-tests: 0.

### PenniLogic/infra

| Fixture | Language | Toolchain | Outcome | Probes |
| --- | --- | --- | --- | --- |
| `workflow-test-step-removed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-test-step-stubbed` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 0 (not_detected) |
| `workflow-step-skipped-by-condition` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-unpinned-action` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-reusable-workflow-job` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); consumer scripts/check_repository.py -> exit 1 (as_expected, rule text surfaced) |
| `workflow-step-continue-on-error` | workflow | python | proved | generator drift check: generate.py --repository <profile> --root <scratch> --check -> exit 1 (as_expected); current infra template check_repository.py over the scratch tree -> exit 1 (as_expected) |
| `python-tests-removed` | python | python | proved | profile command: python -m unittest discover -s governance/tests -> exit 5 (as_expected); profile command: python -m unittest discover -s scripts/tests -> exit 5 (as_expected) |
| `python-test-failing` | python | python | proved | profile command: python -m unittest discover -s governance/tests -> exit 1 (as_expected); profile command: python -m unittest discover -s scripts/tests -> exit 1 (as_expected) |

Detected steps - build: 0, test: 2, lint: 1, consumer self-tests: 0.

## Not run in this report

- java planted defects not exercised for: api
- android planted defects not exercised for: android
