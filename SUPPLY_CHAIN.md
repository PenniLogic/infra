# Supply-chain verification gates (PenniLogic/infra#31, T-QA-11)

Source-level checks for infrastructure, container, Android and built-artifact risks, plus the deployment-gate
verification of signatures, CycloneDX SBOMs and in-toto/SLSA provenance. Python 3.14, standard library only, no
network, no Docker, no scanner binaries and no keys.

**Status: proposed source work, not accepted.** Nothing here is wired into CI, publication or deployment yet, and
nothing here performs real signature verification. The held criteria are listed in
[Held and not claimed](#held-and-not-claimed). Every severity, threshold, rule id and report field below is a
proposal awaiting owner confirmation.

## What is checked

| Gate | Input | Fails on |
| --- | --- | --- |
| `compose` | `docker compose config --format json` rendering | privileged, host namespaces, Docker socket, dangerous capabilities, unconfined profiles, non-loopback published ports, images not pinned by digest |
| `android` | merged release `AndroidManifest.xml` (+ network security config) | debuggable, backup allowed, cleartext traffic, unprotected exported components, legacy storage, user CAs |
| `trivy` | `trivy image` or `trivy config` JSON (SchemaVersion 2) | findings at or above the threshold; an image report must name the expected `sha256:` digest |
| `checkov` | `checkov -o json` report | failed or skipped checks at or above the threshold |
| `sbom` | artifact file + CycloneDX 1.4-1.6 JSON | incomplete components (name, version, `pkg:` purl, strong hash), duplicate `bom-ref`, dangling dependency, missing serial number, `metadata.component` SHA-256 not equal to the artifact digest |
| `provenance` | artifact file + in-toto Statement v1 / SLSA provenance v1 | artifact digest not a subject, missing builder id or build type |
| `deploy` | artifact + SBOM + provenance + detached signatures | any `sbom`/`provenance` finding, and any member (artifact, SBOM, provenance) unsigned or not accepted by the verifier |

Incomplete, errored, empty or malformed inputs are refused (exit 2), never passed: duplicate JSON keys, a BOM,
`NaN`, DOCTYPE/ENTITY declarations, empty scan results, report counts that disagree with the listed checks, and
an image report for a different digest are all refusals. Android boolean attributes are read as the platform
parser reads them (surrounding whitespace ignored; `true`/`TRUE`/`True` and `false`/`FALSE`/`False`); any other
value, including an `@bool/...` resource reference that is resolved only at link time, is refused
(`SC-ANDROID-VALUE`, `SC-ANDROID-NSC-VALUE`) rather than treated as safe.

## Usage

```text
python scripts/supply_chain_cli.py <gate> --artifact-id <id> [--policy <path>] <gate options>

compose    --input <rendering.json>
android    --manifest <AndroidManifest.xml> [--network-config <network_security_config.xml>]
trivy      --kind image|config --input <report.json> [--expected-digest sha256:<hex>]
checkov    --input <report.json>
sbom       --artifact <file> --sbom <bom.cdx.json>
provenance --artifact <file> --provenance <statement.json>
deploy     --artifact <file> --sbom <bom.cdx.json> --provenance <statement.json> --signatures <signatures.json>
```

- `--artifact-id` matches `[a-z0-9][a-z0-9._/-]{0,127}`; it is a label, not a path.
- `trivy --kind image` requires `--expected-digest` (the image digest the report must name); `--kind config`
  refuses it.
- Every option takes exactly one separate value (`--name value`). Unknown, repeated, abbreviated or missing
  options are usage errors. There is no option that selects a verifier, an exceptions source or a report-only
  mode.
- `--signatures` is a JSON object with optional members `artifact`, `sbom` and `provenance`, each a non-empty
  signature object or `null`. An absent or `null` member is **unsigned** and fails the gate.
- The artifact digest is the SHA-256 of the exact bytes read once from `--artifact` (regular files only, at most
  4 GiB). Paths are opened as given and symbolic links are followed: the gate binds the bytes read, not names.
  Directories, FIFOs and devices are refused, also when swapped in between the check and the open.

Exit status: `0` pass, `1` gate failure, `2` usage error or refused input. Each run prints exactly one ASCII JSON
line. A report carries `decision`, `gate`, `blocking_threshold`, the exceptions status, counts by scanner and
severity, by effect and by rule, and findings with static rule ids, severity, severity basis, location class and a
`sha256:` fingerprint. A refusal carries `decision: "refused"`, a static `code` and, for an unreadable input, the
static option name. No argument value, path, file content, digest or exception text is echoed.

### Examples with the committed synthetic fixtures

```text
python scripts/supply_chain_cli.py compose --artifact-id infra/compose \
  --input scripts/tests/fixtures/supply_chain/compose-rendered-planted-privileged.json      # exit 1
python scripts/supply_chain_cli.py android --artifact-id android/release \
  --manifest scripts/tests/fixtures/supply_chain/android-manifest-planted-insecure.xml       # exit 1
```

`deploy` exits 1 with `SC-SIG-VERIFIER-UNAVAILABLE` for every member on every input today: real signature
verification is held (see below), and an unavailable verifier fails closed.

## Policy, exceptions and rollout

- [`scripts/supply-chain/policy.json`](scripts/supply-chain/policy.json) holds one value, `blocking_threshold`
  (`high`: high and critical findings block). It cannot be set weaker than `high`, and it has no mode,
  report-only, per-rule or signature key; any other key is refused. Its `status` is `proposed, not agreed`.
- Signature (`SC-SIG-*`) and subject-binding (`SC-SUBJECT-*`) findings are critical, block at every threshold and
  are never offered to an exceptions source. **Signature verification cannot be disabled or set to report-only.**
- Exceptions belong to [infra#23](https://github.com/PenniLogic/infra/issues/23). Until it integrates, every
  report states `exceptions unavailable (infra#23 not integrated)` and every finding stays unexcepted. The gates
  define no exception record, file or schema; the planned binding is infra#23's
  `security_exceptions.Exceptions.load(path, now)` and `Exceptions.suppression(...)`, which has no supply-chain
  kind yet (open question for the infra#23 owner). A future suppression is published with its id, never hidden.
- Rollout (ticket): run report-only long enough to measure noise, then block high and critical per scanner.
  Rollback (ticket): one noisy rule may return to reporting with a named owner and expiry. Both need the infra#23
  exception mechanism and CI wiring; neither the noise window nor any rollback has happened.

## Observability

Each report counts findings by scanner and severity, by effect (`fail`, `report`, `excepted`) and by rule, so
unsigned-artifact rejections (`SC-SIG-UNSIGNED`) and provenance verification failures
(`SC-SUBJECT-PROVENANCE-MISMATCH`, `SC-PROV-*`) are countable. Exception age needs infra#23. Nothing is published
to a dashboard yet.

## Tests

```text
python -m unittest discover -s scripts/tests -p "test_supply_chain_*.py"
```

All fixtures are synthetic. Each negative has a passing control and one mutation and asserts the exact rule id.
Signature orchestration is tested with a test-only HMAC fake whose key is generated at run time and never stored;
it proves orchestration only, not production signature fidelity. Tests never write inside the repository, use no
network, Docker or external binary, and must pass on Linux and Windows without skips.

## Held and not claimed

These stay open and are not demonstrated by this source work:

- **Real artifacts**: release candidates and AAB/APK outputs from
  [android#37](https://github.com/PenniLogic/android/issues/37); the Android fixtures here are synthetic.
- **Release record**: linking each SBOM from its release record and the release checklist belong to
  [docs#23](https://github.com/PenniLogic/docs/issues/23).
- **Signing custody**: managed key custody, keeping keys away from non-signing build steps, and every signing-key
  or credential action. No key exists in this work.
- **cosign integration**: real signature and attestation (DSSE/bundle) verification, the trust root and the builder
  allow-list. Until then the production verifier is unavailable and `deploy` fails closed.
- **CI wiring**: running the gates and real scanners (trivy, checkov, syft or another CycloneDX generator) in CI,
  scanning images before publication and again before deployment, and registering required checks. Workflows are
  generated files owned by the generator owner.
- **Published result schemas** for the release checklist (scan, SBOM and provenance results): the report shape
  here is proposed, pending infra#28 and infra#23 vocabulary alignment.
- **T-GOV-03 second reviewer**: independent second-reviewer approval (or an external independent review) is a
  hard merge blocker. Author self-reviews do not count.
- **[infra#23](https://github.com/PenniLogic/infra/issues/23)**: exception mechanism integration (acceptance
  criterion 6 stays unmet).
- **[infra#22](https://github.com/PenniLogic/infra/issues/22)**: its unresolved conformance hold is preserved.
