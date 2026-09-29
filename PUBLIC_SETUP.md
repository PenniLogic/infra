# Public setup baseline

Verified on **2026-09-29**. This records repository foundations, not product or
release acceptance.

## Identity and native CI

The new `PenniLogic` organization is on GitHub Free (organization ID `335295566`).
Its nine public repositories are `.github`, `docs`, `contracts`, `api`,
`ai-service`, `android`, `web`, `admin` and `infra`.

This repository is `PenniLogic/infra` (repository ID `1394135059`), not
`PenniLogic-old/infra`. Its verified initial `main` commit is
[`c0dc7a81610a60cd9e4254d3e485658299cc8250`](https://github.com/PenniLogic/infra/commit/c0dc7a81610a60cd9e4254d3e485658299cc8250).
The native [`CI` push run 36517969805](https://github.com/PenniLogic/infra/actions/runs/36517969805)
completed successfully on standard GitHub-hosted Ubuntu. Its check is reported
by GitHub Actions (App ID `15368`), not a custom check publisher.

## Verified infra safeguards

- Active `Protect main` requires PR-only squash integration, resolved review
  threads, linear history and an up-to-date branch with the native `CI` check
  from App ID `15368`. Force pushes and deletion are blocked; bypass is empty.
- The required GitHub approving-review count is zero because there is one owner.
  Separate non-author Core review of the exact commit is still required by the
  [delivery policy](https://github.com/PenniLogic/docs/blob/main/governance/DELIVERY.md);
  multiple AI sessions are not two-human approval.
- Secret scanning and push protection are enabled. Workflow tokens default to
  read-only and cannot approve PRs. Repository Actions policy allows GitHub-owned
  actions and requires SHA pinning; this is not an organization-wide pinning claim.
  The checked-in workflows use immutable action SHAs and standard hosted runners.

## Backlog and implementation boundaries

See the [migration record](https://github.com/PenniLogic/docs/blob/main/MIGRATION.md)
and [new delivery board](https://github.com/orgs/PenniLogic/projects/1).
The board is currently access-restricted and contains 351 unfinished draft cards,
all initially `Todo`; legacy statuses are provenance, not current readiness.
The public [source backlog](https://github.com/PenniLogic/docs/blob/main/planning/backlog.json)
preserves all 427 records, including 76 historically Done cards. Drafts are not
implemented features, and historical Done does not establish new release acceptance.

`infra` provides development-only Compose and repository automation, not production
deployment. The accepted executable application scaffold is the API's Kotlin/Ktor
health service; authentication, ledger and product APIs remain unimplemented.
AI-service, Android, Web, Admin and Contracts still need their product/scaffold
delivery. Passing foundation checks is not evidence that those products work.
Old history, unmerged work and unresolved findings remain in `PenniLogic-old`;
this setup does not accept or clear them.

## Cost and publication limits

Free standard public-repository runner minutes do not mean free AI inference,
Copilot usage, application hosting, larger runners or unlimited artifact/cache
storage. This setup authorizes no deployment, purchase or allowance increase.
No open-source license was selected; public visibility alone is not a license grant.
