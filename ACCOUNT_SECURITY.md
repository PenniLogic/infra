# Owner-account and credential security baseline

**Document preparation: 2026-10-02; not a control verification date.**
Source preparation only for [infra#43](https://github.com/PenniLogic/infra/issues/43)
and threat-model finding E01-F04. Owner verification is **UNAVAILABLE** in this
delivery; every account control is **OWNER_VERIFICATION_PENDING** and the
revocation drill is **NOT_REHEARSED**. This document does not establish that the
account is hardened or satisfy the issue's full acceptance criteria.

The GitHub owner is `basiltt` (user ID `54134686`); the public organization is
`PenniLogic` (ID `335295566`) and Infra is repository ID `1394135059`.
Copilot AI and its subscription remain on **`basil-tt_hpeprod`**, unchanged.
Credential maintenance here concerns only the personal owner's repository
access, not corporate authentication, AI entitlements or billing.

## Policy, observation and verification

**POLICY** below means the required target, not a deployed or verified setting.
Cadences are proposed operating defaults for owner approval; no review or
rotation has been performed. A control gets an actual verification date only
after the owner supplies safe evidence.

**Observed repository baseline:** accepted Infra source
`c4a73a0713c59faaa2c80ce7d78d8b74ea1093a2` contains SHA-pinned GitHub-owned
Actions, read-only workflow permissions, checkout without persisted credentials
and the repository checker. [PUBLIC_SETUP.md](PUBLIC_SETUP.md) is a historical
repository-settings snapshot, not account or organization verification.
Generated source, policies, workflows, hooks, profiles and the check registry
are unchanged by this documentation slice.

These controls do not enforce native per-ticket or per-worktree credentials.
A machine token can be shared by sessions under the same OS user; a compromised
owner can still change administrative settings. The existing
[delivery policy](https://github.com/PenniLogic/docs/blob/main/governance/DELIVERY.md)
and [instruction-provenance procedure](https://github.com/PenniLogic/.github/blob/main/docs/instruction-provenance.md)
still require exclusive ownership and refusal of out-of-scope writes.

| ID | POLICY requirement | Owner verification method; record descriptions only | Proposed cadence | Current state |
| --- | --- | --- | --- | --- |
| C1 | Enable 2FA and use a phishing-resistant security key or passkey for owner sign-in. SMS/TOTP alone does not meet the phishing-resistant requirement. | Describe Password and authentication page state and registered method type; owner confirms a successful sign-in with that method. A passkey can satisfy password and 2FA together; token use is not an MFA challenge. | Before acceptance; quarterly and after authenticator/device changes | OWNER_VERIFICATION_PENDING |
| C2 | Keep current, one-time recovery codes offline, separate from the development machine; retain an independent recovery method. | Confirm offline custody and an accessible independent recovery path without opening, copying or disclosing codes to a session. Record a custody description, not a physical location or secret. | Before any revocation window; quarterly and whenever recovery methods/codes change | OWNER_VERIFICATION_PENDING |
| C3 | Use a distinct fine-grained PAT per machine, selected repositories only, minimum permissions and a finite expiry. Do not share token values between machines. | Describe each token's nonsecret record ID/alias, machine alias, resource owner, selected repositories, permissions and expiry from Developer settings. Check each needed operation against GitHub's permission reference; identify classic/OAuth credentials and deviations explicitly. | At issue/reissue; monthly inventory and on machine loss or scope changes | OWNER_VERIFICATION_PENDING |
| C4 | Store repository credentials in an encrypted OS-keychain-backed credential store, never plaintext files. | Owner confirms the selected `basiltt` credential's actual backend and OS-store binding using nonsecret backend metadata, without extracting a keychain item. A masked local status may help; report only the conclusion and method. If evidence is unavailable, keep this pending. | Before use/recredentialing; monthly and after OS/CLI/helper changes | OWNER_VERIFICATION_PENDING |
| C5 | Set PAT expiry to at most 30 days; for a 30-day token, rotate by seven days before expiry. Shorter lifetimes require an owner-approved lead time that still precedes expiry. Revoke suspected exposed/lost-device credentials immediately; reissue only after incident recovery. | Record old/new token record IDs and expiry/rotation dates, never values. For routine rotation, validate the replacement before revoking the old token; the drill below deliberately tests loss of access before replacement. | Monthly, before expiry, and on incident | OWNER_VERIFICATION_PENDING |
| C6 | Maintain an owner-monitored sign-in/security alert path and review account activity. | Describe the owner's reachable verified primary/backup email path and security-log review. Record only alert/event type and date, not messages, addresses, IPs or device details. Unexpected alerts go privately to the owner and coordinator. | Monitor alerts when received; review security log weekly and after incidents | OWNER_VERIFICATION_PENDING |
| C7 | Revoke all personal-owner tokens and active sessions; prove each delivery session's old credential fails, then owner reissues and restores access without changing corporate Copilot. | Use the approved maintenance procedure below; record session aliases, credential record IDs, timestamps, authenticated failure/recovery outcomes and exceptions. No successful drill is recorded here. | Once before full acceptance; proposed quarterly and after material credential changes | NOT_REHEARSED |

### Least privilege and the credential-store limitation

For C3, select the `PenniLogic` resource owner and only the repositories needed
by that machine's approved work. Metadata read access is inherent; grant
Contents write only to source writers, and Issues/Pull requests permissions only
for specifically assigned operations. Routine delivery tokens should not carry
organization/repository Administration, secrets, permission management, workflow
write or billing/Copilot grants. Administrative owner work needs a separately
approved, short-lived scope, not a blanket delivery credential.

Fine-grained tokens have feature limitations and cannot span resource owners.
Do not silently replace one with a broadly scoped classic token when an endpoint
fails: hand off the unsupported operation and record the owner's decision.
Repository selection does not prevent reading other **public** repositories.
Per-machine scope is also not native per-ticket isolation; that remains unresolved.

GitHub CLI normally uses a system credential store but can fall back to a
plaintext file. Its presence, successful authentication, a masked token,
filesystem ACLs or whole-disk encryption alone do not prove C4. The existing
personal-account selector's ability to retrieve a credential proves neither its
type/scope/expiry nor its storage backend. None was inspected in this delivery.

The CLI also cautions that fine-grained PATs can behave unexpectedly with
`--with-token`; its documented environment-variable alternative is not a reason
to copy tokens into shell commands, environment setup files, logs or agent
prompts. The owner must establish a compatible, keychain-backed path first.
If that cannot be proven safely for the actual CLI/helper, stop and record C4
as pending. Do not use `--insecure-storage`, dump a credential store, print an
authentication token or switch the shared/global active account as a workaround.

GitHub security/device emails are not guaranteed for every sign-in, especially
with 2FA/passkeys. The owner must confirm the alert path rather than treating
absence of an email as evidence of safety. Review the account security log and
Sessions page as well; never forward raw events to public evidence.

## Safe owner evidence checklist

The owner alone performs verification. A session prepares documentation and
records an owner's nonsensitive description; it does not attest to unseen
settings. Keep the issue open while required evidence is missing.

- For each C1-C7 and O1-O7, record the control ID, actual observation date,
  owner account ID, method, short evidence description, outcome, next due date
  and any deviation/decision. Until then, the verification date is **not recorded**.
- Use token/app/session record IDs or synthetic aliases, repository names,
  permission names and dates only. No token strings, recovery codes, passkey
  material, authentication QR codes, credential exports, raw logs or screenshots
  containing sensitive details enter source, issues, PRs, prompts or artifacts.
- Supply separate descriptions for registered phishing-resistant authentication,
  offline recovery, machine token scopes/expiries, actual encrypted storage,
  rotation and alert delivery. One successful GitHub request proves none of these.
- For the drill, account for every delivery session, including dormant sessions,
  scheduled work and the coordinator. Record old-credential failure and
  replacement recovery separately, with missing participants explicitly pending.
- The coordinator records separate non-author Core and Security review of the
  exact source commit and actual native CI evidence on the eventual PR. Author
  self-review is not independent approval; multiple AI sessions are not two humans.

No owner evidence or control verification dates are supplied by this document.

## Owner-only organization blast-radius review

Every row is a **REVIEW recommendation**, **OWNER_VERIFICATION_PENDING**.
The owner must review dependencies and decide before making any change; this
runbook deploys no setting. Review quarterly and after membership, integration
or repository changes. Record current value, proposed value, affected principals
by nonsensitive IDs/aliases, decision/deviation and actual review date.

| ID | Setting and proposed target | Owner review and safety prerequisite |
| --- | --- | --- |
| O1 | Require organization 2FA; retain phishing-resistant C1 for the owner. | Inspect Organization Settings > Security/Authentication security. Confirm owner recovery and notify members, billing managers and outside collaborators first. Noncompliant members can lose access and outside collaborators can be removed; organization 2FA does not itself require phishing-resistant authentication or invalidate every token. |
| O2 | Base repository permission: None; grant only explicit required roles. | Inspect Member privileges and current role dependencies before changing. Public repository contents remain publicly readable; None is not a confidentiality boundary. |
| O3 | Public repository creation: owners only. | Review Member privileges/repository-creation controls and existing workflows. Record any unavailable control or exception; do not purchase a plan or create another owner to obtain it. |
| O4 | Actions policy: selected GitHub-owned actions, full SHA pinning; no additional allowlist. | Inspect organization Actions > General and each affected repository's effective restrictions. The generator's pinned source and historical Infra repository policy do not prove organization enforcement. Preserve existing native CI and approved workflows; identify any reusable-workflow constraint before a change. |
| O5 | Default workflow token: read-only; no workflow approval of PRs. | Review organization/repository workflow permissions and workflow-level grants. Keep existing Contents read, no persisted checkout credentials, public-job secret boundaries and protected-main requirements; a default alone does not prove every effective grant. |
| O6 | Installed GitHub Apps: necessary installations only, minimum repositories/permissions. | Review organization installations and owner-authorized GitHub Apps, their IDs, grants and dependent services. Propose removal/restriction of unused grants for separate owner approval; do not uninstall an app or disrupt CI during document preparation. |
| O7 | OAuth grants: only necessary authorized applications, minimum scope. | Review owner Settings > Applications and organization OAuth access restrictions. Include the CLI and credential helpers. Revoking a grant can invalidate its tokens and disrupt every dependent session; inventory and coordinate before any owner-approved action. |

Preserve PR-only, current-base integration, required native `CI`, resolved
threads, linear history, no force/deletion and an empty bypass list. Do not
weaken protections to restore access or call the source-only integrity gate
bootstrap accepted qualification. Free public Actions minutes do not authorize
paid runners, unlimited artifact/cache storage, inference, entitlement changes
or any allowance increase.

## Revocation and recredentialing runbook - OWNER ONLY, NOT_REHEARSED

This is disruptive, manual maintenance, **not authorization to run it**.
No revocation, logout, credential rotation, session invalidation, grant change
or recredentialing was performed while preparing this document.

1. **Authorize and coordinate.** The owner approves a maintenance window,
   participating machines/sessions, success deadline, abort criteria and recovery
   contact path outside GitHub. The coordinator pauses publication, protected
   merges, credential-dependent scheduled work and automatic authentication
   retries; each session acknowledges the pause. Preserve dirty files, branches,
   review evidence and unsent local work. If the owner or any required participant
   is unavailable, postpone; an unreachable session cannot be counted as passed.
2. **Establish recovery before revocation.** On a trusted device in the personal
   `basiltt` browser profile, confirm the exact account/org IDs, usable
   phishing-resistant authentication, accessible independent offline recovery
   and recovery email path. Do not depend on the tokens, browser sessions or
   GitHub Mobile sessions being revoked for recovery; mobile revocation removes
   that device as a second-factor option. Never expose codes to an AI session.
   Keep the personal recovery browser until the final invalidation step.
3. **Inventory and capture a safe baseline.** Map every machine and delivery
   session to its personal credential record ID/type, source selector and needed
   repositories/permissions. Include fine-grained and classic PATs, CLI OAuth
   tokens/grants, GitHub App user authorizations and personal web/mobile sessions.
   Identify SSH keys, deploy keys, App installation tokens and Actions job tokens
   separately: PAT or browser revocation does not invalidate those mechanisms.
   If any session can fall back to them, obtain an explicit owner-approved
   invalidation/recovery plan before proceeding; otherwise keep the full drill
   blocked. Do not disable unrelated services or runners as an improvised fix.
   Before the window, each participant confirms its existing personal credential
   works with a read-only authenticated identity request; record only outcome
   and time, not raw responses.
4. **Owner revokes, sessions stay paused.** Through supported personal-account
   settings, owner revokes every fine-grained/classic PAT and all inventoried
   personal token-bearing authorizations, including the CLI's OAuth grant where
   applicable. Apply only the separately approved handling of alternate access.
   In Settings > Sessions, revoke personal web and GitHub Mobile sessions;
   invalidate the recovery browser session last using supported account/session
   controls. If a token or session cannot be accounted for or invalidated, stop
   and record the incomplete scope. Do not alter `basil-tt_hpeprod`, global CLI
   account/configuration, Copilot subscription or project/AI authentication.
5. **Prove old access fails before replacements.** Each delivery session uses
   its existing approved credential selector for one read-only authenticated
   identity request (`GET /user`), with no alternate token, corporate credential,
   anonymous fallback, automatic login or retry. Record session alias, old
   credential record ID, timestamp and failure classification only. A GitHub
   authentication rejection of the stale credential is evidence; a local missing
   credential, network error, rate limit or unrelated permission denial is not.
   Public clone/read success
   cannot establish retained authenticated access. Owner checks revoked personal
   sessions require reauthentication. Measure revocation-to-rejection time;
   unresolved successes, missing sessions or an unproven last-browser
   invalidation mean the drill is incomplete, not successful.
6. **Owner recovers and reissues.** Owner signs back into `basiltt` using the
   independent phishing-resistant/recovery path, then issues new per-machine
   fine-grained PATs with approved minimal scope and expiry. Through the verified
   encrypted OS credential store, owner restores each machine's personal
   credential binding and tells sessions only that it is ready and its nonsecret
   record ID. Never send values to prompts/child sessions, copy them into
   environment variables or plaintext files, or reactivate a revoked token.
   Retain corporate Copilot authentication unchanged. Where a compatible secure
   store or endpoint is unavailable, leave that participant paused and record
   the blocker rather than silently widening scope.
7. **Validate and resume deliberately.** Each participant, in a fresh process
   using its approved personal selector, confirms `basiltt:54134686`, the target
   organization's/repository's numeric IDs and read access needed for its work.
   Owner verifies replacement scopes/expiries and storage; no test push to main,
   bypass, branch deletion or settings mutation is an access probe. Coordinator
   compares protections and current base with the pre-window state, records
   failure/recovery timings and exceptions, and resumes acknowledged sessions
   only after the owner authorizes it. Unexpected changes block resumption.

### Abort and recovery

**Before revocation:** abort for unavailable owner/participants, unproven recovery
or encrypted storage, ambiguous account identity, unidentified credentials,
unexpected settings/base changes or an unavailable alert/recovery path. Leave
credentials and services untouched; reschedule with the missing prerequisites.

**After partial/full revocation:** keep sessions and publication paused; notify
the owner/coordinator using the agreed out-of-band path. Revocation cannot be
rolled back by restoring an old token. Owner uses independent authentication
and offline recovery, privately following GitHub's recovery process if needed,
then issues new minimum-scope credentials only on trusted devices. Suspected
compromise is an incident, not a successful drill: stop ordinary recredentialing
until the owner has addressed the affected device/account. Do not disable 2FA,
relax rulesets, reuse revoked credentials or switch the corporate account to
recover. If recovery fails, preserve local work and record an explicit blocker.

## Unresolved owner decisions and delivery boundary

| Decision | Still required from the owner; nothing approved or executed here |
| --- | --- |
| Authentication and continuity | Existing key/passkey choice, independent recovery path and offline-code custody; whether to add a second owner or buy a hardware key. Sole-owner risk remains; no account creation or purchase is authorized. |
| Credentials | Machine inventory, exact minimum repository/permission grants, handling of fine-grained-token feature gaps and proof of the actual CLI/helper's encrypted OS-store path. Native per-ticket isolation remains undelivered. |
| Cadence and alerts | Ratify or tighten the proposed 30-day expiry, seven-day rotation lead, weekly log review and quarterly reviews/drill; designate the private alert/recovery contact path. Any deviation needs an explicit owner decision. |
| Organization | Review O1-O7, effects on current dependencies and any plan/UI limitations; approve changes separately and record deviations rather than treating recommendations as live settings. |
| Maintenance | Owner availability, all-session inventory/acknowledgments, alternate-credential coverage, maintenance window, measurable success deadline and out-of-band recovery arrangements. |

The accepted E01 refresh already hands E01-F04 to infra#43; this source slice
does not edit that record or close the finding. Source publication must go
through the coordinator's current-base PR with separate Core/Security review
and actual native CI, using **Refs #43**, not a closing keyword. Owner evidence,
the first completed revocation rehearsal and recorded organization review remain
outstanding; no full infra#43 closure or security-state claim follows.

Roll out only the reviewed document and its manual-guide link. Documentation
rollback is a normal reviewed additive revert of those changes, not a credential
rollback or a rewrite of accepted history. No generated setup, gate deployment,
service change, qualification waiver or additional automation is included.

## Official behavior references

- [Passkeys](https://docs.github.com/en/authentication/authenticating-with-a-passkey/about-passkeys)
  and [2FA recovery](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication-recovery-methods).
- [Fine-grained PAT scope, expiry and limitations](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
  and [GitHub CLI storage/fallback behavior](https://cli.github.com/manual/gh_auth_login).
- [Personal web/mobile session revocation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/viewing-and-managing-your-sessions),
  [security log](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log)
  and [device verification limits](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/verifying-new-devices-when-signing-in).
- [Organization 2FA impacts](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization)
  and [organization Actions restrictions](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization).
