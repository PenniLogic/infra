# Immutable offline source inputs, not accepted provider registrations

The `adr` files are the exact **unaccepted** Docs PR171 proposal at
`69919765f4ce4798bc85f8dcb685890d18bb5b38`, tree
`1736f2945e8ea74b2d49f130b9fa59d8d8a451a3`, repository ID `1394134442`.
Do not edit, reformat, relabel or use them as a separate policy source of truth.
The production installation's accepted-policy pin is **null**.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `adr/ADR-025.md` | 32503 | `9a7b97abeb9e8bc5a8e722561230b625f793966d34651d7f7ba68d17c7bca048` |
| `adr/embedding-policy.json` | 9884 | `ca9ed351085b5bf34a4b07f68607fb624022245700a4a230b8cd0ead5b8f8af9` |
| `adr/embedding-policy.schema.json` | 18873 | `5251d6f67d50fe5a551efc3cb620d528314f38870b4e304afd74f964326e5514` |
| `adr/accepted-records.json` | 1882 | `83b16677412db095c9242a03bf4fb1c4ef461e8eda4617c09652fee4a69bfee1` |

The separate `accepted-docs-62a` files are exact protected-accepted Docs PR171
source at `62a627f67ced1494679be6321ae9deb7f6af7692`, tree
`b3240b191bf89e540ae03d951ccf46c640459e4d`, sole parent
`47986ef6bef986a3ba9214ccf652609347d73c66`. They were acquired from that immutable
Git tree and checked against raw size, SHA-256 and Git blob identity.
`adr/embedding-policy.json` and `adr/embedding-policy.schema.json` are
byte-identical in this accepted source and are reused without duplication.
Neither source acquisition nor support registers the installed gate's authority.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `accepted-docs-62a/ADR-025.md` | 33609 | `148fe74a232a7bdc1b149f7807adbad24b1679aed0024c8ffe98b94d1cb6fd38` |
| `accepted-docs-62a/accepted-records.json` | 1953 | `ea8c941812c52710ffca99a9f7ea0128ce8b63d4d25d32400a51086d28efca71` |

The original `adr` proposal remains unchanged for obsolete-source refusal
controls. Tests must not treat its old ADR/registry bytes as another accepted
version. Both snapshots retain their source wording rather than being edited
to describe later implementation or acceptance events.

The four `api` SQL files are exact read-only inputs from accepted API
`d39f4692c13413040439c5e87fed81728e0577f1`, tree
`8da895cc998e5ec43105cfb6fa41a82ea2194f8c`, repository ID `1394134582`.
`database_baseline.py` pins their complete checksums. They are never executed
by an Infra SQL runner and do not fork API migration ownership.

Tests use **synthetic temporary installed trust**, with an explicitly invented
Docs installation identity, to exercise both real CLI boundaries offline.
The accepted-commit-specific test also uses synthetic inventory/installed trust,
not a live admission installation.
Those fixtures are not independent acceptance/approval, real GitHub protected
merge evidence, application integration or deployment proof. Removing a real
provider dependency by blessing these fixtures in the shipped trust file is
not permitted.
