# LazorKit Use-Case Guides

End-to-end integration patterns for common LazorKit scenarios. Each guide
walks through the full flow with working code adapted from the test suite,
plus the role/permission and recovery considerations specific to that
pattern.

## Available guides

| Pattern | Who it's for | Guide |
|---|---|---|
| EOA owner + passkey spender | Teams onboarding existing Solana users who want to add a passkey for "tap-to-sign" UX without giving up their EOA key | [eoa-with-passkey-spender.md](./eoa-with-passkey-spender.md) |

## Planned (not yet written)

These patterns work today but don't have dedicated guides yet. The test
suite under `tests-sdk/tests/` covers all of them.

- **Passkey-only wallet** — passkey is the Owner from day one; no EOA
  involved. See `tests-sdk/tests/07-e2e.test.ts`.
- **Multi-device passkey** — primary passkey as Owner adds a second
  device's passkey as Admin. Each device can sign independently.
- **Gasless relayer** — a backend service pays the fee for users; users
  sign with their own passkey/EOA. The protocol-fee mechanism's per-payer
  `FeeRecord` is designed for this; see `docs/Architecture.md` for the
  fee-collection convention.
- **Session with spending limits** — Admin pre-authorizes an ephemeral
  session key with SOL/token caps and program white/blacklists. See
  `tests-sdk/tests/12-session-actions.test.ts`.

## Conventions

Every guide follows the same structure so they're easy to scan:

1. **Who this is for** — the situation and team profile this fits.
2. **End state** — what gets built, with a small diagram.
3. **Step-by-step code** — copy-pasteable, adapted from a real test.
4. **What the user CAN and CANNOT do** — explicit permission table.
5. **Recovery & revocation** — how to handle lost keys / lost passkeys.
6. **Protocol fee notes** — what the user pays per operation.
7. **Common pitfalls** — short list of the things that bite people first.

## Where to read next

- `docs/Architecture.md` — the protocol-level reference (state accounts,
  instruction set, auth flows, fee model).
- `program/src/` — canonical source of truth for all role and permission
  checks. Each guide cites specific files and line numbers.
