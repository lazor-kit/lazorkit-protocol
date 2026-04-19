# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in LazorKit, please report it responsibly:

1. **Do not open a public GitHub issue.**
2. Use [GitHub's private vulnerability reporting](https://github.com/lazor-kit/program-v2/security/advisories/new), **or**
3. Email: security@lazorkit.app

### Response timeline

- **48 hours** — acknowledgement of report
- **7 days** — initial assessment and severity classification
- **30 days** — target for fix and disclosure

## Scope

In scope:

- On-chain Solana program (`program/src/`)
- TypeScript SDK (`sdk/sdk-legacy/`)
- PDA derivation and signature verification logic
- Replay protection mechanisms

Out of scope:

- Frontend applications built on top of LazorKit
- Third-party dependencies (please report to upstream)
- Test files and scripts

## Audit status

LazorKit V2 underwent an audit by **Accretion** (Solana Foundation funded) plus internal pre-mainnet review. All findings were resolved.

## Security mechanisms

- Odometer counter replay protection (monotonic u32 per authority; works with synced passkeys).
- Clock-based slot freshness (150-slot window via `Clock::get()`).
- CPI `stack_height` anti-reentrancy check on every authenticated path.
- Challenge hash binds signature to payer, accounts, counter, and program ID.
- Account ownership + discriminator checks on every PDA read.
- Transfer-allocate-assign pattern prevents create-account DoS.
- Session action enforcement: expired spending limits are a hard deny; expired whitelists block all programs.
- `SolMaxPerTx` uses per-CPI gross-outflow tracking (DeFi round-trips can't bypass the per-tx cap).
- Vault metadata + per-listed-mint token account invariants enforced in session execute (blocks `System::Assign`, SPL Token `SetAuthority`, `Approve` escapes).
- Token balance sum-all-accounts prevents dummy-account bypass.
- Admin-gated protocol instructions verify config ownership before reading admin field.
- Constant-time comparison on the signed challenge field.
- `compact.rs` has runtime assert guards against u8 truncation (not debug-only).
- `actions_len` capped at 2,048 bytes to prevent BPF heap exhaustion.
