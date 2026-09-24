# Kora paymaster config

The relayer sponsors every user transaction, so it is on the critical path and
none of it is visible from the program. These two files are the configuration
that protocol v2 needs; the reasoning for each value is in the comments, and the
findings behind them are in
[`docs/mainnet-deploy-checklist.md`](../../docs/mainnet-deploy-checklist.md#paymaster-kora).

| file | for |
|---|---|
| [`kora.mainnet.toml`](./kora.mainnet.toml) | mainnet, program `LazorjRF…` |
| [`kora.devnet.toml`](./kora.devnet.toml) | devnet, program `4h3XoNRe…` |

Written against **kora v2.2.0-beta.8**. The devnet relayer answered
`2.2.0-beta.7` on 2026-09-24, which is a release behind and missing the fixes
for three of the controls these files rely on (the `--api-key` flag being
applied at all, atomic usage limits, URL redaction in client-facing errors).
Upgrade first: `ghcr.io/solana-foundation/kora:v2.2.0-beta.8`.

## What actually bounds the spend

Two flags have to stay open, because the protocol needs them — the program funds
its PDAs and pays the protocol fee through System CPIs with the fee payer as
source. So `system.allow_transfer` and `system.allow_create_account` are `true`
and everything else in `fee_payer_policy` is shut.

What bounds a stranger is therefore four things, in order of how much they
carry:

1. **`require_one_of_programs`** — a transaction that never touches LazorKit is
   refused outright. Without it, an `allowed_programs` list that contains the
   System program still sponsors a bare transfer.
2. **Authentication** — and be honest about which kind. The API key ships inside
   a browser bundle and an app bundle, so every user has it and so does anyone
   who reads the bundle: it lets you cut off a client, nothing more. reCAPTCHA
   (`KORA_RECAPTCHA_SECRET`, new in beta.8) is the control a public dApp can
   actually hold.
3. **`max_allowed_lamports`** — set from what a real flow costs, measured, not
   rounded. 0.015 SOL on mainnet against the 0.1 the relayer runs today.
4. **Usage limits** — a per-caller ceiling. `enabled = true` with no rules
   **fails startup** on beta.8, which is deliberate: it used to be a silent
   no-op.

Note what an instruction rule can name: Kora's parser only identifies System
`createaccount`/`createaccountwithseed`, ATA `create`/`createidempotent`, and
the loaders. A rule naming a LazorKit instruction never matches, so the rules
here bound the rent a caller can make us spend instead.

## Secrets

None of them live in these files. The host's environment carries:

| variable | what it is |
|---|---|
| `KORA_API_KEY` | the `x-api-key` value; with none set **the auth layer is not mounted at all** |
| `KORA_HMAC_SECRET` | optional second factor; when both are set, both are required |
| `KORA_RECAPTCHA_SECRET` | reCAPTCHA v3 secret, with `protected_methods` naming what it gates |
| `KORA_PRIVATE_KEY` | the fee payer, per `signers.toml` |
| `KORA_REDIS_URL` | shared store for the usage limits |

Never pass the key as `--api-key` on a command line: on beta.7 the flag is
parsed and ignored, so the server comes up **unauthenticated** while the key
sits in the process table. beta.8 applies it, but the process table is still the
wrong place for it.

## Applying it on Railway

The relayer runs as a Railway service (`kora.devnet.lazorkit.com` →
`58btamsd.up.railway.app`). Set the variables above in the service, ship the
file the way that service already gets its config, and redeploy.

Then check from the outside — no key, no transaction, non-zero exit on a
failure, so it can gate the deploy:

```bash
node scripts/kora-check.cjs https://kora.devnet.lazorkit.com --cluster devnet
```

What it should say once this config is live: `version 2.2.0-beta.8`,
`authentication` PASS (anonymous `getConfig` refused with 401 — probe with
`getConfig`, never `liveness`, which bypasses both auth layers by name), every
`program` line PASS including the Secp256r1 precompile, and `metrics` not on the
RPC port.

## Still open

- **Lighthouse** (`[kora.lighthouse]`) appends balance assertions that abort a
  transaction if the fee payer loses more than expected — the most direct
  answer to a drain. It only works with `signTransaction` → client re-signs →
  client sends, and both client packages call `signAndSendTransaction` on the
  main path. Turning it on is a client change first.
- **CORS origins** are configurable only on upstream `main`
  ([#658](https://github.com/solana-foundation/kora/pull/658)), not in beta.8;
  today the relayer answers `access-control-allow-origin: *`.
