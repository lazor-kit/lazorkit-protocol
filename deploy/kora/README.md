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

## Validate before deploying

These files were written from the beta.8 source and parse as TOML, but they have
never been through Kora's own validator — several of its structs are
`deny_unknown_fields`, so a field name that drifted between releases fails at
startup rather than being ignored. Check them with the binary that will run
them, in the same image:

```bash
docker run --rm -v "$PWD/deploy/kora:/cfg" ghcr.io/solana-foundation/kora:v2.2.0-beta.8 \
  kora --config /cfg/kora.devnet.toml config validate
```

`config validate` is fast and makes no RPC calls; `config validate-with-rpc` is
slower and checks more. Both exit non-zero on failure (upstream
[#567](https://github.com/solana-foundation/kora/pull/567)), so either belongs
in front of a deploy.

**Both files pass** against `v2.2.0-beta.8` (run 2026-09-24). Two things it
caught that reading the source had not:

- `price_source = "Jupiter"` is a **hard error** without `JUPITER_API_KEY`, even
  though `price.type = "free"` means no price is ever fetched. Both files use
  `"Mock"`; revisit the day fees are charged in tokens.
- `transfer_hook_policy` was too lax. Under
  `deny_mutable_for_delayed_signing`, a mint whose transfer-hook authority is
  still mutable is accepted on `signAndSendTransaction` — the flow both clients
  use — and that authority can swap the hook program between our signature and
  execution. Both files now say `deny_all`.

The warnings that remain are answered, not ignored:

| warning | our answer |
|---|---|
| Mock price source "not suitable for production" | nothing reads the oracle while pricing is free |
| LazorKit and the Secp256r1 precompile have "no dedicated fee-payer instruction parser" | expected for any non-standard program. It matters less than it reads: our own CPIs go to the System program, which *is* parsed, so the fee-payer policy still gates the instructions that spend our lamports |
| PermanentDelegate not blocked | the warning is about payment tokens being seized after payment, and this relayer takes no token payment. Blocking it would only refuse to sponsor a user moving their own token out of a v1 vault |
| free pricing | that is the product |
| `system.allow_transfer` / `allow_create_account` can drain the fee payer | true, and unavoidable — see above. `require_one_of_programs`, the lamport cap and the usage limits are the bound |
| no authentication configured | the secrets come from the environment, which the validator cannot see. **Confirm with `kora-check.cjs` after deploying**, not here |
| usage limiting without `cache_url` | resolved from `KORA_REDIS_URL` at runtime, likewise invisible here |
| usage-limit fallback disabled | deliberate: if the cache is down, refuse rather than sponsor blindly |

## Applying it on Railway

The relayer runs as a Railway service (`kora.devnet.lazorkit.com` →
`58btamsd.up.railway.app`).

There is no way to hand Kora a config through the environment: the path comes
only from the global `--config <PATH>` flag (default `kora.toml`, resolved
against the process working directory) and no env var overrides it. Upstream's
own Railway guide bakes the file into the image — `COPY kora.toml ./` in the
Dockerfile — so **applying a config change is a rebuild and a redeploy**, not a
variable edit. Nothing in the file is hot-reloadable either; every field is read
once at startup.

Two mechanical notes that cost a deploy each when missed: `--config` is a
top-level flag and must come **before** the subcommand
(`kora --config /cfg/kora.mainnet.toml rpc start`), and a config that fails to
load exits 1 immediately with no partial start and no fallback.

Set the environment variables above in the Railway service, ship the file in the
image, and redeploy.

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
