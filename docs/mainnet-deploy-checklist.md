# Mainnet deploy checklist — protocol v2

The mainnet program at `LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi` holds real
user funds and is live on v1. This upgrade is in-place and cannot be undone
except by another upgrade. Work top to bottom; do not skip a gate.

The mechanics below were rehearsed end to end on a local validator with the
**`--features mainnet`** binaries at the real vanity id
(`scripts/rehearse/run.sh`, see [Rehearsal](#rehearsal)). What is *not* rehearsed
is the human process: keys, comms, and the decisions in section 2.

---

## 0. Hard gates — none of these is optional

- [ ] **External audit of the v2 delta complete**, findings fixed and
      re-reviewed. Prioritise `MigrateWallet` (a new money path; the internal
      review already found a HIGH there), the fee layer (never audited from the
      start), and the rank/policy engine.
- [ ] PR #36 merged to `develop` and forward to the release branch.
- [ ] CI green on the release commit: `cargo fmt`, clippy, `--lib`, the litesvm
      integration suite, and both validator suites.
- [ ] A **fresh** v1 survey run privately (`scripts/survey-v1.ts`) — balances and
      wallet set drift. Keep the output off the public repo.

- [ ] **If fees will be enabled at init:** initialise at least one treasury
      shard BEFORE (or atomically with) enabling fees. Enabling a non-zero fee
      with no shard reverts every CreateWallet/Execute/ExecuteDeferred until a
      shard exists (audit MEDIUM — bootstrap freeze). The existing mainnet
      already has shards, so this applies only to a fresh init.

## 1. Decisions to confirm (operator / team only)

- [ ] **`PROTOCOL_INIT_AUTHORITY`** for the mainnet build is
      `4fZM6RPRLkeW8T5dDctZjWaqidFDACyW41Kqztj7uL5V`. It is compiled in and
      **permanent** — it gates `initialize_protocol` forever. Confirm this key is
      correct and its secret is held.
      - ⚠️ **This is the same key as the program upgrade authority.** One key can
        both upgrade the program and initialise the protocol. Decide whether that
        concentration is acceptable or whether they should be split before deploy.
- [ ] **Custody confirmed**: the upgrade authority
      (`4fZM6RPR…`) and the ProtocolConfig admin (`24fx48GA…`) are both keys you
      can sign with, ideally in cold storage / multisig.
- [ ] **When the upgrade authority moves to the Squads vault.** Recommended:
      after v2 has run cleanly for a few days, so a rollback during the window
      needs one key, not a quorum. Both the transfer and a vault-approved
      upgrade are rehearsed — see [Multisig rehearsal](#multisig-rehearsal).
      Once transferred, every upgrade needs the vault. The extend before it
      does not: while `enable_extend_program_checked` is inactive (devnet and
      mainnet, 2026-09-11) the loader's plain `ExtendProgram` needs no
      authority, and the runtime refuses it via CPI, so any payer sends it
      top-level first. The `PROTOCOL_INIT_AUTHORITY` key is still needed until
      `InitializeProtocol` has run, whoever holds the upgrade authority.
- [x] **Rollout: immediate in-place upgrade** (decided). One upgrade at the
      vanity id. Un-migrated v1 wallets can only call `MigrateWallet` until they
      migrate — a freeze window for normal use; funds stay safe. Two hard
      preconditions this rollout adds:
      - [ ] **The migration UI is live and tested** before the upgrade (built on
            `LazorKitClient.migrateV1Wallet`; see `docs/migration-ui-flow.md`), so
            a frozen user can migrate immediately.
      - [ ] **Users/integrator announced** ahead of the window — a v1 wallet needs
            one signed migration before transacting again.
- [ ] **User / integrator comms drafted.** Migration is **user-signed** — one
      `MigrateWallet` transaction per wallet, Owner-rank key required. Dormant
      wallets that never return keep their funds in v1 vaults (reachable only via
      `MigrateWallet`) indefinitely; this is inherent to non-custodial and must
      be communicated.

## 2. Build and record

- [ ] Build both binaries with `--features mainnet` from pinned commits (v2 from
      the release commit; v1 from the last pre-`lk2:` commit for the rehearsal):
      ```bash
      ( cd program && cargo build-sbf --features mainnet )
      shasum -a 256 target/deploy/lazorkit_program.so
      ```
- [ ] Record the toolchain and both SHA-256 hashes in the deploy log. Builds are
      only trustworthy if reproducible — a second machine must produce the same
      hash.
      ⚠️ **The toolchain moved after the 2026-09-11 rehearsal.** That run used
      solana-cli 4.0.3 with platform-tools v1.53; the machine now has
      `cargo-build-sbf` 4.1.0, which pulls platform-tools v1.54. A rebuild will
      not reproduce the `e22f176d…` hash in the rehearsal table below, and that
      is expected rather than alarming. Record the new hash, and rehearse again
      with the binary you are actually going to deploy.
- [ ] Confirm the v2 binary's compiled id is the vanity id (M-2 pins it; a wrong
      id refuses to run).

## 3. Rehearse (again, with the release binaries)

- [ ] Run `scripts/rehearse/run.sh` with the release `--features mainnet`
      binaries at the vanity id (see the recorded command below). It must end
      `REHEARSAL PASSED`.
- [ ] Rehearse the **rollback**: keep the current v1 `.so` and its hash; confirm
      `solana program deploy` with the v1 `.so` can restore it (an upgrade back to
      v1 — note this does NOT un-migrate any wallet already moved).

## 4. Pre-flight, immediately before the upgrade

- [ ] `solana program show LazorjRF…` — record current Data Length + Last Deployed
      Slot (the v1 baseline).
- [ ] Confirm the upgrade-authority keypair is loaded and is the on-chain upgrade
      authority (`solana program show` reports it).
- [ ] Announce the maintenance window to users/integrator.
- [ ] **Publish the v2 SDKs under the `next` dist-tag before the window**, so
      integrators can build and test against staging first:
      `npm publish --tag next` in `sdk/sdk-legacy` (1.0.0) and `sdk/sdk-kit`
      (1.0.0-rc.1). Leave `latest` on 0.3.2 — it is what mainnet speaks until
      the upgrade lands.

## 5. The upgrade

- [ ] ```bash
      solana program deploy target/deploy/lazorkit_program.so \
        --program-id LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi \
        --upgrade-authority <mainnet-upgrade-authority.json> \
        --url <mainnet-rpc>
      ```
      The deploy extends the program data first. v1 is 137904 bytes and v2
      149296: an 11392-byte growth, above the loader's 10240-byte minimum, so
      the automatic extend succeeds. A later build that grows by less fails with
      `ExtendProgram requires a minimum of 10240 additional bytes` — run
      `solana program extend <id> 10240` first (hit on staging, 2026-09-11).
- [ ] `solana program show LazorjRF…` — confirm Data Length changed to the v2
      size and the slot advanced. Record the upgrade signature.
- [ ] C-1 is now dead. Verify: a `CreateWallet`/`Execute` no longer reverts when
      fees are unconfigured.
- [ ] Until `InitializeProtocol` runs, an SDK older than `@lazorkit/sdk-legacy`
      1.0.0 omits the fee suffix and fails every `CreateWallet`/`Execute` with
      4008. Ship the integrator 1.x (`npm i @lazorkit/sdk-legacy@next`) before
      the window, or run `InitializeProtocol` (plus a treasury shard if fees
      will be on) inside it.

## 6. Post-deploy

- [ ] Move the npm dist-tag now that mainnet speaks v2:
      `npm dist-tag add @lazorkit/sdk-legacy@1.0.0 latest`. Until this runs, a
      plain `npm install` still hands integrators the v1 line.
- [ ] Publish the migration flow (SDK `createMigrateWalletIx`) / UI.
- [ ] Migrate the high-value active wallets first — value is concentrated, so a
      handful covers most of it.
- [ ] Monitor: no unexpected reverts; migrations land; balances move to v2
      vaults.
- [ ] Later: reclaim rent from fully-migrated wallets; decide a policy for
      long-dormant v1 vaults.

---

## Rehearsal

Proven on a local validator with the `--features mainnet` binaries at the real
vanity id — v1 deployed upgradeable, upgraded in place to v2, then `MigrateWallet`
moved SOL + an SPL token and closed the v1 PDAs.

Latest run: **2026-09-11**, against the program that is actually live.

| binary | size | SHA-256 — **re-record at deploy** |
|---|---|---|
| v1 — the live mainnet program, `solana program dump` (last deployed slot 416478802) | 137904 | `8ad5abf5dd8a2443fea6b26b5effa9ce11477ce85ba9564f5c43663744c3255b` |
| v2 — `6f4cb94`, `--features mainnet`, solana-cli 4.0.3 + platform-tools v1.53 (**superseded**: the toolchain is now 4.1.0 / v1.54) | 149296 | `e22f176df7b3a597e6abc16bec3fcfc1bb6301cf8d72c9cc7e34c30969546752` |

> Use the **dump** as v1, not a rebuild. The first rehearsal used a rebuild of
> `bdeffd7` (135704 bytes, `7bab37e2…`), which is not byte-identical to what is
> deployed — the live ELF is 137904 bytes with no padding. The dump is exact,
> and it is also the rollback artifact for §3: an upgrade back to it restores
> the current program byte for byte.
>
> The v2 hash is from one machine and toolchain. The real deploy must rebuild
> and record its own — treat a hash mismatch as a blocking discrepancy, not a
> rounding error.

Command used:

```bash
PROGRAM_ID="LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi" \
V1_SO=<v1-mainnet.so> V2_SO=<v2-mainnet.so> \
  scripts/rehearse/run.sh
```

Result: `Data Length 135704 → 148352` in place, vault SOL + token migrated to the
v2 destination, v1 wallet + authority closed. `REHEARSAL PASSED`.

## Paymaster (Kora)

Read out of `lazor-kit/kora` on 2026-09-21 and **measured against the live
devnet relayer on 2026-09-23**. The relayer sponsors every user transaction, so
it is on the critical path, and none of this is visible from the protocol repo.

### What the live relayer answers today

`https://kora.devnet.lazorkit.com` is a Railway service (`58btamsd.up.railway.app`).
Every call below was made **with no `x-api-key` header** and answered 200:

```
liveness        {"result":null}
getConfig       full config
getPayerSigner  7Pkkhm8YeoBXFGKHTJXJ8ckdYiqtPdVWMefEVqK5vXed
getBlockhash    {"blockhash":...}
```

That is the whole story on authentication: it is not enabled. In
`crates/lib/src/rpc_server/server.rs` the API-key layer is an `option_layer`
over `KORA_API_KEY` (env) or `[kora.auth] api_key` (config) — with neither set
the layer does not exist and no request is checked. `signTransaction` and
`signAndSendTransaction` are enabled on that endpoint, the price policy is
`free`, and the sponsor holds **89.7 SOL on devnet** (0.086 on mainnet). CORS is
`access-control-allow-origin: *`.

So the leaked key is not a gate that someone else can now walk through — there
is no gate. Rotating it changes nothing by itself; **enabling auth is the
change**, and the key rotation rides along with it.

### The key that leaked

`lazor-kit/examples/expo-react-native/app/_layout.tsx:13` carries a literal
`kora_live_…` (78 chars), introduced by commit `ca7ad8b` on **2026-05-02** and
reachable from `origin/main` of a **public** repository ever since. It is the
only live key in any of the six working trees; every other `kora_live_` hit is a
documentation placeholder. The published npm packages are clean
(`@lazorkit/wallet` 2.0.1 and `@lazorkit/wallet-mobile-adapter` 1.5.1 contain no
match).

lazor-kit/lazor-kit#89 replaces the literal with
`EXPO_PUBLIC_PAYMASTER_API_KEY` and adds a `.env.example`; it is open and
unmerged. Merging it fixes `main` and nothing else: the same blob is reachable
from **15 pushed branch tips** (main plus fourteen, mostly dependabot), and
from history on every one of them. Treat the value as public permanently and
rotate — do not try to scrub it.

And note what the replacement does and does not buy: `babel-preset-expo`
inlines `EXPO_PUBLIC_*` as string literals at build time, so the key still
ships inside every distributed bundle. Moving it to an env var keeps it out of
git; it does not make it a secret.

Worth being honest about what an API key can do here at all: this key ships
inside a mobile bundle and, for the web SDK, inside a browser bundle. A
credential handed to every user is not a secret. It raises the cost of casual
abuse and lets you cut off one client, but the controls that actually bound the
damage are `allowed_programs`, `max_allowed_lamports`, the rate limit, usage
limits, and how much SOL the sponsor is allowed to hold.

### Rotation runbook

Nothing here can be done from this repo — the config serving production is not
in any repo, and the secret lives in Railway.

1. Generate a fresh key locally; do not paste the value into a file that git
   can see:
   ```bash
   printf 'kora_live_%s\n' "$(openssl rand -hex 32)"
   ```
2. Railway → the Kora service → Variables → set `KORA_API_KEY` to it (and
   consider `KORA_HMAC_SECRET` as well; when both are configured both are
   required). Redeploy.
3. Verify the gate exists now. **Do not probe with `liveness`** — both auth
   layers short-circuit it (`crates/lib/src/rpc_server/auth.rs:60-64` and
   `:142-146`), so it answers 200 with no key even when auth is on, and reads
   as a failed rotation. Probe with `getConfig`:
   ```bash
   curl -s -o /dev/null -w 'no key: %{http_code}\n' -X POST https://kora.devnet.lazorkit.com \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"getConfig","params":[]}'
   curl -s -o /dev/null -w 'with key: %{http_code}\n' -X POST https://kora.devnet.lazorkit.com \
     -H 'content-type: application/json' -H "x-api-key: $NEW_KEY" \
     -d '{"jsonrpc":"2.0","id":1,"method":"getConfig","params":[]}'
   ```
   Read `$NEW_KEY` from your shell, not from a file in a repo. Expect 401 then
   200. `/metrics` stays outside the auth layer when it shares the RPC port,
   which is the next item below.
4. Put the new value in the consumers: the Expo example's `.env` (after #89
   merges), `app/migrate`'s env, and any deployed front end. Anything still
   sending the old key stops working at step 2 — that is the point.
5. Do **not** pass the key as `--api-key` on the command line. That flag is
   parsed into `RpcArgs.auth_args` and never read by the server
   (`crates/cli/src/main.rs` calls `run_rpc_server(rpc, port)`), so it gives an
   unauthenticated server *and* leaks the key into the process table.

### Config gates for v2

**The one gate that blocks a v2 transaction is the program allowlist.**
`validate_programs` walks `all_instructions` and requires an exact pubkey match
for every one of them, with no exemption for precompiles. The live devnet
config lists System, SPL Token, ATA, Address Lookup Table, ComputeBudget,
`LazorjRF…` and `4h3XoNRe…` — and **not**
`Secp256r1SigVerify1111111111111111111111111`. Any passkey transaction carries
that precompile instruction, so as configured this relayer refuses to sponsor
one.

Everything else about the v2 shape passes: Kora never parses LazorKit
instruction data, so the four-account fee suffix, the forward-signer bit inside
the compact payload, the precompile sitting immediately before the program
instruction, and a prepended ComputeBudget instruction are all invisible to it.
It never reorders or inserts instructions.

- [ ] Add `Secp256r1SigVerify1111111111111111111111111` to `allowed_programs`,
      on devnet and on whatever serves mainnet. Verify with `getConfig`, not by
      reading a repo file — the repo's `kora.toml` is not what production runs
      (it caps `max_allowed_lamports` at 0.001 SOL; the live one allows 0.1).
      **Confirmed the hard way on devnet (2026-09-21):** a migration through the
      UI was refused with `Program 3AN3Wn… is not in the allowed list`. This
      fails at the relayer, before anything reaches the chain.
- [ ] Confirm the live `allowed_programs` contains the mainnet vanity id on the
      mainnet deployment specifically.
- [ ] Kora simulates every transaction before signing and rejects on
      simulation failure, folding the simulated inner instructions into the
      accounts its validator walks. So a v2 transaction that would fail 4008
      never gets sponsored — good — but it also means the protocol fee CPI is
      inside `max_allowed_lamports`. Set that cap high enough for the fee plus
      the one-time `FeeRecord` rent (~0.00111 SOL per payer), or sponsored
      transactions start failing on the cap.
- [ ] Decide the fee-payer custody. The sample signer config is
      `type = "memory"` reading a base58 key out of an environment variable.
      Turnkey and Vault handlers already exist in that repo; a mainnet fee
      payer holding real SOL should use one.
- [ ] Turn on authentication and rotate the key, per the runbook above. Until
      then the endpoint is open to anyone who finds it, which is anyone who
      reads the public client repo.
- [ ] Move the metrics port off the RPC port. When they match, the metrics
      handler is mounted outside the auth layer.
- [ ] Narrow CORS off `*` once the front ends have fixed origins.
- [ ] Fund and monitor the sponsor, and keep the mainnet balance to what a bad
      day may cost. Rent dominates: creating a wallet costs the payer about
      0.00285 SOL (Wallet 8 bytes + Authority 145 bytes; the vault PDA is not
      funded at creation), against a protocol fee measured in thousandths of
      that. Ten thousand new wallets in a day is roughly 29 SOL, of which the
      protocol fee is under 2 per cent.
- [ ] Point the client at a mainnet endpoint. There is none in the client repo,
      and the React package's default
      (`https://lazorkit-paymaster.onrender.com`, in
      `packages/react/config/defaults.ts` and the react-native README) now
      answers **503 "Service suspended"** — every app on that default is
      already broken.

## Seedless migration rehearsal

Run on devnet on 2026-09-21, end to end on a throwaway program id: the live v1
binary deployed, a real v1 wallet created through the published
`@lazorkit/sdk-legacy` 0.3.2, upgraded in place to v2, then migrated with
`@lazorkit/sdk-legacy` 1.1.0 **without the user seed**.

Scripts: [`scripts/rehearse/migrate-v1-create.cjs`](../scripts/rehearse/migrate-v1-create.cjs)
then [`scripts/rehearse/migrate-v1-seedless.cjs`](../scripts/rehearse/migrate-v1-seedless.cjs).

Why it matters: wallets created through `@lazorkit/wallet` used
`userSeed: randomBytes(32)` kept in browser storage. A returning user usually
does not have it, and `MigrateWallet` is the only way their funds move after
the upgrade. The program never needed the seed — it takes the v1 wallet as an
account — but the SDK did, until 1.1.0.

| check | result |
|---|---|
| scan finds the v1 wallet from the owner key alone | `3Fq7dKcy…`, Owner rank |
| plan targets the same v1 accounts, finds the token account | ok |
| a fresh v2 seed is minted, different from the original | ok |
| v1 wallet and authority closed | ok |
| v1 vault emptied | 0 lamports |
| SOL landed in the v2 vault | 0.05 SOL |
| tokens landed in the v2 vault | 1,234,000 of 1,234,000 |

Signatures: setup `UQebUTLC…`, migrate `4PYXoAco…`.

The passkey path was then rehearsed the same way, with a synthetic
authenticator — a P-256 key the script holds, producing the authenticatorData,
clientDataJSON and signature a real one would, so the program and SDK cannot
tell the difference
([`migrate-v1-create-passkey.cjs`](../scripts/rehearse/migrate-v1-create-passkey.cjs),
[`migrate-v1-seedless-passkey.cjs`](../scripts/rehearse/migrate-v1-seedless-passkey.cjs)).
All eleven checks passed: the scan found the wallet from the credential hash
alone and reported a Secp256r1 Owner, the plan took the Secp256r1 branch, the
v1 accounts closed, 0.04 SOL and 777,000 tokens landed in the v2 vault, and
**replaying the same signature was rejected**. Signatures: setup `4r5sycFE…`,
migrate `5b1CcN1P…`.

**Then walked by hand, in a browser, with a real passkey** (2026-09-21): the
maintainer signed in with an existing Touch ID passkey through
`portal.lazor.sh`, the page found the v1 wallet from that passkey alone, and
one approval moved 0.04 SOL and 500,000 tokens into the v2 vault
`G99ePt8w…`. The v1 wallet `Dmhp9WyD…` and its vault are closed. The passkey
prompted exactly once, for the migration itself.

Two defects only that run could have found, both fixed:

- **A returning user has no public key.** Signing in with an existing passkey
  returns an assertion, and an assertion carries no public key — only
  registration does. The page passed the empty value to `migrateV1Wallet` and
  failed on a byte count. Every returning user would have hit it. The key is
  read from the authority account now, and `findV1WalletsByOwner` returns it
  (sdk-legacy 1.1.1).
- **The paymaster refused to sponsor.** Kora answered *"Program 3AN3Wn… is not
  in the allowed list"*, live confirmation of the allowlist gate below. See the
  paymaster section: the mainnet config must list the vanity program id and the
  Secp256r1 precompile, or every sponsored transaction fails this way.

## Multisig rehearsal

Run on devnet on 2026-09-11 with
[`scripts/rehearse/squads-upgrade.cjs`](../scripts/rehearse/squads-upgrade.cjs),
against a throwaway program id holding the live v1 binary: the same shape as
mainnet, 137904 bytes growing to 149296.

| step | result |
|---|---|
| deploy the live v1 dump (`8ad5abf5…`), authority = a single key | ok |
| Squads v4 multisig, 2 of 3, no time lock | multisig `2p5oQ9E8…`, vault `ApQ1Twr4…` |
| `set-upgrade-authority --new-upgrade-authority <vault> --skip-new-upgrade-authority-signer-check` | authority = vault |
| the old key tries to take it back | refused on-chain: `Incorrect upgrade authority provided` |
| `write-buffer` v2, `set-buffer-authority` to the vault | ok |
| top-level `ExtendProgram`, 11392 bytes, signed by a payer that is not the authority | ok |
| vault transaction `[Upgrade]`: propose, 2 approvals, execute | 137904 → 149296 bytes, on-chain == local build |
| `@lazorkit/sdk-legacy` 1.0.0: `createWallet` on the upgraded, uninitialised program | lands; the old suffix-less shape fails 4008 |
| vault transaction `[SetAuthority → key]` | authority back on the key |

What it found, and what carries to mainnet:

- **The extend cannot go through the vault.** The first attempt put
  `ExtendProgramChecked` inside the vault transaction and execution failed:
  `BPFLoaderUpgradeab1e… not supported by inner instructions`. The runtime
  feature `enable_extend_program_checked` is inactive on devnet and mainnet, so
  via CPI the loader accepts only `Upgrade`, `SetAuthority` and `Close`, and the
  plain `ExtendProgram` needs no authority at all. Extend top-level from any
  payer first, then let the vault execute `Upgrade`. Re-check on the day:
  `solana feature status 2oMRZEDWT2tqtYMofhmmfQ8SsjqUFzT6sYXppQDavxwz -um`. The
  script reads the feature account and picks the path itself.
- **`@sqds/multisig` 2.1.4 `rpc.proposalCreate` drops `rentPayer`,** so the
  proposer pays the proposal rent. A member wallet with no SOL fails with
  `insufficient lamports 0, need 2468880`. The script builds the instruction
  itself; in the Squads app, fund whoever proposes.
- **An approved vault transaction stays executable.** The failed first attempt
  left transaction #1 approved; it is dead now only because its buffer was
  consumed by the retry. On mainnet, reject any approved upgrade that failed.
- **Write buffers through the TPU client.** On the public RPC, `--use-rpc` died
  twice on 429s (`Data writes to account failed: Max retries exceeded`), each
  time leaving a buffer holding rent. The TPU client wrote the same 149 KB first
  try. Reclaim a stray buffer with `solana program close <buffer>`.

With a real multisig, members approve from their own wallets:

```bash
solana program write-buffer lazorkit_program.so -um
solana program set-buffer-authority <buffer> --new-buffer-authority <vault> -um
PROPOSE_ONLY=1 RPC_URL=<mainnet-rpc> PROGRAM_ID=LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi \
  PAYER=<payer.json> MEMBERS=<proposer.json> MULTISIG=<multisig address> \
  node scripts/rehearse/squads-upgrade.cjs upgrade <buffer>
# then approve and execute in the Squads app
```

`MULTISIG` is the multisig account the Squads app shows, not its vault. The
proposer must be a member with the Initiate permission.

## Deploy log template

```
date/operator:
release commit (v2):            <sha>
toolchain (rustc / solana):     <versions>
v1 .so sha256:                  <hash>
v2 .so sha256:                  <hash>
survey run (private) at slot:   <slot>   funded vaults: <n>   total: <sol>
upgrade authority:              4fZM6RPR…   (confirmed held: y/n)
upgrade authority after:        <key or vault>   multisig threshold: <m of n>
protocol admin:                 24fx48GA…   (confirmed held: y/n)
pre-upgrade  Data Length/slot:  <n> / <slot>
upgrade tx signature:           <sig>
post-upgrade Data Length/slot:  <n> / <slot>
rollback .so (v1) sha256:       <hash>
```
