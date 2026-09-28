# Mainnet deploy checklist — protocol v2

The mainnet program at `LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi` holds real
user funds and is live on v1 — Seedless runs on it. **v2 does not replace it in
place.** v2 launches at its own program id (phase A) and nobody on v1 notices;
v1 is retired later by upgrading its id to a sunset binary that serves only the
way out (phase B). That is how Squads v3/v4, Jupiter v4/v6 and Token/Token-2022
shipped their breaking majors, and it turns the riskiest hour of the rollout
into one that touches no live user. Work top to bottom; do not skip a gate.

The mechanics below are rehearsed end to end on a local validator with the
live v1 binary, the sunset binary and v2 at separate ids, both owner types
migrating across them (`scripts/rehearse/two-id-rehearsal.mjs`, see
[Two-id rehearsal](#two-id-rehearsal)); §3 repeats that with the exact release
artifacts. What is *not* rehearsed is the human process: keys, comms, and the
decisions in section 1.

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
- [x] **Custody confirmed**: the upgrade authority (`4fZM6RPR…`) and the
      ProtocolConfig admin (`24fx48GA…`) are both keys the maintainer can sign
      with. Neither is in cold storage or a multisig today. The upgrade
      authority has a path out — the Squads vault, below. The **v1** admin has
      none: v1's ProtocolConfig has no propose/accept and never gets it, because
      the v1 id never runs v2. It stays a hot key until phase B retires the fee
      layer it controls (see C-1 under the rollout decision).
- [x] **When the upgrade authority moves to the Squads vault** (decided
      2026-09-23, restated for two ids on 2026-09-27). There are now **two
      programs to hand over**, on two schedules:
      - the **v2 id**, once phase A has settled — every new user's funds sit
        there, so it must not stay on a single key for long;
      - the **v1 id**, after phase B has landed. Keeping it on the key until
        then makes the sunset deploy a plain `solana program deploy`; if it is
        handed over earlier, phase B becomes a vault upgrade instead (buffer,
        `set-buffer-authority` to the vault, propose/approve in the app — see
        step 6 of the Squads section).
      A rollback inside either window then
      needs one key rather than a quorum, and the multisig's first real duty is
      not also the riskiest hour of the year. Quorum is reachable — the
      maintainer holds four of the five member keys, against a threshold of
      three. Everything else for that day is prepared: see
      [Handing the upgrade authority to the Squads vault](#handing-the-upgrade-authority-to-the-squads-vault)
      for the multisig's on-chain state, `preflight`, the `dry-run` that proves
      the members can approve and execute, and the handover command. Both the
      transfer and a vault-approved upgrade are rehearsed on devnet — see
      [Multisig rehearsal](#multisig-rehearsal).
      Once transferred, every upgrade needs the vault. The extend before it
      never does: the loader's `ExtendProgram` takes no authority account at
      all, and the runtime refuses the upgradeable loader via CPI for anything
      but `Upgrade` and `SetAuthority`, so any payer sends it top-level first. The `PROTOCOL_INIT_AUTHORITY` key is still needed until
      `InitializeProtocol` has run, whoever holds the upgrade authority.
- [x] **Rollout: v2 at a new program id, v1 retired later** (decided
      2026-09-27, replacing the earlier in-place decision). The in-place upgrade
      would have frozen every v1 wallet on one flag day — including Seedless,
      which went live on v1 while v2 was being prepared. Instead:
      - **Phase A** deploys v2 fresh at its own id. No v1 wallet is touched.
        Integrators run both SDKs side by side — 0.3.x (an npm alias) for users
        whose wallet lives on v1, 1.x for new users — and route each user by
        where their wallet is. Bumping the SDK outright would strand existing
        users: 1.x has no v1 Execute, and until phase B the v1 id has no
        `MigrateWallet` either.
      - **Phase B**, when the v1 tail is small, upgrades the v1 id to the
        **sunset binary** (`--features mainnet-v1`): `MigrateWallet`,
        `ReclaimDeferred` and `CloseExpiredSession` only, everything else
        refused with `RetiredDeployment` (4018). `MigrateWallet` delivers to any
        destination the owner signs for, so it moves a v1 wallet straight into
        a v2 vault at the v2 id.
      Staying on v1 meanwhile does not expose passkey Owner wallets to a known
      theft finding — H-1 needs an Ed25519 authority, H-2 a Spender, H-4 a
      session — but H-3 lets any v1 transaction conscript the fee payer, which
      is why the v2 relayer does not sponsor the v1 id until phase B.

      **C-1 stays live for the whole A-to-B window, and that window has no end
      date.** On the v1 binary an admin write of `enabled = 0` reverts every
      CreateWallet, Execute and ExecuteDeferred — every Seedless user frozen —
      and v1 has no way to rotate that admin. Accepted for now, with three
      conditions: the v1 admin key `24fx48GA…` is held offline for the duration
      and never touches a relayer or a CI secret; the `mainnet-v1` sunset
      artifact from §2 stays built, hashed and rehearsed, so phase B is ready as
      an emergency path rather than an improvisation; and the migration UI ships
      with phase A, switched off, not with phase B.
- [ ] **User / integrator comms drafted.** Migration is **user-signed** — one
      `MigrateWallet` transaction per wallet, Owner-rank key required. Dormant
      wallets that never return keep their funds in v1 vaults (reachable only via
      `MigrateWallet`) indefinitely; this is inherent to non-custodial and must
      be communicated.

## 2. Build and record

Three artifacts, built once, hashed once, and deployed from exactly those
files. Nothing below deploys a path that a later build could overwrite.

- [ ] Build from the pinned release commit, **each into its own directory**:
      ```bash
      ( cd program && cargo build-sbf --features mainnet    --tools-version v1.53 --sbf-out-dir ../target/artifacts/v2 )
      ( cd program && cargo build-sbf --features mainnet-v1 --tools-version v1.53 --sbf-out-dir ../target/artifacts/sunset )
      solana program dump LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi target/artifacts/v1-live.so --url <mainnet-rpc>
      shasum -a 256 target/artifacts/v2/lazorkit_program.so target/artifacts/sunset/lazorkit_program.so target/artifacts/v1-live.so
      ```
      ⚠️ **Always pass `--sbf-out-dir`.** On the deploy machine a `cargo` wrapper
      in `~/.zshrc` points `CARGO_TARGET_DIR` at `.git/shared-target`, so a bare
      `cargo build-sbf` writes there and leaves `target/deploy/lazorkit_program.so`
      holding whatever was last copied in. On 2026-09-27 that file was a full-v2
      build (150 KB) while the sunset build (45 KB) sat in the shared dir.
      Deployed to `LazorjRF…`, it would have refused every instruction with 4017
      — `MigrateWallet` included — until someone noticed.
- [ ] **Sanity-check sizes before anything else.** Sunset ≈ 45 KB, full v2
      ≈ 150 KB, the v1 dump 137904 bytes (`8ad5abf5…` on 2026-09-27). A "sunset"
      artifact over 100 KB is the wrong file; stop.
- [ ] Record the toolchain and all three SHA-256 hashes in the deploy log.
      Builds are only trustworthy if reproducible — a second machine must
      produce the same hashes.
      ⚠️ **The toolchain moved after the 2026-09-11 rehearsal.** That run used
      solana-cli 4.0.3 with platform-tools v1.53; the machine now has
      `cargo-build-sbf` 4.2.2. Pin `--tools-version v1.53` as above, record what
      you get, and rehearse (§3) with the files you are actually going to deploy.
- [ ] **SBPF version.** These builds are SBPFv0. Mainnet deploys v0 today —
      SIMD-0500 ("disable deployment of SBPF v0, v1 and v2 programs",
      feature `B8JJXCy5…`) was not even proposed on mainnet or devnet on
      2026-09-27 — but Agave 4.2's test validator activates it at genesis. If it
      is scheduled before either phase, rebuild with `--arch v3`, re-hash, and
      rehearse that artifact: a v0 binary will fail to deploy with *Detected
      sbpf_version required by the executable which are not enabled*. (It keeps
      running; only new deploys and upgrades are refused. That includes a
      rollback to the v1 dump, which is v0.)

## 3. Rehearse (again, with the release artifacts)

- [ ] Run the two-id rehearsal against the §2 artifacts on a local validator,
      at the real ids. `--deactivate-feature` mirrors mainnet, where SIMD-0500 is
      not active; the payer is any local keypair, and is the upgrade authority
      only on this validator.
      ```bash
      solana-test-validator --reset --ledger /tmp/two-id-ledger \
        --deactivate-feature B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g \
        --upgradeable-program LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8 target/artifacts/v2/lazorkit_program.so <payer-pubkey> \
        --upgradeable-program LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi target/artifacts/v1-live.so <payer-pubkey>
      solana airdrop 100 <payer-pubkey> -u localhost

      PAYER=<payer.json> RPC_URL=http://127.0.0.1:8899 WS_URL=ws://127.0.0.1:8900 \
      V2_PROGRAM_ID=LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8 V1_PROGRAM_ID=LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi \
      V1_PRELOADED=1 SUNSET_SO=target/artifacts/sunset/lazorkit_program.so \
        node scripts/rehearse/two-id-rehearsal.mjs
      ```
      It must end `14/14 checks passed`. At the real ids this is the whole
      rollout with the files that will ship: the v1 wallets are made by the
      live v1 binary; the sunset upgrade refuses CreateWallet with 4018; an
      Ed25519 wallet leaves through the kit SDK; a passkey wallet leaves through
      sdk-legacy with the **default pairing** (no program id passed — the path
      every integrator will take); a relayer that swaps the system program in a
      passkey migration is refused; the keeper closes an expired v1 session.
      A binary at the wrong id fails the first check with 4017.
- [ ] Rehearse the **rollbacks**. Phase A's is closing or ignoring a program no
      one uses yet. Phase B's is an upgrade of `LazorjRF…` back to
      `v1-live.so` — rehearse it on the same validator, and note it does not
      un-migrate any wallet already moved.

## 4. Phase A — v2 at its own program id

Nothing here touches a v1 account. The same flow has been rehearsed end to
end — see [Two-id rehearsal](#two-id-rehearsal).

- [ ] The v2 program keypair is the ground vanity `LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8`
      (2026-09-28), kept at `~/.config/solana/lazorkit-v2-program/LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8.json`
      (mode 600, never in a repo). Back it up offline before the deploy. It
      only signs the first deploy; after that the upgrade authority rules.
- [ ] Re-hash `target/artifacts/v2/lazorkit_program.so` and compare with the
      deploy log. Any difference: stop. (`mainnet` is pinned to the v2 id; at
      any other id it refuses everything with 4017.)
- [ ] Deploy fresh (a new program, not an upgrade):
      ```bash
      solana program deploy target/artifacts/v2/lazorkit_program.so \
        --program-id ~/.config/solana/lazorkit-v2-program/LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8.json \
        --upgrade-authority <upgrade-authority.json> \
        --url <mainnet-rpc>
      ```
- [ ] `InitializeProtocol` and a treasury shard on the v2 id, in the same
      window — its ProtocolConfig is a fresh `lk2:` PDA, unrelated to v1's.
- [ ] Relayer: **a new service at a new URL**, running
      `deploy/kora/kora.mainnet.toml` (v2 id only), with its own thin-funded
      signer. Pass `scripts/kora-check.cjs <new-url> --cluster mainnet` with no
      FAIL. **Do not edit the relayer v1 apps use today.** Its config is not in
      any repo and Seedless sponsors through it; narrowing its allowlist to the
      v2 id refuses every v1 transaction from that moment — the flag day phase A
      exists to avoid. Before anything else, record its current `getConfig` and
      which apps call it, in the deploy log.
- [ ] Publish the SDKs whose `PROGRAM_ID_MAINNET` is the v2 id, then move
      `latest` to them. Pinned `^0.3` users — Seedless — are not moved by that.
      Any wrapper that switches to sdk-legacy 1.x (`@lazorkit/wallet`) ships it
      as a **new major**, so `^2` installs do not silently move apps to v2 ids.
- [ ] Integrators run the two SDKs side by side, and route by where the user's
      wallet lives:
      ```bash
      npm i @lazorkit/sdk-legacy@^1.2 sdk-v1@npm:@lazorkit/sdk-legacy@0.3.2
      ```
      A returning user with a v1 wallet (`findV1WalletsByOwner` finds it) keeps
      using `sdk-v1`; a new user gets a v2 wallet. **Do not bump outright**: 1.x
      cannot Execute on v1, and the v1 id has no `MigrateWallet` until phase B,
      so a bumped app loses every existing user until then.

## 5. Phase B — retire v1

Only once the v1 tail is small and the integrators that own it agree. This is
still a breaking change for whoever is left on v1, so announce it.

- [ ] Recover what only the v1 binary can reach, or will need later: the
      sponsor's expired DeferredExec rent (`scripts/rehearse/reclaim-deferred.cjs`
      — it also works after phase B, since `ReclaimDeferred` now accepts v1
      accounts) and the treasury shards' fees (`WithdrawTreasury`, admin).
- [ ] Re-hash `target/artifacts/sunset/lazorkit_program.so` (≈ 45 KB) and
      compare with the deploy log and the artifact §3 rehearsed. Any
      difference: stop.
- [ ] Upgrade the v1 id to it. While the v1 id is still on the single key:
      ```bash
      solana program deploy target/artifacts/sunset/lazorkit_program.so \
        --program-id LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi \
        --upgrade-authority <v1-upgrade-authority.json> \
        --url <mainnet-rpc>
      ```
      If the v1 id has already gone to the Squads vault, this command fails with
      *Incorrect upgrade authority*. Instead: `solana program write-buffer` the
      artifact, `set-buffer-authority` to the vault, and propose the upgrade in
      the app (step 6 of the Squads section). The sunset binary is smaller than
      v1, so no extend is needed.
- [ ] Verify it refuses: a `CreateWallet` or `Execute` against the v1 id fails
      with 4018.
- [ ] Only now add the v1 id to the relayer's `allowed_programs` and
      `require_one_of_programs` (commented in `deploy/kora/kora.mainnet.toml`),
      so migrations can be sponsored. Before this it is full v1, and H-3 lets
      any v1 transaction conscript the fee payer. (Reclaiming the sponsor's
      expired v1 authorizations through the relayer is safe from here: the
      sunset binary pays `ReclaimDeferred`'s rent only to the stored payer.)
- [ ] Turn on the migration banner in each integrator app (`migrateV1Wallet`
      with the default pairing: executes at the v1 id, delivers to the v2 id).
- [ ] Run the session keeper after the upgrade
      (`scripts/rehearse/close-expired-sessions.cjs`); the rent goes to whoever
      runs it first.

## 6. Post-deploy

- [ ] Monitor both ids: no unexpected reverts on v2; migrations landing on v1.
- [ ] Dormant v1 wallets keep their funds indefinitely, reachable only through
      `MigrateWallet`. That is inherent to non-custodial and is how it should be
      communicated.

---

## Two-id rehearsal

The rollout this checklist describes, run end to end by
`scripts/rehearse/two-id-rehearsal.mjs`.

**2026-09-27, local validator (Agave 4.2.2, SIMD-0500 deactivated to match
mainnet), at the devnet ids**, with the review fixes in:

| artifact | id | size | SHA-256 |
|---|---|---|---|
| v1 — the live mainnet program, `solana program dump` | `4h3XoNRe…` (devnet v1) | 137904 | `8ad5abf5dd8a2443fea6b26b5effa9ce11477ce85ba9564f5c43663744c3255b` |
| sunset — `--features devnet-v1`, platform-tools v1.53 | `4h3XoNRe…` | 45760 | `6a816c4af90d7f7a237de8e66aeb117a583dea592ae305589c7adf5de6a9401f` |
| v2 — `--features devnet`, platform-tools v1.53 | `57bTNWqt…` | 150656 | `8c3952a5a2464a19ced58854342a2868e7094863522ad5f423babf851135a01a` |

```
ok    the sunset binary refuses CreateWallet with 4018 RetiredDeployment
ok    the v1 wallet is found at the v1 id from the owner key alone
ok    the migrate instruction goes to the v1 program
ok    the v1 wallet and authority are closed
ok    the SOL is in the v2 vault   0.030000 SOL
ok    the token is in the v2 vault   777000
ok    the destination wallet belongs to the v2 program
passkey migration (default pairing)
ok    the passkey wallet is found from its credential alone
ok    the passkey migrate goes to the v1 program
ok    a relayer swapping the system program is refused
ok    the passkey wallet and authority are closed, the vault empty
ok    its SOL is in its own v2 vault   0.020000 SOL
ok    its token is in its own v2 vault   555000
ok    the v1 session is closed
14/14 checks passed
```

Devnet's v2 (`57bTNW…`) was upgraded to this same v2 artifact afterwards
(`24qPWFCY…`, slot 504832702), so devnet matches the SDKs in this release.

The devnet ids pair by default (`legacyProgramIdFor(57bTNW…) = 4h3XoNRe…`), so
the passkey leg is exactly what an integrator's app will do. On devnet itself,
the same script ran earlier the same day against the rehearsal slot
(`3AN3Wn…`) and proved the 4018 refusal on chain before a flaky public RPC cut
it short; the local run replaces it as the record. §3 repeats it with the
mainnet artifacts at the mainnet ids.

**2026-09-28, the same run at the mainnet ids**, with the §2 commands on this
branch — the mainnet v2 id had just been ground. The v1 dump preloaded at
`LazorjRF…`, v2 at `LazorFroi…`, then `LazorjRF…` upgraded to the sunset build:
**14/14**, the passkey leg again on the default pairing
(`legacyProgramIdFor(LazorFroi…) = LazorjRF…`). The phase B rollback was then
rehearsed on the same validator: `LazorjRF…` upgraded back to `v1-live.so`, and
its programdata dumped with the dump's exact bytes.

| artifact | id | size | SHA-256 (this machine — the release commit re-records) |
|---|---|---|---|
| v1 — `solana program dump` of the live program | `LazorjRF…` | 137904 | `8ad5abf5dd8a2443fea6b26b5effa9ce11477ce85ba9564f5c43663744c3255b` |
| sunset — `--features mainnet-v1`, platform-tools v1.53 | `LazorjRF…` | 45760 | `ccbecead5990b02302dbfd56c356d5d958d0f7cde1a4fbcbdf0bf18bc47e4a80` |
| v2 — `--features mainnet`, platform-tools v1.53 | `LazorFroi…` | 150656 | `dd947f6eacebc10ecbd60269caf340b0541640ccb8963d597b0b4f5f6f5a3ffb` |

§3 still has to be run at deploy time: the artifacts that ship are the ones
built from the merged release commit, and those are the ones to rehearse.

Two things the first local attempts surfaced, both now handled in the script
and in §2/§3: a program upgraded in slot N only runs from N+1, and Agave 4.2's
validator refuses to *deploy* SBPFv0 unless SIMD-0500 is deactivated.

## Rehearsal (in-place, historical)

Superseded by the [two-id rehearsal](#two-id-rehearsal): production no longer
upgrades the v1 id to v2. Kept because the v1 dump it identified is still the
v1 artifact and the phase B rollback.

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

## What the v1 estate is worth, and what the upgrade forfeits

Read off mainnet on **2026-09-24** with
[`scripts/survey-v1-rent.ts`](../scripts/survey-v1-rent.ts) (read-only):

| account | count | avg bytes | rent held | closed by |
|---|---:|---:|---:|---|
| Authority | 171 | 133 | 0.304119 SOL | `MigrateWallet` (Owner) |
| Session | 133 | 196 | 0.290408 SOL | `RevokeSession` — **v1 only** |
| DeferredExec | 91 | 176 | 0.189684 SOL | `ReclaimDeferred` — **v1 only** |
| Wallet | 150 | 8 | 0.138745 SOL | `MigrateWallet` (Owner) |
| TreasuryShard | 16 | 8 | 0.016620 SOL | drained by `WithdrawTreasury`; the account stays |
| FeeRecord | 2 | 32 | 0.002227 SOL | nothing |
| ProtocolConfig | 1 | 88 | 0.001503 SOL | nothing — v2 uses a new seed |
| **total** | **564** | | **0.943306 SOL** | |

Three piles, and they behave differently:

- **0.443 SOL comes back through migration** (Wallet + Authority), to each
  migration's refund destination. The SDK sets that to the payer, so on a
  sponsored migration it returns to us; a user who pays their own gets it. The
  emptied source ATAs are closed to the same destination.
- **0.480 SOL is forfeited unless it is closed before the upgrade** (Session +
  DeferredExec). After v2 lands, no instruction in the binary accepts a v1
  discriminator, so those accounts can never be closed by anyone.
- **0.020 SOL is gone either way** — ProtocolConfig, FeeRecord and the sixteen
  TreasuryShards are simply abandoned at their v1 addresses.

The two v1-only paths are not equally reachable:

- **`ReclaimDeferred` is ours to run.** It requires the *original payer* to
  sign, after expiry — and that payer is the paymaster sponsor on every
  sponsored authorization. 91 accounts, **0.19 SOL**, recoverable by us in a
  batch before the upgrade window.
- **`RevokeSession` is not.** It requires the wallet's own Owner or Admin
  authority, which is the user's passkey. 133 accounts, **0.29 SOL**, and
  realistically most of it is lost: asking every user to revoke a session before
  a deadline is not a plan.

Two smaller facts worth knowing before the day:

- There are **21 more Authority accounts than Wallets**. `MigrateWallet` closes
  the one authority that authorises it, so a wallet with a second authority
  leaves that account behind — roughly 0.037 SOL, unreachable afterwards.
- **User assets are not ours and are not at risk**: the vaults' SOL and tokens
  move to each user's v2 vault as part of their migration. What is at risk is a
  vault whose owner never migrates — their funds stay reachable only through
  `MigrateWallet`, indefinitely, which is inherent to non-custodial.

  The estate behind that sentence, same survey: **64 of the 150 vaults hold SOL**
  (5.609562 SOL in total) and **54 hold tokens** — 125 token accounts across 50
  distinct mints, 24 of them with a non-zero balance. Those token accounts carry
  **0.246663 SOL of their own rent**, which `MigrateWallet` reclaims when it
  closes each emptied source account, to the same refund destination as the rest.
  So a fully migrated estate returns roughly 0.69 SOL of rent, not 0.44.

### What the operator can close alone

Everything else on this page needs a user's signature. Two things do not, and
both only work while the v1 binary is still running. Measured on mainnet
2026-09-24:

| | accounts | amount | key needed |
|---|---:|---:|---|
| expired DeferredExec, sponsor's | 68 | **0.141020 SOL** | the paymaster's fee payer — via the relayer, not in hand |
| TreasuryShard fees above rent | 16 shards | **0.005566 SOL** | the ProtocolConfig admin `24fx48GA…` |
| **total, with no user involved** | | **0.146586 SOL** | |

All 91 DeferredExec accounts on mainnet are expired (the newest expired at slot
447676152, against 449960747 now), but 23 of them belong to four other payers:

```
81BjYyuQ9QirHbopz7UQfEUfit5aSCs3jrD3GND6keon  10 accounts  0.021158 SOL
BXp29W5mbaZBauwfyJ54776cGBoNHEE2cpt63jH8ib2F   9 accounts  0.019043 SOL
H7h12NiJiaFGcsgi2XT6V5Nrnp3MoRjtfXMdJf2zetwH   3 accounts  0.006348 SOL
Cg3DeyKhAmkGTN3pJXwZH1STs9SYRthLLK8AeN7Gq8ds   1 account   0.002116 SOL
```

Those are integrators running their own payer. `ReclaimDeferred` demands the
original payer, so only they can recover that 0.049 SOL — worth one message
before the window rather than silently burning it on their behalf.

The 16 TreasuryShard accounts keep their 0.011054 SOL of rent either way:
`WithdrawTreasury` drains the fees and leaves the account. There is no
instruction that closes a shard, a FeeRecord or the ProtocolConfig.

And what stays out of reach today: the 133 Sessions (0.290408 SOL) need each
wallet's own Owner or Admin authority, which is the user's passkey — v1 has no
expiry-based close, so a session's rent is recoverable only by its user, and
only before the upgrade.

#### Making an expired session closable by anyone

The proposal: keep `RevokeSession` as it is before expiry — only the wallet's
authority may end a live session — and let **anyone** close it once it has
expired, claiming the rent. Three things checked against the code, because they
decide the shape:

- **It is safe.** `immediate.rs:210` already refuses a session with
  `current_slot > session.expires_at`, so an expired session authorises nothing
  and closing it removes no capability. The boundary has to match that
  comparison exactly — `>`, not `>=` — or a keeper can kill a session that is
  still valid in its final slot.
- **No replay window opens.** Closing and re-creating the same session PDA does
  not reset anything an attacker can use: the session key signs the transaction
  itself, so an old signature dies with its blockhash. There is no session
  counter to roll back.
- **The account does not remember who paid.** `SessionAccount` is
  `disc | bump | version | pad(5) | wallet(32) | session_key(32) | expires_at(8)`
  — 80 bytes, no payer field. So "whoever closes it keeps the rent" is the only
  permissionless design that works *as the layout stands*, and for sponsored
  sessions that rent was ours. Refunding the funder instead needs a
  `rent_payer: Pubkey` in the header, which is **free to add only until v2
  ships** and a layout migration afterwards.

The second question is whether this also reaches backwards. The v1 and v2
session headers are byte-identical apart from the discriminator — v1 puts
`wallet` at 8, `session_key` at 40, `expires_at` at 72, exactly as v2 does — so
a v2 instruction can read and close a **v1** session with no extra parsing, the
same trick `MigrateWallet` already uses for v1 wallets. That is the difference
between recovering the 0.290408 SOL sitting on mainnet and burning it.

**Decided and built** (2026-09-24): the closer keeps the rent — no header
change, and cleanup pays for itself — and the instruction accepts v1 sessions as
well as v2 ones. `CloseExpiredSession` is instruction **18**; a session that is
still live is refused with **3036**.

This flips the 0.290408 SOL of v1 sessions from *burned by the upgrade* to
*recoverable after it, by anyone*. So there is no rush to sweep sessions before
the window — the opposite of the DeferredExec accounts, which really do have to
be reclaimed first.

The keeper is written and proven on a live chain:
[`scripts/rehearse/close-expired-sessions.cjs`](../scripts/rehearse/close-expired-sessions.cjs)
scans both discriminators, filters on the same expiry comparison the program
uses, and batches the closes. Run on the devnet staging program
`HQ584adp8ub2FzrTx1fdNmXmrL5yuyVndafPB3x4NYG3` on 2026-09-24 against a binary
built with instruction 18: three expired sessions closed in one transaction
(`2efVmYyLgABSeo7EPeh7tTW3QsT2VFayd6yXCdvtARx5WYjqN4crduYn771BcQT3CecHayAtttVfjb6BLZEVwmTd`),
the keeper's balance moved 6.094155 → 6.097319 SOL, and all three accounts read
back as gone. Dry run by default.

```bash
NODE_PATH=tests-sdk/node_modules \
RPC_URL=https://api.mainnet-beta.solana.com \
PROGRAM_ID=LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi \
KEEPER=<keypair.json> node scripts/rehearse/close-expired-sessions.cjs
```

Run it after the upgrade, and do not count on being first: the rent goes to
whoever gets there, which is the point of making it permissionless.

Six litesvm tests cover the instruction itself: a stranger closes an expired session and keeps the
rent; a live one is refused; the session's **final slot still belongs to it**
(the close uses the same `>` as `execute`, so a keeper cannot end it a slot
early); a v1-shaped session closes; a live v1 one does not; and an Authority
account owned by the same program is not closable as a session.

- [ ] Before the upgrade window: reclaim the sponsor's 68 expired DeferredExec
      accounts (0.141 SOL) and drain the sixteen treasury shards (0.0056 SOL).
      Both need the v1 binary, so both are inside the window, not after it.
- [ ] Tell the four integrator payers above that their 0.049 SOL is reclaimable
      until the upgrade and not after.

      **Rehearsed on devnet, 2026-09-24** with
      [`scripts/rehearse/reclaim-deferred.cjs`](../scripts/rehearse/reclaim-deferred.cjs):
      16 of the 17 accounts there belonged to the sponsor and had expired; two
      transactions closed all 16 and returned 0.033853 SOL. Verified after the
      fact — one DeferredExec account left on devnet, the one with a different
      payer, and the sponsor's balance moved 89.748167104 → 89.765088824 SOL
      across the first batch, which is 8 × 0.00211584 minus the 5000-lamport fee
      exactly.

      The useful part is how it signs. `ReclaimDeferred` demands the *original*
      payer, and on every sponsored authorization that is the Kora fee payer — a
      key inside the relayer's environment, not on anyone's laptop. The script
      does not need it: it builds the transactions with the sponsor as fee payer
      and asks the relayer to sign and send them. No key export, and it works
      the same on mainnet.

      ```bash
      RPC_URL=https://api.mainnet-beta.solana.com \
      PROGRAM_ID=LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi \
      PAYMASTER_URL=<mainnet relayer> KORA_API_KEY=<key> \
      NODE_PATH=tests-sdk/node_modules node scripts/rehearse/reclaim-deferred.cjs
      # then --execute
      ```

      One caveat carried from the rehearsal: an account whose payer is not the
      sponsor can only be reclaimed by that payer. Devnet had one; mainnet will
      have its own share, and the script counts them rather than failing on
      them.
- [ ] Decide whether the 133 sessions are worth a user-facing "revoke before the
      upgrade" prompt, or written off at 0.29 SOL.
- [ ] Re-run the survey on the day. Between 2026-09-11 and 2026-09-24 the estate
      grew by 10 wallets, 12 authorities, 12 sessions and 5 deferred accounts —
      it is still in use, so these numbers move.

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

And the open door leads somewhere. `fee_payer_policy` on that relayer is
permissive where it matters — `system.allow_transfer`, `spl_token.allow_transfer`,
`allow_mint_to`, `allow_set_authority`, `allow_close_account` and their
Token-2022 twins are all `true` — so a sponsored transaction may name the fee
payer as the *source* of a transfer, up to `max_allowed_lamports` (0.1 SOL) per
transaction, with `usage_limit` disabled and the price policy `free`. Nothing
counts how many times a caller comes back. On devnet that is 89 SOL of faucet
money; the same configuration on mainnet is the sponsor's balance.

Our own flows need part of that open: the program funds PDAs and pays the
protocol fee through System CPIs with the payer as source, so
`system.allow_transfer` and `system.allow_create_account` cannot simply be shut.
What bounds a stranger is therefore authentication, `max_allowed_lamports` set
to what a real flow costs rather than a round number, and `usage_limit`. All
three are currently off or loose.

### Upgrade the relayer before relying on any of these controls

`getVersion` on the live endpoint answers **`2.2.0-beta.7`** (released
2026-03-27). Upstream's latest tag is **`v2.2.0-beta.8`** (2026-07-29), 164
commits later, and `main` is 42 commits beyond that. The checkout in
`~/Documents/LazorKit/kora` is older still — a year behind what is deployed, and
its sample `kora.toml` describes a flatter `fee_payer_policy` than the running
server reports, so read the upstream tag, not that checkout.

The gap matters because beta.8 fixes the very controls we are about to lean on:

| upstream fix | why it matters here |
|---|---|
| [#602](https://github.com/solana-foundation/kora/pull/602) — apply `--api-key`/`--hmac-secret`, previously parsed and **ignored** | on beta.7 an operator who sets the key on the command line gets an unauthenticated server and the key in the process table |
| [#463](https://github.com/solana-foundation/kora/pull/463), [#571](https://github.com/solana-foundation/kora/pull/571) — atomic, all-or-nothing usage limits | the per-caller ceiling is the main bound on a public relayer; on beta.7 concurrent requests race past it |
| [#620](https://github.com/solana-foundation/kora/pull/620) — transaction-validation and fee-payer accounting hardening | inner-CPI reconstruction so fee-payer policy gates actually run, rent counted in outflow, owner allowlists on Assign/CreateAccount |
| [#552](https://github.com/solana-foundation/kora/pull/552) — redact the URL path and query in client-facing errors | our RPC endpoint carries its credential in the query string; on beta.7 a transport error hands it to whoever made the request, and that endpoint asks for no credentials |
| [#542](https://github.com/solana-foundation/kora/pull/542), [#541](https://github.com/solana-foundation/kora/pull/541) — loader/deploy-authority drain guards | same attack surface as the fee-payer policy above |
| RUSTSEC-2026-0185, -0204 dependency bumps | routine, but they are in the deployed build |

beta.8 also adds an auth mechanism that actually fits a public dApp:
**`[kora.auth].recaptcha_secret`** with `recaptcha_score_threshold` (env
`KORA_RECAPTCHA_SECRET`, header `x-recaptcha-token`). An API key shipped in a
browser bundle is not a secret; a per-visitor reCAPTCHA token is the thing a
bundle reader cannot mint in bulk.

Two things worth having are only on `main`, not yet in a tag: configurable CORS
origins ([#658](https://github.com/solana-foundation/kora/pull/658)) and
`max_priority_fee_lamports` ([#638](https://github.com/solana-foundation/kora/pull/638)).
Upstream has also been fuzzing fee-payer drains specifically (#618, #640,
#648–#651), which is a fair signal about where the risk is.

- [ ] Upgrade the relayer to `ghcr.io/solana-foundation/kora:v2.2.0-beta.8`
      (Railway image bump) **before** enabling auth and usage limits, so the
      controls behave as documented.
- [ ] Re-run `kora-check.cjs` afterwards: `version` should read `2.2.0-beta.8`.
- [ ] Note the one breaking change: `usage_limit.enabled = true` with no rules
      now **fails startup** instead of silently doing nothing.

The configuration itself is written out, for both clusters, in
[`deploy/kora/`](../deploy/kora/) — `kora.mainnet.toml`, `kora.devnet.toml` and
a README covering the env vars and the Railway steps. Every value carries its
reasoning inline; the four things that actually bound a stranger are
`require_one_of_programs` (a transaction that never touches LazorKit is refused
outright), authentication, `max_allowed_lamports` set from measured cost, and
the usage limits.

Check any relayer against all of this from the outside, with no key and no
transaction:

```bash
node scripts/kora-check.cjs https://kora.devnet.lazorkit.com --cluster devnet
```

It exits non-zero on a FAIL, so it can gate a deploy. Today that endpoint
returns three: no authentication, no Secp256r1 precompile in `allowed_programs`,
and the fee-payer policy above on an unauthenticated host.

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
- [ ] Confirm the live `allowed_programs` contains the v2 id (`LazorFroi…`) on the
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
  paymaster section: the mainnet config must list the v2 program id and the
  Secp256r1 precompile, or every sponsored transaction fails this way.

## Kit-SDK migration rehearsal

Run on devnet on **2026-09-24** with
[`scripts/rehearse/migrate-v1-kit.mjs`](../scripts/rehearse/migrate-v1-kit.mjs),
against throwaway program `3AN3WnaAN6SteghykdM96qHSGUJiVAUHWFjiyz31myAA`.

The legacy SDK's migration had already been proven on chain three times. The
kit SDK's had not: `@lazorkit/sdk` 1.0.0-rc.2 shipped `migrateV1Wallet` with
unit tests and a byte-parity check against the legacy builder — which proves the
instruction is identical and nothing about the flow around it. An integrator on
the kit SDK would have been the first to find out.

One run, four steps: create a v1 wallet with `@lazorkit/sdk-legacy` 0.3.2 on the
live v1 binary, fund it (0.03 SOL + 777,000 of a fresh mint), upgrade the
program in place to v2, then migrate with the kit SDK from **the owner key
alone** — no user seed, which is the case a returning user is actually in.

| | |
|---|---|
| v1 wallet | `ExDysxenQEQPXhGRePWRXqXnVPMzaVjGLdwfX7Fz9hvE` |
| upgrade | `7M7Tk81XW1WaJvuXwpMHoBzcDdkYKc4KRcMcjxjnS4hC7xVbzFjB4qS9rUB5mdL7UeJh2c9QFpyCYx3tDRXcsmj` |
| setup | `62e7msSswXpaRehwF6ksh6TRQsA6Bhz3sUnCfBmFq6W9L9duhVzq3ph8jdj8HTxUgAC1q6MWcBpVR1Vm2xuDuqfB` |
| migrate | `2W7yh1iDVfnQ5MTKg3k2kXS2gqVtPnTYbhZc4tKdyN6ZfXMiBjKM5tdkafNrnztZa6WqoBzELaNNJPur5iR9orn5` |

**12/12 checks passed**: the scan finds the wallet with no seed and hands back
the owner key it read off the chain; the plan derives the same vault, enumerates
the token, and mints a destination seed; and after the two transactions the v1
wallet and authority are closed, the v1 vault is empty, 0.030000 SOL and all
777,000 tokens are in the v2 vault, and the emptied source token account is
closed.

One thing the run corrected in the rehearsal harness rather than the SDK: kit's
`signTransactionMessageWithSigners` takes its signers from the message, not from
an options bag, so a second signature the *instruction* requires — the Ed25519
owner — is simply missing. `signTransaction([payerKeyPair, ownerKeyPair],
compileTransaction(message))` is the shape that works, and it is worth saying in
the docs before an integrator hits `Transaction is missing signatures for
addresses: …` with no idea which key it means.

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

- **The extend cannot go through the vault, and never will.** The first attempt
  put `ExtendProgramChecked` inside the vault transaction and execution failed:
  `BPFLoaderUpgradeab1e… not supported by inner instructions`. Via CPI the
  loader accepts only `Upgrade` and `SetAuthority`; the plain `ExtendProgram`
  needs no authority account at all, so any payer sends it top-level first and
  the vault then executes `Upgrade`.

  This was written as "while the feature is inactive, re-check on the day".
  There is nothing to re-check: Agave retired the gate by pointing it at a burn
  address. `solana feature status -um` lists
  `ExtendProgCheckedWi11BeDe1eted11111111111111 | inactive | Enable
  ExtendProgramChecked instruction`, and no one holds that address's key, so it
  can never activate. The id this repo used to name, `2oMRZEDW…`, is not a
  known feature to solana-cli 4.2.2 at all — `solana feature status 2oMRZEDW… -um`
  answers `Unknown feature`. The script no longer reads it; `extend` is its own
  command, because that transaction lands immediately and cannot be undone.
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

## Key custody

Four keys matter, and they are not the same kind of thing. Sorting them by what
a leak costs is what decides where each one lives.

| key | what it can do | today | target |
|---|---|---|---|
| upgrade authority `4fZM6RPR…` — **both** the v1 id `LazorjRF…` and the v2 id | replace either program binary — every vault on it | plaintext file on one laptop | the Squads vault: v2 id after phase A, v1 id after phase B |
| ProtocolConfig admin `24fx48GA…` (v1) | withdraw treasury, rewrite fee config, freeze v1 (C-1) | plaintext file on the same laptop | offline until phase B retires it; v1 cannot rotate it |
| ProtocolConfig admin (v2) | the same, on v2 | set at v2's `InitializeProtocol` | the same Squads vault, via propose/accept |
| Kora sponsor `7Pkkhm8…` | spend the paymaster's balance | the relayer's environment | unchanged — but split per cluster and kept thin |
| devnet throwaway `9AmBA2C7…` | nothing that matters | committed in the repo | unchanged |

**Both catastrophic keys can stop being keys.** The upgrade authority moves to
the vault through Squads' Safe Authority Transfer, which is already written up
below. The admin can follow it: `withdraw_treasury` and `rotate_admin` check
nothing but `admin.is_signer()` and the stored pubkey, and a Squads vault PDA
signing inside a vault transaction satisfies both. The two-step rotation is a
gift here — `accept_protocol_admin` requires the **new** admin to sign, so the
vault proves it can sign before the rotation completes, and a wrong address
fails instead of orphaning the protocol.

`PROTOCOL_INIT_AUTHORITY` is compiled in and permanent, but its power is
one-shot: once `InitializeProtocol` has run, that key can do nothing else. It
does not need long-term custody, only the deploy window.

- [ ] After phase A settles: move the **v2 id's** upgrade authority to the
      vault (below), then rotate the v2 ProtocolConfig admin to the same vault
      with propose/accept.
- [ ] After phase B lands: move the **v1 id's** upgrade authority to the vault
      too. From then on no single key can replace either binary.
- [ ] Until then, the two keys are hot files. At minimum `chmod 600` the keypair
      at `~/.config/solana/`, and delete the commented-out copy of the deployer
      secret from `lazorkit-admin/.env` — being commented out does not protect
      plaintext.

**The sponsor is one key across two clusters.** `7Pkkhm8…` signs on devnet and
on mainnet, and the devnet relayer accepts unauthenticated requests while
holding 89.78 SOL. A compromise there is a compromise of the mainnet payer. Give
each cluster its own signer; there is no reason they are the same key beyond
convenience during setup.

- [ ] Separate the devnet and mainnet paymaster signers before mainnet traffic
      starts.
- [ ] Keep the mainnet float thin and topped up on a schedule rather than
      funded once. It sits at 0.0802 SOL today — about 27 wallet creations —
      so the number to pick is a week of expected traffic, not a year of it.

**For anything a human holds**, the rule is that a key never becomes a
screenshot, a chat message, a repo file or an iCloud-synced document. A hardware
wallet for anything with mainnet authority; a password manager if it has to be
software. A key that has been through any of those channels is not secured by
moving it somewhere better — it is rotated, and the funds and roles move to a
fresh one.

## Handing the upgrade authority to the Squads vault

The multisig already exists on mainnet. Read on 2026-09-23 straight off the
chain, and re-checkable at any time with `preflight` below:

| | |
|---|---|
| multisig | `Gb65EbMEZocGgotuTzJEfogfT3GPr8t8fARWYfMCHaw9` |
| vault (index 0) | `E11nkm79w4rEnB2ZNmTKhWKF4BH5z34LUkTw2L4LBjKa` — 0.001 SOL |
| threshold | **3 of 5**, every member holds Initiate+Vote+Execute |
| config authority | none — only the members can change it |
| time lock | 0 |
| transactions so far | **0 — it has never executed anything** |

```bash
DEPS=$(mktemp -d) && npm i --prefix "$DEPS" @sqds/multisig@2.1.4 @solana/web3.js@1.98.4

# once per program: the v2 id after phase A, LazorjRF… after phase B
RPC_URL=https://api.mainnet-beta.solana.com \
PROGRAM_ID=<LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8 | LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi> \
MULTISIG=Gb65EbMEZocGgotuTzJEfogfT3GPr8t8fARWYfMCHaw9 \
NODE_PATH="$DEPS/node_modules" node scripts/rehearse/squads-upgrade.cjs preflight
```

It signs nothing and needs no keypair: it prints PASS/FAIL for each invariant
and, while the authority is still a single key, the handover command with the
addresses filled in.

**The current authority is not a member.** `4fZM6RPR…` holds the program today
and appears nowhere in that member list, so the handover is a one-way door for
that key: afterwards nothing it can sign touches the program. Whoever holds
three of the five member keys holds the program.

There are two programs to hand over (section 1): the **v2 id once phase A has
settled**, and **`LazorjRF…` once phase B has landed**. Run the steps below for
each — steps 1–3 only once. Step 4 ends the old key's control of that program
for good:

- [x] **1. Reach three signers.** The maintainer holds four of the five member
      keys, against a threshold of three, so quorum does not depend on anyone
      else being available.

      **None of the five is a keypair file on the deploy machine**, and no
      Ledger is attached (`solana-keygen pubkey usb://ledger` → `no device
      found`; a scan of every 64-byte keypair JSON under `~/.config/solana` and
      the repo tree matched none of the members). They live in Phantom — wallets,
      not files —
      which is the right place for them, and which decides how the day runs:
      **`scripts/rehearse/squads-upgrade.cjs` cannot propose, approve or execute
      anything here.** It signs with keypair files only. Its job is
      `preflight`, `addresses`, `status`, and the top-level `extend`, all of
      which need no member key. Everything that needs a member signature
      happens in the Squads app.
- [ ] **2. Prove the multisig works, on mainnet, before it owns anything.** The
      transaction index is 0: these five keys have never approved anything
      together, and the first time they do should not be the hour a live
      program depends on it. In the app: **Programs → Add Program** with
      the v2 id is itself a Squad
      transaction, so it doubles as the rehearsal — propose it, collect three
      approvals, execute. Then `preflight` again: `proven` flips to PASS.

      (If you would rather prove it without touching the program at all, the
      script's `dry-run` proposes a memo signed by the vault — but it needs a
      member keypair *file*, which is exactly what we do not have and should
      not create.)
- [ ] **3. Rehearse a full upgrade against a throwaway program**, with the same
      shape as mainnet, as recorded under [Multisig rehearsal](#multisig-rehearsal).
      That rehearsal used a 2-of-3 with all keys local; repeat the
      propose-then-approve-in-the-app half with this 3-of-5 so the operator has
      seen the actual UI path once.
- [ ] **4. Hand over — prefer Safe Authority Transfer.** The Squads app's
      Add Program step offers three ways to move the authority, and they are not
      equally safe:
      - **Safe Authority Transfer (SAT)** — the app builds a transaction inside
        the Squad that is signed by *both* the vault PDA and the current
        authority. The vault proving it can sign is exactly the check the CLI
        cannot do, so a wrong destination fails instead of bricking the
        program. Use this one.
      - The CLI fallback, if SAT is unavailable:
        ```bash
        solana program set-upgrade-authority <LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8 | LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi> \
          --new-upgrade-authority E11nkm79w4rEnB2ZNmTKhWKF4BH5z34LUkTw2L4LBjKa \
          --skip-new-upgrade-authority-signer-check \
          --upgrade-authority <current-authority-keypair> \
          --url https://api.mainnet-beta.solana.com
        ```
        The flag waives only the new authority's signature, which a PDA cannot
        give. It does **not** check that the address is a vault, or that anyone
        controls it — a typo here is a permanently frozen program. Paste the
        vault address from `preflight`, never by hand.

      Docs: [Squads — Programs](https://docs.squads.so/main/navigating-your-squad/developers-assets/programs).
- [ ] **5. Verify.** `preflight` again: `program authority` must read
      `already the vault`, and `solana program show <program id>` must agree.
- [ ] **6. Note what changes for every upgrade after this.**
      - `solana program deploy` against this program, `set-upgrade-authority`
        and `--final` all now need a vault transaction with three approvals.
      - Buffers must have their authority set to the vault **before** the
        proposal (`solana program set-buffer-authority <buffer>
        --new-buffer-authority <vault>`); the script refuses to propose
        otherwise, and also refuses while the program's authority is not yet the
        vault.
      - **The upgrade itself runs in the app**: Programs → the program → *Add
        upgrade*, giving the buffer address, a spill address and a refund
        address. The app then hands you a CLI line to move the buffer's
        authority, and verifies it before the upgrade can be proposed.
      - **Extend first, separately.** A bigger binary needs the programdata
        grown, and that cannot go through the vault at all — the loader's
        `ExtendProgram` is top-level and needs no authority, so the deploy key
        sends it (`squads-upgrade.cjs extend <bytes>`, or `solana program
        extend`). It lands immediately, with no approval and no undo.
      - **The spill address is real money.** `Upgrade` refunds the buffer's rent
        and the programdata's excess — for this program roughly 0.96 SOL — to
        whatever address is given. The app asks for it; do not leave it on a
        throwaway.
      - The script's own `upgrade` / `resume` / `set-authority` paths stay for
        environments where member keys are files (the devnet rehearsal). On
        mainnet they cannot sign; `resume` there also insists on an explicit
        index, because the newest transaction on the multisig is whatever
        anyone last proposed in the app.
      - The handover is one-way for the old key but **not** irreversible for the
        multisig: `SetAuthority` is one of the two loader instructions the
        runtime allows via CPI, so three members can always hand the authority
        back out (`set-authority <key>`).

`InitializeProtocol` is unaffected: it is authorized by the compiled-in
`PROTOCOL_INIT_AUTHORITY`, not by the upgrade authority, so the order of the
handover against the v2 deploy window is free. (The sunset binary refuses
`InitializeProtocol` outright, so the v1 id's handover has no such question.)

## Deploy log template

```
date/operator:
release commit:                 <sha>
toolchain (rustc / solana):     <versions>   platform-tools: v1.53
v2 id:                          LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8
v2 .so sha256 / size:           <hash> / <bytes>      (target/artifacts/v2)
sunset .so sha256 / size:       <hash> / <bytes>      (target/artifacts/sunset, ≈ 45 KB)
v1 live dump sha256:            <hash>                (target/artifacts/v1-live.so)
§3 two-id rehearsal:            14/14 at <date>
old relayer getConfig + users:  <recorded before phase A>
survey run (private) at slot:   <slot>   funded vaults: <n>   total: <sol>
upgrade authority:              4fZM6RPR…   (confirmed held: y/n)
upgrade authority after:        <key or vault>   multisig threshold: <m of n>
protocol admin:                 24fx48GA…   (confirmed held: y/n)
pre-upgrade  Data Length/slot:  <n> / <slot>
upgrade tx signature:           <sig>
post-upgrade Data Length/slot:  <n> / <slot>
rollback .so (v1) sha256:       <hash>
```
