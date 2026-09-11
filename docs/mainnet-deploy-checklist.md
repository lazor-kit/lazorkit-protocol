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

## 5. The upgrade

- [ ] ```bash
      solana program deploy target/deploy/lazorkit_program.so \
        --program-id LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi \
        --upgrade-authority <mainnet-upgrade-authority.json> \
        --url <mainnet-rpc>
      ```
- [ ] `solana program show LazorjRF…` — confirm Data Length changed to the v2
      size and the slot advanced. Record the upgrade signature.
- [ ] C-1 is now dead. Verify: a `CreateWallet`/`Execute` no longer reverts when
      fees are unconfigured.

## 6. Post-deploy

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
| v2 — `6f4cb94`, `--features mainnet`, solana-cli 4.0.3 | 149296 | `e22f176df7b3a597e6abc16bec3fcfc1bb6301cf8d72c9cc7e34c30969546752` |

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

## Deploy log template

```
date/operator:
release commit (v2):            <sha>
toolchain (rustc / solana):     <versions>
v1 .so sha256:                  <hash>
v2 .so sha256:                  <hash>
survey run (private) at slot:   <slot>   funded vaults: <n>   total: <sol>
upgrade authority:              4fZM6RPR…   (confirmed held: y/n)
protocol admin:                 24fx48GA…   (confirmed held: y/n)
pre-upgrade  Data Length/slot:  <n> / <slot>
upgrade tx signature:           <sig>
post-upgrade Data Length/slot:  <n> / <slot>
rollback .so (v1) sha256:       <hash>
```
