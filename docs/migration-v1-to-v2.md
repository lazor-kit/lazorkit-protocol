# Migrating v1 wallets to v2

## Why this exists

Mainnet is a live deployment with real users — wallets holding SOL and SPL
tokens, most controlled by passkeys on users' own devices. Run
`scripts/survey-v1.ts` for the current on-chain picture (keep its output private;
it is operational intelligence, not repo content). Keeping the vanity program id
and upgrading in place means v2's `lk2:`-namespaced seeds leave every v1 vault at
an address the new binary owns but no longer understands.

A user's funds can only ever be moved by that user's own key. So the migration
is **user-authorized, not operator-driven** — there is no path, and deliberately
no code, that lets anyone else move a user's funds. What v2 adds is the bridge
that makes the user's own move a single signed instruction.

## What `MigrateWallet` does

Discriminator `17`. Because v2 runs at the same program id as the retired v1
binary, it can still sign for a v1 vault with the old seeds. Authorized by the
wallet's v1 authority (an Ed25519 signer, or a Secp256r1 passkey signing a fresh
challenge), one instruction:

1. authenticates against the v1 authority (old discriminator, byte-compatible
   header — see [`program/src/legacy.rs`](../program/src/legacy.rs));
2. moves every named SPL token fully from the v1 vault's token account to a
   token account owned by the destination, and closes the emptied source;
3. sweeps the v1 vault's SOL to the destination;
4. closes the v1 wallet and authority PDAs, refunding their rent.

**The destination is bound into what the key signs.** A relayer cannot redirect
the sweep — a swapped destination breaks the challenge (`InvalidMessageHash`,
3005). The source token account must be the vault's own, the destination token
account must belong to the approved destination, and both must share a mint.

## What is proven, and what you must rehearse

Proven end-to-end in `program/tests/migrate_v1_tests.rs` against the real program
`.so` in a local SVM, for **both** authority types:

- SOL sweep + PDA close (Ed25519 and passkey);
- SOL + SPL token migration (the USDC case), full WebAuthn assertion and
  Secp256r1 precompile for the passkey path;
- authorization negatives: no signature, wrong key, redirected destination
  (3005), and a v2-shaped account refused through the v1 path.

The in-place `solana program deploy --upgrade` mechanics — a runtime guarantee
rather than program logic — are rehearsed live by `scripts/rehearse/run.sh`,
which was run green: a fresh validator with v1 deployed upgradeable at the vanity
id, `solana program deploy --upgrade` swapping the binary in place (Data Length
135704 → 147832, confirmed by `solana program show` before/after), then
MigrateWallet moving 2 SOL and 74 tokens to the v2 destination and closing the v1
PDAs. Re-run it against the real binaries before touching mainnet.

## Rollout: two shapes, pick before you deploy

**A. Immediate in-place upgrade (a short freeze window).** Upgrade the vanity id
to v2 now. The instant you do, a v1 wallet's normal `Execute` stops working (v2
rejects the v1 discriminator), so until a user migrates they can *only* call
`MigrateWallet`. Their funds are never at risk — the vault is untouched until the
user acts — but their wallet is frozen for everything else. Value is
concentrated in a small number of wallets (check the survey), so announcing and
migrating the active users promptly clears most of it quickly.

**B. v1 hotfix first (no freeze).** Ship a v1.x that adds only a migrate-out
helper, leaving all v1 behaviour intact, and optionally fixes C-1. Users migrate
over an open window while v1 still works normally; upgrade to full v2 only after
the vaults are drained. Two mainnet upgrades and a v1 branch, but no user is ever
frozen. Heavier; choose it if the freeze window in (A) is unacceptable.

Either way the migration instruction and its safety properties are identical.

## Pre-mainnet rehearsal (local validator)

`scripts/rehearse/run.sh` automates the whole thing — it preloads v1-shaped
accounts, deploys v1 upgradeable, upgrades in place to v2, and runs MigrateWallet,
asserting the funds landed. Build the two binaries and point the script at them:

```bash
# v2 from HEAD; v1 from the commit before the seed rename, to a separate target.
( cd program && cargo build-sbf --features devnet )
cp target/deploy/lazorkit_program.so /tmp/lazorkit-rehearse/lazorkit_v2.so
git worktree add --detach /tmp/lk-v1 <v1-commit>
( cd /tmp/lk-v1/program && CARGO_TARGET_DIR=/tmp/lk-v1/target cargo build-sbf --features devnet )
cp /tmp/lk-v1/target/deploy/lazorkit_program.so /tmp/lazorkit-rehearse/lazorkit_v1.so

V1_SO=/tmp/lazorkit-rehearse/lazorkit_v1.so \
V2_SO=/tmp/lazorkit-rehearse/lazorkit_v2.so \
  scripts/rehearse/run.sh
```

The manual equivalent, and the mainnet procedure (which uses `--features mainnet`
and real keys):

```bash
# 1. Build the current v1 (the commit before the seed rename) and v2.
git worktree add --detach /tmp/lk-v1 <v1-commit>
( cd /tmp/lk-v1/program && CARGO_TARGET_DIR=/tmp/lk-v1/target cargo build-sbf --features mainnet )
( cd program && cargo build-sbf --features mainnet )

# 2. Record both hashes — these go in the deploy log.
shasum -a 256 /tmp/lk-v1/target/deploy/lazorkit_program.so
shasum -a 256 target/deploy/lazorkit_program.so

# 3. Genesis-deploy v1 upgradeable at the vanity id, upgrade authority = your key.
solana-keygen new -o /tmp/ua.json
solana-test-validator --reset \
  --upgradeable-program LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi \
    /tmp/lk-v1/target/deploy/lazorkit_program.so $(solana-keygen pubkey /tmp/ua.json)

# 4. Create a v1 wallet, fund it, mint it a token (v1 needs its protocol
#    initialized first — mirror the mainnet ProtocolConfig).

# 5. Upgrade in place to v2 (satisfies v2's own-address check).
solana program deploy --program-id LazorjRF... \
  --upgrade-authority /tmp/ua.json target/deploy/lazorkit_program.so

# 6. Run MigrateWallet and confirm the SOL and token landed at the v2 vault and
#    the v1 PDAs closed.
```

> The worktree shares the repo's target directory unless you set
> `CARGO_TARGET_DIR` explicitly, and a shared target dir will let the v1 build
> clobber the v2 artifact. Keep them separate, and verify the two `.so` sizes
> differ before deploying.

Before the real upgrade, also: re-run `scripts/survey-v1.ts` for a current
picture, and confirm the mainnet upgrade-authority and ProtocolConfig-admin keys
are the ones you hold.

## Building the migration transaction

The reusable pieces are in `@lazorkit/sdk-legacy`:

- `findV1WalletPda` / `findV1VaultPda` / `findV1AuthorityPda` (`utils/v1.ts`) —
  the old-seed addresses.
- `createMigrateWalletIx` (`utils/instructions.ts`) — assembles the instruction.

**Ed25519 authority.** Derive the v1 accounts and the v2 destination vault, then:

```ts
const ix = createMigrateWalletIx({
  payer, v1Wallet, v1Authority, v1Vault,
  destination: v2Vault,        // the user's new v2 vault, same owner
  refundDestination: payer,    // where reclaimed rent goes
  authSigner: ownerKeypair.publicKey,
  authSignerIsSigner: true,
  tokens: [{ sourceAta, destAta }],  // one pair per mint held
  programId,
});
// Sign the tx with payer + ownerKeypair.
```

**Secp256r1 passkey.** Produce the auth payload and precompile instruction with
the existing `finalizeSecp256r1` flow, using `DISC_MIGRATE_WALLET` and a
`signedPayload` of `concat(destination, v1Wallet, [tokens.length])`. Place the
precompile instruction immediately before the migrate instruction, and pass the
fee payer as the non-signing `authSigner` placeholder. The wallet and token-count
binding is what stops a relayer replaying the signature against another wallet or
dropping tokens to strand them; **only an Owner-rank authority may migrate.**

## What was rejected, and why

Not built: an admin/operator function that sweeps user vaults without the user's
key. It is theft of funds the operator holds no key to — the survey shows the
vaults are controlled by independent users' own keys — and it is the exact
backdoor class this version exists to remove. Every legitimate migration keeps the user's key on the
authorizing side and the user's funds on the destination side.
