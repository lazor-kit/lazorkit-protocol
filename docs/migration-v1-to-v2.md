# Migrating v1 wallets to v2

## Why this exists

Mainnet is a live deployment with real users — wallets holding SOL and SPL
tokens, most controlled by passkeys on users' own devices. Run
`scripts/survey-v1.ts` for the current on-chain picture (keep its output private;
it is operational intelligence, not repo content).

v2 does not replace v1 in place. It launches at **its own program id**, and the
v1 id keeps running v1 until it is retired by an upgrade to the **sunset
binary** — a build that serves only the ways out of a v1 wallet (see
[`mainnet-deploy-checklist.md`](mainnet-deploy-checklist.md) for the two
phases). A v1 wallet therefore has to move: its vault is a PDA of the v1
program, and only code running at the v1 id can sign for it.

A user's funds can only ever be moved by that user's own key. So the migration
is **user-authorized, not operator-driven** — there is no path, and deliberately
no code, that lets anyone else move a user's funds. What the sunset binary
offers is the bridge that makes the user's own move a single signed
instruction.

## What `MigrateWallet` does

Discriminator `17`, executed **at the v1 id** by the sunset binary (it also
exists in full v2, for the in-place layout the rehearsal slot and staging still
use). Authorized by the wallet's v1 authority — an Ed25519 signer, or a
Secp256r1 passkey signing a fresh challenge that binds the v1 program id — one
instruction:

1. authenticates against the v1 authority (old discriminator, byte-compatible
   header — see [`program/src/legacy.rs`](../program/src/legacy.rs));
2. moves every named token account fully from the v1 vault to a token account
   owned by the destination with `TransferChecked`, and closes the emptied
   source (Token-2022 transfer-fee mints included: the fee is withheld as
   usual and the rest arrives);
3. sweeps the v1 vault's SOL to the destination, through the real System
   Program only, and refuses to finish unless the vault is empty afterwards;
4. closes the v1 wallet and authority PDAs, refunding their rent.

**The destination is any address the owner signs for** — in practice their v2
vault, at the v2 program id. The program never asks whose it is; that is the
client's job, and it matters (see below).

**What the owner signs** is
`destination ‖ v1_wallet ‖ num_tokens ‖ refund_dest ‖ source_ata[0..n]`. A relayer
cannot redirect the sweep, swap which token accounts move, or send the rent
elsewhere — any of those breaks the challenge (`InvalidMessageHash`, 3005). An
Ed25519 owner's transaction signature covers every account besides.

**Token accounts not listed are stranded** when the wallet closes, and after the
sunset nothing else can reach them. Some can never be listed: a **frozen**
account cannot be transferred from, and a Token-2022 mint with a **transfer
hook** needs extra accounts the migration cannot pass. Either would make the
whole migration revert — and a stranger can plant one in anyone's vault for the
price of its rent. The SDK therefore enumerates every vault token account
(SPL Token and Token-2022), leaves those two kinds out, and returns them as
`skippedTokens` so the app can tell the user what stays behind.

## Choosing the destination — the part the program cannot check

`migrateV1Wallet` picks where the funds land:

- with `userSeed`: that seed's v2 wallet;
- otherwise: a v2 wallet this owner already has, or a fresh one from a random
  seed (returned as `destinationUserSeed` — persist it).

A wallet is only reused if `vetMigrationDestination` passes: **exactly one
authority — this key, at Owner rank — no live session, no unexpired deferred
execution.** Being *an* authority on a wallet proves nothing. v2 `CreateWallet`
takes the owner as plain data and `AddAuthority` never asks the key being added,
so anyone can build a wallet that lists a victim's passkey and still keep a hand
on the vault through another authority, a session or a pending authorization.
The v1 `user_seed` is public (it is in the v1 `CreateWallet` instruction data),
so a `userSeed` wallet can be squatted too; one that fails the check throws
rather than being used.

## What is proven

- `program/tests/migrate_v1_tests.rs` — against the real program `.so` in a
  local SVM, for both authority types: SOL and SPL/Token-2022 migration, the
  full WebAuthn assertion and Secp256r1 precompile, a transfer-fee mint,
  redirected destination (3005), swapped source accounts, and a relayer
  swapping the system program (`IncorrectProgramId`).
- `program/tests/sunset_tests.rs` — against the sunset build: every other
  instruction is refused with 4018, and `MigrateWallet` delivers to a
  destination at another program id.
- `scripts/rehearse/two-id-rehearsal.mjs` — the rollout end to end: the live v1
  binary makes the wallets, the v1 id is upgraded to the sunset binary, an
  Ed25519 wallet leaves through the kit SDK and a passkey wallet through
  sdk-legacy with the default pairing, into v2 at its own id. Recorded under
  [Two-id rehearsal](mainnet-deploy-checklist.md#two-id-rehearsal); §3 of the
  checklist repeats it with the release artifacts.

## The rollout, briefly

1. **Phase A** — v2 at its own id. Nothing on v1 changes; apps run the 0.3.x
   SDK for existing users and 1.x for new ones, side by side.
2. **Phase B** — the v1 id is upgraded to the sunset binary
   (`--features mainnet-v1`). From then on a v1 wallet can do exactly one
   useful thing, `MigrateWallet`, and the app's migration banner offers it.
   Dormant wallets keep their funds in v1 vaults, reachable the same way
   whenever their owner returns.

The earlier plan — upgrade the v1 id to v2 in place, freezing every v1 wallet
until its owner migrated — was replaced on 2026-09-27, when Seedless went live
on v1. The migration instruction and its safety properties are the same either
way; only who is frozen, and when, changed.

## Building the migration transaction

Use the client method; it finds the accounts, vets the destination, creates the
destination token accounts and binds the right payload:

```ts
import { LazorKitClient } from '@lazorkit/sdk-legacy';

const client = new LazorKitClient(connection); // the v2 program id
const [found] = await client.findV1WalletsByOwner(credentialIdHash, 'secp256r1');

const plan = await client.migrateV1Wallet({
  payer,
  owner: { type: 'secp256r1', credentialIdHash, compressedPubkey: found.ownerPubkey, rpId },
  v1Wallet: found.wallet,
  // excludeTokenAccounts: [...],   // anything the user chose to abandon
});
// show plan.skippedTokens to the user before they sign
// send plan.setupInstructions, then:
//   passkey:  sign plan.migrate.challenge, send plan.migrate.finalize(response)
//   ed25519:  send plan.migrate.instruction signed by payer + owner
```

The v1 program id is found by pairing (`legacyProgramIdFor`): mainnet v2 pairs
with `LazorjRF…`, devnet v2 with `4h3XoNRe…`. Pass `v1ProgramId` for anything
else. A client built *at* a v1 id throws: the destination would be derived under
a program that can never sign for it.

The kit SDK (`@lazorkit/sdk`) has the same method with the same behaviour.

For a hand-built instruction, `createMigrateWalletIx` takes the v1 accounts, the
destination, and one **`{ sourceAta, destAta, mint, tokenProgram }`** per token
account; sign the payload above with `DISC_MIGRATE_WALLET` through
`prepareSecp256r1` / `finalizeSecp256r1` against the **v1** program id, and put
the precompile instruction immediately before the migrate. **Only an Owner-rank
authority may migrate.**

## What was rejected, and why

Not built: an admin/operator function that sweeps user vaults without the user's
key. It is theft of funds the operator holds no key to — the survey shows the
vaults are controlled by independent users' own keys — and it is the exact
backdoor class this version exists to remove. Every legitimate migration keeps
the user's key on the authorizing side and the user's funds on the destination
side.
