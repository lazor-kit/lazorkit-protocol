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
- otherwise: a v2 wallet this owner already has, **if the owner is a passkey
  that has signed for it before** (`signatureCount > 0`), and on no other
  authority of the program at any rank, and it passes the vet below — an
  Ed25519 owner's wallets are never reused this way, since Ed25519 signing
  records nothing on the authority;
- failing that: the wallet of `destinationUserSeed`, or of a fresh random seed
  (returned as `destinationUserSeed` — persist it).

Being *an* authority on a wallet proves nothing. v2 `CreateWallet` takes the
owner as plain data, `AddAuthority` never asks the key being added, and
`TransferOwnership` hands a wallet to a key without asking it — so anyone can
build a wallet that lists a victim's passkey and keep a hand on the vault. Hence
`vetMigrationDestination(wallet, owner, { watchMints })`: the address must be a
wallet of this program with **exactly one authority — this whole key (for a
passkey: credential-id hash, public key and relying party) at Owner rank — no
session or deferred execution the program still accepts** (live through its
expiry slot; unreadable counts as live), **a vault that is still a plain system
account**, and **no delegate, foreign close authority, handed-away canonical
account of a watched mint, or unreadable account among the vault's token
accounts**. It reads the authorities, then sessions and deferred executions,
then the wallet, vault and token accounts, each at or after the slot of the
read before, so a transaction landing mid-vet cannot be half-seen.

The vet cannot see an SPL Token account an earlier holder moved off the vault
for a mint nobody named: it no longer lists as the vault's, and nothing on
chain leads back to it. The canonical accounts of wSOL, USDC, USDT, devnet
USDC and every mint in `watchMints` are checked; for the rest, only a wallet
the passkey has already signed for — one its user chose — is reused unasked.
A count raised before the program named the wallet in the passkey challenge
may be forged by replay: until then the challenge did not name the wallet for
`CreateSession`, `AddAuthority`, `TransferOwnership` or `Authorize`, so the
signature from a user's first such transaction on one wallet could be submitted
again, within about 150 slots and through the same fee payer, on a wallet
planted for their passkey. So a wallet is reused only when it is the one
authority the passkey has signed on; with two, either may be the copy, and a
fresh wallet is created.

The v1 `user_seed` is public (it is in the v1 `CreateWallet` instruction data),
so a `userSeed` wallet can be squatted, and so can any seed once it shows in a
transaction. A wallet at `userSeed` or `destinationUserSeed` is therefore
vetted, and one that fails throws rather than being used. An address holding
only lamports is not a wallet: the wallet is created there (`CreateWallet`
builds over them), so a few lamports cannot block a migration. An existing
destination token account must be the new vault's alone, or the call throws
naming it.

**Setup and migrate belong in one transaction.** The owner signs the
destination vault, not who owns its wallet. Sent together they succeed or fail
together; sent separately, the migrate goes only after the setup transaction is
confirmed successful — if someone else's `CreateWallet` at that seed lands
first, the setup fails, and a migrate sent anyway pays into their vault.

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
// A passkey user's v1 wallet: the `version: 1` result of findOwnPasskeyWallet
// (proven against a fresh assertion), not the first hit of findV1WalletsByOwner
// — v1's CreateWallet took any owner without its consent too.
const { adopt, needsConfirmation } = await client.findOwnPasskeyWallet({ credentialIdHash, rpId, proof });
const wallet = adopt ?? (await askUserToChoose(needsConfirmation));
if (wallet?.version !== 1) return; // nothing to migrate

const plan = await client.migrateV1Wallet({
  payer,
  owner: { type: 'secp256r1', credentialIdHash, compressedPubkey: wallet.publicKey, rpId },
  v1Wallet: wallet.walletPda,
  // watchMints: [...],             // SPL Token mints your app receives
  // excludeTokenAccounts: [...],   // anything the user chose to abandon
});
// show plan.skippedTokens to the user before they sign; persist
// plan.destinationUserSeed when set, and select plan.destinationWallet
// send plan.setupInstructions and the migrate in one transaction:
//   passkey:  sign plan.migrate.challenge, add plan.migrate.finalize(response)
//   ed25519:  add plan.migrate.instructions, signed by payer + owner
```

The v1 program id is found by pairing (`legacyProgramIdFor`): mainnet v2 pairs
with `LazorjRF…`, devnet v2 with `4h3XoNRe…`. Pass `v1ProgramId` for anything
else. A client built *at* a v1 id throws: the destination would be derived under
a program that can never sign for it.

The kit SDK (`@lazorkit/sdk`) has the same method with the same behaviour.

For a hand-built instruction, `createMigrateWalletIx` takes the v1 accounts, the
destination, and one **`{ sourceAta, destAta, mint, tokenProgram }`** per token
account; sign the payload above with `DISC_MIGRATE_WALLET` through
`prepareSecp256r1` / `finalizeSecp256r1` against the **v1** program id, with
`wallet` set to the **v1** wallet (the challenge names the wallet in the signing
authority's header — the v1 one, not the v2 destination), and put the
precompile instruction immediately before the migrate. **Only an Owner-rank
authority may migrate.**

## What was rejected, and why

Not built: an admin/operator function that sweeps user vaults without the user's
key. It is theft of funds the operator holds no key to — the survey shows the
vaults are controlled by independent users' own keys — and it is the exact
backdoor class this version exists to remove. Every legitimate migration keeps
the user's key on the authorizing side and the user's funds on the destination
side.
