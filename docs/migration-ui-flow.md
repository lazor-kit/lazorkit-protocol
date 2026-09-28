# Migration UI flow

How an app walks a v1 user through migrating to v2. The SDK does the
orchestration; this is the sequence and the UX around it. Snippets below use
`@lazorkit/sdk-legacy` (web3.js v1); `@lazorkit/sdk` (Solana Kit) exposes the
same `findOwnPasskeyWallet` / `findV1WalletsByOwner` / `readV1WalletState` /
`enumerateV1VaultTokens` / `vetMigrationDestination` / `migrateV1Wallet`
surface, with the same rules, addresses instead of `PublicKey`s, `bigint`
lamports and async PDA helpers. All of it is client-side and user-authorized —
no operator ever moves a user's funds.

v2 runs at its own program id; v1 keeps running until its id is upgraded to
the sunset binary (phase B of the
[deploy checklist](mainnet-deploy-checklist.md)). From then on a v1 wallet can
do exactly one useful thing — migrate. The user's funds are safe in the v1
vault, but they must migrate once before transacting again. This flow makes
that one action. Ship it with phase A, switched off, and turn it on with
phase B: until then the v1 id has no `MigrateWallet`.

A working reference implementation of everything below is in
[`examples/react-migration/`](../examples/react-migration/) — a `useV1Migration`
hook, a `MigrateWalletCard` component, and the passkey glue, all built on
`migrateV1Wallet`. Adopt or restyle it; the sequence and UX notes here explain
what it does and why.

## 1. Detect

On app load, check whether the connected identity still has a v1 wallet.

For a **passkey** user this is the same lookup as finding any returning user's
wallet: `findOwnPasskeyWallet` (see "Finding a returning user's wallet" in the
[sdk-legacy README](../sdk/sdk-legacy/README.md)) also scans the v1 deployment
paired with your program id. A result with `version: 1` — adopted, or the one
the user confirmed — is the v1 wallet to migrate, and its `publicKey` is the
owner's compressed key, just verified against a fresh assertion.

```ts
import { LazorKitClient, readV1WalletState } from '@lazorkit/sdk-legacy';

const client = new LazorKitClient(connection); // programId inferred from RPC

const { adopt, needsConfirmation } = await client.findOwnPasskeyWallet({ credentialIdHash, rpId, proof });
const wallet = adopt ?? (await askUserToChoose(needsConfirmation)); // as in the README
if (wallet?.version === 1) {
  // Show a "Migrate your wallet" banner.
}
```

Not the first hit of `findV1WalletsByOwner(credentialIdHash)`: v1's
`CreateWallet` took any owner without its consent too, so a record can list the
user's credential next to someone else's public key. That raw lookup still
serves an **Ed25519** owner, whose key the app holds:

```ts
const found = await client.findV1WalletsByOwner(ownerKeypair.publicKey.toBytes(), 'ed25519');
const owned = found.filter((w) => w.role === 0); // only an Owner may migrate

if (owned.length) {
  const state = await readV1WalletState(connection, owned[0]);
  // Show a "Migrate your wallet" banner.
}
```

**Do not ask the app for a `userSeed`.** Wallets created through
`@lazorkit/wallet` used a random 32-byte seed that lived in browser storage, so
a user who cleared it, or who is on another device, cannot derive their own
wallet any more. The chain can: the authority account holds the owner's key
material and the wallet it belongs to, which is what `findV1WalletsByOwner`
scans for. `MigrateWallet` itself never needs the seed — it takes the v1 wallet
as an account and derives the vault from that key.

If the app *does* still hold the seed, `deriveV1Accounts(userSeed, ownerIdSeed,
programId)` gets to the same place without an RPC scan.

`state` is `null` when there is nothing to migrate (already migrated, or never a
v1 user). Otherwise it carries the owner's auth type, rank, and the vault's SOL.

## 2. Show what will move

```ts
import { classifyV1VaultTokens, enumerateV1VaultTokens } from '@lazorkit/sdk-legacy';

const v1Vault = wallet.vaultPda; // Ed25519: owned[0].vault
const { movable, skipped } = await classifyV1VaultTokens(
  connection,
  await enumerateV1VaultTokens(connection, v1Vault),
);
// Render: the vault's SOL (wallet.lamports, or state.vaultLamports), each
// movable token's mint + amount, and — separately, plainly — what cannot come
// along.
```

Enumerating here is not cosmetic — every vault-owned token account the migration
omits is stranded when the wallet closes, and after the sunset nothing else can
reach it. Two kinds can never move: **frozen** accounts, and Token-2022 mints
with a **transfer hook**. `skipped` lists them with the reason
(`'frozen' | 'transfer-hook' | 'excluded'`); `migrateV1Wallet` leaves them out
the same way and returns them as `plan.skippedTokens`. Anyone can create a
token account for anyone's vault, so expect spam here too — let the user drop
it with `excludeTokenAccounts` rather than pay to carry it across.

## 3. Build and send

One call assembles everything: create the v2 wallet if needed, create the
destination token accounts, and the MigrateWallet step.

```ts
const plan = await client.migrateV1Wallet({
  payer,
  // Passkey: the key from step 1. Ed25519: { type: 'ed25519', publicKey }.
  owner: { type: 'secp256r1', credentialIdHash, compressedPubkey: wallet.publicKey, rpId },
  v1Wallet: wallet.walletPda, // Ed25519: owned[0].wallet
  watchMints: [yourAppsMint], // optional: SPL Token mints your app receives (below)
});

// `plan.destinationUserSeed` is set when this call created the v2 wallet from a
// seed you did not already hold: persist it, nothing else can derive it.
// `plan.skippedTokens` is what stays behind — show it before the user signs.
```

Where the funds land is decided here, and it is the one thing the program cannot
check for you: the owner's signature names the destination vault, not who owns
its wallet. Being listed on a wallet is not owning it — `CreateWallet`,
`AddAuthority` and `TransferOwnership` all take a key without asking it — so
`migrateV1Wallet` chooses like this:

- **Without `userSeed`**, it reuses an existing v2 wallet only when the owner
  is a passkey that has **signed for it before** (`signatureCount > 0`, the
  replay counter on its authority, which only a signature by the key it
  stores advances) and on **no other authority** of the program, at any rank,
  **and** the wallet passes `vetMigrationDestination`. Until the program named
  the wallet in the passkey challenge, a signature the passkey made on one
  wallet for `CreateSession`, `AddAuthority`, `TransferOwnership` or
  `Authorize` could be replayed onto a wallet planted for it, through the same
  fee payer, raising its counter too, and those counts are still on chain;
  with two signed on, either may be the copy, and a fresh wallet is created
  instead. An Ed25519 owner's wallets are never
  reused this way — Ed25519 signing records nothing on the authority — so name
  one with `destinationUserSeed`.
- **Otherwise** the destination is the wallet at `userSeed`,
  `destinationUserSeed`, or a fresh random seed, and one read of its address
  decides. Nothing there, or only lamports (anyone can send lamports to an
  address; `CreateWallet` builds over them): the wallet is created in
  `setupInstructions`. Anything else is an existing wallet, and it must pass
  the vet — named by `destinationUserSeed` too — or the call throws
  `refusing to migrate into the userSeed's v2 wallet: …` (or
  `destinationUserSeed's`). Show the message; retrying will not help. Migrate
  into a fresh wallet instead: `v1Wallet` without `userSeed` or
  `destinationUserSeed`.

`client.vetMigrationDestination(wallet, owner, { watchMints })` returns `null`
or the reason a wallet is unfit. It passes only a wallet of this program with
exactly one authority — this whole key at Owner rank (for a passkey: the
credential-id hash, the public key and the relying party) — no session or
deferred execution the program still accepts (live through its expiry slot;
one too short to read counts as live), a vault that is still a plain system
account or not created yet, and no delegate, close authority other than the
vault, handed-away canonical account of a watched mint, or unreadable account
among the vault's token accounts. It reads the authorities, then the sessions
and deferred executions, then the wallet, vault and token accounts, each read
at or after the slot of the one before, so a transaction landing mid-vet
cannot be half-seen. `migrateV1Wallet` also refuses to deliver into an existing
destination token account that is not the new vault's alone, and names it. If
you pick the destination yourself (a hand-built instruction), vet it first.

A vet cannot see everything. An earlier holder of a wallet can move the
vault's SPL Token account for any mint to themselves (`SetAuthority`); it then
no longer lists as the vault's, and nothing on chain leads back to it. The SDK
checks the canonical account for wSOL, USDC, USDT and devnet USDC, plus every
mint in `watchMints` — pass the mints your app receives. The signed-for rule is
what keeps a wallet with such an account for another mint from being reused.

Send `plan.setupInstructions` and the migrate **in one transaction** where they
fit: they then succeed or fail together. Where they do not, send the setup
first and the migrate only after the setup transaction is confirmed
*successful*. If someone else's `CreateWallet` at that seed lands first — a v1
`userSeed` is public, and a seed shows in any earlier attempt — your setup
fails, and a migrate sent anyway pays into their vault.

By auth type:

**Ed25519 owner** — the owner key signs the transaction. `migrate.instructions`
is any fee harvests, then the migrate:

```ts
if (plan.migrate.type === 'ed25519') {
  await sendAndConfirm(
    connection,
    [...plan.setupInstructions, ...plan.migrate.instructions],
    [payerKeypair, ownerKeypair],
  );
}
```

**Secp256r1 passkey** — the passkey signs the challenge; the tx is payer-signed:

```ts
if (plan.migrate.type === 'secp256r1') {
  const assertion = await navigator.credentials.get({
    publicKey: { challenge: plan.migrate.challenge, /* allowCredentials, rpId … */ },
  });
  const response = toWebAuthnResponse(assertion); // authenticatorData, clientDataJSON, signature
  const instructions = plan.migrate.finalize(response); // [...harvests, precompile, migrate]
  await sendAndConfirm(connection, [...plan.setupInstructions, ...instructions], [payerKeypair]);
}
```

The passkey approves exactly this migration — its signature binds the v2
destination, the v1 wallet, the token count, and the rent-refund destination — so
a relayer submitting the transaction cannot redirect, replay, or strand anything.

## 4. Confirm

After the migrate confirms:
- SOL and every token are in the user's v2 vault.
- The v1 wallet and authority are closed; their rent went to the payer.
- The user now uses their v2 wallet normally. Select `plan.destinationWallet`
  directly and persist it: until its first transaction the passkey has never
  signed for it (`signatureCount: 0`), so a lookup would only offer it for
  confirmation.

Re-run step 1: the v1 wallet is gone (`readV1WalletState` returns `null`, and
`findOwnPasskeyWallet` leaves out a wallet whose account no longer exists), so
the banner disappears.

**The old address is dead after this, not merely stale.** `MigrateWallet` reads
the v1 wallet and authenticates against the v1 authority, and it closed both —
so a second migration is impossible, and anything sent to the old vault address
afterwards can never be moved by anyone. Before the migration that address is
merely frozen; after it, it is a hole.

Two consequences for the app:
- Stop showing the v1 address the moment migration succeeds. If it was ever
  published as a deposit address — in a profile, a QR code, an exchange
  withdrawal entry — the user has to be told to replace it, because the failure
  is silent and total.
- The v2 wallet is at a **different** address: the seeds are namespaced `lk2:`,
  so the same `userSeed` derives a different wallet and vault. Nothing carries
  over automatically.

## Notes for the operator

- **Only an Owner-rank v1 authority may migrate.** `migrateV1Wallet` throws
  otherwise. v1 wallets are single-owner, so this is the wallet's own key.
- **The payer** funds the v2 wallet + ATA rent and receives the reclaimed v1
  rent. In a sponsored/relayer model the app's payer covers this.
- **Transaction size:** the setup step scales with the token count. One
  transaction with the setup and the migrate is the safe shape; for a vault
  with many token accounts, use a v0 transaction with an address lookup table,
  exclude the dust, or split `setupInstructions` across transactions and send
  the migrate only once every one of them is confirmed successful. The migrate
  itself is one instruction, but each token adds four accounts: past about ten
  tokens on the Ed25519 path, or five on the passkey path, it needs the lookup
  table on its own.
- **Prioritise the active, high-value wallets** — value is concentrated, so
  reaching a handful of users covers most of it. Dormant wallets migrate whenever
  their owner returns; their funds wait safely in v1 until then.
