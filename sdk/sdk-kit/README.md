# @lazorkit/sdk

LazorKit Protocol TypeScript SDK for **Solana Kit** (`@solana/kit`, formerly `@solana/web3.js` v2).

This is the tree-shakable counterpart to [`@lazorkit/sdk-legacy`](../sdk-legacy/) (which targets `@solana/web3.js` v1). Both ship a high-level `LazorKit` class (aliased `LazorKitClient`) over the same on-chain protocol and produce equivalent transactions, so pick the one that matches your Solana client library.

## Status

**Release candidate** (`1.0.0-rc.1`), published under the `next` dist-tag. The
surface is complete for protocol v2 and covered by unit tests plus a
local-validator suite, with three public paths still untested
(`revokeSession`, the one-shot `transferOwnership`, `signWithSecp256r1`).

**For mainnet today, use [`@lazorkit/sdk-legacy`](https://www.npmjs.com/package/@lazorkit/sdk-legacy) 0.3.x.** Mainnet
still runs protocol v1, and everything in this package targets v2.

## Install

```bash
npm install @lazorkit/sdk@next @solana/kit
```

`@solana/kit` is declared as a peer dependency — install whichever version your app uses.

## Quick start

```ts
import {
  PROGRAM_ID_DEVNET,
  findWalletPda,
} from '@lazorkit/sdk';

const userSeed = new Uint8Array(32); // exactly 32 bytes, e.g. a random seed you store per user
const [walletPda, bump] = await findWalletPda(userSeed, PROGRAM_ID_DEVNET);
console.log(walletPda); // address(...)
```

## Protocol v2

This SDK targets protocol v2, which is **not wire-compatible with v1**:

- PDA seeds are namespaced `lk2:`, and account discriminators carry the version
  in their high nibble (`0x2N`). v2 addresses are disjoint from v1's.
- Account index bytes in the compact instruction format use bit 7 as a
  forward-signer request, capping the account list at 128. An index of 128 or
  above is rejected rather than masked.
- The accounts hash binds each referenced account's `is_signer`/`is_writable`
  alongside its key, so v1 signatures no longer verify.
- `AddAuthority` carries a rank and an optional spending policy. A Delegate must
  have one; creating an Owner requires `allowOwner: true`.
- `AddAuthority`/`RemoveAuthority` need the wallet account **writable**.
- Serialized `DeferredPayload`s carry a version and are rejected across the
  boundary — re-authorize rather than replaying one.

Both SDKs implement this identically, and a parity suite asserts it: see
`tests/packing.test.ts`, which also checks both against the golden vectors in
[`test-vectors/accounts-hash.json`](../../test-vectors/accounts-hash.json) that
the on-chain program asserts against.

## Finding a returning user's wallet

A returning user signs in with their passkey, and you need their wallet. Do not
take the first wallet that lists the passkey's credential-id hash
(`findWalletsByAuthority`). The hash is public — it sits in every authority
account the passkey has — and `CreateWallet` / `AddAuthority` take any key
without its consent. Anyone can create a wallet listing a user's credential next
to their own public key, or add the user's real passkey to a wallet they
control, and a lookup by hash returns both.

`findOwnPasskeyWallet` takes one assertion over a challenge you generated, and
adopts a wallet only when

- the passkey is an **Owner** on it, created under your `rpId`, and the public
  key stored there is the one that just signed; and
- nothing untrusted can spend from it: no other authority, no live session, no
  pending deferred execution, no delegate or foreign close authority on the
  vault's token accounts (nor its wSOL/USDC/USDT account handed to someone
  else), and a vault that is still a plain system account — apart from
  Ed25519 keys you list in `trustedKeys` (a backend admin, session keys you
  issued, your own delegate). A pending deferred execution is never trusted:
  the chain records only the authority's address, which an earlier key may
  have held; and
- it is the **one** wallet the passkey has **signed for** (`signatureCount > 0`,
  the replay counter on its authority, which only a signature by the key it
  stores advances).

The last condition is there because not everything an earlier holder of a
wallet did can be read back. `TransferOwnership` hands a wallet to a passkey
without asking it (its public key is on chain), and before that its Owner could
move the vault's SPL Token account for any mint to themselves with
`SetAuthority`. That account stops listing as the vault's, nothing on chain
leads back to it, and every later payment of that mint to the vault's address
lands in it. For a mint the SDK does not watch (below) such a wallet looks
spotless, and a lamport more in its vault would outrank the user's own. A
passkey signs only for a wallet its user chose, so a wallet it has never
signed for is never adopted — not even the only one, and not with
`trustedKeys`. That includes the user's own wallet before its first
transaction: they confirm it once. A wallet your app has just created or
migrated into, you already know; keep its address rather than looking it up.

Why "the one": a signature can be copied onto another wallet. The program's
passkey challenge covers the payer, the counter and the instruction's own
arguments, but not the wallet, for `CreateSession`, `AddAuthority`,
`TransferOwnership` and `Authorize`. Whoever planted a wallet for the passkey
can take the signature from the user's first such transaction and submit it
again on theirs, within about 150 slots, through the same fee payer (a relayer
signs for anyone), and its counter goes up too. So when two wallets have been
signed for, neither is adopted; the user chooses, and both rows look used. A
copy of a signature the passkey made where it is not an Owner (an Admin seat
on someone else's wallet), or on an authority since removed, cannot be told
apart this way; binding the wallet into the challenge, in the program, is the
fix for that.

```ts
import { createOwnershipChallenge, selectWalletByAddress } from '@lazorkit/sdk';

const lk = new LazorKit(rpc, PROGRAM_ID_MAINNET);
const rpId = 'your-app.com';
const challenge = createOwnershipChallenge(); // fresh for every sign-in, never reused

const credential = (await navigator.credentials.get({
  publicKey: { challenge, rpId, userVerification: 'preferred' },
})) as PublicKeyCredential;
const response = credential.response as AuthenticatorAssertionResponse;
const credentialIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', credential.rawId));

const { adopt, needsConfirmation, unproven } = await lk.findOwnPasskeyWallet({
  credentialIdHash,
  rpId,
  proof: {
    challenge,
    signature: new Uint8Array(response.signature), // DER, as the browser returns it
    authenticatorData: new Uint8Array(response.authenticatorData),
    clientDataJson: new Uint8Array(response.clientDataJSON),
  },
  trustedKeys: [backendAdmin], // optional: your own Ed25519 addresses on users' wallets
  watchMints: [yourAppsMint], // optional: SPL Token mints your app receives (see below)
});

let wallet;
if (adopt) {
  // This passkey has used it, and only it (and your trusted keys) can spend from it.
  wallet = adopt;
} else if (needsConfirmation.length > 0) {
  // The passkey owns these, but has never signed for them (`signatureCount: 0`
  // — say "not used with this passkey yet"), or has signed for more than one,
  // or something else can spend from them too. Show each vault address, its balance (`lamports`, a bigint) and
  // who else controls it (`otherAuthorities`, `liveSessions`, `pendingDeferred`,
  // `tokenGrants`, `vaultIsSystemAccount`), and let the user choose.
  // Pre-select nothing. "None of these" means stop — not create.
  const chosen = await askUserToChoose(needsConfirmation); // a vault address, or null
  if (!chosen) throw new Error('No wallet confirmed');
  wallet = selectWalletByAddress(needsConfirmation, chosen); // vault or wallet address
} else {
  // This passkey provably owns no wallet: create one. The public key comes from
  // the passkey's registration (navigator.credentials.create) — an assertion
  // carries none.
  const created = await lk.createWallet({
    payer,
    userSeed: crypto.getRandomValues(new Uint8Array(32)),
    owner: { type: 'secp256r1', credentialIdHash, compressedPubkey, rpId },
  });
  // ...send created.instructions
}
// wallet: { walletPda, vaultPda, authorityPda, publicKey, version, lamports, ... }
```

- `unproven` counts wallets that list this credential with some other public
  key. Someone planted them; they are ignored.
- `version: 1` is a pre-v2 wallet on the v1 deployment paired with your program
  id (`includeV1: false` skips it). Among wallets that qualify it comes first —
  its funds have not been migrated yet. Move them with `migrateV1Wallet`, below.
- Order of `needsConfirmation`: signed for first, then v1, then the fuller
  vault, then the wallet address. The balance order is one anyone can change
  by funding a vault — it is not a recommendation.
- The steps are public on their own — `findPasskeyWalletCandidates`,
  `verifyOwnershipProof`, `describeWalletCandidates`, `pickOwnWallet` — for a
  flow that collects the assertion somewhere else and decides here.
- A wallet whose account is gone is left out: migrating a v1 wallet closes it
  and only the authority that migrated it, so another owner's passkey still
  lists it, with nothing left that can move funds.
- **What the chain cannot show unasked.** SPL Token lets an owner hand even an
  associated token account to someone else (`SetAuthority`), and an earlier
  owner of a wallet can do that to the vault's account for any mint before
  giving the wallet away. The account then no longer lists as the vault's, and
  nothing in it names the vault, yet it is still the address a sender of that
  mint pays the vault at. The SDK checks the vault's account for wSOL, USDC,
  USDT and devnet USDC, plus every mint in `watchMints` — pass the mints your
  app receives (also accepted by `describeWalletCandidates`,
  `vetMigrationDestination` and `migrateV1Wallet`). For any other mint,
  `controlledAlone` cannot see it — which is why a wallet the passkey has never
  signed for is only offered, and a clean `tokenGrants` on it proves nothing
  about such mints. When the user confirms one, that is the risk they take.
  Token-2022 associated accounts are created with an immutable owner and are
  not affected.
- The reads are ordered so that one transaction landing mid-read is never
  half-seen: authorities first, then sessions and deferred executions, then
  the wallet, vault and token accounts, each asking the RPC for state at least
  as new as the step before (`minContextSlot`). A node that has not caught up
  is asked again, up to five times, then the call throws.
- Every wallet described costs three `getProgramAccounts` calls (authorities,
  sessions, deferred executions, with `withContext`), two
  `getTokenAccountsByOwner` calls and one `getMultipleAccounts` of six accounts
  (plus one per `watchMints` entry), in three rounds, after one shared
  `getMultipleAccounts` of every candidate's wallet account; use an RPC
  endpoint that allows them.

## Migrating a v1 wallet

After the v2 upgrade, a v1 wallet's normal operations revert and its owner must
migrate once. Both halves of that flow are here.

```ts
const lk = new LazorKit(rpc, PROGRAM_ID_MAINNET);

// 1. Find the wallet. Most users cannot: the v1 `userSeed` was random and lived
//    in browser storage. The chain can: `wallet` from "Finding a returning
//    user's wallet" above (`adopt`, or the one the user confirmed) is a v1
//    wallet when its `version` is 1. Not the first hit of a lookup by
//    credential hash (`findV1WalletsByOwner`): v1's CreateWallet took any
//    owner too.
if (wallet?.version !== 1) return; // no v1 wallet to migrate

// 2. Move everything. One signature; SOL and every token land in the v2 vault
//    and the v1 accounts close.
const { setupInstructions, migrate, destinationUserSeed } = await lk.migrateV1Wallet({
  payer,
  owner: { type: 'secp256r1', credentialIdHash, compressedPubkey: wallet.publicKey, rpId },
  v1Wallet: wallet.walletPda,
});
const instructions =
  migrate.type === 'ed25519'
    ? [...setupInstructions, ...migrate.instructions] // any fee harvests, then MigrateWallet
    : [...setupInstructions, ...migrate.finalize(await signWithPasskey(migrate.challenge))];
```

`wallet.publicKey` is not optional bookkeeping: signing in with an existing
passkey returns a WebAuthn *assertion*, which carries no public key, so the
chain is the only place a returning user's key can be read — and this is the
stored key that assertion was just verified against. Persist
`destinationUserSeed` when it comes back — it is the seed of the freshly created
v2 wallet, and nothing else can derive it — and select `destinationWallet`
directly: until its first transaction, a lookup would only offer it for
confirmation (`signatureCount: 0`).

Send `setupInstructions` and the migration **in one transaction** where they
fit. If they cannot, send the migration only after the setup transaction has
*succeeded*. The owner's signature names the destination vault, not who owns
its wallet. So if someone else's `CreateWallet` at that seed lands first (a
seed shows in the setup transaction, and in any earlier attempt that failed),
your setup fails, and a migration sent anyway pays into their vault.

Where the funds land: without `userSeed`, an existing v2 wallet of this owner
is reused only when the owner is a passkey that has **signed for it before**
(`signatureCount > 0`), and on no other authority of the program at any rank
(a signature from one can be replayed onto another, above), and
`vetMigrationDestination` finds nothing but this key able to spend from it —
one authority, this key at Owner rank; no session or deferred execution the
program still accepts; a vault that is still a plain system account; no
delegate or foreign close authority on the vault's token accounts, nor its
account for a watched mint (see `watchMints` above) handed to anyone else. Any of those can be left behind by an earlier owner who then
handed the wallet over with `TransferOwnership`, which asks the new owner
nothing — and so can a token account for an unwatched mint, which no vet can
see; hence the signature. An Ed25519 owner's wallets are never reused this way
(its authority records no signatures); name one with `destinationUserSeed`.
Failing that, the destination is the wallet of `userSeed`,
`destinationUserSeed`, or a fresh seed, and one read of its address decides:

- nothing there, or only lamports (anyone can send them, and `CreateWallet`
  builds over them): the wallet is created in `setupInstructions`;
- a wallet already there: it must pass the same vet, or the call throws with
  the reason. A seed can be predicted or read out of an earlier transaction,
  and whoever creates the wallet first chooses its owner. It cannot be held to
  the signed-for bar (the wallet this call creates has no signature on it
  either, until used): a `userSeed` is public in the v1 `CreateWallet`
  instruction, so pass `v1Wallet` without `userSeed` for a fresh destination
  when a wallet exists there that your app did not create.

And every existing token account the migration delivers into must be the v2
vault's, with no delegate and no close authority but the vault, or the call
throws naming it.

Sequence, UX and operator notes: [`docs/migration-ui-flow.md`](../../docs/migration-ui-flow.md).

## Package layout

```
sdk-kit/
├── src/
│   ├── codecs/        # @solana/codecs-based account/action codecs
│   ├── instructions/  # instruction builders returning kit Instruction[]
│   ├── secp256r1/     # passkey + sysvar-introspection signing helpers
│   ├── constants.ts   # program addresses (mainnet, devnet, foundation devnet)
│   ├── pdas.ts        # PDA derivation helpers
│   ├── ownership.ts   # which wallet a returning passkey user owns: proof + rule
│   ├── v1.ts          # v1 derivation + seedless lookup, for migration only
│   ├── spl.ts         # the SPL/ATA helpers the migration path needs
│   └── index.ts
└── tests/             # vitest unit tests (PDA parity, codec roundtrips)
```

## Relationship to `@lazorkit/sdk-legacy`

- **Same on-chain protocol, same major.** Identical instruction encoding, identical PDA seeds, identical account layouts, byte-identical PDA derivation (verified in `tests/pdas.test.ts`) — against `sdk-legacy` **1.x**. The `0.3.x` line that `latest` still serves speaks protocol v1 and shares none of it.
- **Different runtime API.** Both expose a high-level class, but `sdk-legacy` takes a v1 `Connection` while this one takes RPC primitives from `@solana/kit`, and the module-level helpers here are tree-shakable.
- **Smaller surface.** No `parseActions`, `findAuthoritiesByWallet` or `getRecoveryStatus` yet; reach for `sdk-legacy` when you need those. The v1 migration path (`findV1WalletsByOwner`, `migrateV1Wallet`, the SPL/ATA helpers it needs) is here and byte-identical — `tests/instructions.test.ts` asserts the `MigrateWallet` instruction matches `sdk-legacy`'s.
- **No flavor branching.** Both SDKs are oblivious to whether the on-chain binary is the commercial (`lazorkit-protocol`) or foundation (`program-v2`) build — they always produce commercial-shape transactions and rely on the on-chain logic to gracefully tolerate or charge fees as appropriate. See the docstring in `src/constants.ts`.

## License

MIT — see [LICENSE](./LICENSE).
