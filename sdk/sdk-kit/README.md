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

Why "the one": a count may hold a signature copied from another wallet. The
v2 program names the wallet in the passkey challenge, so a signature made now
verifies only on the wallet it was made for. v1 never did, nor did v2 before
that change: the challenge covered the payer, the counter and the
instruction's own arguments, but not the wallet, for `CreateSession`,
`AddAuthority`, `TransferOwnership` and `Authorize`, and whoever planted a
wallet for the passkey could take the signature from the user's first such
transaction and submit it again on theirs, within about 150 slots, through the
same fee payer (a relayer signs for anyone), raising its counter too. Those
counts are still on chain, so when two wallets have been signed for, neither
is adopted; the user chooses, and both rows look used. Among them, a copy of a
signature the passkey made where it is not an Owner (an Admin seat on someone
else's wallet), or on an authority since removed, cannot be told apart this
way.

```ts
import { createTaggedOwnershipChallenge, selectWalletByAddress } from '@lazorkit/sdk';

const lk = new LazorKit(rpc, PROGRAM_ID_MAINNET);
const rpId = 'your-app.com';
const challenge = createTaggedOwnershipChallenge(); // fresh for every sign-in, never reused

const credential = (await navigator.credentials.get({
  publicKey: { challenge, rpId, userVerification: 'preferred' },
})) as PublicKeyCredential;
const response = credential.response as AuthenticatorAssertionResponse;
const credentialIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', credential.rawId));
const proof = {
  challenge,
  signature: new Uint8Array(response.signature), // DER, as the browser returns it
  authenticatorData: new Uint8Array(response.authenticatorData),
  clientDataJson: new Uint8Array(response.clientDataJSON),
};

const { adopt, needsConfirmation, unproven } = await lk.findOwnPasskeyWallet({
  credentialIdHash,
  rpId,
  proof,
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
  // This passkey provably owns no wallet: create one. An assertion carries no
  // public key: use the one you kept from the passkey's registration
  // (navigator.credentials.create) or, for a passkey registered somewhere
  // else, recover it — see "A passkey with no wallet" below.
  const compressedPubkey = keptPublicKey ?? (await recoverPublicKey(credential, proof));
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
  id (`includeV1: false` skips it); its funds have not been migrated yet. Move
  them with `migrateV1Wallet`, below. It is adopted by the same rule as any
  other wallet, and has no precedence of its own: when exactly one wallet has
  been signed for and nothing untrusted can spend from it, that one is adopted,
  v1 or v2, and `needsConfirmation` is empty — even with a v1 wallet this
  passkey never signed from.
- Order of `needsConfirmation`: signed for first, then — among wallets equally
  signed for, or not — v1 before v2, then the fuller vault, then the wallet
  address. The balance order is one anyone can change by funding a vault — it is
  not a recommendation.
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

### A passkey with no wallet, whose key you do not hold

Every passkey starts without a v2 wallet, including one a user registered on
another device, in another browser, or through another app under your `rpId`.
Signing in with it gives you an assertion and no public key, and a key taken
from anywhere else — a portal's local storage, a deep link — may be another
passkey's. `createWallet` takes whatever key it is given, and a wallet created
for a key the passkey does not hold is one it can never sign for: whatever is
sent to its vault is stuck.

Recover the key from the passkey itself. An ECDSA signature names its signer
up to a few candidates — almost always two — and a second signature over
another message pins it: only the passkey's own key is common to both. So ask
the same passkey for one more assertion, over a challenge of its own, and pass
both to `resolvePasskeyPublicKey`:

```ts
import { createTaggedOwnershipChallenge, resolvePasskeyPublicKey, type OwnershipProof } from '@lazorkit/sdk';

const sameBytes = (a: ArrayBuffer, b: ArrayBuffer) =>
  a.byteLength === b.byteLength && new Uint8Array(a).every((x, i) => x === new Uint8Array(b)[i]);

async function recoverPublicKey(credential: PublicKeyCredential, proof: OwnershipProof) {
  const challenge = createTaggedOwnershipChallenge(); // not the sign-in challenge: a new one
  const again = (await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId,
      allowCredentials: [{ type: 'public-key', id: credential.rawId }], // the same passkey
      userVerification: 'preferred',
    },
  })) as PublicKeyCredential;
  if (!sameBytes(again.rawId, credential.rawId)) throw new Error('Another passkey answered');
  const response = again.response as AuthenticatorAssertionResponse;

  const publicKey = resolvePasskeyPublicKey(
    [
      proof, // the sign-in assertion
      {
        challenge,
        signature: new Uint8Array(response.signature),
        authenticatorData: new Uint8Array(response.authenticatorData),
        clientDataJson: new Uint8Array(response.clientDataJSON),
      },
    ],
    rpId,
  );
  if (!publicKey) throw new Error("Could not read this passkey's public key"); // ask again; never guess
  return publicKey; // 33-byte compressed: the owner's compressedPubkey
}
```

- The key is the one that signed both assertions. Each is checked as
  `verifyOwnershipProof` checks one (a `webauthn.get` over exactly that
  challenge, this relying party, the user present), and the key returned
  verifies against both. But the signature covers those bytes under the very
  key it names, so anyone holding any P-256 key can make assertions over your
  challenges that pass. What makes it the passkey's key is where the
  assertions come from: `navigator.credentials.get` calls in your own page,
  where the browser sets the relying party and the passkey signs. Take both
  there, the second pinned to the first one's `rawId`, check the two `rawId`s
  match, and hash that `rawId` for `credentialIdHash`.
- Assertions relayed to you — by a portal, over a deep link or a redirect —
  prove only that whoever produced them holds the key. Recovering from them
  corrects an honest portal that reports the wrong key; it does not protect you
  from a channel someone else can write to, who can send assertions signed with
  a key of their own and have you create a wallet they control. Authenticate
  the channel (for a popup, check the `postMessage` origin), or trust the key
  no more than you trust the channel.
- `null` means no single key: fewer than two assertions, two over the same
  challenge, one that fails a check, or two passkeys. Ask again; do not fall
  back to a key from elsewhere.
- `recoverPasskeyPublicKeys(proof, rpId)` is the one-assertion step: every key
  that assertion verifies against (almost always two), the signer's among
  them.
- Only for a passkey with no wallet. When `findOwnPasskeyWallet` finds one,
  its stored key is the one the sign-in assertion was just verified against:
  use `wallet.publicKey`.

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
(before the challenge named the wallet, a signature from one could be replayed
onto another, above), and
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

## Two passkey transactions in a row

A passkey challenge signs the authority's counter + 1, read when you call
`prepare*` (or a one-shot method). If the previous transaction from the same
authority has been sent but not yet executed by the node you read from, that
read returns the counter it is about to use, and the new signature fails with
`SignatureReused` (3006) — after the user has approved it. Wait for the
previous transaction to confirm, then pass the slot it landed in:

```ts
// tx1: wait for it first. sendAndConfirmTransactionFactory throws if it failed.
await sendAndConfirmTransaction(signedTx1, { commitment: 'confirmed' });

const { value: [status] } = await rpc.getSignatureStatuses([signature1]).send();
// null: this node has not seen tx1 yet (another node behind a load balancer
// answered). Ask again; do not prepare without the floor.
if (!status) throw new Error('tx1 not visible on this RPC node yet, retry');

const prepared = await lk.prepareExecute({
  payer,
  walletPda,
  secp256r1: {
    credentialIdHash,
    minContextSlot: status.slot, // read from a node that has executed tx1
    // commitment: 'confirmed',  // the default
  },
  instructions,
});
```

The same `minContextSlot` / `commitment` go on a signer config
(`secp256r1(signer, { minContextSlot, commitment })`), on `migrateV1Wallet` and
on `readCounter`, and apply to the counter, key and slot reads alike. A node
behind the floor answers -32016; the SDK retries with a short backoff for up to
10 s, then throws `MinContextSlotNotReachedError` (its `commitment` says which
bank was behind). If one of the three reads fails for another reason (or, in
`prepareExecute`, the protocol-fee read beside them), the call rejects with
that error at once and the challenge reads stop retrying. Same behaviour as
`@lazorkit/sdk-legacy`, where `minContextSlot` is a `number`.

With `commitment: 'finalized'`, `minContextSlot` is a slot the node must have
*finalized*. How long after its confirmation that happens depends on the
cluster: 31 slots (16.5 s) on a local test validator (Agave 4.2.2), and no time
at all on devnet on 2026-09-30, where the finalized slot was the confirmed one.
The reads wait up to 30 s for it, so where finalization lags, a floor at a
just-confirmed tx1 costs that lag before the passkey prompt. The challenge's
slot is read at `finalized` too, so it is already that many slots old when the
prompt appears, and the program accepts a challenge only until its slot is 150
slots old (about a minute): a 31-slot lag leaves about 119 slots to approve,
send and land it. It is not read at `confirmed` instead because the program
also refuses a slot newer than the one it runs in, so a relayer simulating at
`finalized` would refuse the challenge. Unless you need finalized reads, keep
the default: `confirmed` with the floor is enough to sign the right counter.

Without `minContextSlot` the reads are at `confirmed`, whatever the RPC's own
default. That is enough only when the node answering them has executed the
previous transaction; behind a load-balanced endpoint it may not have, even
after tx1 confirmed on another node, so pass the floor anyway. If you confirm
at `processed`, read at `processed` too (`commitment: 'processed'`, and send
with a `processed` preflight): a `confirmed` read right after misses tx1.

**One passkey flow per authority at a time.** Two flows for the same authority
that overlap — two `prepare*` calls before the first transaction lands, two
tabs or devices with one passkey, an app and a wallet — read the same counter
and both sign counter + 1. Whichever lands second fails with 3006, and no floor
helps: neither has landed when the other reads. Run prepare → sign → send →
confirm for one authority one after another, each floored at the previous
one's slot. The SDK keeps no per-authority state and does not queue for you;
within one app a queue of your own is enough:

```ts
// Your app's, not the SDK's: flows for one authority run one after another.
const tails = new Map<Address, Promise<void>>();

async function oneAtATime<T>(authority: Address, flow: () => Promise<T>): Promise<T> {
  const run = (tails.get(authority) ?? Promise.resolve()).then(flow);
  const tail = run.then(() => undefined, () => undefined);
  tails.set(authority, tail);
  try {
    return await run;
  } finally {
    if (tails.get(authority) === tail) tails.delete(authority);
  }
}

// flow = prepare (floored at the last slot) → passkey prompt → send → confirm
await oneAtATime(authorityPda, () => payWithPasskey(invoice));
```

Across tabs, devices or apps that share a passkey no local queue helps; a 3006
there means another flow used the counter first, and the fix is to prepare
again (a new prompt), floored at a slot that includes it.

**A 3006 is not always LazorKit's.** A program that `execute` calls can fail
with the same custom code — Anchor's account errors use 3000–3017, so an inner
Anchor program's `AccountNotMutable` is 3006 too — and the transaction then
fails with it. A preflight failure's logs name the program: the first
`Program <id> failed: custom program error: 0x…` line is the one that raised
it. A landed failure (`{ InstructionError: [i, { Custom: 3006 }] }` from
`getSignatureStatuses`) names only the top-level instruction, which is the
LazorKit one whichever program inside it failed: read its logs
(`getTransaction(signature)` → `meta.logMessages`) before telling the user to
sign again.

## Messages and ownership proofs: never a transaction challenge

The program approves a transaction by the challenge in a passkey signature,
and a passkey signs whatever challenge it is handed. So each kind of challenge
has its own shape — the same bytes as `@lazorkit/sdk-legacy` 1.4.0,
`@lazorkit/wallet` 3.3.1 and `@lazorkit/wallet-mobile-adapter` 2.3.1 — and no
challenge of one kind can be another:

| Kind | Challenge | Length |
|---|---|---|
| Transaction (every `prepare*`, `Secp256r1Signer.sign`) | SHA-256 of the instruction's inputs | 32 |
| Message | `signedMessageChallenge(message)`: `tag ‖ SHA-256(tag ‖ message)`, tag = UTF-8 `LazorKit signed message v1` (`SIGNED_MESSAGE_DOMAIN`) | 58 |
| Ownership proof | `createTaggedOwnershipChallenge()`: `tag ‖ 32 random bytes`, tag = UTF-8 `LazorKit ownership proof v1` (`OWNERSHIP_PROOF_DOMAIN`) | 59 |

A `Secp256r1Signer` and the `prepare*` challenges are for transactions only.
Never hand a passkey other bytes as its challenge — a message, a nonce from a
server, a challenge from a URL: a 32-byte value is, to the program, an
approval of whatever transaction hashes to it. To have a passkey sign a
message, pass `signedMessageChallenge(message)` to `navigator.credentials.get`
(a string is signed as its UTF-8 bytes). To check the signature, read the key
from the claimed wallet on chain, never from the client. `verifyWalletMessage`
in `@lazorkit/wallet` does, and takes the signature as its `signMessage`
returns it: 64-byte r‖s (low-S or not), not the DER the browser returns, so
convert that first; clientDataJSON and authenticatorData as base64. With this
SDK, which takes DER or r‖s:

```ts
import { signedMessageChallenge, verifyOwnershipProof } from '@lazorkit/sdk';

// The passkey's Owner authorities under this rpId, on the wallet the signer claims.
const candidates = (await lk.findPasskeyWalletCandidates({ credentialIdHash, rpId }))
  .filter((c) => c.walletPda === claimed || c.vaultPda === claimed);
const [signer] = verifyOwnershipProof(candidates, {
  challenge: signedMessageChallenge(message),
  signature, authenticatorData, clientDataJson, // from the assertion
}, rpId);
// A migrated v1 wallet leaves its authorities behind: the wallet must still exist.
const { value: wallet } = signer
  ? await rpc.getAccountInfo(signer.walletPda, { encoding: 'base64' }).send()
  : { value: null };
const verified = !!signer && wallet?.owner === signer.programId;
```

`createOwnershipChallenge()` still returns 32 bare random bytes, as it always
has; it is deprecated as a passkey challenge, since those look exactly like a
transaction challenge. Use `createTaggedOwnershipChallenge()` for every new
proof. `verifyOwnershipProof`, `recoverPasskeyPublicKeys` and
`findOwnPasskeyWallet` check a proof over exactly the challenge it carries, of
any length from 16 bytes, so proofs over either form verify.

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
│   ├── signedMessage.ts # the challenge a passkey signs for a message
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
