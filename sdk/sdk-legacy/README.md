# @lazorkit/sdk-legacy

TypeScript SDK for the LazorKit smart wallet on Solana. Built for `@solana/web3.js` v1. For `@solana/kit` there is [`@lazorkit/sdk`](../sdk-kit/).

Provides:

- Hand-written instruction builders for every LazorKit instruction
- `LazorKitClient` — high-level API that auto-derives PDAs, fetches slots, reads counters, packs compact instructions, and handles protocol fees
- Two-phase passkey signing (`prepare*` / `finalize*`) for async WebAuthn flows
- `DeferredPayload` serialization for TX1-on-device / TX2-on-relayer flows
- Finding a returning passkey user's own wallet from one assertion (`findOwnPasskeyWallet`) — no need to track `walletPda` yourself

## Install

Which version you need depends on which protocol version your target cluster runs.

| npm | protocol | where it works |
|---|---|---|
| `0.3.x` (`latest`) | v1 | mainnet today |
| `1.x` (`next`) | v2 | devnet staging today, mainnet after the upgrade |

The two are not wire-compatible: v2 namespaces every PDA seed, so the same
`userSeed` derives a different wallet address. See
[CHANGELOG.md](../../CHANGELOG.md) for the full list, and
[`docs/migration-ui-flow.md`](../../docs/migration-ui-flow.md) for moving an
existing user's funds across.

```bash
npm install @lazorkit/sdk-legacy          # 0.3.x, talks to mainnet today
npm install @lazorkit/sdk-legacy@next     # 1.x, protocol v2
```

### Browser and React Native

The SDK needs no Node polyfills. Hashing and randomness come from
`@noble/hashes` and `Buffer` is imported from the `buffer` package, so a
browser or React Native bundle resolves everything on its own. Verified by
bundling for the browser and comparing every output byte for byte against Node.

On React Native, add `react-native-get-random-values` once at app start. That
is the same polyfill `@solana/web3.js` already needs for `Keypair.generate()`,
and the SDK uses `crypto.getRandomValues` for treasury shard selection and
ownership challenges.

## Quick start

```typescript
import { Connection, Keypair, Transaction, sendAndConfirmTransaction, SystemProgram } from '@solana/web3.js';
import { LazorKitClient, ed25519 } from '@lazorkit/sdk-legacy';
import * as crypto from 'crypto';

// Cluster is inferred from the RPC endpoint:
//   - URLs containing "mainnet" → mainnet program ID
//   - URLs containing "devnet"  → devnet program ID
//   - localhost / 127.0.0.1     → devnet program ID (local-validator convention)
//   - anything else              → throws; pass an explicit programId
const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
const client = new LazorKitClient(connection);

// Custom RPC providers without a recognisable hostname, forks, or local
// deployments using a different keypair → pass the program ID explicitly:
//
// import { PROGRAM_ID_MAINNET, PROGRAM_ID_DEVNET } from '@lazorkit/sdk-legacy';
// const client = new LazorKitClient(connection, PROGRAM_ID_MAINNET);
```

### Cluster + program IDs

LazorKit binaries embed the program ID via `declare_id!` at compile time
(Pattern D feature flags), so a binary built for one cluster cannot serve
the other.

| Cluster | Program ID | Build feature | Constant |
|---|---|---|---|
| mainnet-beta v2 | `LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8` | `--features mainnet` | `PROGRAM_ID_MAINNET` |
| mainnet-beta v1 (retiring) | `LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi` | `--features mainnet-v1` (sunset) | `PROGRAM_ID_MAINNET_V1` |
| devnet v2 (this repo) | `57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv` | `--features devnet` | `PROGRAM_ID_DEVNET` |
| devnet v1 (retiring) | `4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS` | `--features devnet-v1` (sunset) | `PROGRAM_ID_DEVNET_V1` |
| devnet (foundation: program-v2) | `FLb7fyAtkfA4TSa2uYcAT8QKHd2pkoMHgmqfnXFXo7ao` | (built in `program-v2`) | `PROGRAM_ID_FOUNDATION_DEVNET` |

The mainnet slot is shared between this repo's commercial build (with
protocol fees) and the sibling [`program-v2`](https://github.com/lazor-kit/program-v2)
foundation build (no fees). The same SDK works for both — the
`LazorKitClient` probes the on-chain `ProtocolConfig` PDA on first use and
appends fee accounts to fee-eligible instructions only when the PDA exists
(commercial). For the foundation build the probe returns null and no fee
accounts are appended.

The `LazorKitClient` constructor auto-selects the right program ID based on
the connection's RPC endpoint; pass an explicit `programId` argument to
override (e.g., target `PROGRAM_ID_FOUNDATION_DEVNET` against a localhost
validator running the foundation binary).

### Create a wallet

The `owner` field accepts either of two auth types. A wallet can later hold any mix of Ed25519 and Secp256r1 authorities at any rank, and several of them may be Owners.

**Passkey owner** (Secp256r1 — end-user WebAuthn flows):

```typescript
const { instructions, walletPda, vaultPda, authorityPda } = await client.createWallet({
  payer: payer.publicKey,
  userSeed: crypto.randomBytes(32),
  owner: {
    type: 'secp256r1',
    credentialIdHash,    // SHA-256 of WebAuthn credential ID
    compressedPubkey,    // 33-byte compressed public key
    rpId: 'your-app.com',
  },
});
await sendAndConfirmTransaction(connection, new Transaction().add(...instructions), [payer]);

// When the user comes back, find this wallet with findOwnPasskeyWallet — see
// "Finding a returning user's wallet" below. Not by credential hash alone.
```

**Ed25519 owner** (regular Solana keypair — bots, backends, programmatic signing):

```typescript
const ownerKp = Keypair.generate();
const { instructions, walletPda, vaultPda, authorityPda } = await client.createWallet({
  payer: payer.publicKey,
  userSeed: crypto.randomBytes(32),
  owner: {
    type: 'ed25519',
    publicKey: ownerKp.publicKey,
  },
});
await sendAndConfirmTransaction(connection, new Transaction().add(...instructions), [payer]);

// Lookup — pass 'ed25519' as the second arg. It lists every wallet the key is
// on, including any a stranger added it to: check `role` and the wallet's other
// authorities (findAuthoritiesByWallet) before using one.
const records = await client.findWalletsByAuthority(ownerKp.publicKey.toBytes(), 'ed25519');
```

### Finding a returning user's wallet

A returning user signs in with their passkey, and you need their wallet. Do not
take the first wallet that lists the passkey's credential-id hash. The hash is
public — it sits in every authority account the passkey has — and
`CreateWallet` / `AddAuthority` take any key without its consent. Anyone can
create a wallet listing a user's credential next to their own public key, or
add the user's real passkey to a wallet they control, and a lookup by hash
returns both.

`findOwnPasskeyWallet` takes one assertion over a challenge you generated, and
adopts a wallet only when

- the passkey is an **Owner** on it, created under your `rpId`, and the public
  key stored there is the one that just signed; and
- nothing untrusted can spend from it: no other authority, no live session, no
  pending deferred execution, no delegate or foreign close authority on the
  vault's token accounts (nor its wSOL/USDC/USDT account handed to someone
  else), and a vault that is still a plain system account — apart from
  Ed25519 keys you list in `trustedKeys` (a backend admin, session keys you
  issued, your own delegate); and
- it is the **one** wallet the passkey has **signed for** (`signatureCount > 0`,
  the replay counter on its authority, which only a signature by the key it
  stores advances).

A pending deferred execution always counts, even one that names this passkey's
own authority: the program does not tie it to the key that signed it, and that
authority address can have held someone else's key when it was queued. So does
a vault that is no longer a plain system account (`vaultIsSystemAccount:
false`), whatever you trust: an earlier Owner's `Execute` can `Assign` the
vault to another program, which from then on decides what leaves it.

The last condition is there because not everything an earlier holder of a
wallet did can be read back. `TransferOwnership` hands a wallet to a passkey
without asking it (its public key is on chain), and before that its Owner could
move the vault's SPL Token account for any mint to themselves with
`SetAuthority`. That account stops listing as the vault's, nothing on chain
leads back to it, and every later payment of that mint to the vault's address
lands in it. The SDK checks the canonical account for wSOL, USDC, USDT and
devnet USDC, plus every mint you pass as `watchMints` — pass the mints your
app receives. For any other mint such a wallet looks spotless, and a lamport
more in its vault would outrank the user's own. A passkey signs only for
a wallet its user chose, so a wallet it has never signed for is never adopted —
not even the only one, and not with `trustedKeys`. That includes the user's
own wallet before its first transaction: they confirm it once. A wallet your
app has just created or migrated into, you already know; keep its address
rather than looking it up.

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

```typescript
import { createOwnershipChallenge, selectWalletByAddress } from '@lazorkit/sdk-legacy';

const rpId = 'your-app.com';
const challenge = createOwnershipChallenge(); // fresh for every sign-in, never reused

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

const { adopt, needsConfirmation, unproven } = await client.findOwnPasskeyWallet({
  credentialIdHash,
  rpId,
  proof,
  trustedKeys: [backendAdmin.publicKey], // optional: your own Ed25519 keys on users' wallets
  watchMints: [yourAppsMint], // optional: SPL Token mints your app receives (see below)
});

let wallet;
if (adopt) {
  // This passkey has used it, and only it (and your trusted keys) can spend from it.
  wallet = adopt;
} else if (needsConfirmation.length > 0) {
  // The passkey owns these, but has never signed for them (`signatureCount: 0`
  // — say it gently: "This wallet has not been used with your passkey yet.
  // Continue only if you created it."), or has signed for more than one, or
  // something else can spend from them too. Show each vault address, its balance (`lamports`) and who else
  // controls it (`otherAuthorities`, `liveSessions`, `pendingDeferred`,
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
  const created = await client.createWallet({
    payer: payer.publicKey,
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
  them with `migrateV1Wallet`. It is adopted by the same rule as any other
  wallet, and has no precedence of its own: when exactly one wallet has been
  signed for and nothing untrusted can spend from it, that one is adopted, v1 or
  v2, and `needsConfirmation` is empty — even with a v1 wallet this passkey
  never signed from.
- Order of `needsConfirmation`: signed for first, then — among wallets equally
  signed for, or not — v1 before v2, then the fuller vault, then the wallet
  address. The balance order is one anyone can change by funding a vault — it is
  not a recommendation.
- A wallet whose account no longer exists is left out. Migrating a v1 wallet
  closes it and only the authority that migrated; another passkey's v1
  authority stays behind, and nothing can move funds sent to that vault.
- `tokenGrants` covers SPL Token and Token-2022 accounts the vault owns (any
  mint), plus the vault's SPL Token account for wSOL, USDC, USDT and devnet
  USDC, which `SetAuthority` can hand to another owner while senders keep
  paying into it — and for every mint in `watchMints`. For other mints only
  accounts the vault still owns are seen, so on a wallet never signed for, a
  clean `tokenGrants` proves nothing about them. When the user confirms such
  a wallet, that is the risk they take. Token-2022 associated accounts are
  created with an immutable owner and cannot be moved this way.
- The steps are public on their own — `findPasskeyWalletCandidates`,
  `verifyOwnershipProof`, `describeWalletCandidates`, `pickOwnWallet` — for a
  flow that collects the assertion somewhere else and decides here.
- Every wallet described costs three `getProgramAccounts` calls (authorities,
  sessions, deferred executions), two `getTokenAccountsByOwner`, and six
  accounts (one more per `watchMints` entry) read together; use an RPC
  endpoint that allows them. They are read in the order power flows — the
  authorities; then sessions and deferred executions; then the wallet, vault
  and token accounts — and each step asks for state at least as new as the one
  before (`minContextSlot`), so a transaction landing mid-read (a co-owner
  opening a session and removing itself, say) cannot be half-seen, even
  behind a load-balanced RPC. A node that has not caught up is asked again, up
  to five times. A failed read throws rather than guess.
- `migrateV1Wallet` holds a reused v2 destination to the same standard, and
  stricter: only this passkey as an authority, nothing live, a plain system
  vault and no grants on its token accounts
  (`vetMigrationDestination(wallet, owner, { watchMints })`, read in the same
  order; `migrateV1Wallet` takes `watchMints` too). A wallet it finds by itself
  is reused only if the passkey has signed for it and on no other authority of
  the program, at any rank (before the challenge named the wallet, a signature
  from an Admin seat could be replayed onto an Owner's); an Ed25519 owner's
  never is (name it with
  `destinationUserSeed`). A wallet at `userSeed` or
  `destinationUserSeed` is vetted too, and refused with the reason if it
  fails, but cannot be held to the signed-for bar — the userSeed is public in
  the v1 `CreateWallet` instruction, so anyone could have created and handed
  over a wallet there; pass `v1Wallet` without `userSeed` for a fresh
  destination when one exists that your app did not create. An address that
  only holds lamports gets a wallet created. It also refuses to deliver into an
  existing destination token account that is not the vault's alone, naming it.
  Send `setupInstructions` and the migrate in one transaction where they fit;
  otherwise send the migrate only after the setup transaction is confirmed
  successful — if someone else's `CreateWallet` at that seed lands first, a
  migrate sent anyway pays into their vault.

#### A passkey with no wallet, whose key you do not hold

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

```typescript
import {
  createOwnershipChallenge,
  resolvePasskeyPublicKey,
  type OwnershipProof,
} from '@lazorkit/sdk-legacy';

const sameBytes = (a: ArrayBuffer, b: ArrayBuffer) =>
  a.byteLength === b.byteLength && new Uint8Array(a).every((x, i) => x === new Uint8Array(b)[i]);

async function recoverPublicKey(credential: PublicKeyCredential, proof: OwnershipProof) {
  const challenge = createOwnershipChallenge(); // not the sign-in challenge: a new one
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

### Add more authorities

Any mix of auth types on the same wallet. Typical patterns:

- Passkey owner + Ed25519 admin — user's phone is the owner, a backend bot manages sessions on their behalf.
- Ed25519 owner + Secp256r1 delegate — the backend creates and manages the wallet, the user's passkey does day-to-day spends inside a policy.
- Several passkey owners — one per device, so a surviving device can revoke a lost one.

```typescript
import { ROLE_OWNER, ROLE_ADMIN, ROLE_SPENDER, Actions, serializeActions } from '@lazorkit/sdk-legacy';

// Ed25519 owner adds an Ed25519 admin
const adminKp = Keypair.generate();
const { instructions, newAuthorityPda } = await client.addAuthority({
  payer: payer.publicKey,
  walletPda,
  adminSigner: ed25519(ownerKp.publicKey),
  newAuthority: { type: 'ed25519', publicKey: adminKp.publicKey },
  role: ROLE_ADMIN,
});
await sendAndConfirmTransaction(connection, new Transaction().add(...instructions), [payer, ownerKp]);

// Ed25519 owner adds a Secp256r1 (passkey) spender — the user's phone
const { instructions: addPasskeyIxs } = await client.addAuthority({
  payer: payer.publicKey,
  walletPda,
  adminSigner: ed25519(ownerKp.publicKey),
  newAuthority: {
    type: 'secp256r1',
    credentialIdHash,
    compressedPubkey,
    rpId: 'your-app.com',
  },
  role: ROLE_SPENDER,
  // A Delegate must carry a policy. Rank says what an authority may manage;
  // the policy says what it may spend, and the two are independent — without
  // one, "spender" would name a tier with full control of the vault.
  policy: serializeActions([Actions.solLimit(1_000_000_000n)]),
});

// A second device, as a full Owner. `allowOwner` is required: an Owner can
// manage and revoke every authority on the wallet, including the one adding it.
const { instructions: addOwnerIxs } = await client.addAuthority({
  payer: payer.publicKey,
  walletPda,
  adminSigner: ed25519(ownerKp.publicKey),
  newAuthority: { type: 'secp256r1', credentialIdHash, compressedPubkey, rpId: 'your-app.com' },
  role: ROLE_OWNER,
  allowOwner: true,
});
```

To let a **passkey** admin add the new authority, use `prepareAddAuthority` + `finalizeAddAuthority` (same two-phase pattern as `prepareExecute` below).

## Signing a transaction

### Ed25519 authority (simple)

The keypair signs the transaction at the Solana level — no prepare/finalize needed. Just pass the public key as the signer and include the keypair in the tx signers.

```typescript
const { instructions } = await client.execute({
  payer: payer.publicKey,
  walletPda,
  signer: ed25519(ownerKp.publicKey),
  instructions: [SystemProgram.transfer({
    fromPubkey: vaultPda, toPubkey: recipient, lamports: 1_000_000,
  })],
});
await sendAndConfirmTransaction(connection, new Transaction().add(...instructions), [payer, ownerKp]);

// Convenience helper:
const { instructions: xferIxs } = await client.transferSol({
  payer: payer.publicKey,
  walletPda,
  signer: ed25519(ownerKp.publicKey),
  recipient,
  lamports: 1_000_000n,
});
```

### Passkey authority (two-phase flow)

Real WebAuthn is asynchronous — the browser popup happens between challenge computation and transaction construction. The SDK splits signing accordingly.

```typescript
// 1. SDK computes the challenge
const prepared = await client.prepareExecute({
  payer: payer.publicKey,
  walletPda: wallet.walletPda,
  secp256r1: {
    credentialIdHash,
    authorityPda: wallet.authorityPda,
    // publicKeyBytes is optional — auto-fetched from on-chain authority if omitted
  },
  instructions: [SystemProgram.transfer({
    fromPubkey: wallet.vaultPda,
    toPubkey: recipient,
    lamports: 1_000_000,
  })],
});

// 2. Authenticator signs (your code calls navigator.credentials.get)
const credential = await navigator.credentials.get({
  publicKey: {
    challenge: prepared.challenge,
    rpId: 'your-app.com',
    allowCredentials: [{ type: 'public-key', id: credentialIdBytes }],
  },
});
const response = credential.response as AuthenticatorAssertionResponse;

// 3. SDK builds the transaction
const { instructions: execIxs } = client.finalizeExecute(prepared, {
  signature: normalizeToLowS(response.signature),
  authenticatorData: new Uint8Array(response.authenticatorData),
  clientDataJsonHash: await sha256(response.clientDataJSON),
  clientDataJson: new Uint8Array(response.clientDataJSON),
});
```

**Every passkey operation has this three-phase shape** — `prepareExecute`, `prepareAddAuthority`, `prepareRemoveAuthority`, `prepareTransferOwnership`, `prepareCreateSession`, `prepareRevokeSession`, `prepareAuthorize`. Each pairs with a `finalizeX` that takes the WebAuthn response.

#### Two passkey transactions in a row

The challenge signs the authority's counter + 1, read in step 1. If the previous transaction from the same authority has been sent but not yet executed by the node you read from, that read returns the counter it is about to use, and the new signature fails with `SignatureReused` (3006) — after the user has approved it, and nothing can repair it. So wait for the previous transaction to confirm, and pass a slot at or after the one it landed in:

```typescript
// The context slot of the confirmation is at or after the slot tx1 landed in.
const { context, value } = await connection.confirmTransaction(
  { signature, blockhash, lastValidBlockHeight },
  'confirmed',
);
if (value.err) throw new Error(`previous transaction failed: ${JSON.stringify(value.err)}`);

const prepared = await client.prepareExecute({
  payer: payer.publicKey,
  walletPda: wallet.walletPda,
  secp256r1: {
    credentialIdHash,
    authorityPda: wallet.authorityPda,
    minContextSlot: context.slot, // read from a node that has executed tx1
    // commitment: 'confirmed',   // the default ('processed' on a 'processed' Connection)
  },
  instructions,
});
```

The same two options go on a signer config for the one-shot methods (`secp256r1(signer, { minContextSlot, commitment })`), on `migrateV1Wallet`, and on `readCounter`. They apply to all three reads a challenge is built from: the counter, the key and the slot. A node that has not reached `minContextSlot` answers -32016; the SDK retries with a short backoff for up to 10 s, then throws `MinContextSlotNotReachedError` (its `commitment` says which bank was behind). If one of the three reads fails for another reason (or, in `prepareExecute`, the protocol-fee read beside them), the call rejects with that error at once and the challenge reads stop retrying.

With `commitment: 'finalized'`, `minContextSlot` is a slot the node must have *finalized*. How long after its confirmation that happens depends on the cluster: 31 slots (16.5 s) on a local test validator (Agave 4.2.2), and no time at all on devnet on 2026-09-30, where the finalized slot was the confirmed one. The reads wait up to 30 s for it, so where finalization lags, a floor at a just-confirmed tx1 costs that lag before the passkey prompt. The challenge's slot is read at `finalized` too, so it is already that many slots old when the prompt appears, and the program accepts a challenge only until its slot is 150 slots old (about a minute): a 31-slot lag leaves about 119 slots to approve, send and land it. It is not read at `confirmed` instead because the program also refuses a slot newer than the one it runs in, so a relayer simulating at `finalized` would refuse the challenge. Unless you need finalized reads, keep the default: `confirmed` with the floor is enough to sign the right counter.

Without `minContextSlot` the reads are at `confirmed`, or at `processed` when the Connection itself is at `processed` (never staler than the Connection, as in 1.2.0). That is enough only when the node that answers the reads has itself executed the previous transaction. Behind a load-balanced RPC endpoint the confirmation and the next reads can reach different nodes, and the one that answers may still be behind: pass the floor even after confirming.

**One passkey flow per authority at a time.** Two flows for the same authority that overlap — two `prepare*` calls before the first transaction lands, two tabs or devices with one passkey, an app and a wallet — read the same counter and both sign counter + 1. Whichever lands second fails with 3006, and no floor helps: neither has landed when the other reads. Run prepare → sign → send → confirm for one authority one after another, each floored at the previous one's slot. The SDK keeps no per-authority state and does not queue for you; within one app a queue of your own is enough:

```typescript
// Your app's, not the SDK's: flows for one authority run one after another.
const tails = new Map<string, Promise<void>>();

async function oneAtATime<T>(authority: PublicKey, flow: () => Promise<T>): Promise<T> {
  const key = authority.toBase58();
  const run = (tails.get(key) ?? Promise.resolve()).then(flow);
  const tail = run.then(() => undefined, () => undefined);
  tails.set(key, tail);
  try {
    return await run;
  } finally {
    if (tails.get(key) === tail) tails.delete(key);
  }
}

// flow = prepare (floored at the last slot) → passkey prompt → send → confirm
await oneAtATime(wallet.authorityPda, () => payWithPasskey(invoice));
```

Across tabs, devices or apps that share a passkey no local queue helps; a 3006 there means another flow used the counter first, and the fix is to prepare again (a new prompt), floored at a slot that includes it.

Helper for wrapping the `navigator.credentials.get` → `WebAuthnResponse` conversion once:

```typescript
import type { WebAuthnResponse } from '@lazorkit/sdk-legacy';

async function getWebAuthnResponse(
  challenge: Uint8Array, rpId: string, credentialId: BufferSource,
): Promise<WebAuthnResponse> {
  const credential = await navigator.credentials.get({
    publicKey: { challenge, rpId, allowCredentials: [{ type: 'public-key', id: credentialId }] },
  });
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    signature: normalizeToLowS(response.signature),  // DER → raw r||s, low-S
    authenticatorData: new Uint8Array(response.authenticatorData),
    clientDataJsonHash: new Uint8Array(await crypto.subtle.digest('SHA-256', response.clientDataJSON)),
    clientDataJson: new Uint8Array(response.clientDataJSON),
  };
}
```

## High-level client API

Every method returns `{ instructions: TransactionInstruction[]; ...extraPdas }`.

### Wallet operations

```typescript
client.createWallet({ payer, userSeed, owner });

// Execute (Ed25519 or session key — for passkeys use prepareExecute/finalizeExecute)
client.execute({ payer, walletPda, signer, instructions });

// Convenience: SOL transfer
client.transferSol({ payer, walletPda, signer, recipient, lamports });

// Authority management — for passkeys use prepare/finalize pairs
client.addAuthority({ payer, walletPda, adminSigner, newAuthority, role });
client.removeAuthority({ payer, walletPda, adminSigner, targetAuthorityPda });
client.transferOwnership({ payer, walletPda, ownerSigner, newOwner });
```

### Protocol fees & auto-registration

When the protocol is initialized and enabled (admin-only operation), the SDK transparently appends the four fee accounts (`protocol_config`, `fee_record`, `treasury_shard`, `system_program`) to every fee-eligible instruction (`createWallet`, `execute`, `executeDeferred`). The on-chain entrypoint transfers the fee from the payer to a randomly-chosen treasury shard, then strips the accounts before dispatching to the processor.

```typescript
// Nothing extra to do — fee handling is automatic
await client.createWallet({ payer, userSeed, owner });   // 5000 lamport protocol fee
await client.execute({ payer, walletPda, signer, instructions });  // 5000 lamport protocol fee
```

**Auto-registration**: a `FeeRecord` PDA tracks per-payer cumulative fees and is required for every successful fee-paying instruction. The SDK auto-prepends a one-time `RegisterPayer` instruction on the payer's first fee-paying tx (~0.00112 SOL of FeeRecord rent, paid by the payer). An in-memory cache short-circuits the existence check on subsequent calls. The on-chain entrypoint also creates the canonical `FeeRecord` inline when a custom client supplies the correct system-owned PDA.

If you want to register explicitly (e.g. to front-load the cost during onboarding):

```typescript
const { instructions, feeRecordPda } = client.registerPayer({ payer: payer.publicKey });
await sendAndConfirmTransaction(connection, new Transaction().add(...instructions), [payer]);
```

The `registerPayer` instruction is **permissionless** — any payer registers themselves, no admin signature needed.

For advanced flows (custom tx assembly, gasless relayer pre-sim), the resolver methods are exposed:

```typescript
// Returns { protocolConfigPda, feeRecordPda, treasuryShardPda } | undefined
const fee = await client.resolveProtocolFee(payer);

// Same plus an optional `registerIx` to prepend if the FeeRecord doesn't exist yet
const { accounts, registerIx } = await client.resolveProtocolFeeWithRegister(payer) ?? {};
```

If the protocol isn't initialized or is disabled, both resolvers return `undefined` and the SDK skips fee accounts entirely.

### Sessions

```typescript
import { Actions } from '@lazorkit/sdk-legacy';

const { instructions, sessionPda } = await client.createSession({
  payer, walletPda,
  adminSigner: ed25519(ownerKp.publicKey),
  sessionKey: sessionKp.publicKey,
  expiresAt: currentSlot + 9000n,
  actions: [
    Actions.programWhitelist(SystemProgram.programId),
    Actions.solMaxPerTx(1_000_000_000n),
    Actions.solLimit(10_000_000_000n),
  ],
});

// Later, execute via session key
await client.execute({
  payer, walletPda,
  signer: session(sessionPda, sessionKp.publicKey),
  instructions: [...],
});

// Early revoke
client.revokeSession({ payer, walletPda, adminSigner, sessionPda });
```

Action builders (via `Actions`):

| Builder | Notes |
|---|---|
| `Actions.solLimit(remaining, expiresAt?)` | Lifetime SOL cap |
| `Actions.solRecurringLimit({ limit, window, expiresAt? })` | Per-window SOL cap |
| `Actions.solMaxPerTx(max, expiresAt?)` | Max SOL per execute (gross outflow, not net) |
| `Actions.tokenLimit({ mint, remaining, expiresAt? })` | Lifetime token cap |
| `Actions.tokenRecurringLimit({ mint, limit, window, expiresAt? })` | Per-window token cap |
| `Actions.tokenMaxPerTx({ mint, max, expiresAt? })` | Max tokens per execute |
| `Actions.programWhitelist(programId, expiresAt?)` | Only allow these programs (repeatable) |
| `Actions.programBlacklist(programId, expiresAt?)` | Block these programs (repeatable) |

### Deferred execution (2-tx flow)

For payloads that don't fit in a single Secp256r1 Execute tx (e.g., Jupiter swaps with complex routing):

```typescript
// TX1 — on user's device
const prepared = await client.prepareAuthorize({
  payer, walletPda,
  secp256r1: { credentialIdHash, authorityPda },
  instructions: [jupiterSwapIx],
  expiryOffset: 300,  // slots (~2 min)
  executor: relayer.publicKey,  // who sends TX2; defaults to `payer`
});
const webauthnResponse = await getWebAuthnResponse(prepared.challenge, rpId, credentialId);
const { instructions: tx1, deferredPayload } = client.finalizeAuthorize(prepared, webauthnResponse);
await sendAndConfirmTransaction(connection, new Transaction().add(...tx1), [payer]);

// Send `deferredPayload` to a relayer (HTTP, WebSocket, whatever)
import { serializeDeferredPayload } from '@lazorkit/sdk-legacy';
const wire = serializeDeferredPayload(deferredPayload);

// TX2 — on the relayer
import { deserializeDeferredPayload } from '@lazorkit/sdk-legacy';
const payload = deserializeDeferredPayload(receivedWire);
const { instructions: tx2 } = await client.executeDeferredFromPayload({
  payer: relayer.publicKey,
  deferredPayload: payload,
});
```

The accounts hash the passkey signs covers TX2's accounts with the flags the
program will read there, and TX2's payer and refund destination (always the
TX1 `payer`) read differently depending on who sends it. So name the
`executor` up front whenever an inner instruction may pay either of them back;
`executeDeferredFromPayload` refuses another sender for such a payload rather
than build a TX2 that fails with `DeferredHashMismatch` (3015). The refund
destination defaults to the TX1 payer the payload records.

If TX2 never gets submitted and the expiry passes, the original payer can reclaim their rent via `client.reclaimDeferred(...)`.

### Wallet lookup

```typescript
// A returning passkey user's own wallet — see "Finding a returning user's wallet"
const { adopt, needsConfirmation, unproven } =
  await client.findOwnPasskeyWallet({ credentialIdHash, rpId, proof, trustedKeys });

// Raw lookup: every wallet that lists the credential, at any rank, including
// wallets a stranger created with it or added it to. It proves nothing.
const wallets = await client.findWalletsByAuthority(credentialIdHash);
const ed25519Wallets = await client.findWalletsByAuthority(pubkeyBytes, 'ed25519');
// Each: { walletPda, authorityPda, vaultPda, role, authorityType }
```

Both use `getProgramAccounts` with discriminator + authority_type + credential
filters; `findOwnPasskeyWallet` also filters on the relying party and reads each
proven wallet's account, authorities, sessions, deferred executions and vault
token accounts.

### PDA helpers

```typescript
import {
  findWalletPda, findVaultPda, findAuthorityPda, findSessionPda, findDeferredExecPda,
  findProtocolConfigPda, findFeeRecordPda, findTreasuryShardPda,
} from '@lazorkit/sdk-legacy';
```

### Generated account readers

```typescript
import {
  AuthorityAccount, SessionAccount, ProtocolConfigAccount, FeeRecordAccount, TreasuryShardAccount,
} from '@lazorkit/sdk-legacy';

const authority = await AuthorityAccount.fromAccountAddress(connection, authorityPda);
```

## Transactions (legacy + v0)

Every `client.*` method returns raw `TransactionInstruction[]` — composable so you can append your own ix (priority fees, custom CPIs) before sending. For when you want to skip the boilerplate, the SDK ships three small helpers:

```typescript
import {
  buildLegacyTx,
  buildV0Tx,
  createAndExtendLut,
} from '@lazorkit/sdk-legacy';
```

### Legacy

```typescript
const { blockhash } = await connection.getLatestBlockhash('confirmed');

const tx = buildLegacyTx({
  payer: payer.publicKey,
  instructions,
  blockhash,
  signers: [payer],
});

await connection.sendRawTransaction(tx.serialize());
```

### Versioned (v0) with Address Lookup Tables

A LazorKit-tuned ALT containing the system program, sysvars, `protocol_config`, and all `treasury_shard` PDAs saves **~88 B per Secp256r1 Execute** — useful headroom when chaining multiple inner instructions or calling Jupiter/bridges.

```typescript
import {
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SYSVAR_RENT_PUBKEY,
} from '@solana/web3.js';

// One-time setup — bootstrap the LUT
const [protocolConfigPda] = client.findProtocolConfig();
const treasuryShards = Array.from({ length: numShards }, (_, i) =>
  client.findTreasuryShard(i)[0],
);

const lut = await createAndExtendLut({
  connection,
  authority: relayerKeypair,   // also pays rent + becomes the LUT authority
  addresses: [
    SystemProgram.programId,
    SYSVAR_INSTRUCTIONS_PUBKEY,
    SYSVAR_RENT_PUBKEY,
    protocolConfigPda,
    ...treasuryShards,
  ],
});

// Per-tx — wrap any client.* result
const v0Tx = buildV0Tx({
  payer: payer.publicKey,
  instructions,
  blockhash,
  signers: [payer],
  lookupTables: [lut],
});

await connection.sendRawTransaction(v0Tx.serialize());
```

`createAndExtendLut` handles the slot-finalization quirk (the AddressLookupTable program rejects `recentSlot` from `confirmed` as too new), chunks extends in groups of 30, and waits one slot before returning so the table is usable in the same session.

**When to use which**: prefer v0+LUT for `execute` (especially Secp256r1) and `executeDeferred`. For tiny instructions (`removeAuthority`, `revokeSession`, `reclaimDeferred`) the v0 wrapper actually adds 2 B because the LUT reference itself costs more than was saved — keep using legacy for those. Full size deltas per instruction are in [`tests-sdk/tests/benchmark-fees.ts`](../../tests-sdk/tests/benchmark-fees.ts).

## Low-level builders

If you need to construct transactions outside the client API, the instruction builders are directly importable:

```typescript
import {
  createCreateWalletIx, createAddAuthorityIx, createExecuteIx,
  prepareSecp256r1, finalizeSecp256r1,
  packCompactInstructions, computeAccountsHash, computeInstructionsHash,
  buildDataPayloadForAdd, buildDataPayloadForTransfer, buildDataPayloadForSession,
} from '@lazorkit/sdk-legacy';
```

`prepareSecp256r1` takes the `wallet` the signing authority belongs to — the
wallet PDA, or the v1 wallet for `MigrateWallet` — and hashes it into the
challenge after the payer:
`SHA256(discriminator || auth_payload[..14] || signed_payload || payer || wallet || counter_le4 || program_id)`.
`computeAccountsHash` hashes the flags each meta carries, and the program
compares them with the runtime's, which are per key: give the fee payer as a
writable signer (declare the Execute payer writable) and a key listed twice the
union of its entries — see §5 of `docs/integrator-wire-format-v2.md`. The
`prepare*` methods do this for their own accounts; `prepareExecute` and
`prepareAuthorize` take `feePayer` when another key pays the fee, and
`prepareAuthorize` takes the `executor` that will send tx2.
The ref implementations are in `tests-sdk/tests/05-replay.test.ts`, `06-counter.test.ts`, and `08-deferred.test.ts`.

## Constants

```typescript
// Instruction discriminators
DISC_CREATE_WALLET = 0
DISC_ADD_AUTHORITY = 1
DISC_REMOVE_AUTHORITY = 2
DISC_TRANSFER_OWNERSHIP = 3
DISC_EXECUTE = 4
DISC_CREATE_SESSION = 5
DISC_AUTHORIZE = 6
DISC_EXECUTE_DEFERRED = 7
DISC_RECLAIM_DEFERRED = 8
DISC_REVOKE_SESSION = 9
// Protocol admin (10-14)

// Auth types
AUTH_TYPE_ED25519 = 0
AUTH_TYPE_SECP256R1 = 1

// Ranks — what an authority may *manage*. What it may *spend* is its policy.
ROLE_OWNER = 0     // manages everything, including other Owners
ROLE_ADMIN = 1     // manages Delegates
ROLE_SPENDER = 2   // manages nothing; must carry a policy
```

Rank rules:

| Rank | May add | May remove |
|---|---|---|
| Owner | Owner, Admin, Delegate | Owner (not the last), Admin, Delegate |
| Admin | Delegate | Delegate |
| Delegate | nothing | nothing |

An authority that carries a policy itself may not add authorities at all.

## Error codes

| Code | Name |
|---|---|
| 3001 | InvalidAuthorityPayload |
| 3002 | PermissionDenied |
| 3005 | InvalidMessageHash |
| 3006 | SignatureReused (counter mismatch — often a challenge read before the previous transaction executed; see [Two passkey transactions in a row](#two-passkey-transactions-in-a-row)). Not always LazorKit's: see the note below the table |
| 3007 | InvalidSignatureAge |
| 3008 | InvalidSessionDuration |
| 3009 | SessionExpired |
| 3013 | SelfReentrancyNotAllowed |
| 3014 | DeferredAuthorizationExpired |
| 3015 | DeferredHashMismatch |
| 3016 | InvalidExpiryWindow |
| 3020–3029 | Action errors (buffer invalid, whitelist/blacklist, spending limits exceeded) |
| 3030 | SessionVaultOwnerChanged (H1 fix) |
| 3031 | SessionVaultDataLenChanged (H1 fix) |
| 3032 | SessionTokenAuthorityChanged (H1 fix) |
| 4001–4007 | Protocol fee errors |

A program that `Execute` calls can fail with the same custom code, and the transaction then fails with it too: Anchor's account errors use 3000–3017, so an inner Anchor program's `AccountNotMutable` is also `Custom(3006)`. `extractErrorCode` and `errorFromCode` read only the number. The transaction logs name the program: the first `Program <id> failed: custom program error: 0x…` line is the one that raised it, and only when that id is the LazorKit program is the code one of the above. A landed failure (`{"InstructionError":[i,{"Custom":3006}]}` from `confirmTransaction` or `getSignatureStatuses`) names only the top-level instruction — the LazorKit one, whichever program inside it failed — so it cannot be attributed without its logs: read them with `getTransaction(signature)` → `meta.logMessages` before telling the user to sign again. `extractErrorCode` returns `null` for that object (it reads error text only).

See [`docs/Architecture.md`](../../docs/Architecture.md) for the full security model and account layouts.

## License

MIT
