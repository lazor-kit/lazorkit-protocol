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

## Migrating a v1 wallet

After the v2 upgrade, a v1 wallet's normal operations revert and its owner must
migrate once. Both halves of that flow are here.

```ts
const lk = new LazorKit(rpc, PROGRAM_ID_MAINNET);

// 1. Find the wallet. Most users cannot: the v1 `userSeed` was random and lived
//    in browser storage. The chain can — the v1 authority stores both the
//    owner's key and its wallet.
const [found] = await lk.findV1WalletsByOwner(credentialIdHash);

// 2. Move everything. One signature; SOL and every token land in the v2 vault
//    and the v1 accounts close.
const { setupInstructions, migrate, destinationUserSeed } = await lk.migrateV1Wallet({
  payer,
  owner: { type: 'secp256r1', credentialIdHash, compressedPubkey: found.ownerPubkey },
  v1Wallet: found.wallet,
});
const instructions =
  migrate.type === 'ed25519'
    ? [...setupInstructions, migrate.instruction]
    : [...setupInstructions, ...migrate.finalize(await signWithPasskey(migrate.challenge))];
```

`found.ownerPubkey` is not optional bookkeeping: signing in with an existing
passkey returns a WebAuthn *assertion*, which carries no public key, so the
chain is the only place a returning user's key can be read. Persist
`destinationUserSeed` when it comes back — it is the seed of the freshly created
v2 wallet, and nothing else can derive it.

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
