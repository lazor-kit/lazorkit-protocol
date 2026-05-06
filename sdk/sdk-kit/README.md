# @lazorkit/sdk

LazorKit Protocol TypeScript SDK for **Solana Kit** (`@solana/kit`, formerly `@solana/web3.js` v2).

This is the modern, tree-shakable, functional-API counterpart to [`@lazorkit/sdk-legacy`](../sdk-legacy/) (which targets `@solana/web3.js` v1). Both SDKs talk to the same on-chain program and produce equivalent transactions; pick the one that matches your stack.

## Status

**Alpha.** Currently in active development as part of the SDK consolidation effort. APIs may change before the first stable `0.1.0`. The `0.1.0-alpha.x` line is published for early integrators who want to build against `@solana/kit`.

For production use today, prefer [`@lazorkit/sdk-legacy`](https://www.npmjs.com/package/@lazorkit/sdk-legacy).

## Install

```bash
npm install @lazorkit/sdk @solana/kit
```

`@solana/kit` is declared as a peer dependency — install whichever version your app uses.

## Quick start

```ts
import {
  PROGRAM_ID_DEVNET,
  findWalletPda,
} from '@lazorkit/sdk';

const userSeed = new Uint8Array(/* 16-byte cred-id digest, etc. */);
const [walletPda, bump] = await findWalletPda(userSeed, PROGRAM_ID_DEVNET);
console.log(walletPda); // address(...)
```

## Package layout

```
sdk-kit/
├── src/
│   ├── codecs/        # @solana/codecs-based account/action codecs
│   ├── instructions/  # instruction builders returning kit Instruction[]
│   ├── secp256r1/     # passkey + sysvar-introspection signing helpers
│   ├── constants.ts   # program addresses (mainnet, devnet, foundation devnet)
│   ├── pdas.ts        # PDA derivation helpers
│   └── index.ts
└── tests/             # vitest unit tests (PDA parity, codec roundtrips)
```

## Relationship to `@lazorkit/sdk-legacy`

- **Same on-chain protocol.** Identical instruction encoding, identical PDA seeds, identical account layouts. PDA derivation is byte-identical (verified in `tests/pdas.test.ts`).
- **Different runtime API.** `sdk-legacy` exposes a `LazorKitClient` class that takes a v1 `Connection`; `sdk-kit` is functional, taking RPC primitives from `@solana/kit`.
- **No flavor branching.** Both SDKs are oblivious to whether the on-chain binary is the commercial (`lazorkit-protocol`) or foundation (`program-v2`) build — they always produce commercial-shape transactions and rely on the on-chain logic to gracefully tolerate or charge fees as appropriate. See the docstring in `src/constants.ts`.

## License

MIT — see [LICENSE](./LICENSE).
