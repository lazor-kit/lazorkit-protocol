# @lazorkit/sdk-legacy

TypeScript SDK for the LazorKit smart wallet on Solana. Built for `@solana/web3.js` v1. (A `@lazorkit/sdk` for web3.js v2 is coming soon.)

Provides:

- Hand-written instruction builders for every LazorKit instruction
- `LazorKitClient` — high-level API that auto-derives PDAs, fetches slots, reads counters, packs compact instructions, and handles protocol fees
- Two-phase passkey signing (`prepare*` / `finalize*`) for async WebAuthn flows
- `DeferredPayload` serialization for TX1-on-device / TX2-on-relayer flows
- Wallet lookup by credential hash (no need to track `walletPda` yourself)

## Install

```bash
npm install @lazorkit/sdk-legacy
```

## Quick start

```typescript
import { Connection, Transaction, sendAndConfirmTransaction, SystemProgram } from '@solana/web3.js';
import { LazorKitClient } from '@lazorkit/sdk-legacy';
import * as crypto from 'crypto';

const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
const client = new LazorKitClient(connection);

// Create a passkey-owned wallet
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

// Later: find the same wallet back from just the credential hash
const [wallet] = await client.findWalletsByAuthority(credentialIdHash);
```

## Signing a passkey transaction (two-phase flow)

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

## Ed25519 signer (bots, backends, in-process tests)

Pass an Ed25519 keypair's public key — it signs the transaction at the Solana level, no prepare/finalize needed.

```typescript
import { ed25519 } from '@lazorkit/sdk-legacy';

const { instructions } = await client.execute({
  payer: payer.publicKey,
  walletPda,
  signer: ed25519(ownerKp.publicKey),
  instructions: [SystemProgram.transfer({ ... })],
});
await sendAndConfirmTransaction(connection, new Transaction().add(...instructions), [payer, ownerKp]);
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

If TX2 never gets submitted and the expiry passes, the original payer can reclaim their rent via `client.reclaimDeferred(...)`.

### Wallet lookup

```typescript
// All wallets the credential can access
const wallets = await client.findWalletsByAuthority(credentialIdHash);

// Ed25519 authority lookup
const ed25519Wallets = await client.findWalletsByAuthority(pubkeyBytes, 'ed25519');

// Each: { walletPda, authorityPda, vaultPda, role, authorityType }
```

Uses `getProgramAccounts` with discriminator + authority_type + credential filters.

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

// Roles
ROLE_OWNER = 0
ROLE_ADMIN = 1
ROLE_SPENDER = 2
```

## Error codes

| Code | Name |
|---|---|
| 3001 | InvalidAuthorityPayload |
| 3002 | PermissionDenied |
| 3005 | InvalidMessageHash |
| 3006 | SignatureReused (counter mismatch) |
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

See [`docs/Architecture.md`](../../docs/Architecture.md) for the full security model and account layouts.

## License

MIT
