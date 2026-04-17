# @lazorkit/sdk-legacy

TypeScript SDK for the LazorKit Protocol smart wallet on Solana. Built with `@solana/web3.js` v1.

> This is the legacy SDK for `@solana/web3.js` v1. A new `@lazorkit/sdk` for web3.js v2 is coming soon.

Features: passkey/WebAuthn authentication, session keys with spending limits and program whitelist/blacklist, deferred execution, wallet lookup by credential.

## Installation

```bash
npm install @lazorkit/sdk-legacy
```

## Quick Start

```typescript
import { Connection, Keypair, Transaction, sendAndConfirmTransaction, SystemProgram } from '@solana/web3.js';
import { LazorKitClient } from '@lazorkit/sdk-legacy';
import * as crypto from 'crypto';

const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
const client = new LazorKitClient(connection);

// Create a wallet with passkey owner
const { instructions, walletPda, vaultPda, authorityPda } = await client.createWallet({
  payer: payer.publicKey,
  userSeed: crypto.randomBytes(32),
  owner: {
    type: 'secp256r1',
    credentialIdHash,      // 32-byte SHA256 of WebAuthn credential ID
    compressedPubkey,      // 33-byte compressed public key
    rpId: 'your-app.com',
  },
});
await sendAndConfirmTransaction(connection, new Transaction().add(...instructions), [payer]);

// User comes back later — find wallet by credential only
const [wallet] = await client.findWalletsByAuthority(credentialIdHash);
// Returns: { walletPda, authorityPda, vaultPda, role, authorityType }

// Execute a SOL transfer with passkey (two-phase flow)
// Step 1: SDK computes the challenge
const prepared = await client.prepareExecute({
  payer: payer.publicKey,
  walletPda: wallet.walletPda,
  secp256r1: { credentialIdHash, publicKeyBytes: compressedPubkey, authorityPda: wallet.authorityPda },
  instructions: [
    SystemProgram.transfer({ fromPubkey: wallet.vaultPda, toPubkey: recipient, lamports: 1_000_000 }),
  ],
});

// Step 2: Browser authenticator signs the challenge
const credential = await navigator.credentials.get({
  publicKey: { challenge: prepared.challenge, rpId: 'your-app.com', allowCredentials: [{ type: 'public-key', id: credentialId }] },
});
const response = credential.response as AuthenticatorAssertionResponse;

// Step 3: SDK builds the transaction
const { instructions: execIxs } = client.finalizeExecute(prepared, {
  signature: normalizeToLowS(response.signature),
  authenticatorData: new Uint8Array(response.authenticatorData),
  clientDataJsonHash: await sha256(response.clientDataJSON),
  clientDataJson: new Uint8Array(response.clientDataJSON),
});
await sendAndConfirmTransaction(connection, new Transaction().add(...execIxs), [payer]);
```

> **Protocol fees are automatic.** If the payer is registered with the protocol, fees are collected transparently. If not, the SDK works identically to open-source LazorKit. No extra params needed.

## API Reference

### Wallet Lookup

Find wallets from just a credential — no need to store `walletPda`.

```typescript
// Passkey user returns (default: secp256r1)
const [wallet] = await client.findWalletsByAuthority(credentialIdHash);

// Ed25519 lookup
const [wallet] = await client.findWalletsByAuthority(pubkeyBytes, 'ed25519');

// Multiple wallets for same credential
const wallets = await client.findWalletsByAuthority(credentialIdHash);
// Each: { walletPda, authorityPda, vaultPda, role, authorityType }
```

Uses `getProgramAccounts` with discriminator + authority_type + credential data filters.

### PDA Helpers

```typescript
import {
  findWalletPda, findVaultPda, findAuthorityPda, findSessionPda,
  findDeferredExecPda, findProtocolConfigPda, findFeeRecordPda, findTreasuryShardPda,
} from '@lazorkit/sdk-legacy';

const [walletPda] = findWalletPda(userSeed);
const [vaultPda] = findVaultPda(walletPda);
const [authorityPda] = findAuthorityPda(walletPda, credentialIdHash);
const [sessionPda] = findSessionPda(walletPda, sessionKeyBytes);
const [deferredPda] = findDeferredExecPda(walletPda, authorityPda, counter);
const [configPda] = findProtocolConfigPda();
const [feeRecordPda] = findFeeRecordPda(payerPubkey);
const [shardPda] = findTreasuryShardPda(shardId);
```

### Signer Types (Convenience Wrappers)

For Ed25519 and session keys, use these helpers with the unified client methods:

```typescript
import { ed25519, session } from '@lazorkit/sdk-legacy';

// Ed25519 — Keypair signs at transaction level
const signer = ed25519(ownerKp.publicKey, authorityPda);  // authorityPda optional

// Session — ephemeral key
const signer = session(sessionPda, sessionKp.publicKey);
```

For Secp256r1 (passkey) operations, use the **two-phase prepare/finalize API** (see next section). A `secp256r1()` convenience wrapper exists for programmatic/in-process signing but is not recommended for real browser flows.

### Two-Phase Passkey API (Secp256r1)

Real WebAuthn flows are asynchronous — the browser shows a popup, the user touches their fingerprint reader, the response comes back later. The SDK splits this into two phases:

1. **`prepare*()`** — SDK computes the challenge. Send this to the authenticator.
2. **`finalize*()`** — SDK takes the WebAuthn response and builds transaction instructions.

#### Types

```typescript
// What you pass to prepare methods (identity info, no signing callback)
interface Secp256r1Params {
  credentialIdHash: Uint8Array;  // 32-byte SHA256 of credential ID
  publicKeyBytes: Uint8Array;    // 33-byte compressed P-256 key
  authorityPda?: PublicKey;      // optional — SDK derives if omitted
  slotOverride?: bigint;         // optional — SDK fetches current slot if omitted
}

// What the browser authenticator returns (pass to finalize methods)
interface WebAuthnResponse {
  signature: Uint8Array;         // 64-byte raw ECDSA r||s, low-S normalized
  authenticatorData: Uint8Array; // from authenticator
  clientDataJsonHash: Uint8Array;// SHA256 of clientDataJSON
  clientDataJson: Uint8Array;    // raw clientDataJSON bytes from authenticator
}
```

#### Method Pairs

Every Secp256r1-capable operation has a prepare/finalize pair:

```typescript
// Execute arbitrary instructions
const prepared = await client.prepareExecute({ payer, walletPda, secp256r1, instructions });
const { instructions } = client.finalizeExecute(prepared, webauthnResponse);

// Add authority
const prepared = await client.prepareAddAuthority({ payer, walletPda, secp256r1, newAuthority, role });
const { instructions, newAuthorityPda } = client.finalizeAddAuthority(prepared, webauthnResponse);

// Remove authority
const prepared = await client.prepareRemoveAuthority({ payer, walletPda, secp256r1, targetAuthorityPda });
const { instructions } = client.finalizeRemoveAuthority(prepared, webauthnResponse);

// Transfer ownership
const prepared = await client.prepareTransferOwnership({ payer, walletPda, secp256r1, newOwner });
const { instructions, newOwnerAuthorityPda } = client.finalizeTransferOwnership(prepared, webauthnResponse);

// Create session
const prepared = await client.prepareCreateSession({ payer, walletPda, secp256r1, sessionKey, expiresAt, actions? });
const { instructions, sessionPda } = client.finalizeCreateSession(prepared, webauthnResponse);

// Revoke session
const prepared = await client.prepareRevokeSession({ payer, walletPda, secp256r1, sessionPda });
const { instructions } = client.finalizeRevokeSession(prepared, webauthnResponse);

// Deferred execution (Authorize)
const prepared = await client.prepareAuthorize({ payer, walletPda, secp256r1, instructions, expiryOffset? });
const { instructions, deferredExecPda, deferredPayload } = client.finalizeAuthorize(prepared, webauthnResponse);
```

All prepare methods return `{ challenge: Uint8Array, ... }`. Pass `prepared.challenge` to `navigator.credentials.get()`.

### High-Level Client API

Every method returns `{ instructions: TransactionInstruction[]; ...extraPdas }`. The client auto-derives PDAs, auto-fetches slots, auto-reads counters, auto-packs compact instructions, auto-computes hashes, and auto-detects protocol fees.

#### Wallet Operations

```typescript
const client = new LazorKitClient(connection);

// Create wallet (works for both Ed25519 and Secp256r1 — no signing needed)
const { instructions, walletPda, vaultPda, authorityPda } = await client.createWallet({
  payer, userSeed,
  owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
});

// Execute with Ed25519 signer
const { instructions } = await client.execute({
  payer, walletPda,
  signer: ed25519(ownerKp.publicKey),
  instructions: [SystemProgram.transfer({ fromPubkey: vault, toPubkey: recipient, lamports: 1_000_000 })],
});

// Execute with passkey (prepare/finalize)
const prepared = await client.prepareExecute({
  payer, walletPda,
  secp256r1: { credentialIdHash, publicKeyBytes, authorityPda },
  instructions: [SystemProgram.transfer({ fromPubkey: vault, toPubkey: recipient, lamports: 1_000_000 })],
});
// ... browser authenticator signs prepared.challenge ...
const { instructions } = client.finalizeExecute(prepared, webauthnResponse);

// Add authority (Ed25519 admin)
const { instructions, newAuthorityPda } = await client.addAuthority({
  payer, walletPda,
  adminSigner: ed25519(ownerKp.publicKey),
  newAuthority: { type: 'ed25519', publicKey: adminKp.publicKey },
  role: ROLE_ADMIN,
});

// Add authority (passkey admin — prepare/finalize)
const prepared = await client.prepareAddAuthority({
  payer, walletPda,
  secp256r1: { credentialIdHash, publicKeyBytes, authorityPda },
  newAuthority: { type: 'ed25519', publicKey: adminKp.publicKey },
  role: ROLE_ADMIN,
});
const { instructions, newAuthorityPda } = client.finalizeAddAuthority(prepared, webauthnResponse);

// Remove authority
const { instructions } = await client.removeAuthority({
  payer, walletPda, adminSigner: ed25519(adminKp.publicKey), targetAuthorityPda,
});

// Transfer ownership (passkey — prepare/finalize)
const prepared = await client.prepareTransferOwnership({
  payer, walletPda,
  secp256r1: { credentialIdHash, publicKeyBytes, authorityPda },
  newOwner: { type: 'secp256r1', credentialIdHash: newCredHash, compressedPubkey: newPubkey, rpId },
});
const { instructions } = client.finalizeTransferOwnership(prepared, webauthnResponse);

// Create session (Ed25519 admin — no prepare/finalize needed)
const { instructions, sessionPda } = await client.createSession({
  payer, walletPda, adminSigner: ed25519(ownerKp.publicKey),
  sessionKey: sessionKp.publicKey, expiresAt: currentSlot + 9000n,
  actions: [  // optional �� omit for unrestricted session
    { type: 'SolMaxPerTx', max: 1_000_000_000n },
    { type: 'SolLimit', remaining: 10_000_000_000n },
    { type: 'ProgramWhitelist', programId: SystemProgram.programId },
  ],
});

// Revoke session
const { instructions } = await client.revokeSession({
  payer, walletPda, adminSigner: ed25519(ownerKp.publicKey), sessionPda,
});

// Deferred execution — TX1 (passkey — prepare/finalize)
const prepared = await client.prepareAuthorize({
  payer, walletPda,
  secp256r1: { credentialIdHash, publicKeyBytes, authorityPda },
  instructions: [jupiterSwapIx], expiryOffset: 300,
});
const { instructions, deferredPayload } = client.finalizeAuthorize(prepared, webauthnResponse);

// Deferred execution — TX2 (permissionless — any payer can submit)
const { instructions } = await client.executeDeferredFromPayload({
  payer, deferredPayload,
});

// Reclaim expired deferred
const { instructions } = client.reclaimDeferred({ payer, deferredExecPda });
```

---

## Internal: Protocol Fee Management (Admin Only)

> The following section is for LazorKit admin operations only. Integrators do not need this.

#### Protocol Fee Management

```typescript
// Initialize protocol (one-time)
const { instructions, protocolConfigPda } = client.initializeProtocol({
  payer, admin, treasury, creationFee: 5000n, executionFee: 2000n, numShards: 16,
});

// Initialize treasury shards (call per shard)
const { instructions } = client.initializeTreasuryShard({ payer, admin, shardId: 0 });

// Register a payer for fee tracking
const { instructions, feeRecordPda } = client.registerPayer({
  payer, admin, targetPayer: integratorPayerKey,
});

// Update protocol config
const { instructions } = client.updateProtocol({
  admin, creationFee: 10000n, executionFee: 5000n, enabled: true, newTreasury,
});

// Withdraw fees from a shard
const { instructions } = client.withdrawTreasury({ admin, shardId: 0, treasury });
```

#### Protocol Fee Auto-Detection

The SDK automatically detects protocol fees. No action needed from integrators.

```typescript
// Manually check (for debugging)
const protocolFee = await client.resolveProtocolFee(payer.publicKey);
// Returns: { protocolConfigPda, feeRecordPda, treasuryShardPda } or undefined

// ProtocolConfig is cached after first fetch
client.invalidateProtocolCache(); // Clear cache after UpdateProtocol
```

### Constants

```typescript
// Instruction discriminators
DISC_CREATE_WALLET        // 0
DISC_ADD_AUTHORITY        // 1
DISC_REMOVE_AUTHORITY     // 2
DISC_TRANSFER_OWNERSHIP   // 3
DISC_EXECUTE              // 4
DISC_CREATE_SESSION       // 5
DISC_AUTHORIZE            // 6
DISC_EXECUTE_DEFERRED     // 7
DISC_RECLAIM_DEFERRED     // 8
DISC_REVOKE_SESSION       // 9
DISC_INITIALIZE_PROTOCOL  // 10
DISC_UPDATE_PROTOCOL      // 11
DISC_REGISTER_PAYER       // 12
DISC_WITHDRAW_TREASURY    // 13
DISC_INITIALIZE_TREASURY_SHARD // 14

// Auth types
AUTH_TYPE_ED25519     // 0
AUTH_TYPE_SECP256R1   // 1

// Roles
ROLE_OWNER   // 0
ROLE_ADMIN   // 1
ROLE_SPENDER // 2
```

## WebAuthn Signing Modes

LazorKit supports two secp256r1 (passkey) signing modes to handle both real browser authenticators and programmatic/bot signing.

### Mode 1: Raw clientDataJSON (default — recommended)

For **real users** with browser authenticators (Chrome, Safari, Android, security keys). The authenticator produces `clientDataJSON` with varying formats across browsers (different field order, extra fields like `androidPackageName`, missing `crossOrigin` on Safari). Mode 1 sends the raw bytes to the on-chain program, which validates only the `challenge` and `type` fields, then hashes the raw bytes as-is.

**This is the default mode.** All `prepare*/finalize*` methods use Mode 1 automatically.

```typescript
// Recommended: Client-level prepare/finalize
const prepared = await client.prepareExecute({
  payer: payer.publicKey,
  walletPda,
  secp256r1: { credentialIdHash, publicKeyBytes, authorityPda },
  instructions: [transferIx],
});

// Browser authenticator signs the challenge
const credential = await navigator.credentials.get({
  publicKey: { challenge: prepared.challenge, rpId: 'your-app.com', allowCredentials: [...] },
});
const response = credential.response as AuthenticatorAssertionResponse;

// Build transaction
const { instructions } = client.finalizeExecute(prepared, {
  signature: normalizeToLowS(response.signature),
  authenticatorData: new Uint8Array(response.authenticatorData),
  clientDataJsonHash: await sha256(response.clientDataJSON),
  clientDataJson: new Uint8Array(response.clientDataJSON),
});
```

### Mode 0: Reconstructed clientDataJSON

For **programmatic/bot signing** where you control the signing environment. The SDK generates `authenticatorData` and `clientDataJSON` is reconstructed on-chain from flags. Only works when the SDK controls the exact JSON format.

```typescript
// Only for programmatic signing — requires a Secp256r1Signer callback
import { secp256r1 } from '@lazorkit/sdk-legacy';

const signer = secp256r1(myProgrammaticSigner, { rawMode: false });
const { instructions } = await client.execute({ payer, walletPda, signer, instructions: [...] });
```

### Low-Level Signing API

For custom instruction builders that need direct control over auth payloads:

```typescript
import { prepareSecp256r1, finalizeSecp256r1 } from '@lazorkit/sdk-legacy';

const prepared = prepareSecp256r1({
  discriminator, signedPayload, sysvarIxIndex,
  slot, counter, payer: payer.publicKey, programId: PROGRAM_ID,
  publicKeyBytes: compressedPubkey,
});
// ... authenticator signs prepared.challenge ...
const { authPayload, precompileIx } = finalizeSecp256r1(prepared, webauthnResponse);
```

### Implementing a browser WebAuthn helper

Convert the raw browser authenticator response to a `WebAuthnResponse`:

```typescript
import type { WebAuthnResponse } from '@lazorkit/sdk-legacy';

async function getWebAuthnResponse(challenge: Uint8Array, rpId: string, credentialId: BufferSource): Promise<WebAuthnResponse> {
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId,
      allowCredentials: [{ type: 'public-key', id: credentialId }],
    },
  });
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    signature: normalizeToLowS(response.signature),  // DER -> raw r||s, low-S
    authenticatorData: new Uint8Array(response.authenticatorData),
    clientDataJsonHash: new Uint8Array(await crypto.subtle.digest('SHA-256', response.clientDataJSON)),
    clientDataJson: new Uint8Array(response.clientDataJSON),
  };
}

// Usage with prepare/finalize:
const prepared = await client.prepareExecute({ payer, walletPda, secp256r1: { ... }, instructions: [...] });
const webauthnResponse = await getWebAuthnResponse(prepared.challenge, 'your-app.com', credentialId);
const { instructions } = client.finalizeExecute(prepared, webauthnResponse);
```

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 3001 | InvalidAuthorityPayload | Malformed auth payload |
| 3002 | PermissionDenied | Insufficient role permissions |
| 3005 | InvalidMessageHash | Challenge hash mismatch |
| 3006 | SignatureReused | Counter mismatch (replay attempt) |
| 3007 | InvalidSignatureAge | Slot too old (>150 slots) |
| 3008 | InvalidSessionDuration | Session expiry out of range |
| 3009 | SessionExpired | Session past expires_at slot |
| 3013 | SelfReentrancyNotAllowed | CPI back into program rejected |
| 3014 | DeferredAuthorizationExpired | DeferredExec expired |
| 3015 | DeferredHashMismatch | Instructions/accounts hash mismatch |
| 3016 | InvalidExpiryWindow | Expiry offset out of range (10-9000) |
| 4001 | ProtocolAlreadyInitialized | Config already exists |
| 4002 | InvalidProtocolAdmin | Admin key mismatch |
| 4006 | IntegratorAlreadyRegistered | Payer already registered |
| 4007 | InvalidTreasury | Treasury address mismatch |

### Generated Accounts

```typescript
import {
  WalletAccount, AuthorityAccount, SessionAccount,
  ProtocolConfigAccount, FeeRecordAccount, TreasuryShardAccount,
} from '@lazorkit/sdk-legacy';

const authority = await AuthorityAccount.fromAccountAddress(connection, authorityPda);
const config = await ProtocolConfigAccount.fromAccountAddress(connection, configPda);
const feeRecord = await FeeRecordAccount.fromAccountAddress(connection, feeRecordPda);
```

## SDK Regeneration

After modifying program instructions:

```bash
# 1. Regenerate IDL
cd program && shank idl -o . --out-filename idl.json -p 4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS

# 2. Regenerate SDK
cd sdk/sdk-legacy && node generate.mjs
```

## License

MIT
