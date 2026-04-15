# @lazorkit/solita-client

TypeScript SDK for the LazorKit Protocol smart wallet program on Solana. Built with `@solana/web3.js` v1 and hand-written instruction builders.

Includes protocol fee support (auto-detected), wallet lookup by credential, sharded treasury, and session action permissions (spending limits, program whitelist/blacklist).

## Installation

```bash
npm install @lazorkit/solita-client
```

## Quick Start

```typescript
import { Connection, Keypair, Transaction, sendAndConfirmTransaction } from '@solana/web3.js';
import { LazorKitClient, secp256r1 } from '@lazorkit/solita-client';
import * as crypto from 'crypto';

const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
const client = new LazorKitClient(connection);

// Create a wallet with passkey owner
const { instructions, walletPda } = await client.createWallet({
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

// Execute a SOL transfer
const { instructions: execIxs } = await client.execute({
  payer: payer.publicKey,
  walletPda: wallet.walletPda,
  signer: secp256r1(mySigner),
  instructions: [
    SystemProgram.transfer({ fromPubkey: wallet.vaultPda, toPubkey: recipient, lamports: 1_000_000 }),
  ],
});
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
} from '@lazorkit/solita-client';

const [walletPda] = findWalletPda(userSeed);
const [vaultPda] = findVaultPda(walletPda);
const [authorityPda] = findAuthorityPda(walletPda, credentialIdHash);
const [sessionPda] = findSessionPda(walletPda, sessionKeyBytes);
const [deferredPda] = findDeferredExecPda(walletPda, authorityPda, counter);
const [configPda] = findProtocolConfigPda();
const [feeRecordPda] = findFeeRecordPda(payerPubkey);
const [shardPda] = findTreasuryShardPda(shardId);
```

### Signer Types

```typescript
import { ed25519, secp256r1, session } from '@lazorkit/solita-client';

// Ed25519 — Keypair signs at transaction level
const signer = ed25519(ownerKp.publicKey, authorityPda);  // authorityPda optional

// Secp256r1 — passkey/WebAuthn
const signer = secp256r1(myPasskeySigner, { authorityPda, slotOverride });  // both optional

// Session — ephemeral key
const signer = session(sessionPda, sessionKp.publicKey);
```

### High-Level Client API

Every method returns `{ instructions: TransactionInstruction[]; ...extraPdas }`. The client auto-derives PDAs, auto-fetches slots, auto-reads counters, auto-packs compact instructions, auto-computes hashes, and auto-detects protocol fees.

#### Wallet Operations

```typescript
const client = new LazorKitClient(connection);

// Create wallet
const { instructions, walletPda, vaultPda, authorityPda } = await client.createWallet({
  payer, userSeed,
  owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
});

// Execute arbitrary instructions
const { instructions } = await client.execute({
  payer, walletPda,
  signer: secp256r1(mySigner),
  instructions: [SystemProgram.transfer({ fromPubkey: vault, toPubkey: recipient, lamports: 1_000_000 })],
});

// Transfer SOL (convenience)
const { instructions } = await client.transferSol({
  payer, walletPda, signer: secp256r1(mySigner), recipient, lamports: 1_000_000n,
});

// Add authority
const { instructions, newAuthorityPda } = await client.addAuthority({
  payer, walletPda,
  adminSigner: ed25519(ownerKp.publicKey),
  newAuthority: { type: 'ed25519', publicKey: adminKp.publicKey },
  role: ROLE_ADMIN,
});

// Remove authority
const { instructions } = await client.removeAuthority({
  payer, walletPda, adminSigner: ed25519(adminKp.publicKey), targetAuthorityPda,
});

// Transfer ownership
const { instructions } = await client.transferOwnership({
  payer, walletPda, ownerSigner: secp256r1(ceoSigner),
  newOwner: { type: 'secp256r1', credentialIdHash, compressedPubkey, rpId },
});

// Create session (with optional spending limits / whitelist)
const { instructions, sessionPda } = await client.createSession({
  payer, walletPda, adminSigner: ed25519(ownerKp.publicKey),
  sessionKey: sessionKp.publicKey, expiresAt: currentSlot + 9000n,
  actions: [  // optional — omit for unrestricted session
    { type: 'SolMaxPerTx', max: 1_000_000_000n },
    { type: 'SolLimit', remaining: 10_000_000_000n },
    { type: 'ProgramWhitelist', programId: SystemProgram.programId },
  ],
});

// Revoke session
const { instructions } = await client.revokeSession({
  payer, walletPda, adminSigner: ed25519(ownerKp.publicKey), sessionPda,
});

// Deferred execution — TX1
const { instructions, deferredPayload } = await client.authorize({
  payer, walletPda, signer: secp256r1(mySigner),
  instructions: [jupiterSwapIx], expiryOffset: 300,
});

// Deferred execution — TX2
const { instructions } = await client.executeDeferredFromPayload({
  payer, deferredPayload,
});

// Reclaim expired deferred
const { instructions } = client.reclaimDeferred({ payer, deferredExecPda });
```

#### Protocol Fee Management (Admin Only)

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
} from '@lazorkit/solita-client';

const authority = await AuthorityAccount.fromAccountAddress(connection, authorityPda);
const config = await ProtocolConfigAccount.fromAccountAddress(connection, configPda);
const feeRecord = await FeeRecordAccount.fromAccountAddress(connection, feeRecordPda);
```

## SDK Regeneration

After modifying program instructions:

```bash
# 1. Regenerate IDL
cd program && shank idl -o . --out-filename idl.json -p FLb7fyAtkfA4TSa2uYcAT8QKHd2pkoMHgmqfnXFXo7ao

# 2. Regenerate SDK
cd sdk/solita-client && node generate.mjs
```

## License

MIT
