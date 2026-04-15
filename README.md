# LazorKit Protocol

A high-performance smart wallet on Solana with passkey (WebAuthn/Secp256r1) authentication, role-based access control, and session keys with programmable spending limits. Built with [pinocchio](https://github.com/febo/pinocchio) for zero-copy serialization.

---

## Key Features

- **Passkey Authentication**: WebAuthn/Secp256r1 (Apple Secure Enclave, Touch ID, Windows Hello) + Ed25519
- **Role-Based Access Control**: Owner / Admin / Spender with strict permission hierarchy
- **Session Keys with Actions**: Ephemeral keys with programmable spending limits, per-tx caps, and program whitelist/blacklist
- **Deferred Execution**: 2-tx flow for large payloads (e.g. Jupiter swaps) exceeding the single-tx limit
- **Wallet Lookup**: Find wallets by credential hash — no need to store `walletPda`
- **Parallel Execution**: Different authorities execute concurrently (per-authority PDA, no shared write locks)
- **Odometer Replay Protection**: Monotonic u32 counter per authority (works with synced passkeys)

---

## Quick Start

```typescript
import { Connection, Keypair, Transaction, sendAndConfirmTransaction, SystemProgram } from '@solana/web3.js';
import { LazorKitClient, ed25519, secp256r1, session, ROLE_ADMIN } from '@lazorkit/sdk-legacy';
import * as crypto from 'crypto';

const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
const client = new LazorKitClient(connection);
```

### Create a Wallet

```typescript
const { instructions, walletPda, vaultPda } = client.createWallet({
  payer: payer.publicKey,
  userSeed: crypto.randomBytes(32),
  owner: {
    type: 'secp256r1',
    credentialIdHash,       // 32-byte SHA256 of WebAuthn credential ID
    compressedPubkey,       // 33-byte compressed Secp256r1 public key
    rpId: 'your-app.com',
  },
});
```

### Transfer SOL

```typescript
const { instructions } = await client.transferSol({
  payer: payer.publicKey,
  walletPda,
  signer: secp256r1(mySigner),
  recipient,
  lamports: 1_000_000n,
});
```

### Find Wallet by Credential (Returning Users)

```typescript
const [wallet] = await client.findWalletsByAuthority(credentialIdHash);
// Returns: { walletPda, authorityPda, vaultPda, role, authorityType }
```

---

## Session Keys with Spending Limits

Session keys are ephemeral signers with an expiry and optional **actions** that restrict what they can do. This is the core permission system for delegated access.

### Action Types

| Type | Description | Data |
|---|---|---|
| `SolLimit` | Lifetime SOL spending cap | Decrements on each spend until 0 |
| `SolRecurringLimit` | Per-window SOL cap (e.g. 1 SOL per day) | Resets each window period |
| `SolMaxPerTx` | Max SOL gross outflow per single execute | Prevents large single transfers |
| `TokenLimit` | Lifetime token spending cap (per mint) | Same as SolLimit but for SPL tokens |
| `TokenRecurringLimit` | Per-window token cap (per mint) | Same as SolRecurringLimit for tokens |
| `TokenMaxPerTx` | Max tokens per execute (per mint) | Same as SolMaxPerTx for tokens |
| `ProgramWhitelist` | Only allow CPI to this program (repeatable) | Session can only call listed programs |
| `ProgramBlacklist` | Block CPI to this program (repeatable) | Session cannot call listed programs |

### Create a Restricted Session

```typescript
const { instructions, sessionPda } = await client.createSession({
  payer: payer.publicKey,
  walletPda,
  adminSigner: ed25519(ownerKp.publicKey),
  sessionKey: sessionKp.publicKey,
  expiresAt: currentSlot + 216_000n,  // ~1 day
  actions: [
    // Max 1 SOL per transaction
    { type: 'SolMaxPerTx', max: 1_000_000_000n },
    // 10 SOL lifetime budget
    { type: 'SolLimit', remaining: 10_000_000_000n },
    // Only allow System Program transfers
    { type: 'ProgramWhitelist', programId: SystemProgram.programId },
  ],
});
```

### Create a Token-Limited Session

```typescript
const { instructions, sessionPda } = await client.createSession({
  payer: payer.publicKey,
  walletPda,
  adminSigner: secp256r1(ownerSigner),
  sessionKey: sessionKp.publicKey,
  expiresAt: currentSlot + 432_000n,  // ~2 days
  actions: [
    // 1000 USDC lifetime cap
    { type: 'TokenLimit', mint: USDC_MINT, remaining: 1_000_000_000n },
    // Max 100 USDC per transaction
    { type: 'TokenMaxPerTx', mint: USDC_MINT, max: 100_000_000n },
  ],
});
```

### Unrestricted Session (No Actions)

```typescript
// Omit `actions` for a fully open session — session key can do anything the wallet can
const { instructions, sessionPda } = await client.createSession({
  payer: payer.publicKey,
  walletPda,
  adminSigner: ed25519(ownerKp.publicKey),
  sessionKey: sessionKp.publicKey,
  expiresAt: currentSlot + 9000n,
});
```

### Execute via Session Key

```typescript
const { instructions } = await client.transferSol({
  payer: payer.publicKey,
  walletPda,
  signer: session(sessionPda, sessionKp.publicKey),
  recipient,
  lamports: 500_000_000n,  // 0.5 SOL — within the 1 SOL per-tx limit
});
```

### Expired Action Behavior

- **Expired spending limits** (SolLimit, TokenLimit, etc.) are treated as **fully exhausted** — any spend is rejected
- **Expired whitelist** is a **hard deny** — all programs are blocked
- **Expired blacklist** entries are **silently dropped** — the ban has lifted
- **Unrestricted sessions** (no actions) remain fully open until the session itself expires

---

## Architecture

| Account | Seeds | Size | Description |
|---|---|---|---|
| Wallet PDA | `["wallet", user_seed]` | 8 | Identity anchor |
| Vault PDA | `["vault", wallet]` | 0 | Holds SOL/tokens, program signs via PDA |
| Authority PDA | `["authority", wallet, id_hash]` | 48+ | Per-key auth with role + counter |
| Session PDA | `["session", wallet, session_key]` | 80+ | Ephemeral sub-key with expiry + optional actions |
| DeferredExec PDA | `["deferred", wallet, authority, counter]` | 176 | Temporary pre-authorized execution |

### Instructions

| Disc | Instruction | Description |
|------|-----------|-------------|
| 0 | CreateWallet | Create wallet + vault + authority |
| 1 | AddAuthority | Add Ed25519/Secp256r1 authority |
| 2 | RemoveAuthority | Remove authority, refund rent |
| 3 | TransferOwnership | Atomic owner swap |
| 4 | Execute | Execute instructions via CPI |
| 5 | CreateSession | Create session key (optional spending limits/whitelist) |
| 6 | Authorize | Deferred execution TX1 |
| 7 | ExecuteDeferred | Deferred execution TX2 |
| 8 | ReclaimDeferred | Reclaim expired deferred auth |
| 9 | RevokeSession | Early session revocation |

See [docs/Architecture.md](docs/Architecture.md) for account structures, security mechanisms, and instruction details.

---

## Cost Overview

| Auth Type | Wallet Creation | Execute (per tx) |
|---|---|---|
| Ed25519 | 0.002399 SOL | 0.000005 SOL |
| Secp256r1 (Passkey) | 0.002713 SOL | 0.000005 SOL |
| Session Key | 0.001453 SOL (setup) | 0.000005 SOL |

Session keys are ideal for frequent transactions — they skip the Secp256r1 precompile, resulting in lower CU and smaller transactions. Session rent is refundable after expiry.

See [docs/Costs.md](docs/Costs.md) for full CU benchmarks, rent costs, and deferred execution analysis.

---

## Security

Audited by **Accretion** (Solana Foundation funded) and internally audited pre-mainnet. See [AUDIT.md](AUDIT.md).

Key security properties:
- Odometer counter replay protection (per-authority monotonic u32)
- Clock-based slot freshness (150-slot window)
- CPI reentrancy prevention (stack_height check)
- Expired session actions = hard deny (not unrestricted)
- SolMaxPerTx uses gross outflow tracking (prevents DeFi round-trip bypass)
- Token balance sum-all-accounts (prevents dummy account bypass)

Report vulnerabilities via [SECURITY.md](SECURITY.md).

---

## Documentation

| Document | Description |
|---|---|
| [Architecture](docs/Architecture.md) | Account structures, security mechanisms, instruction reference |
| [Costs](docs/Costs.md) | CU benchmarks, rent costs, transaction sizes |
| [SDK API](sdk/sdk-legacy/README.md) | TypeScript SDK reference (`@lazorkit/sdk-legacy`) |
| [Audit Report](AUDIT.md) | Pre-mainnet security audit findings |
| [Development](DEVELOPMENT.md) | Build, test, deploy workflow |
| [Changelog](CHANGELOG.md) | Version history |

---

## License

[MIT](LICENSE)
