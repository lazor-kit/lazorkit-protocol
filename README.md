# LazorKit Protocol

A revenue-enabled fork of [LazorKit Smart Wallet](https://github.com/nicola-onspeedhp/wallet-management-contract) with protocol fees, integrator reward tracking, and sharded treasury. Built for B2B — integrators earn token rewards proportional to the fees their users generate.

> **Base**: LazorKit V2 (audited by Accretion, Solana Foundation funded, 17/17 issues resolved)
> **This fork adds**: Protocol fee system, sharded treasury, payer tracking, wallet lookup by credential

---

## What's Different from Open-Source LazorKit

| | Open-Source LazorKit | LazorKit Protocol (this repo) |
|---|---|---|
| Program ID | `FLb7...7ao` | Deployed by LazorKit team |
| Protocol fees | None | Optional, per-instruction |
| Integrator rewards | None | FeeRecord per payer, token distribution ready |
| Treasury | None | Sharded (16-32 PDAs), zero contention |
| Wallet lookup | Requires stored `walletPda` | `findWalletsByAuthority(credentialIdHash)` |
| Instructions | 10 | 15 (+5 protocol management) |
| Account types | 4 | 7 (+ProtocolConfig, FeeRecord, TreasuryShard) |

**All original security properties are preserved.** The 10 original instruction processors are untouched — fee collection happens at the entrypoint level before dispatch.

---

## Protocol Fee System

### How It Works

1. **Admin** initializes protocol config + treasury shards (one-time setup)
2. **Admin** registers integrator payer keys (`RegisterPayer`)
3. **Integrators** use the SDK normally — fee detection is automatic
4. On fee-eligible instructions (CreateWallet, Execute, ExecuteDeferred):
   - SDK checks if payer has a FeeRecord (cached, 1 RPC call)
   - If yes: appends protocol accounts, fee goes to random treasury shard
   - If no: works exactly like open-source LazorKit (zero overhead)
5. **Admin** withdraws from shards to treasury whenever needed

### Sharded Treasury

Fees distribute across N treasury shard PDAs (e.g. 16), selected randomly by the SDK. Different transactions hit different shards — **zero write contention**, preserving LazorKit's parallel execution advantage.

### Integrator Token Rewards

FeeRecord tracks cumulative `total_fees_paid` per payer. To distribute token rewards:
1. Snapshot all FeeRecord accounts (`getProgramAccounts` with discriminator filter)
2. Calculate proportional share per integrator
3. Distribute via merkle airdrop

---

## Architecture

### Account Types

| Account | Seeds | Disc | Size | Description |
|---|---|---|---|---|
| Wallet PDA | `["wallet", user_seed]` | 1 | 8 | Identity anchor |
| Authority PDA | `["authority", wallet, id_hash]` | 2 | 48+ | Per-key auth with role + counter |
| Session PDA | `["session", wallet, session_key]` | 3 | 80 | Ephemeral sub-key with expiry |
| DeferredExec PDA | `["deferred", wallet, authority, counter]` | 4 | 176 | Temporary pre-authorized execution |
| ProtocolConfig PDA | `["protocol_config"]` | 5 | 88 | Fee config, admin, treasury, num_shards |
| FeeRecord PDA | `["fee_record", payer_pubkey]` | 6 | 32 | Per-payer fee tracking |
| TreasuryShard PDA | `["treasury_shard", shard_id]` | 7 | 8 | Fee accumulation shard |

### Instructions

| Disc | Instruction | Description |
|------|-----------|-------------|
| 0 | CreateWallet | Create wallet + vault + authority (fee-eligible) |
| 1 | AddAuthority | Add Ed25519/Secp256r1 authority |
| 2 | RemoveAuthority | Remove authority, refund rent |
| 3 | TransferOwnership | Atomic owner swap |
| 4 | Execute | Execute instructions via CPI (fee-eligible) |
| 5 | CreateSession | Create ephemeral session key |
| 6 | Authorize | Deferred execution TX1 |
| 7 | ExecuteDeferred | Deferred execution TX2 (fee-eligible) |
| 8 | ReclaimDeferred | Reclaim expired deferred auth |
| 9 | RevokeSession | Early session revocation |
| **10** | **InitializeProtocol** | One-time protocol config setup |
| **11** | **UpdateProtocol** | Update fees/treasury/enabled |
| **12** | **RegisterPayer** | Register payer for fee tracking |
| **13** | **WithdrawTreasury** | Sweep fees from shard to treasury |
| **14** | **InitializeTreasuryShard** | Create a treasury shard PDA |

See [docs/ProtocolFee.md](docs/ProtocolFee.md) for detailed protocol fee architecture.
See [docs/Architecture.md](docs/Architecture.md) for full wallet architecture reference.

---

## Quick Start

### Protocol Setup (LazorKit Admin — One-Time)

```typescript
import { LazorKitClient } from '@lazorkit/solita-client';

const client = new LazorKitClient(connection);

// 1. Initialize protocol
const { instructions } = client.initializeProtocol({
  payer, admin, treasury,
  creationFee: 5000n,   // lamports per CreateWallet
  executionFee: 2000n,  // lamports per Execute
  numShards: 16,
});

// 2. Initialize treasury shards
for (let i = 0; i < 16; i++) {
  const { instructions } = client.initializeTreasuryShard({ payer, admin, shardId: i });
}

// 3. Register integrator payer keys
const { instructions } = client.registerPayer({ payer, admin, targetPayer: integratorPayerKey });
```

### Integrator Usage (Zero Config)

Integrators use the LazorKit Protocol program directly — no deployment needed. Once LazorKit admin registers your payer key, fees are auto-collected and your FeeRecord tracks rewards.

```typescript
import { LazorKitClient, secp256r1 } from '@lazorkit/solita-client';

const client = new LazorKitClient(connection);

// Create wallet — fee auto-detected if your payer is registered
const { instructions, walletPda } = await client.createWallet({
  payer: payer.publicKey,
  userSeed: crypto.randomBytes(32),
  owner: { type: 'secp256r1', credentialIdHash, compressedPubkey, rpId: 'app.com' },
});

// User comes back later — find wallet by credential only
const [wallet] = await client.findWalletsByAuthority(credentialIdHash);
// Returns: { walletPda, authorityPda, vaultPda, role, authorityType }

// Execute — fee auto-detected, shard randomly selected
const { instructions } = await client.execute({
  payer: payer.publicKey,
  walletPda: wallet.walletPda,
  signer: secp256r1(mySigner),
  instructions: [SystemProgram.transfer({ fromPubkey: vault, toPubkey: recipient, lamports: 1_000_000 })],
});
```

### Revenue Collection (Admin)

```typescript
for (let i = 0; i < 16; i++) {
  const { instructions } = client.withdrawTreasury({ admin, shardId: i, treasury });
}
```

---

## Cost Overview

### Base Wallet Costs (Same as Open-Source)

| Auth Type | Wallet Creation | Execute (per tx) |
|---|---|---|
| Ed25519 | 0.002399 SOL | 0.000005 SOL |
| Secp256r1 (Passkey) | 0.002713 SOL | 0.000005 SOL |
| Session Key | -- | 0.000005 SOL |

### Protocol Fee Overhead (When Opted In)

| Item | Cost |
|---|---|
| Protocol fee (CreateWallet) | Configurable (e.g. 5,000 lamports) |
| Protocol fee (Execute) | Configurable (e.g. 2,000 lamports) |
| Extra accounts per TX | +4 (config, fee_record, shard, system_program) |
| Extra CU per TX | ~3,000 |
| FeeRecord rent (one-time per payer) | ~0.0009 SOL |
| TreasuryShard rent (one-time per shard) | ~0.0009 SOL |
| ProtocolConfig rent (one-time) | ~0.0016 SOL |

---

## Project Structure

```
program/src/              Rust smart contract (pinocchio, zero-copy)
  auth/                   Ed25519 + Secp256r1/WebAuthn authentication
  processor/              14 instruction handlers (9 original + 5 protocol)
  state/                  7 account data structures (4 original + 3 protocol)
sdk/solita-client/        TypeScript SDK
  src/generated/          Auto-generated (Solita) instructions, accounts, errors
  src/utils/              Instruction builders, PDA helpers, signing, wallet lookup
tests-sdk/                Integration tests (vitest, 70 tests)
docs/                     Architecture, cost analysis, protocol fee docs
```

---

## Testing

```bash
# Start local validator
cd tests-sdk && npm run validator:start

# Run all 70 tests
npm test
```

12 test suites covering: wallet lifecycle, authority management, execute, deferred execution, sessions, replay protection, counter edge cases, E2E workflows, permission boundaries, session execution, security vectors, and protocol fees.

---

## Security

Based on LazorKit V2, audited by **Accretion** (Solana Foundation funded). 17/17 issues resolved.

Protocol fee additions preserve all original security:
- **Zero changes** to existing processors, auth, or signing logic
- Fee collection at entrypoint level — atomic with processor execution
- Checked arithmetic on all counter updates
- Admin-gated: only protocol admin can register payers, withdraw, update config
- Sharded treasury eliminates single write-lock contention

Report vulnerabilities via [SECURITY.md](SECURITY.md).

---

## Documentation

| Document | Description |
|---|---|
| [Protocol Fee](docs/ProtocolFee.md) | Protocol fee architecture, sharding, reward distribution |
| [Architecture](docs/Architecture.md) | Wallet account structures, security mechanisms |
| [Costs](docs/Costs.md) | CU benchmarks, rent costs, transaction sizes |
| [SDK API](sdk/solita-client/README.md) | TypeScript SDK reference |
| [Development](DEVELOPMENT.md) | Build, test, deploy workflow |
| [Changelog](CHANGELOG.md) | Version history |

---

## License

[MIT](LICENSE)
