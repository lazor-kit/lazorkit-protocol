# Admin Guide — Protocol Fee System

> **Internal document.** This covers protocol management operations that only the LazorKit admin team performs.

## Overview

LazorKit's protocol fee system enables revenue collection and payer reward tracking for B2B integrators. It's **fully optional** — if a payer has no FeeRecord, no fee is collected.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌───────────────────┐
│   Payer      │────▶│  Entrypoint      │────▶│  Processor        │
│  (fee src)   │     │  (fee collection)│     │  (unchanged)      │
└─────────────┘     └───────┬──────────┘     └───────────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │ Shard 0  │ │ Shard 1  │ │ Shard N  │  ← fee goes here (random)
        └──────────┘ └──────────┘ └──────────┘
              │             │             │
              └──────┬──────┘─────────────┘
                     ▼
              ┌──────────────┐
              │   Treasury   │  ← admin withdraws
              └──────────────┘

        ┌──────────────┐
        │  FeeRecord   │  ← tracks cumulative fees (no SOL, just counters)
        │  per payer   │
        └──────────────┘
```

## How It Works

1. **Admin registers a payer** via `RegisterPayer` — creates FeeRecord PDA keyed by payer pubkey
2. **SDK auto-detects**: before building a TX, checks if payer has a FeeRecord
   - If yes → appends `[protocol_config, fee_record, treasury_shard, system_program]` to accounts
   - If no → proceeds normally (no fee)
3. **Entrypoint detects** the 4 trailing accounts, collects fee to a random treasury shard
4. **Admin withdraws** from shards to treasury via `WithdrawTreasury`

## Account Structures

### ProtocolConfig PDA `["protocol_config"]` — 88 bytes, disc: 5

| Field | Type | Offset | Description |
|-------|------|--------|-------------|
| discriminator | u8 | 0 | `5` |
| version | u8 | 1 | Account version |
| bump | u8 | 2 | PDA bump |
| enabled | u8 | 3 | 0=disabled, 1=enabled |
| num_shards | u8 | 4 | Number of treasury shards (e.g. 16) |
| _padding | [u8; 3] | 5 | Alignment |
| admin | Pubkey | 8 | Protocol admin |
| treasury | Pubkey | 40 | Withdrawal destination |
| creation_fee | u64 | 72 | Lamports per CreateWallet |
| execution_fee | u64 | 80 | Lamports per Execute/ExecuteDeferred |

### FeeRecord PDA `["fee_record", payer_pubkey]` — 32 bytes, disc: 6

| Field | Type | Offset | Description |
|-------|------|--------|-------------|
| discriminator | u8 | 0 | `6` |
| bump | u8 | 1 | PDA bump |
| version | u8 | 2 | Account version |
| _padding | [u8; 5] | 3 | Alignment |
| total_fees_paid | u64 | 8 | Cumulative fees (for token rewards) |
| tx_count | u32 | 16 | Fee-eligible transactions |
| wallet_count | u32 | 20 | Wallets created |
| registered_at | u64 | 24 | Registration slot |

### TreasuryShard PDA `["treasury_shard", shard_id(u8)]` — 8 bytes, disc: 7

| Field | Type | Offset | Description |
|-------|------|--------|-------------|
| discriminator | u8 | 0 | `7` |
| bump | u8 | 1 | PDA bump |
| shard_id | u8 | 2 | Shard index |
| _padding | [u8; 5] | 3 | Alignment |

## Instructions

| Disc | Instruction | Description |
|------|-----------|-------------|
| 10 | InitializeProtocol | One-time config setup |
| 11 | UpdateProtocol | Update fees/treasury/enabled |
| 12 | RegisterPayer | Register a payer for fee tracking |
| 13 | WithdrawTreasury | Sweep SOL from a shard to treasury |
| 14 | InitializeTreasuryShard | Create a treasury shard PDA |

## Fee Collection (Entrypoint)

For **CreateWallet** (disc 0), **Execute** (disc 4), **ExecuteDeferred** (disc 7):

1. SDK checks if payer has a FeeRecord (RPC call)
2. If yes, appends 4 accounts: `[protocol_config, fee_record, treasury_shard(random), system_program]`
3. Entrypoint detects last 4 accounts by discriminator
4. System Transfer: payer → treasury_shard
5. Update FeeRecord counters (wallet_count or tx_count, total_fees_paid)
6. Strip 4 accounts, pass rest to processor

## Sharded Treasury

Fees go to **N treasury shards** (e.g. 16), selected randomly by the SDK. This eliminates write contention — different transactions hit different shards.

Admin withdraws from each shard individually via `WithdrawTreasury`.

## SDK Usage

```typescript
const client = new LazorKitClient(connection);

// ── Admin setup (one-time) ──────────────────────────────────────────
client.initializeProtocol({ payer, admin, treasury, creationFee: 5000n, executionFee: 2000n, numShards: 16 });
for (let i = 0; i < 16; i++) client.initializeTreasuryShard({ payer, admin, shardId: i });
client.registerPayer({ payer, admin, targetPayer: integratorPayerKey });

// ── Integrator usage (zero config) ─────────────────────────────────
// SDK auto-detects everything: fetches ProtocolConfig (cached),
// checks if payer has a FeeRecord, picks a random shard.
// No extra params needed.

const { instructions } = await client.createWallet({ payer, userSeed, owner });
const { instructions } = await client.execute({ payer, walletPda, signer, instructions: [...] });

// If payer is NOT registered → no fee, works exactly as before.
// If payer IS registered → fee auto-collected to random shard.

// ── Admin revenue collection ────────────────────────────────────────
for (let i = 0; i < 16; i++) client.withdrawTreasury({ admin, shardId: i, treasury });
```

## Token Reward Distribution

FeeRecord stores `total_fees_paid` per payer. To distribute token rewards:

1. Snapshot all FeeRecord accounts (use `getProgramAccounts` with discriminator filter)
2. Calculate proportional share: `payer_share = total_fees_paid / sum_all_fees`
3. Distribute via merkle airdrop or direct transfer
