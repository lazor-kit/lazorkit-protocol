# LazorKit v2 — wire-format reference for direct integrators

For teams that build LazorKit instructions themselves rather than through the
SDK. It gives you exactly what you need to map your account infrastructure onto
v2: the PDA derivations, the account discriminators and layouts, the instruction
set, and the two things that most often bite a hand-written client — the fee
suffix and the Secp256r1 challenge. Full struct layouts live in
[Architecture.md](Architecture.md); the machine-readable instruction list is
`program/idl.json`.

> **Test against staging first.** A v2 build is live on **devnet** at program id
> `HQ584adp8ub2FzrTx1fdNmXmrL5yuyVndafPB3x4NYG3` (throwaway slot, ProtocolConfig
> initialised, fees 5000/5000, 16 treasury shards). Point your direct client at
> it and reproduce this document before the mainnet swap. Mainnet keeps the
> vanity id `LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi`; the upgrade is
> in-place.

## 1. What changed from v1 (map this first)

| | v1 (deployed today) | v2 |
|---|---|---|
| PDA seeds | bare: `wallet`, `vault`, `authority`, … | prefixed `lk2:` — `lk2:wallet`, `lk2:vault`, … |
| Account discriminators | 1–7 (`0x0N`) | `0x21`–`0x27` (high nibble = protocol version 2) |
| Authority permission | one `role` field | `role` = **rank** (manage) + a **policy** buffer (spend); a Delegate must carry a policy |
| Wallet account | — | gains `owner_count: u32` (multi-owner) |
| Execute accounts hash | keys only | binds one **signer/writable flags byte** per account (see §5) |
| Fee | opt-in | **4-account suffix required** on disc 0/4/7 (see §4) |
| Migration | — | `MigrateWallet` (disc 17) bridges a v1 wallet to v2 |

Because both the seeds and the discriminators change, every PDA your v1 client
derives resolves to a different address on v2, and your existing v1 accounts are
rejected by v2's normal paths until migrated. Re-derive everything with the
`lk2:` seeds; move existing wallets with `MigrateWallet` (§7).

## 2. PDA derivation

All PDAs are `findProgramAddress(seeds, PROGRAM_ID)`. Seeds (a literal prefix
string, then the dynamic parts):

| Account | Seeds |
|---|---|
| Wallet | `["lk2:wallet", user_seed(32)]` |
| Vault | `["lk2:vault", wallet_pubkey]` |
| Authority | `["lk2:authority", wallet_pubkey, id_hash(32)]` |
| Session | `["lk2:session", wallet_pubkey, session_key(32)]` |
| DeferredExec | `["lk2:deferred", wallet_pubkey, authority_pubkey, counter(4 LE)]` |
| ProtocolConfig | `["lk2:protocol_config"]` |
| TreasuryShard | `["lk2:treasury_shard", shard_id(1)]` |
| FeeRecord | `["lk2:fee_record", payer_pubkey]` |

`id_hash` is the SHA-256 of the passkey credential id for a Secp256r1 authority,
or the 32-byte Ed25519 public key for an Ed25519 authority.

## 3. Account discriminators & layouts

Byte 0 of every account is its discriminator. Full `#[repr(C)]` structs are in
[Architecture.md § Account layouts](Architecture.md); the fields a direct client
reads most:

```
Wallet         0x21  disc(1) bump(1) version(1) _pad(1) owner_count(u32)             = 8
Authority      0x22  disc(1) type(1) role(1) bump(1) version(1) _pad(3)
                     counter(u32) policy_len(u16) _pad(2) wallet(32)                 = 48 header
                       + Ed25519:  pubkey(32)                                        -> 80  (+policy)
                       + Secp256r1: cred_id_hash(32) compressed_pubkey(33) rpIdHash(32) -> 145 (+policy)
Session        0x23  header(80) + optional actions buffer (len>80 => actions present)
DeferredExec   0x24
ProtocolConfig 0x25  disc(1) version(1) bump(1) enabled(u8) num_shards(u8) _pad(3)
                     admin(32) treasury(32) creation_fee(u64) execution_fee(u64) …
FeeRecord      0x26  disc(1) bump(1) version(1) _pad(5) total_fees_paid(u64) … tx_count(u32) wallet_count(u32)
TreasuryShard  0x27
```

`type`: 0 = Ed25519, 1 = Secp256r1. `role` (rank): 0 = Owner, 1 = Admin, 2 =
Delegate. `policy_len`: bytes of spend policy after the key material; `0` =
unbounded.

## 4. Instruction set

Discriminator is byte 0 of the instruction data. Full account lists + data
fields are in `program/idl.json`.

```
0  CreateWallet        4  Execute            8  ReclaimDeferred    12 RegisterIntegrator   16 AcceptAdminRotation
1  AddAuthority         5  CreateSession      9  RevokeSession      13 WithdrawTreasury     17 MigrateWallet
2  RemoveAuthority      6  Authorize         10  InitializeProtocol 14 InitializeTreasuryShard
3  TransferOwnership    7  ExecuteDeferred   11  UpdateProtocol     15 ProposeAdminRotation
```

**Fee suffix (disc 0, 4, 7).** These three instructions require a trailing
4-account suffix, in this order, appended after the instruction's own accounts:

```
[ ProtocolConfig, FeeRecord(["lk2:fee_record", payer]), TreasuryShard(shard_id), SystemProgram ]
```

Pick the shard the same way the program does (see `entrypoint.rs`); if you have
never paid a fee from this payer, its FeeRecord is created inline on first use.
Omitting the suffix returns `FeeAccountsRequired` (custom error 4008). All other
discriminators — including `MigrateWallet` — take no suffix.

## 5. Secp256r1 (passkey) authentication

The passkey signs a challenge your client computes; the program recomputes it
from the on-chain accounts and rejects any mismatch with `InvalidMessageHash`
(custom error 3005). Get this byte-exact:

```
challenge = SHA256(
    discriminator(1)        // the instruction's disc byte
  ‖ auth_payload[..14]      // slot(8 LE) ‖ counter(4 LE) ‖ sysvar_ix_index(1) ‖ flags(1)
  ‖ signed_payload          // per-instruction, see below
  ‖ payer(32)               // accounts[0]
  ‖ counter(4 LE)           // the authority odometer value being consumed (stored+1)
  ‖ program_id(32)
)
```

Put `base64url(challenge)` (no padding) into `clientDataJSON.challenge`, with
`"type":"webauthn.get"`. Submit a real Secp256r1 precompile instruction
immediately before the LazorKit instruction; the program pins its offsets and
verifies your assertion against it.

`counter` is a program-controlled odometer on the authority account — read
`authority.counter` and submit `counter + 1`; it replaces the WebAuthn hardware
counter. `sysvar_ix_index` is where the Instructions sysvar sits in your account
list. `flags` is 0.

**`signed_payload` per instruction** (the identity the signature commits to):

| disc | signed_payload |
|---|---|
| 4 Execute | `compact_instruction_bytes ‖ accounts_hash` |
| 6 Authorize | `instructions_hash ‖ accounts_hash ‖ expiry_offset(2)` |
| 1 AddAuthority | `new_type(1) ‖ new_role(1) ‖ key_material ‖ policy ‖ payer(32)` |
| 3 TransferOwnership | `new_key_material ‖ payer(32) ‖ refund_dest(32)` |
| 5 CreateSession | `session_key(32) ‖ expires_at(8) ‖ actions ‖ payer(32)` |
| 9 RevokeSession | `session_pubkey(32) ‖ refund_dest(32)` |
| 17 MigrateWallet | `destination(32) ‖ v1_wallet(32) ‖ num_tokens(1) ‖ refund_dest(32) ‖ source_ata[0..num_tokens]` |

**`accounts_hash`** (used by Execute and Authorize) binds the inner CPI accounts
*with their privileges*:

```
accounts_hash = SHA256( for each compact instruction:
    program_id_key(32) ‖ flags(1)
    then for each referenced account: key(32) ‖ flags(1) )

flags = (is_signer as u8) | ((is_writable as u8) << 1)
```

Use the account's **runtime** signer/writable flags, in the walk order above.
The compact instruction's account-index byte carries an opt-in forward-signer
bit in its high bit (`0x80`); mask it off (`& 0x7f`) before using the index for
this hash, and account for it in your compact encoding (see `compact.rs`).

## 6. Ed25519 authentication

No challenge. The authority's key is a real transaction signer; the runtime's
own signature check binds the whole message (every account and the data). Put
the owner keypair in the signer set for AddAuthority / TransferOwnership /
CreateSession / Execute / RevokeSession / MigrateWallet.

## 7. Migrating an existing v1 wallet

`MigrateWallet` (disc 17) runs at the same program id, so it can sign for the v1
vault's old-seed PDAs. It sweeps the vault's SOL and every token account to a
`destination` the wallet's own key approves, and closes the v1 wallet + authority
(rent to `refund_dest`). It is **Owner-rank only** and takes no fee suffix.

Account order: `payer, v1_wallet, v1_authority, v1_vault, destination,
refund_dest, system_program, instructions_sysvar, auth_signer, then (source_ata,
dest_ata, token_program) triples`. Note the passkey `signed_payload` (§5) binds
the destination, the wallet, the token count **and each source ATA** — so a
relayer cannot redirect the sweep or swap the token set. Enumerate **all** of the
vault's token accounts (SPL Token and Token-2022); any you omit is stranded when
the wallet closes.

A React reference for the migration UX is in
[`examples/react-migration/`](../examples/react-migration).
