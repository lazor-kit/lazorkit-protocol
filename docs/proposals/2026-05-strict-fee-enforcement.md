# Strict Fee Enforcement

Status: implementation branch self-review  
Branch: `feat/strict-fee-enforcement`  
Scope: commercial `lazorkit-protocol` binary

## Summary

The commercial binary must not allow fee-eligible instructions to run without
protocol fee collection and payer accounting. For these discriminators:

- `0` - `CreateWallet`
- `4` - `Execute`
- `7` - `ExecuteDeferred`

the entrypoint must require the trailing fee-account suffix:

```text
[ProtocolConfig, FeeRecord, TreasuryShard, SystemProgram]
```

Every successful fee-eligible instruction must:

1. validate the fee suffix,
2. ensure the payer has a canonical `FeeRecord` PDA,
3. transfer the configured fee from payer to treasury shard,
4. update `FeeRecord.total_fees_paid`,
5. increment `wallet_count` for `CreateWallet` or `tx_count` for `Execute`
   and `ExecuteDeferred`.

There is no silent skip path.

## Mandatory Fee Records

Fee payers must always have a `FeeRecord` PDA derived from:

```text
[b"fee_record", payer]
```

The SDK should make this easy by checking the record account and prepending
`RegisterPayer` when it is missing. The on-chain entrypoint must still handle
custom clients safely: if the canonical record account is system-owned, it is
initialized inline before the fee is recorded. If the supplied record account
is non-canonical, foreign-owned, malformed, or has the wrong discriminator,
the instruction fails.

The record is keyed by the fee payer, not by the wallet owner. For sponsored
transactions this means the paymaster/dev signer gets the `FeeRecord`, and
SDK-created `Execute` / `ExecuteDeferred` transactions must prepend
`RegisterPayer` for that paymaster when the record is missing.

`RegisterPayer` remains public for compatibility and explicit pre-registration,
but successful fee-paying instructions no longer depend on users calling it
manually.

## Error Codes

Existing protocol errors remain unchanged:

| Code | Name |
|---|---|
| `4001` | `ProtocolAlreadyInitialized` |
| `4002` | `InvalidProtocolAdmin` |
| `4003` | `ProtocolDisabled` |
| `4004` | `InvalidIntegratorRecord` |
| `4005` | `InsufficientFeeBalance` |
| `4006` | `IntegratorAlreadyRegistered` |
| `4007` | `InvalidTreasury` |

Strict-fee additions:

| Code | Name | Cause |
|---|---|---|
| `4008` | `FeeAccountsRequired` | Missing fee suffix or trailing account is not System Program |
| `4009` | `ProtocolNotInitialized` | ProtocolConfig missing, non-program-owned, malformed, or wrong discriminator |
| `4010` | `InvalidTreasuryShard` | Treasury shard missing, non-program-owned, malformed, or non-canonical |
| `4011` | `InvalidFeeRecord` | FeeRecord PDA is wrong, foreign-owned, malformed, or wrong discriminator |
| `4012` | `FeeNotConfigured` | Configured creation or execution fee is zero |

## Test Checklist

Local validator tests must prove:

- `CreateWallet`, `Execute`, and `ExecuteDeferred` fail when fee accounts are
  omitted.
- Fake ProtocolConfig fails with `4009`.
- Fake TreasuryShard fails with `4010`.
- Non-canonical FeeRecord fails with `4011`.
- Disabled protocol fails with `4003`.
- Zero fee fails with `4012`.
- SDK first-time payers receive a prepended `RegisterPayer` instruction.
- Low-level/custom clients can still succeed when they pass the canonical
  missing FeeRecord PDA because the entrypoint initializes it inline.
- Every successful fee-paying path increments exact counters and treasury
  balances by the expected fee.

## Audit Checklist

- Review `try_collect_fee` mutation order: validation, optional record
  initialization, fee transfer, counter update.
- Confirm all validation failures happen before fee transfer.
- Confirm every success path updates the fee record.
- Confirm treasury shard validation checks the canonical shard PDA.
- Confirm custom clients cannot bypass fee collection by omitting, reordering,
  or substituting the fee suffix.
- Run Rust tests, SDK builds, local-validator integration tests, and both
  devnet/mainnet SBF builds before requesting audit sign-off.

## Mainnet Deploy Notes

After deploying the commercial binary, the admin must initialize:

1. `ProtocolConfig`
2. every configured `TreasuryShard`

before public traffic. Until that is done, fee-eligible instructions fail
loudly instead of running without fees.
