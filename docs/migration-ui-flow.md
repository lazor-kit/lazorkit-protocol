# Migration UI flow

How an app walks a v1 user through migrating to v2. The SDK
(`@lazorkit/sdk-legacy`) does the orchestration; this is the sequence and the
UX around it. All of it is client-side and user-authorized — no operator ever
moves a user's funds.

After the v2 upgrade lands, a v1 wallet's normal operations revert (v2 rejects
the old account discriminators). The user's funds are safe in the v1 vault, but
they must migrate once before transacting again. This flow makes that one action.

## 1. Detect

On app load, check whether the connected identity still has a v1 wallet.

```ts
import { LazorKitClient, deriveV1Accounts, readV1WalletState } from '@lazorkit/sdk-legacy';

const client = new LazorKitClient(connection); // programId inferred from RPC

// `ownerIdSeed` is the passkey credential-id hash, or the Ed25519 public-key bytes.
const v1 = deriveV1Accounts(userSeed, ownerIdSeed, client.programId);
const state = await readV1WalletState(connection, v1);

if (state) {
  // Show a "Migrate your wallet" banner.
}
```

`state` is `null` when there is nothing to migrate (already migrated, or never a
v1 user). Otherwise it carries the owner's auth type, rank, and the vault's SOL.

## 2. Show what will move

```ts
import { enumerateV1VaultTokens } from '@lazorkit/sdk-legacy';

const tokens = await enumerateV1VaultTokens(connection, v1.vault);
// Render: state.vaultLamports (SOL) + each token's mint + amount.
```

Enumerating here is not cosmetic — every vault-owned token account the migration
omits is stranded when the wallet closes, so the migration must move all of them.
`enumerateV1VaultTokens` returns both SPL Token and Token-2022 accounts.

## 3. Build and send

One call assembles everything: create the v2 wallet if needed, create the
destination token accounts, and the MigrateWallet step.

```ts
const plan = await client.migrateV1Wallet({ payer, userSeed, owner });
```

`plan.setupInstructions` creates the v2 wallet and the destination ATAs — send
these first (payer signs):

```ts
if (plan.setupInstructions.length) {
  await sendAndConfirm(connection, plan.setupInstructions, [payerKeypair]);
}
```

Then the migrate, by auth type:

**Ed25519 owner** — the owner key signs the transaction:

```ts
if (plan.migrate.type === 'ed25519') {
  await sendAndConfirm(connection, [plan.migrate.instruction], [payerKeypair, ownerKeypair]);
}
```

**Secp256r1 passkey** — the passkey signs the challenge; the tx is payer-signed:

```ts
if (plan.migrate.type === 'secp256r1') {
  const assertion = await navigator.credentials.get({
    publicKey: { challenge: plan.migrate.challenge, /* allowCredentials, rpId … */ },
  });
  const response = toWebAuthnResponse(assertion); // authenticatorData, clientDataJSON, signature
  const instructions = plan.migrate.finalize(response); // [precompile, migrate]
  await sendAndConfirm(connection, instructions, [payerKeypair]);
}
```

The passkey approves exactly this migration — its signature binds the v2
destination, the v1 wallet, the token count, and the rent-refund destination — so
a relayer submitting the transaction cannot redirect, replay, or strand anything.

## 4. Confirm

After the migrate confirms:
- SOL and every token are in the user's v2 vault.
- The v1 wallet and authority are closed; their rent went to the payer.
- The user now uses their v2 wallet normally.

Re-run step 1: `readV1WalletState` returns `null`, so the banner disappears.

## Notes for the operator

- **Only an Owner-rank v1 authority may migrate.** `migrateV1Wallet` throws
  otherwise. v1 wallets are single-owner, so this is the wallet's own key.
- **The payer** funds the v2 wallet + ATA rent and receives the reclaimed v1
  rent. In a sponsored/relayer model the app's payer covers this.
- **Transaction size:** the setup step scales with the token count; for a vault
  with many token accounts, split `setupInstructions` across transactions. The
  migrate itself is one instruction regardless.
- **Prioritise the active, high-value wallets** — value is concentrated, so
  reaching a handful of users covers most of it. Dormant wallets migrate whenever
  their owner returns; their funds wait safely in v1 until then.
