# Reference: v1 → v2 migration UI (React)

A drop-in skeleton for the one action an existing user takes after the v2
in-place upgrade: move their wallet's assets from v1 to v2. Everything here is
client-side and **authorized by the user's own key** — no operator moves funds.

- `useV1Migration.ts` — detect → enumerate → run the user-signed migration.
- `MigrateWalletCard.tsx` — presentational card (renders nothing unless a v1 wallet exists).
- `webauthn.ts` — browser passkey assertion → the byte shape the SDK expects.

Built on `@lazorkit/sdk-legacy` (`migrateV1Wallet`, `deriveV1Accounts`,
`readV1WalletState`, `enumerateV1VaultTokens`). Restyle the card freely.

## What it does

After the upgrade a v1 wallet's normal operations revert (v2 rejects the old
account discriminators), but the funds sit safe in the v1 vault. This flow makes
the single migration that:

1. creates the user's v2 wallet + destination token accounts (payer signs),
2. runs `MigrateWallet` — the user's key authorizes sweeping **all** SOL and
   tokens (SPL + Token-2022) to their v2 vault and closing the v1 PDAs.

Same passkey, same wallet identity — just moved to v2 addresses. One-time.

## Wiring it up

You provide four things: a `LazorKitClient`, the `payer`, the user's
`userSeed` + `owner` descriptor, and a `sendTransaction` that signs and sends
(this is where a relayer/sponsor co-signs).

### Passkey (secp256r1) — the common case

```tsx
import { Connection } from '@solana/web3.js';
import { LazorKitClient, PROGRAM_ID_MAINNET } from '@lazorkit/sdk-legacy';
import { MigrateWalletCard } from './examples/react-migration/MigrateWalletCard';

const client = new LazorKitClient(new Connection(RPC_URL), PROGRAM_ID_MAINNET);

<MigrateWalletCard
  client={client}
  payer={sponsor.publicKey}
  userSeed={user.userSeed}
  owner={{
    type: 'secp256r1',
    credentialIdHash: user.credentialIdHash,
    compressedPubkey: user.passkeyPubkey,
    rpId: 'your-rp-id.app',
  }}
  assertionOptions={{ rpId: 'your-rp-id.app', allowCredentialIds: [user.credentialId] }}
  sendTransaction={(ixs) => sponsor.signAndSend(ixs)}
/>;
```

### Ed25519 owner

```tsx
<MigrateWalletCard
  client={client}
  payer={sponsor.publicKey}
  userSeed={user.userSeed}
  owner={{ type: 'ed25519', publicKey: ownerKeypair.publicKey }}
  ed25519Signer={ownerKeypair}
  sendTransaction={(ixs, signers = []) => sponsor.signAndSend(ixs, signers)}
/>;
```

`sendTransaction(instructions, extraSigners?)` must add `payer` as fee payer,
add a recent blockhash, sign with the payer **and** any `extraSigners`, send,
and return the confirmed signature.

## Notes

- **The payer funds** the v2 wallet + ATA rent and **receives** the reclaimed v1
  rent. In a sponsored model the app's payer covers this and the user pays nothing.
- **All tokens must move.** `enumerateV1VaultTokens` returns every SPL and
  Token-2022 account the vault holds; any omitted is stranded when the wallet
  closes. The hook passes them all — do not filter the list.
- **Large vaults:** `plan.setupInstructions` scales with token count. For a vault
  with many token accounts, split it across transactions; the migrate itself is
  one instruction regardless.
- **Precondition for the rollout:** this UI must be live and tested **before** the
  mainnet upgrade, so a frozen v1 user can migrate the moment they open the app.
