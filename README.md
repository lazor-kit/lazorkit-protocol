# LazorKit Protocol

A high-performance smart wallet on Solana with **passkey (WebAuthn/Secp256r1) authentication**, role-based access control, and session keys with programmable spending limits. Built with [pinocchio](https://github.com/febo/pinocchio) for zero-copy serialization.

- **Passkeys** — Apple Touch ID / Face ID, Windows Hello, Android biometrics, hardware security keys. Real WebAuthn flow with raw `clientDataJSON`.
- **RBAC** — Owner / Admin / Spender with strict role hierarchy.
- **Session keys with policies** — ephemeral signers restricted by per-tx / per-window / lifetime SOL + token caps, and program whitelists.
- **Deferred execution** — 2-tx flow for payloads exceeding a single tx size limit (e.g. Jupiter swaps).
- **Wallet lookup** — find wallets by credential hash; no need to store `walletPda` locally.
- **Parallel execution** — different authorities on the same wallet never block each other.

## Install

```bash
npm install @lazorkit/sdk-legacy
```

Program ID: `4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS` (devnet).

## Quick start

```typescript
import { Connection, SystemProgram } from '@solana/web3.js';
import { LazorKitClient } from '@lazorkit/sdk-legacy';
import * as crypto from 'crypto';

const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
const client = new LazorKitClient(connection);

// Create a wallet owned by a passkey
const { instructions, walletPda, vaultPda, authorityPda } = await client.createWallet({
  payer: payer.publicKey,
  userSeed: crypto.randomBytes(32),
  owner: {
    type: 'secp256r1',
    credentialIdHash,   // SHA-256 of WebAuthn credential ID
    compressedPubkey,   // 33-byte compressed public key
    rpId: 'your-app.com',
  },
});
// ...submit instructions as a regular Solana tx

// Returning user: find their wallet from just the credential hash
const [wallet] = await client.findWalletsByAuthority(credentialIdHash);
```

Passkey-signed SOL transfer (two-phase for async WebAuthn):

```typescript
// Phase 1 — SDK computes the challenge
const prepared = await client.prepareExecute({
  payer: payer.publicKey,
  walletPda: wallet.walletPda,
  secp256r1: { credentialIdHash, authorityPda: wallet.authorityPda },
  instructions: [SystemProgram.transfer({
    fromPubkey: wallet.vaultPda,
    toPubkey: recipient,
    lamports: 1_000_000,
  })],
});

// Phase 2 — browser authenticator signs
const response = await navigator.credentials.get({
  publicKey: { challenge: prepared.challenge, rpId: 'your-app.com', allowCredentials: [...] },
});

// Phase 3 — SDK builds the transaction
const { instructions } = client.finalizeExecute(prepared, toWebAuthnResponse(response));
```

Full SDK reference: [`sdk/sdk-legacy/README.md`](sdk/sdk-legacy/README.md).

## Session keys

Ephemeral signers with an expiry and optional spending policies. Ideal for frequent transactions (gaming, DeFi) that would otherwise require passkey re-auth every time.

```typescript
import { Actions } from '@lazorkit/sdk-legacy';

const { instructions, sessionPda } = await client.createSession({
  payer: payer.publicKey,
  walletPda,
  adminSigner: ed25519(ownerKp.publicKey),
  sessionKey: sessionKp.publicKey,
  expiresAt: currentSlot + 216_000n,  // ~1 day
  actions: [
    Actions.programWhitelist(SystemProgram.programId),
    Actions.solMaxPerTx(1_000_000_000n),       // 1 SOL per tx
    Actions.solLimit(10_000_000_000n),         // 10 SOL lifetime
  ],
});
```

**Action types**: `SolLimit`, `SolRecurringLimit`, `SolMaxPerTx`, `TokenLimit`, `TokenRecurringLimit`, `TokenMaxPerTx`, `ProgramWhitelist`, `ProgramBlacklist`.

**Important scoping notes**:
- Token limits apply **per-mint**. A session with `TokenLimit(USDC)` has unrestricted access to other token mints the vault holds. Enumerate every mint you want bounded, or use `ProgramWhitelist` to restrict which programs the session can call.
- `ProgramWhitelist` checks program IDs but not inner instruction discriminators. LazorKit automatically enforces vault metadata + per-listed-mint token authority invariants to block escape routes (`System::Assign`, SPL Token `SetAuthority`, `Approve`, etc.).
- Expired spending limits = **fully exhausted** (deny). Expired whitelists = **hard deny**. Expired blacklists = silently dropped.
- Omitting `actions` creates an unrestricted session — it can do anything the wallet can until it expires.

## Cost

Measured on devnet (November 2025):

| Operation | Compute Units | Transaction fee |
|---|---|---|
| Execute via session key | ~4,100 | 0.000005 SOL |
| Execute with Ed25519 authority | ~5,900 | 0.000005 SOL |
| Execute with passkey (Secp256r1) | ~9,440 | 0.000005 SOL |
| CreateWallet | ~15,000–20,000 | 0.000005 SOL + rent |

All paths fit comfortably within Solana's 200,000 CU default budget. The ~2,300 CU precompile verification is the largest fixed cost on the passkey path.

**One-time rent** (fully refundable when accounts close):

| Account | Size | Rent |
|---|---|---|
| Wallet PDA | 8 bytes | 0.000947 SOL |
| Authority (Ed25519) | 80 bytes | 0.001448 SOL |
| Authority (Secp256r1) | 145 bytes | 0.001900 SOL |
| Session | 80 bytes + actions (0–2048) | 0.001448+ SOL |

**Total wallet creation cost**: ~0.0024 SOL (Ed25519) or ~0.0028 SOL (Secp256r1) — roughly $0.40 USD at $150/SOL.

## Parallel execution

Each authority has its own PDA, so different authorities on the same wallet execute **concurrently** on Solana's scheduler. An admin managing permissions doesn't block a session key sending payments. Only the same authority running two txs has a counter-conflict lock.

## Security

- Odometer counter replay protection (monotonic u32 per authority; works with synced passkeys).
- Clock-based slot freshness (150-slot window).
- CPI reentrancy prevention (`stack_height` check on every authenticated path).
- Expired session limits treated as fully exhausted (never "unlocked").
- `SolMaxPerTx` uses per-CPI gross-outflow tracking — DeFi round-trips can't bypass the per-tx cap by returning most lamports.
- Vault + per-listed-mint token account invariants enforced during session execute (blocks `System::Assign`, `SetAuthority`, `Approve` escapes).
- Token balance sums across all accounts (prevents dummy-account bypass).

Report vulnerabilities via [SECURITY.md](SECURITY.md).

## Further reading

| | |
|---|---|
| [SDK API reference](sdk/sdk-legacy/README.md) | TypeScript client + instruction builders |
| [Architecture](docs/Architecture.md) | Account layouts, security mechanisms, instruction reference |
| [Development](DEVELOPMENT.md) | Local build + test workflow |
| [Contributing](CONTRIBUTING.md) | PR guidelines |

## License

[MIT](LICENSE)
