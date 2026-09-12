# Threat model

The one invariant everything else serves: **no key other than a wallet's own
authority can move that wallet's funds.** The program signs for user vaults with
PDA seeds, so "the program can sign" must never become "someone made the program
sign for me."

## Actors and trust

| Actor | Trusted for | Must NOT be able to |
|---|---|---|
| **Relayer / paymaster** | Nothing. It pays fees and submits transactions on a user's behalf. | Steal, redirect, or strand any user's funds. It chooses account order and which accounts to pass, and it can drop or alter anything the user did not sign over. |
| **Wallet owner (Owner rank)** | Their own wallet's funds. | Affect any other wallet. |
| **Admin (rank 1)** | Managing Delegates on wallets it controls. | Escalate to Owner; spend beyond its policy if it carries one. |
| **Delegate (rank 2)** | Spending within its policy. | Spend beyond the policy on *any* execution path; manage anything. |
| **Session key** | Spending within its action buffer, for its lifetime. | Forward any signer but its own; exceed its limits. |
| **Protocol admin** | Setting fees (capped), withdrawing treasury to the configured sink, rotating admin. | Freeze or seize user funds (the C-1 class); set an unpayable fee; be replaced without the two-step accept. |
| **Program upgrade authority** | Deploying code. | (Out of scope for the program audit — a key-management concern. **Flag:** the mainnet upgrade authority is the same key as `PROTOCOL_INIT_AUTHORITY`; note the concentration.) |

## Trust boundaries worth probing

- **The relayer is the primary adversary for the wire format and MigrateWallet.**
  Anything the user's signature does not cover, the relayer controls. Examples the
  code must get right: account privileges (`is_signer`/`is_writable`) are bound
  into the accounts hash (M-4); the fee payer is never forwarded as a signer into
  an inner CPI (H-3); MigrateWallet's signature binds the destination, the wallet,
  and the token count so a relayer cannot redirect, replay cross-wallet, or drop
  tokens.

- **Rank vs policy.** `role` says what an authority may *manage*; its policy says
  what it may *spend*. These are independent. The historical bug (H-2) was that
  `role` gated management and gated spending nowhere. Probe every path that moves
  value and confirm it enforces the policy of a policy-bearing authority — the
  internal review found the deferred path had missed this.

- **The vault-signing surface.** The program signs for vault PDAs (current `lk2:`
  seeds, and the old bare seeds inside MigrateWallet). Any instruction that makes
  the program sign for a vault must first prove the caller controls that vault.

- **Version separation.** v2 seeds (`lk2:`) and discriminators (`0x2N`) are
  disjoint from v1. MigrateWallet is the *only* code that deliberately reaches v1
  accounts. Confirm no other path can be confused across the version boundary.

- **Governance.** ProtocolConfig is the root of the fee system with no prior
  on-chain trust anchor, so `initialize_protocol` is gated on a compile-time key.
  Every admin read pins the config PDA *address*, not just its owner. The C-1 fix
  turns a config-flag revert into a *skip* — confirm the skip cannot be turned
  back into a freeze (e.g. via a spoofed config, an unpayable fee, or an
  enable-before-shard-exists state).

## Non-goals / accepted risks (state, so the auditor doesn't re-litigate)

- A **dormant user who never signs** a migration keeps their funds (and rent) in
  a v1 vault indefinitely. This is inherent to non-custodial; there is
  deliberately no operator path to move those funds.
- A **granter can write a weak policy.** A policy bounds only the dimensions its
  actions cover (a whitelist-only policy caps no amount). "Delegate requires a
  policy" means non-empty, not spend-limited on every asset. This is a granter
  choice, documented in `docs/Architecture.md`.
- The **upgrade authority is all-powerful** by Solana's design; the program
  cannot constrain it. Key management is out of scope for the code audit.
