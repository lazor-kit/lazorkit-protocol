# LazorKit Protocol

LazorKit Protocol is the production Solana smart-wallet program for passkey and Ed25519 authorization, role-based access control, and scoped session keys.

| Cluster | Program ID | Status |
| --- | --- | --- |
| Mainnet | `LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi` | Production |
| Devnet | `4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS` | Protocol devnet |

- [Production integration and deployment matrix](https://docs.lazorkit.com/networks)
- [Protocol source and build instructions](https://github.com/lazor-kit/lazorkit-protocol/tree/release/sdk-legacy-0.3.2)
- [Report a vulnerability privately](SECURITY.md)

The Protocol client line is `@lazorkit/sdk-legacy` 0.3.x. For reproducible integrations, pin a compatible release and use the program ID for your cluster.

## Other LazorKit programs

**LazorKit Enterprise** is an independent Solana program with its own repository, program IDs, deployment approvals, and SDK compatibility. The Enterprise source and build files in this branch are retained as history from before the repository split. Use the production source branch linked above for the deployed Protocol program.

The [LazorKit Public Goods Program](https://github.com/lazor-kit/lazorkit-public-good-program) is an open-source public-goods implementation with no mainnet deployment. The [LazorKit Anchor Program](https://github.com/lazor-kit/program) is archived.
