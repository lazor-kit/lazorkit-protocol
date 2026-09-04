// Reference hook for the v1 -> v2 migration flow.
//
// It does three things, all client-side and user-authorized — no operator ever
// moves a user's funds:
//   1. detect whether the connected identity still has a v1 wallet,
//   2. enumerate what will move (SOL + every token, both SPL and Token-2022),
//   3. run one user-signed migration: create the v2 wallet + destination ATAs,
//      then MigrateWallet, which sweeps the vault and closes the v1 PDAs.
//
// You supply how transactions are sent (`sendTransaction`) so it drops into a
// sponsored/relayer setup unchanged: the payer funds rent and gets the reclaimed
// v1 rent back; the user only authorizes.

import { useCallback, useEffect, useState } from 'react';
import type { Connection, PublicKey, Keypair, TransactionInstruction } from '@solana/web3.js';
import {
  LazorKitClient,
  deriveV1Accounts,
  readV1WalletState,
  enumerateV1VaultTokens,
  type CreateWalletOwner,
} from '@lazorkit/sdk-legacy';
import { getPasskeyAssertion, type WebAuthnResponse, type AssertionOptions } from './webauthn';

export interface MigrationAssets {
  /** Lamports sitting in the v1 vault. */
  sol: bigint;
  tokens: { mint: string; amount: bigint; tokenProgram: string }[];
}

export type MigrationStatus =
  | { phase: 'detecting' }
  | { phase: 'none' } // already migrated, or never a v1 user — render nothing
  | { phase: 'ready'; assets: MigrationAssets }
  | { phase: 'migrating'; step: 'setup' | 'authorize'; assets: MigrationAssets }
  | { phase: 'done'; signature: string }
  | { phase: 'error'; message: string; assets?: MigrationAssets };

export interface UseV1MigrationParams {
  client: LazorKitClient;
  payer: PublicKey;
  /** The same inputs that derive the wallet: the user seed and owner descriptor. */
  userSeed: Uint8Array;
  owner: CreateWalletOwner;
  /**
   * Sign (payer + any extra signers) and send. Return the confirmed signature.
   * In a relayer model this is where the sponsor co-signs. `extraSigners` carries
   * the Ed25519 owner keypair when the owner is Ed25519; it is empty for passkeys.
   */
  sendTransaction: (
    instructions: TransactionInstruction[],
    extraSigners?: Keypair[],
  ) => Promise<string>;
  /** Required only when `owner.type === 'ed25519'`: the owner keypair that signs the migrate. */
  ed25519Signer?: Keypair;
  /** Override the passkey prompt (secp256r1 owners). Defaults to `getPasskeyAssertion`. */
  getAssertion?: (challenge: Uint8Array) => Promise<WebAuthnResponse>;
  /** Passed to the default passkey prompt (rpId + allowed credential ids). */
  assertionOptions?: AssertionOptions;
}

export function useV1Migration(params: UseV1MigrationParams) {
  const { client, payer, userSeed, owner, sendTransaction, ed25519Signer, getAssertion, assertionOptions } = params;
  const [status, setStatus] = useState<MigrationStatus>({ phase: 'detecting' });

  const detect = useCallback(async () => {
    setStatus({ phase: 'detecting' });
    try {
      const ownerIdSeed = owner.type === 'ed25519' ? owner.publicKey.toBytes() : owner.credentialIdHash;
      const v1 = deriveV1Accounts(userSeed, ownerIdSeed, client.programId);
      const state = await readV1WalletState(client.connection, v1);
      if (!state) {
        setStatus({ phase: 'none' });
        return;
      }
      const tokens = await enumerateV1VaultTokens(client.connection, v1.vault);
      setStatus({
        phase: 'ready',
        assets: {
          sol: BigInt(state.vaultLamports),
          tokens: tokens.map((t) => ({
            mint: t.mint.toBase58(),
            amount: t.amount,
            tokenProgram: t.tokenProgram.toBase58(),
          })),
        },
      });
    } catch (e) {
      setStatus({ phase: 'error', message: e instanceof Error ? e.message : String(e) });
    }
  }, [client, userSeed, owner]);

  useEffect(() => {
    void detect();
  }, [detect]);

  const migrate = useCallback(async () => {
    const assets = status.phase === 'ready' ? status.assets : undefined;
    try {
      const plan = await client.migrateV1Wallet({ payer, userSeed, owner });

      // 1. Create the v2 wallet + destination ATAs (payer signs). For a vault
      //    with many token accounts this may need splitting across transactions.
      if (plan.setupInstructions.length) {
        setStatus({ phase: 'migrating', step: 'setup', assets: assets! });
        await sendTransaction(plan.setupInstructions);
      }

      // 2. Authorize + run the migrate.
      setStatus({ phase: 'migrating', step: 'authorize', assets: assets! });
      let signature: string;
      if (plan.migrate.type === 'ed25519') {
        if (!ed25519Signer) throw new Error('ed25519Signer is required for an Ed25519 owner');
        signature = await sendTransaction([plan.migrate.instruction], [ed25519Signer]);
      } else {
        const response = await (getAssertion ?? ((c) => getPasskeyAssertion(c, assertionOptions)))(
          plan.migrate.challenge,
        );
        signature = await sendTransaction(plan.migrate.finalize(response));
      }

      setStatus({ phase: 'done', signature });
    } catch (e) {
      setStatus({ phase: 'error', message: e instanceof Error ? e.message : String(e), assets });
    }
  }, [client, payer, userSeed, owner, sendTransaction, ed25519Signer, getAssertion, assertionOptions, status]);

  return { status, migrate, refresh: detect };
}
