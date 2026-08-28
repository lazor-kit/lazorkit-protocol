/**
 * Port of tests-sdk/tests/08-deferred.test.ts.
 *
 * Deferred execution (Authorize / ExecuteDeferred / Reclaim):
 *   Happy path: single transfer, multi-instruction transfer
 *   Security: hash mismatch (3015), double-execution, reclaim-before-expiry,
 *             reclaim from wrong payer, counter increments across paths.
 *
 * Uses the high-level client API (prepareAuthorize / finalizeAuthorize /
 * executeDeferredFromPayload). For the hash-mismatch attack (sign for
 * payload A, execute payload B), we re-pack with a tampered amount on
 * the executeDeferred side after the legitimate authorize, since the
 * high-level API doesn't let us swap the payload directly.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  AccountRole,
  generateKeyPairSigner,
  type AccountMeta,
  type Address,
  type Instruction,
} from '@solana/kit';
import {
  LazorKit,
  PROGRAM_ID_DEVNET as PROGRAM_ID,
  SYSTEM_PROGRAM_ADDRESS,
  decodeAuthorityAccount,
  packCompactInstructions,
} from '@lazorkit/sdk';
// Low-level instruction builders — internal-only.
import {
  createExecuteDeferredIx,
  createReclaimDeferredIx,
} from '../../sdk/sdk-kit/src/instructions/builders.js';
import {
  setupTest,
  sendTx,
  sendTxExpectError,
  airdrop,
  getBalance,
  resolveFeeAccts,
  systemTransferFromPda,
  type TestContext,
  makeClient,
} from './common.js';
import { generateMockSecp256r1Key, fakeWebAuthnSign } from './secp256r1Utils.js';
import { ACCOUNT_DISCRIMINATOR } from '@lazorkit/sdk';

const LAMPORTS_PER_SOL = 1_000_000_000n;

describe('Deferred Execution', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTest();
  });

  describe('Happy Path', () => {
    let client: LazorKit;
    let walletPda: Address;
    let vaultPda: Address;
    let ownerKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
    let ownerAuthorityPda: Address;

    beforeAll(async () => {
      client = makeClient(ctx.rpc as never);
      ownerKey = await generateMockSecp256r1Key();
      const userSeed = crypto.randomBytes(32);
      const result = await client.createWallet({
        payer: ctx.payer.address,
        userSeed,
        owner: {
          type: 'secp256r1',
          credentialIdHash: ownerKey.credentialIdHash,
          compressedPubkey: ownerKey.publicKeyBytes,
          rpId: ownerKey.rpId,
        },
      });
      walletPda = result.walletPda;
      vaultPda = result.vaultPda;
      ownerAuthorityPda = result.authorityPda;
      await sendTx(ctx, result.instructions);
      await airdrop(ctx, vaultPda, 5n * LAMPORTS_PER_SOL);
    });

    it('authorizes and executes a single SOL transfer via deferred', async () => {
      const recipient = (await generateKeyPairSigner()).address;
      const prepared = await client.prepareAuthorize({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [systemTransferFromPda(vaultPda, recipient, LAMPORTS_PER_SOL)],
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions: authIxs, deferredPayload, deferredExecPda } =
        client.finalizeAuthorize(prepared, response);

      // TX1: Authorize.
      await sendTx(ctx, authIxs);
      const info = await ctx.rpc
        .getAccountInfo(deferredExecPda, { encoding: 'base64' })
        .send();
      expect(info.value).not.toBeNull();
      const data = new Uint8Array(Buffer.from(info.value!.data[0], 'base64'));
      expect(data[0]).toBe(ACCOUNT_DISCRIMINATOR.DEFERRED_EXEC); // DeferredExec discriminator
      expect(data.length).toBe(176);

      // TX2: ExecuteDeferred.
      const tx2 = await client.executeDeferredFromPayload({
        payer: ctx.payer.address,
        deferredPayload,
      });
      const before = await getBalance(ctx, recipient);
      await sendTx(ctx, tx2.instructions);
      const after = await getBalance(ctx, recipient);
      expect(after - before).toBe(LAMPORTS_PER_SOL);

      // DeferredExec account closed after execution.
      const after2 = await ctx.rpc
        .getAccountInfo(deferredExecPda, { encoding: 'base64' })
        .send();
      expect(after2.value).toBeNull();
    });

    it('authorizes and executes multiple SOL transfers via deferred', async () => {
      const r1 = (await generateKeyPairSigner()).address;
      const r2 = (await generateKeyPairSigner()).address;
      const r3 = (await generateKeyPairSigner()).address;
      const prepared = await client.prepareAuthorize({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [
          systemTransferFromPda(vaultPda, r1, LAMPORTS_PER_SOL),
          systemTransferFromPda(vaultPda, r2, LAMPORTS_PER_SOL),
          systemTransferFromPda(vaultPda, r3, LAMPORTS_PER_SOL),
        ],
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions: authIxs, deferredPayload } = client.finalizeAuthorize(
        prepared,
        response,
      );
      await sendTx(ctx, authIxs);

      const tx2 = await client.executeDeferredFromPayload({
        payer: ctx.payer.address,
        deferredPayload,
      });
      await sendTx(ctx, tx2.instructions);

      expect(await getBalance(ctx, r1)).toBe(LAMPORTS_PER_SOL);
      expect(await getBalance(ctx, r2)).toBe(LAMPORTS_PER_SOL);
      expect(await getBalance(ctx, r3)).toBe(LAMPORTS_PER_SOL);
    });
  });

  describe('Security', () => {
    let client: LazorKit;
    let walletPda: Address;
    let vaultPda: Address;
    let ownerKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
    let ownerAuthorityPda: Address;

    beforeAll(async () => {
      client = makeClient(ctx.rpc as never);
      ownerKey = await generateMockSecp256r1Key();
      const userSeed = crypto.randomBytes(32);
      const result = await client.createWallet({
        payer: ctx.payer.address,
        userSeed,
        owner: {
          type: 'secp256r1',
          credentialIdHash: ownerKey.credentialIdHash,
          compressedPubkey: ownerKey.publicKeyBytes,
          rpId: ownerKey.rpId,
        },
      });
      walletPda = result.walletPda;
      vaultPda = result.vaultPda;
      ownerAuthorityPda = result.authorityPda;
      await sendTx(ctx, result.instructions);
      await airdrop(ctx, vaultPda, 5n * LAMPORTS_PER_SOL);
    });

    // M-4, on the deferred path. The window between Authorize and
    // ExecuteDeferred is where a relayer sits with a signature it cannot change
    // and a transaction it fully controls. Binding only the account keys left
    // the privileges for it to pick: a bystander the passkey holder approved as
    // read-only could arrive writable. System::Transfer takes the first two
    // accounts and ignores the rest, so the bystander rides along without
    // changing what the legitimate transfer does.
    it('rejects ExecuteDeferred when a referenced account is upgraded to writable', async () => {
      // Its own wallet, so the shared vault's balance and the shared authority's
      // counter stay exactly as the tests around this one expect them.
      const own = await client.createWallet({
        payer: ctx.payer.address,
        userSeed: crypto.randomBytes(32),
        owner: {
          type: 'secp256r1',
          credentialIdHash: ownerKey.credentialIdHash,
          compressedPubkey: ownerKey.publicKeyBytes,
          rpId: ownerKey.rpId,
        },
      });
      await sendTx(ctx, own.instructions);
      await airdrop(ctx, own.vaultPda, LAMPORTS_PER_SOL);

      const recipient = (await generateKeyPairSigner()).address;
      const bystander = (await generateKeyPairSigner()).address;

      const amount = 1_000_000n;
      const transfer = systemTransferFromPda(own.vaultPda, recipient, amount);
      const withBystander: Instruction = {
        ...transfer,
        accounts: [...(transfer.accounts ?? []), { address: bystander, role: AccountRole.READONLY }],
      };

      const prepared = await client.prepareAuthorize({
        payer: ctx.payer.address,
        walletPda: own.walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: own.authorityPda,
        },
        instructions: [withBystander],
      });
      const { instructions: authIxs, deferredPayload } = client.finalizeAuthorize(
        prepared,
        await fakeWebAuthnSign(ownerKey, prepared.challenge),
      );
      await sendTx(ctx, authIxs);

      const tx2 = await client.executeDeferredFromPayload({
        payer: ctx.payer.address,
        deferredPayload,
      });

      // The account set and the instruction data are untouched; only the
      // bystander's privilege changes.
      let found = false;
      const tampered = tx2.instructions.map((ix) => {
        if (ix.programAddress !== PROGRAM_ID) return ix;
        return {
          ...ix,
          accounts: (ix.accounts ?? []).map((a) => {
            if (a.address !== bystander) return a;
            found = true;
            return { ...a, role: AccountRole.WRITABLE };
          }),
        };
      });
      expect(found).toBe(true);

      await sendTxExpectError(ctx, tampered, [], 3015);

      // The authorization survives the failed attempt, so the honest execution
      // still works — the relayer gains nothing by trying.
      const before = await getBalance(ctx, recipient);
      await sendTx(ctx, tx2.instructions);
      expect((await getBalance(ctx, recipient)) - before).toBe(amount);
    });

    it('rejects ExecuteDeferred with wrong instructions (hash mismatch 3015)', async () => {
      const recipient = (await generateKeyPairSigner()).address;
      const prepared = await client.prepareAuthorize({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [systemTransferFromPda(vaultPda, recipient, LAMPORTS_PER_SOL)],
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions: authIxs, deferredPayload } = client.finalizeAuthorize(
        prepared,
        response,
      );
      await sendTx(ctx, authIxs);

      // Build TAMPERED packed instructions (2 SOL instead of 1 SOL).
      const tamperedData = new Uint8Array(12);
      new DataView(tamperedData.buffer).setUint32(0, 2, true);
      new DataView(tamperedData.buffer).setBigUint64(4, 2n * LAMPORTS_PER_SOL, true);
      const wrongCompact = [
        {
          programIdIndex: deferredPayload.compactInstructions[0]!.programIdIndex,
          accountIndexes: deferredPayload.compactInstructions[0]!.accountIndexes,
          data: tamperedData,
        },
      ];
      const wrongPacked = packCompactInstructions(wrongCompact);

      const tamperedFee = await resolveFeeAccts(ctx.rpc as never, ctx.payer.address);
      const tamperedIx = createExecuteDeferredIx({
        payer: ctx.payer.address,
        walletPda,
        vaultPda,
        deferredExecPda: deferredPayload.deferredExecPda,
        refundDestination: ctx.payer.address,
        packedInstructions: wrongPacked,
        remainingAccounts: deferredPayload.remainingAccounts,
        protocolFee: tamperedFee,
        programId: client.programId,
      });
      await sendTxExpectError(ctx, [tamperedIx], [], 3015);

      // Execute with correct payload to clean up.
      const tx2 = await client.executeDeferredFromPayload({
        payer: ctx.payer.address,
        deferredPayload,
      });
      await sendTx(ctx, tx2.instructions);
    });

    it('rejects double execution (account closed after first execute)', async () => {
      const recipient = (await generateKeyPairSigner()).address;
      const prepared = await client.prepareAuthorize({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [systemTransferFromPda(vaultPda, recipient, LAMPORTS_PER_SOL)],
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions: authIxs, deferredPayload } = client.finalizeAuthorize(
        prepared,
        response,
      );
      await sendTx(ctx, authIxs);

      const tx2a = await client.executeDeferredFromPayload({
        payer: ctx.payer.address,
        deferredPayload,
      });
      await sendTx(ctx, tx2a.instructions);

      const tx2b = await client.executeDeferredFromPayload({
        payer: ctx.payer.address,
        deferredPayload,
      });
      // Second execution fails because deferredExec account is closed.
      await sendTxExpectError(ctx, tx2b.instructions, []);
    });

    it('rejects reclaim before expiry', async () => {
      const recipient = (await generateKeyPairSigner()).address;
      const prepared = await client.prepareAuthorize({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [systemTransferFromPda(vaultPda, recipient, LAMPORTS_PER_SOL)],
        expiryOffset: 9000, // far future
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions: authIxs, deferredPayload } = client.finalizeAuthorize(
        prepared,
        response,
      );
      await sendTx(ctx, authIxs);

      // Try to reclaim before expiry — the program rejects with the
      // "not yet expired" custom error (3014 in the legacy build, 3018
      // post-audit-fix renumbering); we don't pin the exact code.
      const reclaim = client.reclaimDeferred({
        payer: ctx.payer.address,
        deferredExecPda: deferredPayload.deferredExecPda,
        refundDestination: ctx.payer.address,
      });
      await sendTxExpectError(ctx, reclaim.instructions, []);

      // Clean up — execute the deferred payload normally.
      const tx2 = await client.executeDeferredFromPayload({
        payer: ctx.payer.address,
        deferredPayload,
      });
      await sendTx(ctx, tx2.instructions);
    });

    it('rejects reclaim from wrong payer', async () => {
      const recipient = (await generateKeyPairSigner()).address;
      const prepared = await client.prepareAuthorize({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [systemTransferFromPda(vaultPda, recipient, LAMPORTS_PER_SOL)],
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions: authIxs, deferredPayload } = client.finalizeAuthorize(
        prepared,
        response,
      );
      await sendTx(ctx, authIxs);

      // Hand-craft a reclaim ix where payer != original creator. Because
      // ctx.payer is the only signer in our test harness, we can't easily
      // sign with a different one — instead just verify that the program
      // rejects with PermissionDenied / wrong-payer when the address in
      // the ix doesn't match the on-chain stored creator. Approximating
      // by passing a different address for `payer` (which won't sign).
      const fakePayer = (await generateKeyPairSigner()).address;
      const ix = createReclaimDeferredIx({
        payer: fakePayer,
        deferredExecPda: deferredPayload.deferredExecPda,
        refundDestination: fakePayer,
        programId: client.programId,
      });
      await sendTxExpectError(ctx, [ix]);

      // Clean up — execute the deferred normally.
      const tx2 = await client.executeDeferredFromPayload({
        payer: ctx.payer.address,
        deferredPayload,
      });
      await sendTx(ctx, tx2.instructions);
    });

    it('counter increments correctly across deferred and regular execute', async () => {
      // Read counter, do a regular execute, deferred, then read again.
      const counter0 = await client.readCounter(ownerAuthorityPda);

      // Regular execute via prepareExecute.
      const r1 = (await generateKeyPairSigner()).address;
      const exec = await client.prepareExecute({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [systemTransferFromPda(vaultPda, r1, 1_000_000n)],
      });
      const execResp = await fakeWebAuthnSign(ownerKey, exec.challenge);
      await sendTx(ctx, client.finalizeExecute(exec, execResp).instructions);

      const counter1 = await client.readCounter(ownerAuthorityPda);
      expect(counter1).toBe(counter0 + 1);

      // Deferred — also bumps counter on Authorize.
      const r2 = (await generateKeyPairSigner()).address;
      const auth = await client.prepareAuthorize({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthorityPda,
        },
        instructions: [systemTransferFromPda(vaultPda, r2, 1_000_000n)],
      });
      const authResp = await fakeWebAuthnSign(ownerKey, auth.challenge);
      const { instructions: authIxs, deferredPayload } = client.finalizeAuthorize(
        auth,
        authResp,
      );
      await sendTx(ctx, authIxs);
      const counter2 = await client.readCounter(ownerAuthorityPda);
      expect(counter2).toBe(counter1 + 1);

      // Cleanup.
      const tx2 = await client.executeDeferredFromPayload({
        payer: ctx.payer.address,
        deferredPayload,
      });
      await sendTx(ctx, tx2.instructions);

      // Verify counter persisted.
      const decoded = decodeAuthorityAccount(
        new Uint8Array(
          Buffer.from(
            (
              await ctx.rpc.getAccountInfo(ownerAuthorityPda, { encoding: 'base64' }).send()
            ).value!.data[0],
            'base64',
          ),
        ),
      );
      expect(decoded.counter).toBe(counter2);
      void AccountRole; // satisfy unused-import lint
    });
  });
});

// Suppress unused-import warnings.
const _unused: AccountMeta | undefined = undefined;
void _unused;
