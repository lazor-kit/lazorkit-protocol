/**
 * Port of tests-sdk/tests/11-security.test.ts.
 *
 * Security-focused tests:
 *   - Counter increments on admin operations (Secp256r1)
 *   - Self-reentrancy prevention (CPI back into LazorKit program)
 *   - Cross-wallet authority isolation
 *   - Accounts-hash binding (swapped-recipient attack)
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
  DISC_EXECUTE,
  LazorKit,
  PROGRAM_ID_DEVNET,
  ROLE_ADMIN,
  ROLE_SPENDER,
  SYSVAR_INSTRUCTIONS_ADDRESS,
  buildCompactLayout,
  computeAccountsHash,
  ed25519,
  finalizeSecp256r1,
  packCompactInstructions,
  prepareSecp256r1,
} from '@lazorkit/sdk';
// Low-level instruction builders — internal-only.
import { createExecuteIx } from '../../sdk/sdk-kit/src/instructions/builders.js';
import {
  delegatePolicy,
  setupTest,
  sendTx,
  sendTxExpectError,
  airdrop,
  getBalance,
  getSlot,
  resolveFeeAccts,
  systemTransferFromPda,
  type TestContext,
  makeClient,
} from './common.js';
import { generateMockSecp256r1Key, fakeWebAuthnSign } from './secp256r1Utils.js';

describe('Security', () => {
  let ctx: TestContext;
  let client: LazorKit;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);
  });

  describe('Counter increments on admin operations', () => {
    let walletPda: Address;
    let ownerKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
    let ownerAuthPda: Address;

    beforeAll(async () => {
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
      ownerAuthPda = result.authorityPda;
      await sendTx(ctx, result.instructions);
    });

    it('counter increments after addAuthority', async () => {
      const counterBefore = await client.readCounter(ownerAuthPda);
      expect(counterBefore).toBe(0);

      const adminSigner = await generateKeyPairSigner();
      const prepared = await client.prepareAddAuthority({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthPda,
        },
        newAuthority: { type: 'ed25519', publicKey: adminSigner.address },
        role: ROLE_ADMIN,
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions } = client.finalizeAddAuthority(prepared, response);
      await sendTx(ctx, instructions);

      expect(await client.readCounter(ownerAuthPda)).toBe(1);
    });

    it('counter increments after createSession', async () => {
      const counterBefore = await client.readCounter(ownerAuthPda);
      const sessionSigner = await generateKeyPairSigner();
      const currentSlot = await getSlot(ctx);

      const prepared = await client.prepareCreateSession({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthPda,
        },
        sessionKey: sessionSigner.address,
        expiresAt: currentSlot + 9000n,
        // Deliberately unrestricted: this test exercises the actionless session.
        unrestricted: true,
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions } = client.finalizeCreateSession(prepared, response);
      await sendTx(ctx, instructions);

      expect(await client.readCounter(ownerAuthPda)).toBe(counterBefore + 1);
    });

    it('counter increments after removeAuthority', async () => {
      const spenderSigner = await generateKeyPairSigner();
      const addPrepared = await client.prepareAddAuthority({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthPda,
        },
        newAuthority: { type: 'ed25519', publicKey: spenderSigner.address },
        role: ROLE_SPENDER,
        policy: delegatePolicy(),
      });
      const addResponse = await fakeWebAuthnSign(ownerKey, addPrepared.challenge);
      const addResult = client.finalizeAddAuthority(addPrepared, addResponse);
      await sendTx(ctx, addResult.instructions);

      const counterBefore = await client.readCounter(ownerAuthPda);

      const prepared = await client.prepareRemoveAuthority({
        payer: ctx.payer.address,
        walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: ownerAuthPda,
        },
        targetAuthorityPda: addPrepared.newAuthorityPda,
      });
      const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions } = client.finalizeRemoveAuthority(prepared, response);
      await sendTx(ctx, instructions);

      expect(await client.readCounter(ownerAuthPda)).toBe(counterBefore + 1);
    });
  });

  describe('Self-reentrancy', () => {
    it('rejects CPI back into own program via execute', async () => {
      const ownerSigner = await generateKeyPairSigner();
      const userSeed = crypto.randomBytes(32);
      const result = await client.createWallet({
        payer: ctx.payer.address,
        userSeed,
        owner: { type: 'ed25519', publicKey: ownerSigner.address },
      });
      await sendTx(ctx, result.instructions);
      await airdrop(ctx, result.vaultPda, 2n * 1_000_000_000n);

      const selfCallIx: Instruction = {
        programAddress: PROGRAM_ID_DEVNET,
        accounts: [
          { address: ctx.payer.address, role: AccountRole.READONLY_SIGNER },
        ],
        data: new Uint8Array([0xff]),
      };

      const { instructions } = await client.execute({
        payer: ctx.payer.address,
        walletPda: result.walletPda,
        signer: ed25519(ownerSigner.address, result.authorityPda),
        instructions: [selfCallIx],
      });

      await sendTxExpectError(ctx, instructions, [ownerSigner], 3013);
    });
  });

  describe('Cross-wallet authority isolation', () => {
    it('authority from wallet A cannot execute on wallet B', async () => {
      const ownerA = await generateKeyPairSigner();
      const seedA = crypto.randomBytes(32);
      const resultA = await client.createWallet({
        payer: ctx.payer.address,
        userSeed: seedA,
        owner: { type: 'ed25519', publicKey: ownerA.address },
      });
      await sendTx(ctx, resultA.instructions);
      await airdrop(ctx, resultA.vaultPda, 2n * 1_000_000_000n);

      const ownerB = await generateKeyPairSigner();
      const seedB = crypto.randomBytes(32);
      const resultB = await client.createWallet({
        payer: ctx.payer.address,
        userSeed: seedB,
        owner: { type: 'ed25519', publicKey: ownerB.address },
      });
      await sendTx(ctx, resultB.instructions);
      await airdrop(ctx, resultB.vaultPda, 2n * 1_000_000_000n);

      const newSigner = await generateKeyPairSigner();
      const { instructions } = await client.addAuthority({
        payer: ctx.payer.address,
        walletPda: resultB.walletPda,
        adminSigner: ed25519(ownerA.address, resultA.authorityPda),
        newAuthority: { type: 'ed25519', publicKey: newSigner.address },
        role: ROLE_SPENDER,
        policy: delegatePolicy(),
      });
      await sendTxExpectError(ctx, instructions, [ownerA]);
    });
  });

  describe('Accounts hash binding', () => {
    /// Rebuild the LazorKit instruction with one referenced account's privilege
    /// changed, leaving the account set and every byte of instruction data alone.
    /// This is the relayer's position: it cannot alter what was signed, but it
    /// does choose the privileges the accounts carry when the transaction lands.
    function reprivilege(
      instructions: readonly Instruction[],
      target: Address,
      role: AccountRole,
    ): Instruction[] {
      let found = false;
      const out = instructions.map((ix) => {
        if (ix.programAddress !== PROGRAM_ID_DEVNET) return ix;
        return {
          ...ix,
          accounts: (ix.accounts ?? []).map((a) => {
            if (a.address !== target) return a;
            found = true;
            return { ...a, role };
          }),
        };
      });
      if (!found) throw new Error(`${target} is not in the LazorKit instruction`);
      return out;
    }

    // M-4. The accounts hash used to cover only the 32-byte keys, so the flags
    // byte was the relayer's to choose: it could hand an inner instruction an
    // account the passkey holder had approved as read-only and mark it writable.
    // The bystander below is exactly that — System::Transfer takes the first two
    // accounts and ignores the rest, so it rides along as read-only and the
    // legitimate transfer still lands.
    it('rejects execute when a referenced account is upgraded to writable after signing', async () => {
      const ownerKey = await generateMockSecp256r1Key();
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
      await sendTx(ctx, result.instructions);
      await airdrop(ctx, result.vaultPda, 2n * 1_000_000_000n);

      const recipient = (await generateKeyPairSigner()).address;
      const bystander = (await generateKeyPairSigner()).address;

      const withBystander = (): Instruction => {
        const base = systemTransferFromPda(result.vaultPda, recipient, 1_000_000n);
        return {
          ...base,
          accounts: [...(base.accounts ?? []), { address: bystander, role: AccountRole.READONLY }],
        };
      };

      const prepare = async () =>
        client.prepareExecute({
          payer: ctx.payer.address,
          walletPda: result.walletPda,
          secp256r1: {
            credentialIdHash: ownerKey.credentialIdHash,
            publicKeyBytes: ownerKey.publicKeyBytes,
            authorityPda: result.authorityPda,
          },
          instructions: [withBystander()],
        });

      // Control: signed and submitted with the bystander read-only, as approved.
      const good = await prepare();
      const { instructions: goodIxs } = client.finalizeExecute(
        good,
        await fakeWebAuthnSign(ownerKey, good.challenge),
      );
      const before = await getBalance(ctx, recipient);
      await sendTx(ctx, goodIxs);
      expect((await getBalance(ctx, recipient)) - before).toBe(1_000_000n);

      // Attack: same signature, same accounts, bystander promoted to writable.
      const tampered = await prepare();
      const { instructions: tamperedIxs } = client.finalizeExecute(
        tampered,
        await fakeWebAuthnSign(ownerKey, tampered.challenge),
      );
      await sendTxExpectError(
        ctx,
        reprivilege(tamperedIxs, bystander, AccountRole.WRITABLE),
        [],
        3005,
      );
    });

    it('rejects execute with swapped recipient accounts', async () => {
      const ownerKey = await generateMockSecp256r1Key();
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
      await sendTx(ctx, result.instructions);
      await airdrop(ctx, result.vaultPda, 2n * 1_000_000_000n);

      const recipientA = (await generateKeyPairSigner()).address;
      const recipientB = (await generateKeyPairSigner()).address;

      // Step 1: confirm a legitimate transfer to recipientA works.
      const prepared = await client.prepareExecute({
        payer: ctx.payer.address,
        walletPda: result.walletPda,
        secp256r1: {
          credentialIdHash: ownerKey.credentialIdHash,
          publicKeyBytes: ownerKey.publicKeyBytes,
          authorityPda: result.authorityPda,
        },
        instructions: [systemTransferFromPda(result.vaultPda, recipientA, 1_000_000n)],
      });
      const execResponse = await fakeWebAuthnSign(ownerKey, prepared.challenge);
      const { instructions: goodIxs } = client.finalizeExecute(prepared, execResponse);
      const before = await getBalance(ctx, recipientA);
      await sendTx(ctx, goodIxs);
      const after = await getBalance(ctx, recipientA);
      expect(after - before).toBe(1_000_000n);

      // Step 2: build a tampered tx — sign for recipientA, execute with B.
      const authorityPda = result.authorityPda;
      const slot = await getSlot(ctx);
      const counter = (await client.readCounter(authorityPda)) + 1;

      const transferIx = systemTransferFromPda(result.vaultPda, recipientA, 1_000_000n);
      const fixedAccounts: Address[] = [
        ctx.payer.address,
        result.walletPda,
        authorityPda,
        result.vaultPda,
        SYSVAR_INSTRUCTIONS_ADDRESS,
      ];
      const { compactInstructions, remainingAccounts } = buildCompactLayout(
        fixedAccounts,
        [transferIx],
        ctx.payer.address,
      );
      const packed = packCompactInstructions(compactInstructions);

      const allAccountMetas: AccountMeta[] = [
        { address: ctx.payer.address, role: AccountRole.READONLY_SIGNER },
        { address: result.walletPda, role: AccountRole.READONLY },
        { address: authorityPda, role: AccountRole.WRITABLE },
        { address: result.vaultPda, role: AccountRole.WRITABLE },
        { address: SYSVAR_INSTRUCTIONS_ADDRESS, role: AccountRole.READONLY },
        ...remainingAccounts,
      ];
      const accountsHash = computeAccountsHash(allAccountMetas, compactInstructions);
      const signedPayload = new Uint8Array(packed.length + accountsHash.length);
      signedPayload.set(packed, 0);
      signedPayload.set(accountsHash, packed.length);

      const tamperedPrepared = prepareSecp256r1({
        discriminator: new Uint8Array([DISC_EXECUTE]),
        signedPayload,
        sysvarIxIndex: 4,
        slot,
        counter,
        payer: ctx.payer.address,
        programId: PROGRAM_ID_DEVNET,
        publicKeyBytes: ownerKey.publicKeyBytes,
      });
      const tamperedResponse = await fakeWebAuthnSign(
        ownerKey,
        tamperedPrepared.challenge,
      );
      const { authPayload, precompileIx } = finalizeSecp256r1(
        tamperedPrepared,
        tamperedResponse,
      );

      // Swap recipientA → recipientB in the remaining accounts list.
      const tamperedRemaining: AccountMeta[] = remainingAccounts.map((acc) =>
        acc.address === recipientA ? { ...acc, address: recipientB } : acc,
      );

      const protocolFee = await resolveFeeAccts(ctx.rpc as never, ctx.payer.address);
      const tamperedIx = createExecuteIx({
        payer: ctx.payer.address,
        walletPda: result.walletPda,
        authorityPda,
        vaultPda: result.vaultPda,
        packedInstructions: packed,
        authPayload,
        remainingAccounts: tamperedRemaining,
        protocolFee,
        programId: PROGRAM_ID_DEVNET,
      });

      // Should fail — accounts hash won't match.
      await sendTxExpectError(ctx, [precompileIx, tamperedIx]);
    });
  });
});
