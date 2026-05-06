/**
 * Port of tests-sdk/tests/06-counter.test.ts.
 *
 * Counter edge cases:
 *  - Counter persists across different ix types (AddAuthority then Execute).
 *  - Two Secp256r1 authorities have independent counters.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  AccountRole,
  generateKeyPairSigner,
  getAddressEncoder,
  type AccountMeta,
} from '@solana/kit';
import {
  AUTH_TYPE_ED25519,
  AUTH_TYPE_SECP256R1,
  DISC_ADD_AUTHORITY,
  DISC_EXECUTE,
  PROGRAM_ID_DEVNET,
  ROLE_ADMIN,
  ROLE_SPENDER,
  SYSTEM_PROGRAM_ADDRESS,
  computeAccountsHash,
  createAddAuthorityIx,
  createCreateWalletIx,
  createExecuteIx,
  decodeAuthorityAccount,
  finalizeSecp256r1,
  findAuthorityPda,
  findVaultPda,
  findWalletPda,
  packCompactInstructions,
  prepareSecp256r1,
} from '@lazorkit/sdk';
import {
  setupTest,
  sendTx,
  airdrop,
  getSlot,
  type TestContext,
} from './common.js';
import { generateMockSecp256r1Key, fakeWebAuthnSign } from './secp256r1Utils.js';

const addressEncoder = getAddressEncoder();

async function readCounter(
  ctx: TestContext,
  pda: import('@solana/kit').Address,
): Promise<number> {
  const info = await ctx.rpc.getAccountInfo(pda, { encoding: 'base64' }).send();
  return decodeAuthorityAccount(
    new Uint8Array(Buffer.from(info.value!.data[0], 'base64')),
  ).counter;
}

describe('Counter Edge Cases', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await setupTest();
  });

  it('counter persists across different instruction types', async () => {
    const ownerKey = await generateMockSecp256r1Key();
    const userSeed = crypto.randomBytes(32);

    const [walletPda] = await findWalletPda(userSeed, PROGRAM_ID_DEVNET);
    const [vaultPda] = await findVaultPda(walletPda, PROGRAM_ID_DEVNET);
    const [ownerAuthPda, authBump] = await findAuthorityPda(
      walletPda,
      ownerKey.credentialIdHash,
      PROGRAM_ID_DEVNET,
    );

    await sendTx(ctx, [
      createCreateWalletIx({
        payer: ctx.payer.address,
        walletPda,
        vaultPda,
        authorityPda: ownerAuthPda,
        userSeed,
        authType: AUTH_TYPE_SECP256R1,
        authBump,
        credentialOrPubkey: ownerKey.credentialIdHash,
        secp256r1Pubkey: ownerKey.publicKeyBytes,
        rpId: ownerKey.rpId,
        programId: PROGRAM_ID_DEVNET,
      }),
    ]);

    await airdrop(ctx, vaultPda, 2n * 1_000_000_000n);

    // 1. AddAuthority — counter becomes 1.
    const adminSigner = await generateKeyPairSigner();
    const adminPubkeyBytes = addressEncoder.encode(adminSigner.address) as Uint8Array;
    const [adminAuthPda] = await findAuthorityPda(
      walletPda,
      adminPubkeyBytes,
      PROGRAM_ID_DEVNET,
    );

    const slot1 = await getSlot(ctx);
    const dataPayload = new Uint8Array(2 + 6 + 32);
    dataPayload[0] = AUTH_TYPE_ED25519;
    dataPayload[1] = ROLE_ADMIN;
    dataPayload.set(adminPubkeyBytes, 8);
    const signedPayload1 = new Uint8Array(dataPayload.length + 32);
    signedPayload1.set(dataPayload, 0);
    signedPayload1.set(addressEncoder.encode(ctx.payer.address) as Uint8Array, dataPayload.length);

    const prepared1 = prepareSecp256r1({
      discriminator: new Uint8Array([DISC_ADD_AUTHORITY]),
      signedPayload: signedPayload1,
      sysvarIxIndex: 6,
      slot: slot1,
      counter: 1,
      payer: ctx.payer.address,
      programId: PROGRAM_ID_DEVNET,
      publicKeyBytes: ownerKey.publicKeyBytes,
    });
    const response1 = await fakeWebAuthnSign(ownerKey, prepared1.challenge);
    const { authPayload: ap1, precompileIx: pi1 } = finalizeSecp256r1(prepared1, response1);

    await sendTx(ctx, [
      pi1,
      createAddAuthorityIx({
        payer: ctx.payer.address,
        walletPda,
        adminAuthorityPda: ownerAuthPda,
        newAuthorityPda: adminAuthPda,
        newType: AUTH_TYPE_ED25519,
        newRole: ROLE_ADMIN,
        credentialOrPubkey: adminPubkeyBytes,
        authPayload: ap1,
        programId: PROGRAM_ID_DEVNET,
      }),
    ]);

    expect(await readCounter(ctx, ownerAuthPda)).toBe(1);

    // 2. Execute — counter becomes 2.
    const slot2 = await getSlot(ctx);
    const transferData = new Uint8Array(12);
    new DataView(transferData.buffer).setUint32(0, 2, true);
    new DataView(transferData.buffer).setBigUint64(4, 1_000_000n, true);

    const compactIxs = [
      { programIdIndex: 5, accountIndexes: [3, 6], data: transferData },
    ];
    const packed = packCompactInstructions(compactIxs);

    const execRecipient = (await generateKeyPairSigner()).address;
    const allAccountMetas: AccountMeta[] = [
      { address: ctx.payer.address, role: AccountRole.READONLY_SIGNER },
      { address: walletPda, role: AccountRole.READONLY },
      { address: ownerAuthPda, role: AccountRole.WRITABLE },
      { address: vaultPda, role: AccountRole.WRITABLE },
      { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
      { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
      { address: execRecipient, role: AccountRole.WRITABLE },
    ];
    const accountsHash = computeAccountsHash(allAccountMetas, compactIxs);
    const signedPayload2 = new Uint8Array(packed.length + accountsHash.length);
    signedPayload2.set(packed, 0);
    signedPayload2.set(accountsHash, packed.length);

    const prepared2 = prepareSecp256r1({
      discriminator: new Uint8Array([DISC_EXECUTE]),
      signedPayload: signedPayload2,
      sysvarIxIndex: 4,
      slot: slot2,
      counter: 2,
      payer: ctx.payer.address,
      programId: PROGRAM_ID_DEVNET,
      publicKeyBytes: ownerKey.publicKeyBytes,
    });
    const response2 = await fakeWebAuthnSign(ownerKey, prepared2.challenge);
    const { authPayload: ap2, precompileIx: pi2 } = finalizeSecp256r1(prepared2, response2);

    await sendTx(ctx, [
      pi2,
      createExecuteIx({
        payer: ctx.payer.address,
        walletPda,
        authorityPda: ownerAuthPda,
        vaultPda,
        packedInstructions: packed,
        authPayload: ap2,
        remainingAccounts: [
          { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
          { address: execRecipient, role: AccountRole.WRITABLE },
        ],
        programId: PROGRAM_ID_DEVNET,
      }),
    ]);

    expect(await readCounter(ctx, ownerAuthPda)).toBe(2);
  });

  it('two Secp256r1 authorities have independent counters', async () => {
    const key1 = await generateMockSecp256r1Key();
    const key2 = await generateMockSecp256r1Key();
    const userSeed = crypto.randomBytes(32);

    const [walletPda] = await findWalletPda(userSeed, PROGRAM_ID_DEVNET);
    const [vaultPda] = await findVaultPda(walletPda, PROGRAM_ID_DEVNET);
    const [auth1Pda, auth1Bump] = await findAuthorityPda(
      walletPda,
      key1.credentialIdHash,
      PROGRAM_ID_DEVNET,
    );

    await sendTx(ctx, [
      createCreateWalletIx({
        payer: ctx.payer.address,
        walletPda,
        vaultPda,
        authorityPda: auth1Pda,
        userSeed,
        authType: AUTH_TYPE_SECP256R1,
        authBump: auth1Bump,
        credentialOrPubkey: key1.credentialIdHash,
        secp256r1Pubkey: key1.publicKeyBytes,
        rpId: key1.rpId,
        programId: PROGRAM_ID_DEVNET,
      }),
    ]);

    const [auth2Pda] = await findAuthorityPda(
      walletPda,
      key2.credentialIdHash,
      PROGRAM_ID_DEVNET,
    );
    const slot = await getSlot(ctx);

    const rpIdBytes = new TextEncoder().encode(key2.rpId);
    const dataPayload = new Uint8Array(
      2 + 6 + 32 + 33 + 1 + rpIdBytes.length,
    );
    dataPayload[0] = AUTH_TYPE_SECP256R1;
    dataPayload[1] = ROLE_SPENDER;
    dataPayload.set(key2.credentialIdHash, 8);
    dataPayload.set(key2.publicKeyBytes, 40);
    dataPayload[73] = rpIdBytes.length;
    dataPayload.set(rpIdBytes, 74);

    const signedPayloadAdd = new Uint8Array(dataPayload.length + 32);
    signedPayloadAdd.set(dataPayload, 0);
    signedPayloadAdd.set(
      addressEncoder.encode(ctx.payer.address) as Uint8Array,
      dataPayload.length,
    );

    const prepared = prepareSecp256r1({
      discriminator: new Uint8Array([DISC_ADD_AUTHORITY]),
      signedPayload: signedPayloadAdd,
      sysvarIxIndex: 6,
      slot,
      counter: 1,
      payer: ctx.payer.address,
      programId: PROGRAM_ID_DEVNET,
      publicKeyBytes: key1.publicKeyBytes,
    });
    const response = await fakeWebAuthnSign(key1, prepared.challenge);
    const { authPayload, precompileIx } = finalizeSecp256r1(prepared, response);

    await sendTx(ctx, [
      precompileIx,
      createAddAuthorityIx({
        payer: ctx.payer.address,
        walletPda,
        adminAuthorityPda: auth1Pda,
        newAuthorityPda: auth2Pda,
        newType: AUTH_TYPE_SECP256R1,
        newRole: ROLE_SPENDER,
        credentialOrPubkey: key2.credentialIdHash,
        secp256r1Pubkey: key2.publicKeyBytes,
        rpId: key2.rpId,
        authPayload,
        programId: PROGRAM_ID_DEVNET,
      }),
    ]);

    expect(await readCounter(ctx, auth1Pda)).toBe(1);
    expect(await readCounter(ctx, auth2Pda)).toBe(0);
  });
});
