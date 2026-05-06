/**
 * Port of tests-sdk/tests/05-replay.test.ts.
 *
 * Verifies the on-chain odometer (Secp256r1 counter) prevents replay
 * by exercising sequential counters, behind-stored counters, ahead-jumps,
 * and stale-after-sequential. Operates at low level — bypasses
 * client.execute / prepareExecute and constructs the Secp256r1 path
 * manually so an off-by-one counter can be injected.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  AccountRole,
  generateKeyPairSigner,
  type AccountMeta,
  type Address,
} from '@solana/kit';
import {
  AUTH_TYPE_SECP256R1,
  DISC_EXECUTE,
  PROGRAM_ID_DEVNET,
  computeAccountsHash,
  createCreateWalletIx,
  createExecuteIx,
  finalizeSecp256r1,
  findAuthorityPda,
  findVaultPda,
  findWalletPda,
  packCompactInstructions,
  prepareSecp256r1,
  SYSTEM_PROGRAM_ADDRESS,
} from '@lazorkit/sdk';
import {
  setupTest,
  sendTx,
  sendTxExpectError,
  airdrop,
  getSlot,
  type TestContext,
} from './common.js';
import {
  generateMockSecp256r1Key,
  fakeWebAuthnSign,
} from './secp256r1Utils.js';

describe('Replay Prevention (Odometer)', () => {
  let ctx: TestContext;
  let walletPda: Address;
  let vaultPda: Address;
  let ownerKey: Awaited<ReturnType<typeof generateMockSecp256r1Key>>;
  let ownerAuthorityPda: Address;

  // Compact ix: System Transfer (programIdIndex=5, accounts=[3 vault, 6 recipient])
  const compactIxDef = [
    {
      programIdIndex: 5,
      accountIndexes: [3, 6],
      data: (() => {
        const d = new Uint8Array(12);
        new DataView(d.buffer).setUint32(0, 2, true);
        new DataView(d.buffer).setBigUint64(4, 1_000_000n, true);
        return d;
      })(),
    },
  ];

  function buildTransferPacked() {
    return packCompactInstructions(compactIxDef);
  }

  async function buildExecuteIx(counter: number, packed: Uint8Array) {
    const slot = await getSlot(ctx);
    const recipient = (await generateKeyPairSigner()).address;

    const accountMetas: AccountMeta[] = [
      { address: ctx.payer.address, role: AccountRole.READONLY_SIGNER },
      { address: walletPda, role: AccountRole.READONLY },
      { address: ownerAuthorityPda, role: AccountRole.WRITABLE },
      { address: vaultPda, role: AccountRole.WRITABLE },
      // Sysvar instructions placeholder (default address; index 4 in fixed
      // accounts but is the SYSVAR address in real txs — for hash purposes
      // its specific value doesn't matter since the program uses it for
      // index lookup, not hashing — same approach as the legacy test.)
      { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
      { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
      { address: recipient, role: AccountRole.WRITABLE },
    ];
    const accountsHash = computeAccountsHash(accountMetas, compactIxDef);
    const signedPayload = new Uint8Array(packed.length + accountsHash.length);
    signedPayload.set(packed, 0);
    signedPayload.set(accountsHash, packed.length);

    const prepared = prepareSecp256r1({
      discriminator: new Uint8Array([DISC_EXECUTE]),
      signedPayload,
      sysvarIxIndex: 4,
      slot,
      counter,
      payer: ctx.payer.address,
      programId: PROGRAM_ID_DEVNET,
      publicKeyBytes: ownerKey.publicKeyBytes,
    });
    const response = await fakeWebAuthnSign(ownerKey, prepared.challenge);
    const { authPayload, precompileIx } = finalizeSecp256r1(prepared, response);

    const ix = createExecuteIx({
      payer: ctx.payer.address,
      walletPda,
      authorityPda: ownerAuthorityPda,
      vaultPda,
      packedInstructions: packed,
      authPayload,
      remainingAccounts: [
        { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
        { address: recipient, role: AccountRole.WRITABLE },
      ],
      programId: PROGRAM_ID_DEVNET,
    });
    return { precompileIx, ix };
  }

  beforeAll(async () => {
    ctx = await setupTest();
    ownerKey = await generateMockSecp256r1Key();
    const userSeed = crypto.randomBytes(32);

    [walletPda] = await findWalletPda(userSeed, PROGRAM_ID_DEVNET);
    [vaultPda] = await findVaultPda(walletPda, PROGRAM_ID_DEVNET);
    const [authPda, authBump] = await findAuthorityPda(
      walletPda,
      ownerKey.credentialIdHash,
      PROGRAM_ID_DEVNET,
    );
    ownerAuthorityPda = authPda;

    await sendTx(ctx, [
      createCreateWalletIx({
        payer: ctx.payer.address,
        walletPda,
        vaultPda,
        authorityPda: authPda,
        userSeed,
        authType: AUTH_TYPE_SECP256R1,
        authBump,
        credentialOrPubkey: ownerKey.credentialIdHash,
        secp256r1Pubkey: ownerKey.publicKeyBytes,
        rpId: ownerKey.rpId,
        programId: PROGRAM_ID_DEVNET,
      }),
    ]);

    await airdrop(ctx, vaultPda, 5n * 1_000_000_000n);
  });

  async function readCounterAtOffset8(): Promise<number> {
    const info = await ctx.rpc
      .getAccountInfo(ownerAuthorityPda, { encoding: 'base64' })
      .send();
    const bytes = new Uint8Array(Buffer.from(info.value!.data[0], 'base64'));
    return new DataView(bytes.buffer, bytes.byteOffset).getUint32(8, true);
  }

  it('accepts counter=1 for fresh authority (stored=0)', async () => {
    const packed = buildTransferPacked();
    const { precompileIx, ix } = await buildExecuteIx(1, packed);
    await sendTx(ctx, [precompileIx, ix]);
    expect(await readCounterAtOffset8()).toBe(1);
  });

  it('rejects same counter=1 replay (SignatureReused 3006)', async () => {
    const packed = buildTransferPacked();
    const a = await buildExecuteIx(1, packed);
    const b = await buildExecuteIx(1, packed);
    void b;
    await sendTxExpectError(ctx, [a.precompileIx, a.ix], [], 3006);
  });

  it('rejects counter=0 (behind stored)', async () => {
    const packed = buildTransferPacked();
    const a = await buildExecuteIx(0, packed);
    await sendTxExpectError(ctx, [a.precompileIx, a.ix], [], 3006);
  });

  it('rejects counter=5 (skipping ahead)', async () => {
    const packed = buildTransferPacked();
    const a = await buildExecuteIx(5, packed);
    await sendTxExpectError(ctx, [a.precompileIx, a.ix], [], 3006);
  });

  it('accepts sequential counter 2, 3, 4', async () => {
    for (const c of [2, 3, 4]) {
      const packed = buildTransferPacked();
      const { precompileIx, ix } = await buildExecuteIx(c, packed);
      await sendTx(ctx, [precompileIx, ix]);
    }
    expect(await readCounterAtOffset8()).toBe(4);
  });

  it('rejects stale counter after sequential ops', async () => {
    const packed = buildTransferPacked();
    const a = await buildExecuteIx(3, packed);
    await sendTxExpectError(ctx, [a.precompileIx, a.ix], [], 3006);
  });
});
