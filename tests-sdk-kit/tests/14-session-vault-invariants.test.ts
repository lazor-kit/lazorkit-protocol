/**
 * Port of tests-sdk/tests/14-session-vault-invariants.test.ts.
 *
 * H1 fix coverage — session+actions vault invariants. Programs that are
 * on the session whitelist (e.g. SystemProgram) could otherwise be used
 * to mutate the vault's owner / data_len silently, draining funds in a
 * future tx. The on-chain fix snapshots vault.owner / vault.data.len()
 * before the session-CPI loop and re-checks them after, throwing
 * 3030 (SessionVaultOwnerChanged) or 3031 (SessionVaultDataLenChanged).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import {
  AccountRole,
  generateKeyPairSigner,
  type Address,
  type IInstruction as Instruction,
  type KeyPairSigner,
} from '@solana/kit';
import {
  Actions,
  LazorKit,
  SYSTEM_PROGRAM_ADDRESS,
  ed25519,
  session,
} from '@lazorkit/sdk';
import {
  setupTest,
  sendTx,
  sendTxExpectError,
  airdrop,
  getBalance,
  getSlot,
  systemTransferFromPda,
  type TestContext,
  makeClient,
} from './common.js';

/** Raw `System::Assign { new_owner }` targeting `target` (which must sign). */
function systemAssignIx(target: Address, newOwner: Address): Instruction {
  const data = new Uint8Array(4 + 32);
  new DataView(data.buffer).setUint32(0, 1, true); // System ix 1 = Assign
  // newOwner is an Address (base58 string); convert via @solana/kit codec.
  const encoder = new TextEncoder();
  void encoder;
  // Use kit's getAddressEncoder to produce 32 raw bytes.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { getAddressEncoder } = require('@solana/kit');
  const ownerBytes = getAddressEncoder().encode(newOwner) as Uint8Array;
  data.set(ownerBytes, 4);
  return {
    programAddress: SYSTEM_PROGRAM_ADDRESS,
    accounts: [{ address: target, role: AccountRole.WRITABLE_SIGNER }],
    data,
  };
}

/** Raw `System::Allocate { space }` targeting `target` (which must sign). */
function systemAllocateIx(target: Address, space: bigint): Instruction {
  const data = new Uint8Array(4 + 8);
  new DataView(data.buffer).setUint32(0, 8, true); // System ix 8 = Allocate
  new DataView(data.buffer).setBigUint64(4, space, true);
  return {
    programAddress: SYSTEM_PROGRAM_ADDRESS,
    accounts: [{ address: target, role: AccountRole.WRITABLE_SIGNER }],
    data,
  };
}

describe('H1 — Session vault invariants', () => {
  let ctx: TestContext;
  let client: LazorKit;
  let walletPda: Address;
  let vaultPda: Address;
  let ownerSigner: KeyPairSigner;
  let ownerAuthPda: Address;

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);
    ownerSigner = await generateKeyPairSigner();
    const result = await client.createWallet({
      payer: ctx.payer.address,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'ed25519', publicKey: ownerSigner.address },
    });
    walletPda = result.walletPda;
    vaultPda = result.vaultPda;
    ownerAuthPda = result.authorityPda;
    await sendTx(ctx, result.instructions);
    await airdrop(ctx, vaultPda, 5n * 1_000_000_000n);
  });

  async function createLockedDownSession(): Promise<{
    sessionSigner: KeyPairSigner;
    sessionPda: Address;
  }> {
    const sessionSigner = await generateKeyPairSigner();
    const currentSlot = await getSlot(ctx);
    const { instructions, sessionPda } = await client.createSession({
      payer: ctx.payer.address,
      walletPda,
      adminSigner: ed25519(ownerSigner.address, ownerAuthPda),
      sessionKey: sessionSigner.address,
      expiresAt: currentSlot + 9000n,
      actions: [
        Actions.programWhitelist(SYSTEM_PROGRAM_ADDRESS),
        Actions.solMaxPerTx(100_000_000n),
        Actions.solLimit(1_000_000_000n),
      ],
    });
    await sendTx(ctx, instructions, [ownerSigner]);
    return { sessionSigner, sessionPda };
  }

  it('allows a normal SOL transfer via the locked-down session', async () => {
    const { sessionSigner, sessionPda } = await createLockedDownSession();
    const recipient = (await generateKeyPairSigner()).address;
    const { instructions } = await client.execute({
      payer: ctx.payer.address,
      walletPda,
      signer: session(sessionPda, sessionSigner.address),
      instructions: [systemTransferFromPda(vaultPda, recipient, 90_000_000n)],
    });

    const before = await getBalance(ctx, recipient);
    await sendTx(ctx, instructions, [sessionSigner]);
    const after = await getBalance(ctx, recipient);
    expect(after - before).toBe(90_000_000n);
  });

  it('rejects System::Assign on vault (error 3030 SessionVaultOwnerChanged)', async () => {
    const { sessionSigner, sessionPda } = await createLockedDownSession();
    const attackerProgram = (await generateKeyPairSigner()).address;
    const { instructions } = await client.execute({
      payer: ctx.payer.address,
      walletPda,
      signer: session(sessionPda, sessionSigner.address),
      instructions: [systemAssignIx(vaultPda, attackerProgram)],
    });
    await sendTxExpectError(ctx, instructions, [sessionSigner], 3030);
  });

  it('rejects System::Allocate on vault (error 3031 SessionVaultDataLenChanged)', async () => {
    const { sessionSigner, sessionPda } = await createLockedDownSession();
    const { instructions } = await client.execute({
      payer: ctx.payer.address,
      walletPda,
      signer: session(sessionPda, sessionSigner.address),
      instructions: [systemAllocateIx(vaultPda, 1024n)],
    });
    await sendTxExpectError(ctx, instructions, [sessionSigner], 3031);
  });

  it('vault owner and data_len remain unchanged after attack attempts', async () => {
    const info = await ctx.rpc
      .getAccountInfo(vaultPda, { encoding: 'base64' })
      .send();
    expect(info.value).not.toBeNull();
    expect(info.value!.owner).toBe(SYSTEM_PROGRAM_ADDRESS);
    const dataBytes = new Uint8Array(
      Buffer.from(info.value!.data[0], 'base64'),
    );
    expect(dataBytes.length).toBe(0);
  });
});
