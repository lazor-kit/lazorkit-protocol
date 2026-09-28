/**
 * Port of tests-sdk/tests/17-ownership.test.ts (validator half).
 *
 * Which wallet a returning passkey user owns, against the real program:
 *   - findPasskeyWalletCandidates → verifyOwnershipProof → describeWalletCandidates
 *   - what makes a wallet shared (another authority, a live session, any
 *     pending deferred execution, a vault handed to another program, a
 *     delegate or foreign owner on the vault's token accounts) and what does
 *     not (trusted keys)
 *   - the attacks behind those: an owner with no policy rigs the vault or
 *     queues a drain, then hands the wallet to the victim's real passkey
 *   - what is never a candidate (Admin rank, another relying party) and what is
 *     found but never proven (the victim's hash next to someone else's key)
 *   - the same rigged wallets as a v1 migration's destination:
 *     vetMigrationDestination refuses each one, and says why
 *   - what the chain cannot show unasked: a handed-away token account for a
 *     mint outside the watched ones, found only through `watchMints` — and
 *     why only a wallet the passkey has signed for is adopted
 *     (`signatureCount`): the user's own new wallet is offered until its
 *     first transaction, and a spotless, richer planted one never outranks it
 *   - why only the *one* wallet signed for is adopted: the passkey challenge
 *     does not name the wallet, so the victim's first signature replays onto
 *     a planted wallet and raises its count too
 *   - why a migration creates a destination wallet whose address holds only
 *     lamports: CreateWallet builds over them, for whoever runs it first
 *
 * The pure rules and the RPC contract are unit-tested in
 * sdk/sdk-kit/tests/ownership.test.ts.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'node:crypto';
import { getCreateAccountInstruction } from '@solana-program/system';
import {
  AccountRole,
  generateKeyPairSigner,
  getAddressEncoder,
  type Address,
  type Instruction,
  type KeyPairSigner,
} from '@solana/kit';
import {
  Actions,
  LazorKit,
  ROLE_ADMIN,
  ROLE_OWNER,
  SYSTEM_PROGRAM_ADDRESS,
  TOKEN_PROGRAM_ADDRESS,
  createAssociatedTokenAccountIdempotentIx,
  createOwnershipChallenge,
  ed25519,
  getAssociatedTokenAddress,
  secp256r1,
  selectWalletByAddress,
  verifyOwnershipProof,
  type OwnershipProof,
} from '@lazorkit/sdk';
import {
  PROGRAM_ID,
  airdrop,
  getBalance,
  getSlot,
  makeClient,
  sendTx,
  setupTest,
  systemTransferFromPda,
  type TestContext,
} from './common.js';
import {
  createMockSigner,
  fakeWebAuthnSign,
  generateMockSecp256r1Key,
  type MockSecp256r1Key,
} from './secp256r1Utils.js';

const RP_ID = 'example.com';
/** The native mint: present on every validator, and one of the watched mints. */
const WSOL = 'So11111111111111111111111111111111111111112' as Address;
const addressEncoder = getAddressEncoder();

/** `System::Assign { new_owner }` of `target`, which must sign. */
function systemAssignIx(target: Address, newOwner: Address): Instruction {
  const data = new Uint8Array(36);
  new DataView(data.buffer).setUint32(0, 1, true); // Assign
  data.set(addressEncoder.encode(newOwner), 4);
  return {
    programAddress: SYSTEM_PROGRAM_ADDRESS,
    accounts: [{ address: target, role: AccountRole.WRITABLE_SIGNER }],
    data,
  };
}

/** SPL Token `Approve`: `delegate` may move up to `amount` out of `account`. */
function tokenApproveIx(account: Address, delegate: Address, owner: Address, amount: bigint): Instruction {
  const data = new Uint8Array(9);
  data[0] = 4;
  new DataView(data.buffer).setBigUint64(1, amount, true);
  return {
    programAddress: TOKEN_PROGRAM_ADDRESS,
    accounts: [
      { address: account, role: AccountRole.WRITABLE },
      { address: delegate, role: AccountRole.READONLY },
      { address: owner, role: AccountRole.READONLY_SIGNER },
    ],
    data,
  };
}

/** SPL Token `MintTo`: `amount` of `mint` into `account`, signed by the mint authority. */
function tokenMintToIx(mint: Address, account: Address, mintAuthority: Address, amount: bigint): Instruction {
  const data = new Uint8Array(9);
  data[0] = 7;
  new DataView(data.buffer).setBigUint64(1, amount, true);
  return {
    programAddress: TOKEN_PROGRAM_ADDRESS,
    accounts: [
      { address: mint, role: AccountRole.WRITABLE },
      { address: account, role: AccountRole.WRITABLE },
      { address: mintAuthority, role: AccountRole.READONLY_SIGNER },
    ],
    data,
  };
}

/** SPL Token `Transfer` of `amount` from `source` to `destination`, signed by the source's owner. */
function tokenTransferIx(source: Address, destination: Address, owner: Address, amount: bigint): Instruction {
  const data = new Uint8Array(9);
  data[0] = 3;
  new DataView(data.buffer).setBigUint64(1, amount, true);
  return {
    programAddress: TOKEN_PROGRAM_ADDRESS,
    accounts: [
      { address: source, role: AccountRole.WRITABLE },
      { address: destination, role: AccountRole.WRITABLE },
      { address: owner, role: AccountRole.READONLY_SIGNER },
    ],
    data,
  };
}

/** SPL Token `SetAuthority` on a token account: 2 = AccountOwner, 3 = CloseAccount. */
function tokenSetAuthorityIx(
  account: Address,
  current: Address,
  authorityType: 2 | 3,
  newAuthority: Address,
): Instruction {
  const data = new Uint8Array(35);
  data[0] = 6;
  data[1] = authorityType;
  data[2] = 1; // Some
  data.set(addressEncoder.encode(newAuthority), 3);
  return {
    programAddress: TOKEN_PROGRAM_ADDRESS,
    accounts: [
      { address: account, role: AccountRole.WRITABLE },
      { address: current, role: AccountRole.READONLY_SIGNER },
    ],
    data,
  };
}

describe('passkey wallet ownership (validator)', () => {
  let ctx: TestContext;
  let client: LazorKit;

  async function createPasskeyWallet(key: MockSecp256r1Key, compressedPubkey = key.publicKeyBytes) {
    const result = await client.createWallet({
      payer: ctx.payer.address,
      userSeed: crypto.randomBytes(32),
      owner: {
        type: 'secp256r1',
        credentialIdHash: key.credentialIdHash,
        compressedPubkey,
        rpId: key.rpId,
      },
    });
    await sendTx(ctx, result.instructions);
    return result;
  }

  /** Receives the lamport `signOnce` moves; funded in beforeAll, so one lamport is no rent problem. */
  let sink: Address;

  /** The passkey signs one Execute on the wallet: a lamport out of its (funded) vault. */
  async function signOnce(key: MockSecp256r1Key, walletPda: Address, vaultPda: Address) {
    const { instructions } = await client.execute({
      payer: ctx.payer.address,
      walletPda,
      signer: secp256r1(createMockSigner(key)),
      instructions: [systemTransferFromPda(vaultPda, sink, 1n)],
    });
    await sendTx(ctx, instructions);
  }

  /** A passkey wallet its passkey has used: funded, and signed for once. */
  async function createUsedPasskeyWallet(key: MockSecp256r1Key) {
    const created = await createPasskeyWallet(key);
    await airdrop(ctx, created.vaultPda, 2_000_000n);
    await signOnce(key, created.walletPda, created.vaultPda);
    return created;
  }

  async function proofFrom(key: MockSecp256r1Key): Promise<OwnershipProof> {
    const challenge = createOwnershipChallenge();
    const response = await fakeWebAuthnSign(key, challenge);
    return {
      challenge,
      signature: response.signature,
      authenticatorData: response.authenticatorData,
      clientDataJson: response.clientDataJson,
    };
  }

  async function executeAs(owner: KeyPairSigner, walletPda: Address, instructions: Instruction[]) {
    const executed = await client.execute({
      payer: ctx.payer.address,
      walletPda,
      signer: ed25519(owner.address),
      instructions,
    });
    await sendTx(ctx, executed.instructions, [owner]);
  }

  /**
   * A wallet an attacker creates under their own Ed25519 key, rigs with
   * `rig` while they own it, then hands to the victim's real passkey with
   * TransferOwnership — which asks the new owner nothing. What is left has
   * one authority, the victim's, at Owner rank: by the authorities alone it
   * is theirs.
   */
  async function handedOver(
    victim: MockSecp256r1Key,
    rig: (w: { walletPda: Address; vaultPda: Address; attacker: KeyPairSigner }) => Promise<void>,
  ) {
    const attacker = await generateKeyPairSigner();
    const created = await client.createWallet({
      payer: ctx.payer.address,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'ed25519', publicKey: attacker.address },
    });
    await sendTx(ctx, created.instructions);
    await rig({ walletPda: created.walletPda, vaultPda: created.vaultPda, attacker });
    const handed = await client.transferOwnership({
      payer: ctx.payer.address,
      walletPda: created.walletPda,
      ownerSigner: ed25519(attacker.address),
      newOwner: {
        type: 'secp256r1',
        credentialIdHash: victim.credentialIdHash,
        compressedPubkey: victim.publicKeyBytes,
        rpId: RP_ID,
      },
    });
    await sendTx(ctx, handed.instructions, [attacker]);
    return { ...created, attacker, victimAuthorityPda: handed.newOwnerAuthorityPda };
  }

  /** A fresh SPL Token mint (6 decimals, no freeze authority): outside the SDK's watched mints. */
  async function createSplMint(): Promise<Address> {
    const mint = await generateKeyPairSigner();
    const initializeMint2 = new Uint8Array(35);
    initializeMint2[0] = 20;
    initializeMint2[1] = 6;
    initializeMint2.set(addressEncoder.encode(ctx.payer.address), 2);
    // [34] = 0: no freeze authority.
    await sendTx(
      ctx,
      [
        getCreateAccountInstruction({
          payer: ctx.payer,
          newAccount: mint,
          lamports: 10_000_000n,
          space: 82n,
          programAddress: TOKEN_PROGRAM_ADDRESS,
        }),
        {
          programAddress: TOKEN_PROGRAM_ADDRESS,
          accounts: [{ address: mint.address, role: AccountRole.WRITABLE }],
          data: initializeMint2,
        },
      ],
      [mint],
    );
    return mint.address;
  }

  /** The passkey as a migration owner: vetMigrationDestination checks all of it. */
  const passkeyOwner = (key: MockSecp256r1Key) => ({
    type: 'secp256r1' as const,
    credentialIdHash: key.credentialIdHash,
    compressedPubkey: key.publicKeyBytes,
    rpId: key.rpId,
  });

  /** The victim signs in: their only wallet is the one handed to them. */
  async function offeredToVictim(victim: MockSecp256r1Key, walletPda: Address) {
    const own = await client.findOwnPasskeyWallet({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(victim),
    });
    expect(own.adopt).toBeNull();
    expect(own.unproven).toBe(0);
    expect(own.needsConfirmation.map((f) => f.walletPda)).toEqual([walletPda]);
    const f = own.needsConfirmation[0]!;
    // No other authority and no session: only the vault gives it away.
    expect(f.otherAuthorities).toEqual([]);
    expect(f.liveSessions).toEqual([]);
    return f;
  }

  beforeAll(async () => {
    ctx = await setupTest();
    client = makeClient(ctx.rpc as never);
    sink = (await generateKeyPairSigner()).address;
    await airdrop(ctx, sink, 1_000_000n);
  });

  describe('one passkey wallet, as others gain a way to spend from it', () => {
    let key: MockSecp256r1Key;
    let walletPda: Address;
    let vaultPda: Address;
    let authorityPda: Address;
    let admin: KeyPairSigner;
    let sessionKey: KeyPairSigner;

    beforeAll(async () => {
      key = await generateMockSecp256r1Key(RP_ID);
      admin = await generateKeyPairSigner();
      sessionKey = await generateKeyPairSigner();
      ({ walletPda, vaultPda, authorityPda } = await createPasskeyWallet(key));
      await airdrop(ctx, vaultPda, 25_000_000n);
    });

    it('finds it, verifies a real assertion against it, and adopts it once the passkey has signed for it', async () => {
      const candidates = await client.findPasskeyWalletCandidates({
        credentialIdHash: key.credentialIdHash,
        rpId: RP_ID,
      });
      expect(candidates).toHaveLength(1);
      const c = candidates[0]!;
      expect(c.version).toBe(2);
      expect(c.programId).toBe(PROGRAM_ID);
      expect(c.walletPda).toBe(walletPda);
      expect(c.vaultPda).toBe(vaultPda);
      expect(c.authorityPda).toBe(authorityPda);
      expect(Buffer.from(c.publicKey)).toEqual(Buffer.from(key.publicKeyBytes));

      const proof = await proofFrom(key);
      expect(verifyOwnershipProof(candidates, proof, RP_ID)).toEqual(candidates);

      const [f] = await client.describeWalletCandidates(candidates);
      expect(f!.controlledAlone).toBe(true);
      expect(f!.otherAuthorities).toEqual([]);
      expect(f!.liveSessions).toEqual([]);
      expect(f!.pendingDeferred).toEqual([]);
      expect(f!.vaultIsSystemAccount).toBe(true);
      expect(f!.tokenGrants).toEqual([]);
      expect(f!.lamports).toBe(await getBalance(ctx, vaultPda));
      expect(f!.slot > 0n).toBe(true);
      expect(f!.signatureCount).toBe(0);

      // Created and not used yet: offered, not adopted. A wallet someone
      // handed to this passkey would look exactly the same.
      const fresh = await client.findOwnPasskeyWallet({
        credentialIdHash: key.credentialIdHash,
        rpId: RP_ID,
        proof,
      });
      expect(fresh.adopt).toBeNull();
      expect(fresh.needsConfirmation.map((x) => x.walletPda)).toEqual([walletPda]);
      expect(fresh.unproven).toBe(0);
      // A v1 migration may deliver into it when named (it would not pick it by itself).
      expect(await client.vetMigrationDestination(walletPda, passkeyOwner(key))).toBeNull();

      await signOnce(key, walletPda, vaultPda);
      const own = await client.findOwnPasskeyWallet({
        credentialIdHash: key.credentialIdHash,
        rpId: RP_ID,
        proof: await proofFrom(key),
      });
      expect(own.adopt?.walletPda).toBe(walletPda);
      expect(own.adopt?.signatureCount).toBe(1);
      expect(own.needsConfirmation).toEqual([]);
      expect(own.unproven).toBe(0);
    });

    it('an Ed25519 admin makes it shared — unless the integrator trusts that key', async () => {
      const { instructions } = await client.addAuthority({
        payer: ctx.payer.address,
        walletPda,
        adminSigner: secp256r1(createMockSigner(key)),
        newAuthority: { type: 'ed25519', publicKey: admin.address },
        role: ROLE_ADMIN,
      });
      await sendTx(ctx, instructions);

      const candidates = await client.findPasskeyWalletCandidates({
        credentialIdHash: key.credentialIdHash,
        rpId: RP_ID,
      });
      const [shared] = await client.describeWalletCandidates(candidates);
      expect(shared!.controlledAlone).toBe(false);
      expect(shared!.otherAuthorities).toHaveLength(1);
      expect(shared!.otherAuthorities[0]).toMatchObject({
        type: 'ed25519',
        role: 'admin',
        publicKey: admin.address,
        trusted: false,
      });

      const [trusted] = await client.describeWalletCandidates(candidates, {
        trustedKeys: [admin.address],
      });
      expect(trusted!.controlledAlone).toBe(true);
      expect(trusted!.otherAuthorities[0]!.trusted).toBe(true);
      // A migration trusts no one: it must land where only this passkey reaches.
      expect(await client.vetMigrationDestination(walletPda, passkeyOwner(key))).toBe(
        `wallet ${walletPda} has 2 authorities; a migration destination must have only its owner`,
      );
    });

    it('a live session makes it shared — unless its key is trusted too', async () => {
      const expiresAt = (await getSlot(ctx)) + 9_000n;
      const { instructions, sessionPda } = await client.createSession({
        payer: ctx.payer.address,
        walletPda,
        adminSigner: ed25519(admin.address),
        sessionKey: sessionKey.address,
        expiresAt,
        actions: [Actions.solLimit(1_000_000n)],
      });
      await sendTx(ctx, instructions, [admin]);

      const candidates = await client.findPasskeyWalletCandidates({
        credentialIdHash: key.credentialIdHash,
        rpId: RP_ID,
      });
      const [withSession] = await client.describeWalletCandidates(candidates, {
        trustedKeys: [admin.address],
      });
      expect(withSession!.liveSessions).toEqual([
        { sessionPda, sessionKey: sessionKey.address, expiresAtSlot: expiresAt, trusted: false },
      ]);
      expect(withSession!.controlledAlone).toBe(false);

      const [trusted] = await client.describeWalletCandidates(candidates, {
        trustedKeys: [admin.address, sessionKey.address as string],
      });
      expect(trusted!.liveSessions[0]!.trusted).toBe(true);
      expect(trusted!.controlledAlone).toBe(true);
    });

    it('findOwnPasskeyWallet then asks the user instead of adopting it', async () => {
      const own = await client.findOwnPasskeyWallet({
        credentialIdHash: key.credentialIdHash,
        rpId: RP_ID,
        proof: await proofFrom(key),
      });
      expect(own.adopt).toBeNull();
      expect(own.needsConfirmation.map((f) => f.walletPda)).toEqual([walletPda]);
      // The user names it by the vault, the address they know.
      expect(selectWalletByAddress(own.needsConfirmation, vaultPda)?.walletPda).toBe(walletPda);

      const trusting = await client.findOwnPasskeyWallet({
        credentialIdHash: key.credentialIdHash,
        rpId: RP_ID,
        proof: await proofFrom(key),
        trustedKeys: [admin.address, sessionKey.address],
      });
      expect(trusting.adopt?.walletPda).toBe(walletPda);
    });
  });

  it('a pending deferred execution makes it shared, even one its own authority authorized', async () => {
    // The chain cannot tell this passkey's own tx1 from one an earlier key at
    // the same address queued (next test), so the user is asked — once, for
    // at most ~9000 slots.
    const key = await generateMockSecp256r1Key(RP_ID);
    const { walletPda, vaultPda, authorityPda } = await createPasskeyWallet(key);
    await airdrop(ctx, vaultPda, 10_000_000n);
    const recipient = (await generateKeyPairSigner()).address;
    const authorized = await client.authorize({
      payer: ctx.payer.address,
      walletPda,
      signer: secp256r1(createMockSigner(key)),
      instructions: [systemTransferFromPda(vaultPda, recipient, 1_000_000n)],
      expiryOffset: 9_000,
    });
    await sendTx(ctx, authorized.instructions);

    const own = await client.findOwnPasskeyWallet({
      credentialIdHash: key.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(key),
    });
    expect(own.adopt).toBeNull();
    expect(own.needsConfirmation.map((f) => f.walletPda)).toEqual([walletPda]);
    // Signed for (the authorize), and still not adopted: both conditions hold or neither counts.
    expect(own.needsConfirmation[0]!.signatureCount).toBe(1);
    expect(own.needsConfirmation[0]!.pendingDeferred).toHaveLength(1);
    expect(own.needsConfirmation[0]!.pendingDeferred[0]).toMatchObject({
      deferredPda: authorized.deferredExecPda,
      authorizedBy: authorityPda,
      trusted: false,
    });
    expect(await client.vetMigrationDestination(walletPda, passkeyOwner(key))).toBe(
      `wallet ${walletPda} has a pending deferred execution`,
    );
  });

  it('a drain queued under the passkey’s authority address by an earlier key is not adopted — and still runs', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    // The attacker's own P-256 key, listed under the victim's (public)
    // credential-id hash: the same authority address the victim's key gets.
    const impostor = await generateMockSecp256r1Key(RP_ID, victim.credentialIdHash);
    const thief = (await generateKeyPairSigner()).address;
    let queued!: Awaited<ReturnType<LazorKit['authorize']>>;
    let impostorPda!: Address;

    const w = await handedOver(victim, async ({ walletPda, vaultPda, attacker }) => {
      await airdrop(ctx, vaultPda, 20_000_000n);
      const added = await client.addAuthority({
        payer: ctx.payer.address,
        walletPda,
        adminSigner: ed25519(attacker.address),
        newAuthority: {
          type: 'secp256r1',
          credentialIdHash: victim.credentialIdHash,
          compressedPubkey: impostor.publicKeyBytes,
          rpId: RP_ID,
        },
        role: ROLE_ADMIN,
      });
      await sendTx(ctx, added.instructions, [attacker]);
      impostorPda = added.newAuthorityPda;
      queued = await client.authorize({
        payer: ctx.payer.address,
        walletPda,
        signer: secp256r1(createMockSigner(impostor)),
        instructions: [systemTransferFromPda(vaultPda, thief, 10_000_000n)],
        expiryOffset: 9_000,
      });
      await sendTx(ctx, queued.instructions);
      // Clear the address, so TransferOwnership can put the victim's key there.
      const removed = await client.removeAuthority({
        payer: ctx.payer.address,
        walletPda,
        adminSigner: ed25519(attacker.address),
        targetAuthorityPda: impostorPda,
      });
      await sendTx(ctx, removed.instructions, [attacker]);
    });
    expect(w.victimAuthorityPda).toBe(impostorPda);

    const f = await offeredToVictim(victim, w.walletPda);
    expect(f.pendingDeferred).toEqual([
      {
        deferredPda: queued.deferredExecPda,
        authorizedBy: w.victimAuthorityPda,
        expiresAtSlot: expect.any(BigInt),
        trusted: false,
      },
    ]);

    // Why: ExecuteDeferred checks the hashes and the expiry, never the key now
    // at that address. Anyone can still run it.
    const run = await client.executeDeferredFromPayload({
      payer: ctx.payer.address,
      deferredPayload: queued.deferredPayload,
    });
    await sendTx(ctx, run.instructions);
    expect(await getBalance(ctx, thief)).toBe(10_000_000n);
  });

  it('a vault its former owner handed to another program is only ever offered', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const attackerProgram = (await generateKeyPairSigner()).address;
    const w = await handedOver(victim, async ({ walletPda, vaultPda, attacker }) => {
      await airdrop(ctx, vaultPda, 5_000_000n);
      // An Owner with no policy: nothing checks the vault's owner after its CPIs.
      await executeAs(attacker, walletPda, [systemAssignIx(vaultPda, attackerProgram)]);
    });
    const vault = await ctx.rpc.getAccountInfo(w.vaultPda, { encoding: 'base64' }).send();
    expect(vault.value!.owner).toBe(attackerProgram);

    const f = await offeredToVictim(victim, w.walletPda);
    expect(f.pendingDeferred).toEqual([]);
    expect(f.tokenGrants).toEqual([]);
    expect(f.vaultIsSystemAccount).toBe(false);
    expect(f.controlledAlone).toBe(false);
    // By its authorities alone the victim's — but no migration may land there.
    expect(await client.vetMigrationDestination(w.walletPda, passkeyOwner(victim))).toBe(
      `wallet ${w.walletPda}'s vault ${w.vaultPda} is owned by program ${attackerProgram}, not the System Program`,
    );
  });

  it('a delegate or close authority left on a vault token account makes it shared — unless trusted', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const spender = (await generateKeyPairSigner()).address;
    let ata!: Address;
    const w = await handedOver(victim, async ({ walletPda, vaultPda, attacker }) => {
      ata = await getAssociatedTokenAddress(WSOL, vaultPda, TOKEN_PROGRAM_ADDRESS);
      await sendTx(ctx, [
        createAssociatedTokenAccountIdempotentIx({
          payer: ctx.payer.address,
          ata,
          owner: vaultPda,
          mint: WSOL,
          tokenProgram: TOKEN_PROGRAM_ADDRESS,
        }),
      ]);
      await executeAs(attacker, walletPda, [
        tokenApproveIx(ata, spender, vaultPda, 0xffff_ffff_ffff_ffffn),
        tokenSetAuthorityIx(ata, vaultPda, 3, spender),
      ]);
    });

    const f = await offeredToVictim(victim, w.walletPda);
    expect(f.vaultIsSystemAccount).toBe(true);
    expect(f.tokenGrants).toEqual([
      { tokenAccount: ata, tokenProgram: TOKEN_PROGRAM_ADDRESS, mint: WSOL, kind: 'delegate', grantee: spender, trusted: false },
      { tokenAccount: ata, tokenProgram: TOKEN_PROGRAM_ADDRESS, mint: WSOL, kind: 'closeAuthority', grantee: spender, trusted: false },
    ]);

    // An integrator's own delegate is declared like any other trusted key: it
    // clears the facts. A wallet handed to this passkey is still only offered,
    // as it has never signed for it.
    const trusting = await client.findOwnPasskeyWallet({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(victim),
      trustedKeys: [spender],
    });
    expect(trusting.adopt).toBeNull();
    expect(trusting.needsConfirmation).toHaveLength(1);
    expect(trusting.needsConfirmation[0]).toMatchObject({
      walletPda: w.walletPda,
      controlledAlone: true,
      signatureCount: 0,
    });
    // A migration trusts no delegate.
    expect(await client.vetMigrationDestination(w.walletPda, passkeyOwner(victim))).toBe(
      `wallet ${w.walletPda}'s vault token account ${ata} has a delegate, ${spender}`,
    );
  });

  it('the vault’s wSOL account handed to another owner is only ever offered', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    let ata!: Address;
    const w = await handedOver(victim, async ({ walletPda, vaultPda, attacker }) => {
      ata = await getAssociatedTokenAddress(WSOL, vaultPda, TOKEN_PROGRAM_ADDRESS);
      await sendTx(ctx, [
        createAssociatedTokenAccountIdempotentIx({
          payer: ctx.payer.address,
          ata,
          owner: vaultPda,
          mint: WSOL,
          tokenProgram: TOKEN_PROGRAM_ADDRESS,
        }),
      ]);
      // No longer listed as the vault's — but it is still the address a sender
      // derives for the vault's wSOL, and the attacker now owns it.
      await executeAs(attacker, walletPda, [tokenSetAuthorityIx(ata, vaultPda, 2, attacker.address)]);
    });

    const f = await offeredToVictim(victim, w.walletPda);
    expect(f.tokenGrants).toEqual([
      { tokenAccount: ata, tokenProgram: TOKEN_PROGRAM_ADDRESS, mint: WSOL, kind: 'owner', grantee: w.attacker.address, trusted: false },
    ]);
    expect(f.controlledAlone).toBe(false);
    expect(await client.vetMigrationDestination(w.walletPda, passkeyOwner(victim))).toBe(
      `wallet ${w.walletPda}'s vault token account ${ata} (the vault's own account for mint ${WSOL}) belongs to ${w.attacker.address}`,
    );
  });

  // What the chain cannot show without being told the mint: once handed away,
  // an associated token account no longer lists as the vault's and nothing in
  // it names the vault. Only a caller who names the mint (watchMints) finds it
  // — and only the missing signature keeps such a wallet from being adopted.
  it("a wallet handed over with an unwatched mint's token account moved away looks clean, and is not adopted over the one the passkey signed for", async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const real = await createUsedPasskeyWallet(victim);
    const realBalance = await getBalance(ctx, real.vaultPda);

    // An SPL Token mint other than the four watched ones (a JUP, a BONK, an
    // app's own token): its canonical vault account is moved to the attacker.
    const mint = await createSplMint();
    let ata!: Address;
    const w = await handedOver(victim, async ({ walletPda, vaultPda, attacker }) => {
      ata = await getAssociatedTokenAddress(mint, vaultPda, TOKEN_PROGRAM_ADDRESS);
      await sendTx(ctx, [
        createAssociatedTokenAccountIdempotentIx({
          payer: ctx.payer.address,
          ata,
          owner: vaultPda,
          mint,
          tokenProgram: TOKEN_PROGRAM_ADDRESS,
        }),
      ]);
      await executeAs(attacker, walletPda, [tokenSetAuthorityIx(ata, vaultPda, 2, attacker.address)]);
      // One lamport more than the victim's own vault, to rank first by balance.
      await airdrop(ctx, vaultPda, realBalance + 1n);
    });

    // Nothing on chain leads back to the moved account: the facts are
    // spotless, and vetting passes it. Only the missing signature tells it apart.
    const candidates = await client.findPasskeyWalletCandidates({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
    });
    const facts = await client.describeWalletCandidates(
      verifyOwnershipProof(candidates, await proofFrom(victim), RP_ID),
    );
    const baitFacts = facts.find((f) => f.walletPda === w.walletPda)!;
    expect(baitFacts).toMatchObject({
      controlledAlone: true,
      vaultIsSystemAccount: true,
      tokenGrants: [],
      signatureCount: 0,
      lamports: realBalance + 1n,
    });
    expect(facts.find((f) => f.walletPda === real.walletPda)!.signatureCount).toBe(1);
    expect(await client.vetMigrationDestination(w.walletPda, passkeyOwner(victim))).toBeNull();

    const own = await client.findOwnPasskeyWallet({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(victim),
    });
    expect(own.adopt?.walletPda).toBe(real.walletPda);
    expect(own.needsConfirmation).toEqual([]);

    // Unless the app names the mint: then the account shows.
    const [watched] = await client.describeWalletCandidates([baitFacts], { watchMints: [mint] });
    expect(watched!.controlledAlone).toBe(false);
    expect(watched!.tokenGrants).toEqual([
      { tokenAccount: ata, tokenProgram: TOKEN_PROGRAM_ADDRESS, mint, kind: 'owner', grantee: w.attacker.address, trusted: false },
    ]);
    expect(await client.vetMigrationDestination(w.walletPda, passkeyOwner(victim), { watchMints: [mint] })).toBe(
      `wallet ${w.walletPda}'s vault token account ${ata} (the vault's own account for mint ${mint}) belongs to ${w.attacker.address}`,
    );

    // What that would have cost: tokens paid to the bait vault's address for
    // this mint land in the moved account, and the attacker alone moves them.
    const theirs = await getAssociatedTokenAddress(mint, w.attacker.address, TOKEN_PROGRAM_ADDRESS);
    await sendTx(ctx, [tokenMintToIx(mint, ata, ctx.payer.address, 1_000n)]);
    await sendTx(
      ctx,
      [
        createAssociatedTokenAccountIdempotentIx({
          payer: ctx.payer.address,
          ata: theirs,
          owner: w.attacker.address,
          mint,
          tokenProgram: TOKEN_PROGRAM_ADDRESS,
        }),
        tokenTransferIx(ata, theirs, w.attacker.address, 1_000n),
      ],
      [w.attacker],
    );
    const balance = await ctx.rpc.getTokenAccountBalance(theirs, { commitment: 'confirmed' }).send();
    expect(balance.value.amount).toBe('1000');
  });

  // The program's passkey challenge binds the payer, the counter and the
  // instruction's own arguments, but not the wallet, for CreateSession (and
  // AddAuthority, TransferOwnership, Authorize). So the signature from the
  // victim's first transaction on their own wallet also works on a wallet
  // planted for their passkey — through the same fee payer, which a relayer
  // lends to anyone — and raises its counter too.
  it("a planted wallet's signature count can be raised by replaying the victim's own first signature, so two signed-for wallets are never adopted", async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const real = await createPasskeyWallet(victim);
    await airdrop(ctx, real.vaultPda, 2_000_000n);
    const bait = await handedOver(victim, async () => {});

    // The victim's first passkey transaction: a session for the app's key.
    const appSessionKey = (await generateKeyPairSigner()).address;
    const session = await client.createSession({
      payer: ctx.payer.address,
      walletPda: real.walletPda,
      adminSigner: secp256r1(createMockSigner(victim)),
      sessionKey: appSessionKey,
      expiresAt: (await getSlot(ctx)) + 9_000n,
      actions: [Actions.solLimit(1_000_000n)],
    });
    await sendTx(ctx, session.instructions);

    // The same precompile instruction and instruction data, pointed at the
    // bait wallet, its victim authority and the session address there.
    const [baitSession] = await client.findSession(bait.walletPda, addressEncoder.encode(appSessionKey) as Uint8Array);
    const swap = new Map<Address, Address>([
      [real.walletPda, bait.walletPda],
      [real.authorityPda, bait.victimAuthorityPda],
      [session.sessionPda, baitSession],
    ]);
    const replayed: Instruction[] = session.instructions.map((ix) => ({
      ...ix,
      accounts: ix.accounts?.map((a) => ({ ...a, address: swap.get(a.address) ?? a.address })),
    }));
    await sendTx(ctx, replayed);
    // A lamport more than the victim's own vault, to rank first by balance.
    await airdrop(ctx, bait.vaultPda, (await getBalance(ctx, real.vaultPda)) + 1n);

    // With the app's session key trusted, both wallets are clean and both
    // signed for once: the counts cannot tell the user's wallet from the copy.
    const own = await client.findOwnPasskeyWallet({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(victim),
      trustedKeys: [appSessionKey],
    });
    expect(own.adopt).toBeNull();
    expect(own.needsConfirmation.map((f) => f.walletPda)).toEqual([bait.walletPda, real.walletPda]);
    for (const f of own.needsConfirmation) {
      expect(f).toMatchObject({ controlledAlone: true, signatureCount: 1, otherAuthorities: [], tokenGrants: [] });
      expect(f.liveSessions.map((s) => s.sessionKey)).toEqual([appSessionKey]);
    }
  });

  // Why migrateV1Wallet creates a destination wallet whose address holds only
  // lamports instead of taking it for an existing one: CreateWallet builds
  // over them, and whoever runs it first owns the vault — and whatever a
  // migration already paid into it.
  it('a wallet address holding only lamports is no wallet: CreateWallet builds over it, and its creator owns the vault', async () => {
    const seed = crypto.randomBytes(32);
    const [walletPda] = await client.findWallet(seed);
    const [vaultPda] = await client.findVault(walletPda);
    await airdrop(ctx, walletPda, 1_000_000n);
    await airdrop(ctx, vaultPda, 30_000_000n);
    const before = await ctx.rpc.getAccountInfo(walletPda, { encoding: 'base64' }).send();
    expect(before.value!.owner).toBe(SYSTEM_PROGRAM_ADDRESS);

    const claimant = await generateKeyPairSigner();
    const created = await client.createWallet({
      payer: ctx.payer.address,
      userSeed: seed,
      owner: { type: 'ed25519', publicKey: claimant.address },
    });
    await sendTx(ctx, created.instructions);
    const after = await ctx.rpc.getAccountInfo(walletPda, { encoding: 'base64' }).send();
    expect(after.value!.owner).toBe(PROGRAM_ID);

    const sink = (await generateKeyPairSigner()).address;
    await executeAs(claimant, walletPda, [systemTransferFromPda(vaultPda, sink, 29_000_000n)]);
    expect(await getBalance(ctx, sink)).toBe(29_000_000n);
  });

  it('a close authority alone, left on a vault token account, keeps it from receiving a migration', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const closer = (await generateKeyPairSigner()).address;
    let ata!: Address;
    const w = await handedOver(victim, async ({ walletPda, vaultPda, attacker }) => {
      ata = await getAssociatedTokenAddress(WSOL, vaultPda, TOKEN_PROGRAM_ADDRESS);
      await sendTx(ctx, [
        createAssociatedTokenAccountIdempotentIx({
          payer: ctx.payer.address,
          ata,
          owner: vaultPda,
          mint: WSOL,
          tokenProgram: TOKEN_PROGRAM_ADDRESS,
        }),
      ]);
      // Closing a wSOL account pays out every lamport in it, wrapped or not.
      await executeAs(attacker, walletPda, [tokenSetAuthorityIx(ata, vaultPda, 3, closer)]);
    });

    const f = await offeredToVictim(victim, w.walletPda);
    expect(f.tokenGrants.map((g) => [g.kind, g.grantee])).toEqual([['closeAuthority', closer]]);
    expect(await client.vetMigrationDestination(w.walletPda, passkeyOwner(victim))).toBe(
      `wallet ${w.walletPda}'s vault token account ${ata} has a close authority other than the vault, ${closer}`,
    );
  });

  it('a wallet handed over with nothing left behind is offered, not adopted, until the passkey signs for it', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const w = await handedOver(victim, async ({ vaultPda }) => {
      await airdrop(ctx, vaultPda, 3_000_000n);
    });
    // Clean by every fact the chain has — which is what an unwatched mint's
    // moved token account (above) looks like too.
    const f = await offeredToVictim(victim, w.walletPda);
    expect(f).toMatchObject({ controlledAlone: true, tokenGrants: [], pendingDeferred: [], signatureCount: 0 });
    // A migration may deliver into it when named; it would not pick it by itself.
    expect(await client.vetMigrationDestination(w.walletPda, passkeyOwner(victim))).toBeNull();

    // Once the user has chosen it and signed with it, it is theirs to adopt.
    await signOnce(victim, w.walletPda, w.vaultPda);
    const own = await client.findOwnPasskeyWallet({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(victim),
    });
    expect(own.adopt?.walletPda).toBe(w.walletPda);
    expect(own.adopt?.signatureCount).toBe(1);
  });

  it('a passkey authority at Admin rank is not a candidate', async () => {
    const key = await generateMockSecp256r1Key(RP_ID);
    const owner = await generateKeyPairSigner();
    const created = await client.createWallet({
      payer: ctx.payer.address,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'ed25519', publicKey: owner.address },
    });
    await sendTx(ctx, created.instructions);
    const { instructions } = await client.addAuthority({
      payer: ctx.payer.address,
      walletPda: created.walletPda,
      adminSigner: ed25519(owner.address),
      newAuthority: {
        type: 'secp256r1',
        credentialIdHash: key.credentialIdHash,
        compressedPubkey: key.publicKeyBytes,
        rpId: RP_ID,
      },
      role: ROLE_ADMIN,
    });
    await sendTx(ctx, instructions, [owner]);

    // The raw lookup lists it; the candidate finder does not.
    const raw = await client.findWalletsByAuthority(key.credentialIdHash);
    expect(raw.map((r) => r.walletPda)).toEqual([created.walletPda]);
    expect(
      await client.findPasskeyWalletCandidates({ credentialIdHash: key.credentialIdHash, rpId: RP_ID }),
    ).toEqual([]);
  });

  it('a wallet created under another relying party is not a candidate', async () => {
    const key = await generateMockSecp256r1Key('other-rp.example');
    const { walletPda } = await createPasskeyWallet(key);

    expect(
      await client.findPasskeyWalletCandidates({ credentialIdHash: key.credentialIdHash, rpId: RP_ID }),
    ).toEqual([]);
    const underItsOwn = await client.findPasskeyWalletCandidates({
      credentialIdHash: key.credentialIdHash,
      rpId: 'other-rp.example',
    });
    expect(underItsOwn.map((c) => c.walletPda)).toEqual([walletPda]);
  });

  it('a wallet listing the same credential hash with another public key is found but not proven', async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    // The attacker knows the victim's credential-id hash (it is public) and
    // lists it next to a key they hold. CreateWallet asks neither.
    const attacker = await generateMockSecp256r1Key(RP_ID, victim.credentialIdHash);
    const real = await createPasskeyWallet(victim);
    const planted = await createPasskeyWallet(victim, attacker.publicKeyBytes);

    const candidates = await client.findPasskeyWalletCandidates({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
    });
    expect(candidates.map((c) => c.walletPda).sort()).toEqual(
      [real.walletPda, planted.walletPda].sort(),
    );

    const proven = verifyOwnershipProof(candidates, await proofFrom(victim), RP_ID);
    expect(proven.map((c) => c.walletPda)).toEqual([real.walletPda]);
    const theirs = verifyOwnershipProof(candidates, await proofFrom(attacker), RP_ID);
    expect(theirs.map((c) => c.walletPda)).toEqual([planted.walletPda]);

    const own = await client.findOwnPasskeyWallet({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(victim),
    });
    // Only the real wallet is offered (not adopted: it has not been used yet).
    expect(own.adopt).toBeNull();
    expect(own.needsConfirmation.map((f) => f.walletPda)).toEqual([real.walletPda]);
    expect(own.unproven).toBe(1);
  });

  it("the victim's real passkey added to someone else's wallet is proven, but only ever offered", async () => {
    const victim = await generateMockSecp256r1Key(RP_ID);
    const attacker = await generateKeyPairSigner();
    const created = await client.createWallet({
      payer: ctx.payer.address,
      userSeed: crypto.randomBytes(32),
      owner: { type: 'ed25519', publicKey: attacker.address },
    });
    await sendTx(ctx, created.instructions);
    // AddAuthority asks the new owner nothing either.
    const { instructions } = await client.addAuthority({
      payer: ctx.payer.address,
      walletPda: created.walletPda,
      adminSigner: ed25519(attacker.address),
      newAuthority: {
        type: 'secp256r1',
        credentialIdHash: victim.credentialIdHash,
        compressedPubkey: victim.publicKeyBytes,
        rpId: RP_ID,
      },
      role: ROLE_OWNER,
      allowOwner: true,
    });
    await sendTx(ctx, instructions, [attacker]);

    const lured = await client.findOwnPasskeyWallet({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(victim),
    });
    expect(lured.adopt).toBeNull();
    expect(lured.unproven).toBe(0);
    expect(lured.needsConfirmation.map((f) => f.walletPda)).toEqual([created.walletPda]);
    expect(lured.needsConfirmation[0]!.otherAuthorities).toEqual([
      {
        authorityPda: created.authorityPda,
        type: 'ed25519',
        role: 'owner',
        publicKey: attacker.address,
        trusted: false,
      },
    ]);

    // Once the victim has a wallet of their own and has used it, that one is
    // adopted and the shared one is not even offered.
    const real = await createUsedPasskeyWallet(victim);
    const own = await client.findOwnPasskeyWallet({
      credentialIdHash: victim.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(victim),
    });
    expect(own.adopt?.walletPda).toBe(real.walletPda);
    expect(own.needsConfirmation).toEqual([]);
  });

  it('with no wallet this passkey provably owns, there is nothing to adopt or confirm', async () => {
    const key = await generateMockSecp256r1Key(RP_ID);
    const own = await client.findOwnPasskeyWallet({
      credentialIdHash: key.credentialIdHash,
      rpId: RP_ID,
      proof: await proofFrom(key),
    });
    expect(own).toEqual({ adopt: null, needsConfirmation: [], unproven: 0 });
  });
});
