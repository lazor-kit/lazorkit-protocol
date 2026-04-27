/**
 * Fee-aware benchmark for every non-admin LazorKit instruction.
 *
 *   creation_fee  = 5000 lamports
 *   execution_fee = 5000 lamports
 *
 * Reports:
 *   - CU
 *   - Legacy tx size
 *   - V0 tx size with an Address Lookup Table (common pubkeys deduped to 1 byte each)
 *   - Sig fee + protocol fee + rent delta + total cost in lamports
 *
 * Fee-eligible instructions are run twice:
 *   - "cold"  → first fee-paying tx for that payer (SDK auto-prepends RegisterPayer)
 *   - "warm"  → fee record already exists, no auto-prepend
 *
 * Run:
 *   npm run validator:start
 *   npx tsx tests/benchmark-fees.ts
 */
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  sendAndConfirmTransaction,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SYSVAR_RENT_PUBKEY,
  Transaction,
  type AddressLookupTableAccount,
  type TransactionInstruction,
  type Signer,
} from '@solana/web3.js';
import * as crypto from 'crypto';
import {
  LazorKitClient,
  ed25519,
  secp256r1,
  session,
  ROLE_ADMIN,
  buildLegacyTx,
  buildV0Tx,
  createAndExtendLut,
} from '../../sdk/sdk-legacy/src';
import { generateMockSecp256r1Key, createMockRawSigner } from './secp256r1Utils';

const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8899';
const NUM_SHARDS = 4;
const FEE = 5000n;

interface Row {
  name: string;
  feeEligible: boolean;
  cold: boolean; // true = ran with auto-prepended RegisterPayer
  cu: number;
  txSizeLegacy: number;
  txSizeV0Lut: number;
  ixCount: number;
  baseFee: number;
  protocolFee: number;
  rentDelta: number;
  totalCost: number;
}

const rows: Row[] = [];

async function airdrop(c: Connection, who: PublicKey, sol: number) {
  const sig = await c.requestAirdrop(who, sol * LAMPORTS_PER_SOL);
  await c.confirmTransaction(sig, 'confirmed');
}

/**
 * Serialize the same instruction list two ways:
 *   - legacy (what we'll actually send)
 *   - v0 with the supplied ALT
 * Returns sizes for both, plus the legacy tx so we can send it.
 */
function buildBoth(
  payer: PublicKey,
  blockhash: string,
  ixs: TransactionInstruction[],
  signers: Signer[],
  lut?: AddressLookupTableAccount,
): { legacy: Transaction; legacySize: number; v0Size: number } {
  const legacy = buildLegacyTx({ payer, instructions: ixs, blockhash, signers });
  const v0 = buildV0Tx({
    payer,
    instructions: ixs,
    blockhash,
    signers,
    lookupTables: lut ? [lut] : undefined,
  });
  return { legacy, legacySize: legacy.serialize().length, v0Size: v0.serialize().length };
}

async function sendAndMeasure(
  c: Connection,
  payer: Keypair,
  ixs: TransactionInstruction[],
  signers: Signer[],
  lut?: AddressLookupTableAccount,
): Promise<{
  cu: number;
  txSizeLegacy: number;
  txSizeV0Lut: number;
  baseFee: number;
  balDelta: number;
}> {
  const { blockhash } = await c.getLatestBlockhash('confirmed');
  const all = [payer, ...signers];
  const { legacy, legacySize, v0Size } = buildBoth(payer.publicKey, blockhash, ixs, all, lut);

  const balBefore = await c.getBalance(payer.publicKey);
  const sig = await sendAndConfirmTransaction(c, legacy, all, { commitment: 'confirmed' });
  const balAfter = await c.getBalance(payer.publicKey);

  const info = await c.getTransaction(sig, {
    commitment: 'confirmed',
    maxSupportedTransactionVersion: 0,
  });
  const cu = info?.meta?.computeUnitsConsumed ?? 0;
  const baseFee = info?.meta?.fee ?? 0;
  return { cu, txSizeLegacy: legacySize, txSizeV0Lut: v0Size, baseFee, balDelta: balBefore - balAfter };
}

function record(
  name: string,
  feeEligible: boolean,
  cold: boolean,
  r: { cu: number; txSizeLegacy: number; txSizeV0Lut: number; baseFee: number; balDelta: number },
  ixCount: number,
  protocolFee: number,
) {
  const rentDelta = r.balDelta - r.baseFee - protocolFee;
  rows.push({
    name,
    feeEligible,
    cold,
    cu: r.cu,
    txSizeLegacy: r.txSizeLegacy,
    txSizeV0Lut: r.txSizeV0Lut,
    ixCount,
    baseFee: r.baseFee,
    protocolFee,
    rentDelta,
    totalCost: r.balDelta,
  });
  const tag = feeEligible ? (cold ? '[cold]' : '[warm]') : '       ';
  console.log(
    `  ${tag} ${name.padEnd(40)} cu=${String(r.cu).padStart(7)}  legacy=${String(r.txSizeLegacy).padStart(4)}B  v0+lut=${String(r.txSizeV0Lut).padStart(4)}B  cost=${r.balDelta}`,
  );
}

async function main() {
  const c = new Connection(RPC_URL, 'confirmed');
  const admin = Keypair.generate();
  await airdrop(c, admin.publicKey, 50);

  const client = new LazorKitClient(c);

  // ─── Phase 0: protocol setup (admin only — not in the table) ───
  console.log('Setting up protocol (5000/5000 fees, 4 shards)...');
  {
    const { instructions } = client.initializeProtocol({
      payer: admin.publicKey,
      admin: admin.publicKey,
      treasury: admin.publicKey,
      creationFee: FEE,
      executionFee: FEE,
      numShards: NUM_SHARDS,
    });
    await sendAndConfirmTransaction(c, new Transaction().add(...instructions), [admin], {
      commitment: 'confirmed',
    });
  }
  const treasuryShards: PublicKey[] = [];
  for (let i = 0; i < NUM_SHARDS; i++) {
    const { instructions, treasuryShardPda } = client.initializeTreasuryShard({
      payer: admin.publicKey,
      admin: admin.publicKey,
      shardId: i,
    });
    await sendAndConfirmTransaction(c, new Transaction().add(...instructions), [admin], {
      commitment: 'confirmed',
    });
    treasuryShards.push(treasuryShardPda);
  }
  client.invalidateProtocolCache();
  const [protocolConfigPda] = client.findProtocolConfig();
  console.log('Protocol ready.\n');

  // Build a shared ALT containing pubkeys reused across many txs.
  // Adding read-only deduplicated entries that show up in nearly every fee-paying tx
  // (system program, sysvars, protocol config, treasury shards) gives the biggest win.
  console.log('Creating shared address lookup table (system + sysvars + protocol pdas)...');
  const lut = await createAndExtendLut({
    connection: c,
    authority: admin,
    addresses: [
      SystemProgram.programId,
      SYSVAR_INSTRUCTIONS_PUBKEY,
      SYSVAR_RENT_PUBKEY,
      protocolConfigPda,
      ...treasuryShards,
    ],
  });
  console.log(`LUT ready: ${lut.key.toBase58()} (${lut.state.addresses.length} addrs)\n`);

  console.log('Benchmarks:\n');

  // Two payers: dev1 used for "cold" fee-paying txs (one-shot) + warm setup-only ops.
  // For the "cold" measurement we need a payer whose FeeRecord doesn't exist yet,
  // so each cold ix gets its own fresh payer.
  const dev = Keypair.generate();
  await airdrop(c, dev.publicKey, 50);
  const sharedClient = new LazorKitClient(c);

  // Helper: fresh payer + client for "cold" measurements
  async function freshPayer(sol = 5): Promise<{ payer: Keypair; client: LazorKitClient }> {
    const k = Keypair.generate();
    await airdrop(c, k.publicKey, sol);
    return { payer: k, client: new LazorKitClient(c) };
  }

  // ─── Setup wallets we'll reuse ───
  const ownerEd = Keypair.generate();
  const seedShared = new Uint8Array(crypto.randomBytes(32));
  const wEdRes = await sharedClient.createWallet({
    payer: dev.publicKey,
    userSeed: seedShared,
    owner: { type: 'ed25519', publicKey: ownerEd.publicKey },
  });
  await sendAndConfirmTransaction(
    c,
    new Transaction().add(...wEdRes.instructions),
    [dev],
    { commitment: 'confirmed' },
  );
  await airdrop(c, wEdRes.vaultPda, 5);

  const skey = await generateMockSecp256r1Key();
  const sSigner = createMockRawSigner(skey);
  const seedSecp = new Uint8Array(crypto.randomBytes(32));
  const wSecpRes = await sharedClient.createWallet({
    payer: dev.publicKey,
    userSeed: seedSecp,
    owner: {
      type: 'secp256r1',
      credentialIdHash: skey.credentialIdHash,
      compressedPubkey: skey.publicKeyBytes,
      rpId: skey.rpId,
    },
  });
  await sendAndConfirmTransaction(
    c,
    new Transaction().add(...wSecpRes.instructions),
    [dev],
    { commitment: 'confirmed' },
  );
  await airdrop(c, wSecpRes.vaultPda, 5);

  // ─── 1. CreateWallet (Ed25519) — fee-eligible ───
  // cold
  {
    const { payer, client } = await freshPayer();
    const owner = Keypair.generate();
    const seed = new Uint8Array(crypto.randomBytes(32));
    const { instructions } = await client.createWallet({
      payer: payer.publicKey,
      userSeed: seed,
      owner: { type: 'ed25519', publicKey: owner.publicKey },
    });
    const r = await sendAndMeasure(c, payer, instructions, [], lut);
    record('CreateWallet (Ed25519)', true, true, r, instructions.length, Number(FEE));
  }
  // warm — reuse `dev` who already has a FeeRecord from setup
  {
    const owner = Keypair.generate();
    const seed = new Uint8Array(crypto.randomBytes(32));
    const { instructions } = await sharedClient.createWallet({
      payer: dev.publicKey,
      userSeed: seed,
      owner: { type: 'ed25519', publicKey: owner.publicKey },
    });
    const r = await sendAndMeasure(c, dev, instructions, [], lut);
    record('CreateWallet (Ed25519)', true, false, r, instructions.length, Number(FEE));
  }

  // ─── 2. CreateWallet (Secp256r1) — fee-eligible ───
  // cold
  {
    const { payer, client } = await freshPayer();
    const k = await generateMockSecp256r1Key();
    const seed = new Uint8Array(crypto.randomBytes(32));
    const { instructions } = await client.createWallet({
      payer: payer.publicKey,
      userSeed: seed,
      owner: {
        type: 'secp256r1',
        credentialIdHash: k.credentialIdHash,
        compressedPubkey: k.publicKeyBytes,
        rpId: k.rpId,
      },
    });
    const r = await sendAndMeasure(c, payer, instructions, [], lut);
    record('CreateWallet (Secp256r1)', true, true, r, instructions.length, Number(FEE));
  }
  // warm
  {
    const k = await generateMockSecp256r1Key();
    const seed = new Uint8Array(crypto.randomBytes(32));
    const { instructions } = await sharedClient.createWallet({
      payer: dev.publicKey,
      userSeed: seed,
      owner: {
        type: 'secp256r1',
        credentialIdHash: k.credentialIdHash,
        compressedPubkey: k.publicKeyBytes,
        rpId: k.rpId,
      },
    });
    const r = await sendAndMeasure(c, dev, instructions, [], lut);
    record('CreateWallet (Secp256r1)', true, false, r, instructions.length, Number(FEE));
  }

  // ─── 3. AddAuthority (Ed25519 admin → Ed25519 admin) ───
  let extraAuthEd: PublicKey;
  {
    const newAuth = Keypair.generate();
    const { instructions, newAuthorityPda } = await sharedClient.addAuthority({
      payer: dev.publicKey,
      walletPda: wEdRes.walletPda,
      adminSigner: ed25519(ownerEd.publicKey),
      newAuthority: { type: 'ed25519', publicKey: newAuth.publicKey },
      role: ROLE_ADMIN,
    });
    const r = await sendAndMeasure(c, dev, instructions, [ownerEd], lut);
    record('AddAuthority (Ed25519)', false, false, r, instructions.length, 0);
    extraAuthEd = newAuthorityPda;
  }

  // ─── 4. AddAuthority (Secp256r1 admin → Ed25519) ───
  {
    const newAuth = Keypair.generate();
    const { instructions } = await sharedClient.addAuthority({
      payer: dev.publicKey,
      walletPda: wSecpRes.walletPda,
      adminSigner: secp256r1(sSigner),
      newAuthority: { type: 'ed25519', publicKey: newAuth.publicKey },
      role: ROLE_ADMIN,
    });
    const r = await sendAndMeasure(c, dev, instructions, [], lut);
    record('AddAuthority (Secp256r1 admin)', false, false, r, instructions.length, 0);
  }

  // ─── 5. RemoveAuthority (Ed25519) ───
  {
    const { instructions } = await sharedClient.removeAuthority({
      payer: dev.publicKey,
      walletPda: wEdRes.walletPda,
      adminSigner: ed25519(ownerEd.publicKey),
      targetAuthorityPda: extraAuthEd,
      refundDestination: dev.publicKey,
    });
    const r = await sendAndMeasure(c, dev, instructions, [ownerEd], lut);
    record('RemoveAuthority (Ed25519)', false, false, r, instructions.length, 0);
  }

  // ─── 6. TransferOwnership (Ed25519 → Ed25519) ───
  const newOwner = Keypair.generate();
  {
    const { instructions } = await sharedClient.transferOwnership({
      payer: dev.publicKey,
      walletPda: wEdRes.walletPda,
      ownerSigner: ed25519(ownerEd.publicKey),
      newOwner: { type: 'ed25519', publicKey: newOwner.publicKey },
      refundDestination: dev.publicKey,
    });
    const r = await sendAndMeasure(c, dev, instructions, [ownerEd], lut);
    record('TransferOwnership (Ed25519)', false, false, r, instructions.length, 0);
  }

  // ─── 7. CreateSession (Ed25519 admin) ───
  const sessionKey = Keypair.generate();
  let sessionPda: PublicKey;
  {
    const { instructions, sessionPda: spda } = await sharedClient.createSession({
      payer: dev.publicKey,
      walletPda: wEdRes.walletPda,
      adminSigner: ed25519(newOwner.publicKey),
      sessionKey: sessionKey.publicKey,
      expiresAt: BigInt(await c.getSlot('confirmed')) + 1000n,
      actions: [],
    });
    const r = await sendAndMeasure(c, dev, instructions, [newOwner], lut);
    record('CreateSession (Ed25519 admin)', false, false, r, instructions.length, 0);
    sessionPda = spda;
  }

  // ─── 8. CreateSession (Secp256r1 admin) ───
  const sessionKey2 = Keypair.generate();
  {
    const { instructions } = await sharedClient.createSession({
      payer: dev.publicKey,
      walletPda: wSecpRes.walletPda,
      adminSigner: secp256r1(sSigner),
      sessionKey: sessionKey2.publicKey,
      expiresAt: BigInt(await c.getSlot('confirmed')) + 1000n,
      actions: [],
    });
    const r = await sendAndMeasure(c, dev, instructions, [], lut);
    record('CreateSession (Secp256r1 admin)', false, false, r, instructions.length, 0);
  }

  // ─── 9. Execute (Ed25519 signer) — fee-eligible ───
  const recipient = Keypair.generate().publicKey;
  // warm only (Ed25519 signer can't produce a "first tx by a brand new dev" without setup)
  {
    const { instructions } = await sharedClient.execute({
      payer: dev.publicKey,
      walletPda: wEdRes.walletPda,
      signer: ed25519(newOwner.publicKey),
      instructions: [
        SystemProgram.transfer({
          fromPubkey: wEdRes.vaultPda,
          toPubkey: recipient,
          lamports: 1_000_000,
        }),
      ],
    });
    const r = await sendAndMeasure(c, dev, instructions, [newOwner], lut);
    record('Execute (Ed25519)', true, false, r, instructions.length, Number(FEE));
  }

  // ─── 10. Execute (Secp256r1 signer) — fee-eligible, includes precompile ───
  // cold — fresh payer signs as relay; signer is shared sSigner
  {
    const { payer, client } = await freshPayer();
    // need a fresh wallet too (so sSigner counter is fresh)
    const k = await generateMockSecp256r1Key();
    const sg = createMockRawSigner(k);
    const seed = new Uint8Array(crypto.randomBytes(32));
    const cw = await client.createWallet({
      payer: payer.publicKey,
      userSeed: seed,
      owner: {
        type: 'secp256r1',
        credentialIdHash: k.credentialIdHash,
        compressedPubkey: k.publicKeyBytes,
        rpId: k.rpId,
      },
    });
    await sendAndConfirmTransaction(c, new Transaction().add(...cw.instructions), [payer], {
      commitment: 'confirmed',
    });
    await airdrop(c, cw.vaultPda, 2);

    // Use a SECOND fresh payer for the actual measured execute (so it's "cold" too)
    const { payer: relayer } = await freshPayer();
    const c2 = new LazorKitClient(c);
    const { instructions } = await c2.execute({
      payer: relayer.publicKey,
      walletPda: cw.walletPda,
      signer: secp256r1(sg),
      instructions: [
        SystemProgram.transfer({
          fromPubkey: cw.vaultPda,
          toPubkey: recipient,
          lamports: 1_000_000,
        }),
      ],
    });
    const r = await sendAndMeasure(c, relayer, instructions, [], lut);
    record('Execute (Secp256r1)', true, true, r, instructions.length, Number(FEE));
  }
  // warm
  {
    const { instructions } = await sharedClient.execute({
      payer: dev.publicKey,
      walletPda: wSecpRes.walletPda,
      signer: secp256r1(sSigner),
      instructions: [
        SystemProgram.transfer({
          fromPubkey: wSecpRes.vaultPda,
          toPubkey: recipient,
          lamports: 1_000_000,
        }),
      ],
    });
    const r = await sendAndMeasure(c, dev, instructions, [], lut);
    record('Execute (Secp256r1)', true, false, r, instructions.length, Number(FEE));
  }

  // ─── 11. Execute (Session signer) — fee-eligible ───
  {
    const { instructions } = await sharedClient.execute({
      payer: dev.publicKey,
      walletPda: wEdRes.walletPda,
      signer: session(sessionPda, sessionKey.publicKey),
      instructions: [
        SystemProgram.transfer({
          fromPubkey: wEdRes.vaultPda,
          toPubkey: recipient,
          lamports: 1_000_000,
        }),
      ],
    });
    const r = await sendAndMeasure(c, dev, instructions, [sessionKey], lut);
    record('Execute (Session)', true, false, r, instructions.length, Number(FEE));
  }

  // ─── 12. RevokeSession ───
  {
    const { instructions } = await sharedClient.revokeSession({
      payer: dev.publicKey,
      walletPda: wEdRes.walletPda,
      adminSigner: ed25519(newOwner.publicKey),
      sessionPda,
      refundDestination: dev.publicKey,
    });
    const r = await sendAndMeasure(c, dev, instructions, [newOwner], lut);
    record('RevokeSession (Ed25519)', false, false, r, instructions.length, 0);
  }

  // ─── 13. Authorize (Secp256r1) ───
  let dPayload: any;
  {
    const result = await sharedClient.authorize({
      payer: dev.publicKey,
      walletPda: wSecpRes.walletPda,
      signer: secp256r1(sSigner),
      instructions: [
        SystemProgram.transfer({
          fromPubkey: wSecpRes.vaultPda,
          toPubkey: recipient,
          lamports: 1_000_000,
        }),
      ],
      expiryOffset: 300,
    });
    const r = await sendAndMeasure(c, dev, result.instructions, [], lut);
    record('Authorize (Secp256r1, TX1)', false, false, r, result.instructions.length, 0);
    dPayload = result.deferredPayload;
  }

  // ─── 14. ExecuteDeferred (TX2) — fee-eligible ───
  {
    const { instructions } = await sharedClient.executeDeferredFromPayload({
      payer: dev.publicKey,
      deferredPayload: dPayload,
    });
    const r = await sendAndMeasure(c, dev, instructions, [], lut);
    record('ExecuteDeferred (TX2)', true, false, r, instructions.length, Number(FEE));
  }

  // ─── 15. ReclaimDeferred ───
  {
    const result = await sharedClient.authorize({
      payer: dev.publicKey,
      walletPda: wSecpRes.walletPda,
      signer: secp256r1(sSigner),
      instructions: [
        SystemProgram.transfer({
          fromPubkey: wSecpRes.vaultPda,
          toPubkey: recipient,
          lamports: 1_000,
        }),
      ],
      expiryOffset: 10,
    });
    await sendAndConfirmTransaction(
      c,
      new Transaction().add(...result.instructions),
      [dev],
      { commitment: 'confirmed' },
    );
    await new Promise((res) => setTimeout(res, 6000));
    const { instructions } = sharedClient.reclaimDeferred({
      payer: dev.publicKey,
      deferredExecPda: result.deferredExecPda,
    });
    const r = await sendAndMeasure(c, dev, instructions, [], lut);
    record('ReclaimDeferred', false, false, r, instructions.length, 0);
  }

  // ─── 16. RegisterPayer (standalone, for reference) ───
  {
    const { payer, client } = await freshPayer(1);
    const { instructions } = client.registerPayer({ payer: payer.publicKey });
    const r = await sendAndMeasure(c, payer, instructions, [], lut);
    record('RegisterPayer (standalone)', false, false, r, instructions.length, 0);
  }

  // ─── Print results ───
  console.log('\n\n## Non-admin instructions @ 5000 / 5000 lamport fees\n');
  console.log(
    '| Instruction | Mode | CU | Legacy size | V0+LUT size | Δ size | Sig fee | Protocol fee | Rent Δ | Total cost |',
  );
  console.log(
    '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|',
  );
  for (const r of rows) {
    const mode = r.feeEligible ? (r.cold ? 'cold' : 'warm') : '—';
    const dSize = r.txSizeV0Lut - r.txSizeLegacy;
    console.log(
      `| ${r.name} | ${mode} | ${r.cu.toLocaleString()} | ${r.txSizeLegacy} B | ${r.txSizeV0Lut} B | ${dSize >= 0 ? '+' : ''}${dSize} B | ${r.baseFee} | ${r.protocolFee} | ${r.rentDelta} | ${r.totalCost} |`,
    );
  }

  console.log('\nNotes:');
  console.log('  - Mode: "cold" = first fee-paying tx for the payer (SDK auto-prepends RegisterPayer ix);');
  console.log('          "warm" = FeeRecord already exists, no auto-prepend; "—" = not fee-eligible.');
  console.log('  - V0+LUT size uses an Address Lookup Table containing system program, sysvars,');
  console.log('    protocol_config, and all treasury_shard PDAs (5 + N_shards entries).');
  console.log('  - All values in lamports. Total cost = payer balance delta. Negative rent Δ = rent refunded.');
  console.log('\nDone.');
}

main().catch((err) => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
