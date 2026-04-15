/**
 * Devnet Protocol Setup + Smoke Test
 *
 * Deploys the protocol fee config, treasury shards, registers the payer,
 * then runs through all wallet operations to verify everything works.
 *
 * Run: cd tests-sdk && npx tsx tests/devnet-setup-protocol.ts
 *
 * Prerequisites:
 *   - Program deployed to devnet (solana program deploy target/deploy/lazorkit_program.so -u d)
 *   - Solana CLI keypair funded (~5 SOL): solana airdrop 5 -u d
 */
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
  type TransactionInstruction,
  type Signer,
} from '@solana/web3.js';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  LazorKitClient,
  ed25519,
  session,
  ROLE_ADMIN,
} from '../../sdk/sdk-legacy/src';
import { SessionActionType, type SessionAction } from '../../sdk/sdk-legacy/src/utils/actions';

const RPC_URL = process.env.RPC_URL || 'https://api.devnet.solana.com';
const NUM_SHARDS = 16;
const CREATION_FEE = 5000n; // lamports
const EXECUTION_FEE = 2000n; // lamports

// ─── Helpers ────────────────────────────────────────────────────────

function loadPayer(): Keypair {
  const keypairPath = path.resolve(process.env.HOME || '~', '.config/solana/id.json');
  const raw = JSON.parse(fs.readFileSync(keypairPath, 'utf-8'));
  return Keypair.fromSecretKey(new Uint8Array(raw));
}

async function send(
  connection: Connection,
  payer: Keypair,
  instructions: TransactionInstruction[],
  signers: Signer[] = [],
): Promise<string> {
  const tx = new Transaction();
  for (const ix of instructions) tx.add(ix);
  return sendAndConfirmTransaction(connection, tx, [payer, ...signers], {
    commitment: 'confirmed',
  });
}

function ok(msg: string) { console.log(`  ✓ ${msg}`); }
function step(msg: string) { console.log(`\n── ${msg} ──`); }

// ─── Main ───────────────────────────────────────────────────────────

async function main() {
  const connection = new Connection(RPC_URL, 'confirmed');
  const payer = loadPayer();
  const client = new LazorKitClient(connection);

  console.log(`Program ID: ${client.programId.toBase58()}`);
  console.log(`Payer:      ${payer.publicKey.toBase58()}`);
  const balance = await connection.getBalance(payer.publicKey);
  console.log(`Balance:    ${(balance / LAMPORTS_PER_SOL).toFixed(4)} SOL`);

  if (balance < 2 * LAMPORTS_PER_SOL) {
    console.log('\nNot enough SOL. Run: solana airdrop 5 -u d');
    process.exit(1);
  }

  // ════════════════════════════════════════════════════════════════
  // PHASE 1: Protocol Setup (Admin — one-time)
  // ════════════════════════════════════════════════════════════════

  step('1. Initialize Protocol Config');
  // Helper: skip if already initialized (catches both runtime and custom errors)
  const skipIfExists = (e: any, label: string) => {
    const msg = String(e?.message || e);
    // Catch all "already exists" patterns: runtime errors + protocol custom errors (0xfa1-0xfa7)
    if (msg.includes('already in use') || msg.includes('uninitialized account') ||
        msg.includes('AlreadyInitialized') || /0xfa[0-9a-f]/.test(msg)) {
      ok(`${label} already exists (skipping)`);
      return;
    }
    throw e;
  };

  try {
    const { instructions, protocolConfigPda } = client.initializeProtocol({
      payer: payer.publicKey,
      admin: payer.publicKey, // payer is admin for devnet
      treasury: payer.publicKey, // treasury goes back to payer for testing
      creationFee: CREATION_FEE,
      executionFee: EXECUTION_FEE,
      numShards: NUM_SHARDS,
    });
    await send(connection, payer, instructions);
    ok(`ProtocolConfig: ${protocolConfigPda.toBase58()}`);
  } catch (e: any) {
    skipIfExists(e, 'ProtocolConfig');
  }

  step('2. Initialize Treasury Shards');
  for (let i = 0; i < NUM_SHARDS; i++) {
    try {
      const { instructions, treasuryShardPda } = client.initializeTreasuryShard({
        payer: payer.publicKey,
        admin: payer.publicKey,
        shardId: i,
      });
      await send(connection, payer, instructions);
      ok(`Shard ${i}: ${treasuryShardPda.toBase58()}`);
    } catch (e: any) {
      skipIfExists(e, `Shard ${i}`);
    }
  }

  step('3. Register Payer for Fee Tracking');
  try {
    const { instructions, feeRecordPda } = client.registerPayer({
      payer: payer.publicKey,
      admin: payer.publicKey,
      targetPayer: payer.publicKey,
    });
    await send(connection, payer, instructions);
    ok(`FeeRecord: ${feeRecordPda.toBase58()}`);
  } catch (e: any) {
    skipIfExists(e, 'FeeRecord');
  }

  // ════════════════════════════════════════════════════════════════
  // PHASE 2: Smoke Test — Wallet Operations
  // ════════════════════════════════════════════════════════════════

  step('4. Create Wallet (Ed25519 Owner)');
  const ownerKp = Keypair.generate();
  const userSeed = new Uint8Array(crypto.randomBytes(32));
  const { instructions: createIxs, walletPda, vaultPda, authorityPda } = await client.createWallet({
    payer: payer.publicKey,
    userSeed,
    owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
  });
  await send(connection, payer, createIxs);
  ok(`Wallet:    ${walletPda.toBase58()}`);
  ok(`Vault:     ${vaultPda.toBase58()}`);
  ok(`Authority: ${authorityPda.toBase58()}`);

  step('5. Fund Vault');
  const fundIx = SystemProgram.transfer({
    fromPubkey: payer.publicKey,
    toPubkey: vaultPda,
    lamports: 0.1 * LAMPORTS_PER_SOL,
  });
  await send(connection, payer, [fundIx]);
  ok(`Funded vault with 0.1 SOL`);

  step('6. Add Admin Authority');
  const adminKp = Keypair.generate();
  const { instructions: addIxs, newAuthorityPda: adminAuthPda } = await client.addAuthority({
    payer: payer.publicKey,
    walletPda,
    adminSigner: ed25519(ownerKp.publicKey, authorityPda),
    newAuthority: { type: 'ed25519', publicKey: adminKp.publicKey },
    role: ROLE_ADMIN,
  });
  await send(connection, payer, addIxs, [ownerKp]);
  ok(`Admin Authority: ${adminAuthPda.toBase58()}`);

  step('7. Create Session Key');
  const sessionKp = Keypair.generate();
  const currentSlot = BigInt(await connection.getSlot());
  const { instructions: sessIxs, sessionPda } = await client.createSession({
    payer: payer.publicKey,
    walletPda,
    adminSigner: ed25519(ownerKp.publicKey, authorityPda),
    sessionKey: sessionKp.publicKey,
    expiresAt: currentSlot + 10_000n,
    actions: [
      { type: SessionActionType.SolMaxPerTx, max: BigInt(0.05 * LAMPORTS_PER_SOL) },
      { type: SessionActionType.SolLimit, remaining: BigInt(0.1 * LAMPORTS_PER_SOL) },
    ] as SessionAction[],
  });
  await send(connection, payer, sessIxs, [ownerKp]);
  ok(`Session: ${sessionPda.toBase58()} (SolMaxPerTx: 0.05 SOL, SolLimit: 0.1 SOL)`);

  step('8. Execute SOL Transfer via Session Key');
  const recipient = Keypair.generate().publicKey;
  const { instructions: execIxs } = await client.transferSol({
    payer: payer.publicKey,
    walletPda,
    signer: session(sessionPda, sessionKp.publicKey),
    recipient,
    lamports: BigInt(0.01 * LAMPORTS_PER_SOL),
  });
  await send(connection, payer, execIxs, [sessionKp]);
  const recipientBal = await connection.getBalance(recipient);
  ok(`Transferred 0.01 SOL to ${recipient.toBase58()} (balance: ${recipientBal / LAMPORTS_PER_SOL} SOL)`);

  step('9. Execute SOL Transfer via Owner (Direct)');
  const recipient2 = Keypair.generate().publicKey;
  const { instructions: execIxs2 } = await client.transferSol({
    payer: payer.publicKey,
    walletPda,
    signer: ed25519(ownerKp.publicKey, authorityPda),
    recipient: recipient2,
    lamports: BigInt(0.01 * LAMPORTS_PER_SOL),
  });
  await send(connection, payer, execIxs2, [ownerKp]);
  ok(`Owner direct transfer: 0.01 SOL`);

  step('10. Revoke Session');
  const { instructions: revokeIxs } = await client.revokeSession({
    payer: payer.publicKey,
    walletPda,
    adminSigner: ed25519(ownerKp.publicKey, authorityPda),
    sessionPda,
  });
  await send(connection, payer, revokeIxs, [ownerKp]);
  ok('Session revoked');

  step('11. Remove Admin Authority');
  const { instructions: removeIxs } = await client.removeAuthority({
    payer: payer.publicKey,
    walletPda,
    adminSigner: ed25519(ownerKp.publicKey, authorityPda),
    targetAuthorityPda: adminAuthPda,
  });
  await send(connection, payer, removeIxs, [ownerKp]);
  ok('Admin authority removed');

  // ════════════════════════════════════════════════════════════════
  // DONE
  // ════════════════════════════════════════════════════════════════

  const finalBalance = await connection.getBalance(payer.publicKey);
  console.log(`\n══════════════════════════════════════════`);
  console.log(`  All operations passed on devnet!`);
  console.log(`  Program: ${client.programId.toBase58()}`);
  console.log(`  SOL used: ${((balance - finalBalance) / LAMPORTS_PER_SOL).toFixed(4)} SOL`);
  console.log(`══════════════════════════════════════════\n`);
}

main().catch((err) => {
  console.error('\nFailed:', err);
  process.exit(1);
});
