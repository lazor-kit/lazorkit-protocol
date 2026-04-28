/**
 * Verifies the on-chain FeeRecord counter updates for the admin payer.
 * Snapshots FeeRecord → runs one fee-eligible CreateWallet → snapshots again.
 * Asserts: wallet_count += 1, total_fees_paid += creation_fee.
 */
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  Transaction,
  sendAndConfirmTransaction,
} from '@solana/web3.js';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { LazorKitClient } from '../sdk/sdk-legacy/src';

const RPC_URL = 'https://api.devnet.solana.com';

interface FeeRecordState {
  exists: boolean;
  totalFeesPaid: bigint;
  txCount: number;
  walletCount: number;
  registeredAt: bigint;
}

async function readFeeRecord(
  connection: Connection,
  pda: import('@solana/web3.js').PublicKey,
): Promise<FeeRecordState> {
  const info = await connection.getAccountInfo(pda);
  if (!info) {
    return {
      exists: false,
      totalFeesPaid: 0n,
      txCount: 0,
      walletCount: 0,
      registeredAt: 0n,
    };
  }
  const data = info.data;
  return {
    exists: true,
    totalFeesPaid: data.readBigUInt64LE(8),
    txCount: data.readUInt32LE(16),
    walletCount: data.readUInt32LE(20),
    registeredAt: data.readBigUInt64LE(24),
  };
}

async function main() {
  const connection = new Connection(RPC_URL, 'confirmed');
  const raw = JSON.parse(
    fs.readFileSync(
      path.resolve(process.env.HOME || '~', '.config/solana/id.json'),
      'utf-8',
    ),
  );
  const payer = Keypair.fromSecretKey(new Uint8Array(raw));
  const client = new LazorKitClient(connection);

  const [feeRecordPda] = client.findFeeRecord(payer.publicKey);
  console.log('Payer:          ', payer.publicKey.toBase58());
  console.log('FeeRecord PDA:  ', feeRecordPda.toBase58());

  const before = await readFeeRecord(connection, feeRecordPda);
  console.log('\n--- FeeRecord BEFORE ---');
  console.log('  exists:         ', before.exists);
  console.log('  total_fees_paid:', before.totalFeesPaid.toString(), 'lamports');
  console.log('  tx_count:       ', before.txCount);
  console.log('  wallet_count:   ', before.walletCount);

  // Run one CreateWallet to trigger a counter update
  const ownerKp = Keypair.generate();
  const { instructions, walletPda } = await client.createWallet({
    payer: payer.publicKey,
    userSeed: crypto.randomBytes(32),
    owner: { type: 'ed25519', publicKey: ownerKp.publicKey },
  });

  const tx = new Transaction();
  for (const ix of instructions) tx.add(ix);
  const { blockhash } = await connection.getLatestBlockhash('confirmed');
  tx.recentBlockhash = blockhash;
  tx.feePayer = payer.publicKey;
  tx.sign(payer);
  const sig = await sendAndConfirmTransaction(connection, tx, [payer], {
    commitment: 'confirmed',
  });
  console.log('\nCreateWallet tx:', sig);
  console.log('  walletPda:    ', walletPda.toBase58());

  // Re-read FeeRecord
  const after = await readFeeRecord(connection, feeRecordPda);
  console.log('\n--- FeeRecord AFTER ---');
  console.log('  total_fees_paid:', after.totalFeesPaid.toString(), 'lamports');
  console.log('  tx_count:       ', after.txCount);
  console.log('  wallet_count:   ', after.walletCount);

  console.log('\n--- DELTAS ---');
  const feeDelta = after.totalFeesPaid - before.totalFeesPaid;
  const txDelta = after.txCount - before.txCount;
  const walletDelta = after.walletCount - before.walletCount;
  console.log('  total_fees_paid +', feeDelta.toString(), 'lamports');
  console.log('  tx_count        +', txDelta);
  console.log('  wallet_count    +', walletDelta);

  // Expectations for CreateWallet:
  //   wallet_count += 1
  //   total_fees_paid += creation_fee (5000 on devnet)
  //   tx_count unchanged (tx_count is for Execute / ExecuteDeferred, not CreateWallet)
  let ok = true;
  if (walletDelta !== 1) {
    console.error(`  ❌ wallet_count expected +1, got +${walletDelta}`);
    ok = false;
  } else {
    console.log('  ✓ wallet_count incremented by 1');
  }
  if (feeDelta !== 5000n) {
    console.error(`  ❌ total_fees_paid expected +5000, got +${feeDelta}`);
    ok = false;
  } else {
    console.log('  ✓ total_fees_paid incremented by 5000 lamports');
  }
  if (txDelta !== 0) {
    console.error(`  ❌ tx_count expected unchanged, got +${txDelta}`);
    ok = false;
  } else {
    console.log('  ✓ tx_count unchanged (CreateWallet does not bump tx_count)');
  }

  if (!ok) process.exit(1);
  console.log('\n✓ Fee recording working end-to-end on devnet');
}

main().catch((err) => {
  console.error('Failed:', err);
  process.exit(1);
});
