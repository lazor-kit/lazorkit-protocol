// Builds SIMD-0385 v1 transactions for the tests and scripts/txv1-smoke.mjs.
// The relayer itself never builds one: it only reads and signs them.
//
// The construction is the wallets' writer's (lazor-kit
// packages/react/core/wallet/txv1.ts, compileTransactionV1): web3.js's own
// compiler gives the account order, the header and the indexes, then the v1
// layout is written (see src/txv1.mjs). test/txv1.test.mjs checks that it
// reproduces every vector in test/fixtures/txv1-vectors.json byte for byte.
//
// Unlike the writer it refuses nothing: a test needs v1 bytes the relayer must
// refuse (a missing limit, a heap request, 4,097 bytes, 65 addresses). Only the
// config fields given are written, each with its mask bit, in the mask's order.

import { PublicKey, TransactionInstruction, TransactionMessage } from '@solana/web3.js';

const MASK = { priorityFee: 0b00011, computeUnitLimit: 0b00100, loadedAccountsDataSizeLimit: 0b01000, heapSize: 0b10000 };

/**
 * { wire, messageLength, signers, addresses } for `instructions` paid by
 * `payer`, with empty (zero) signature slots. `config` may hold
 * computeUnitLimit, loadedAccountsDataSizeLimit, heapSize (u32 each) and
 * priorityFeeLamports (a u64: bigint, number or decimal string). `mask`
 * overrides the mask that is written, to build malformed transactions.
 */
export function buildTxV1({ payer, blockhash, instructions, config = {}, mask }) {
  const message = new TransactionMessage({
    payerKey: new PublicKey(payer),
    recentBlockhash: blockhash,
    instructions: [...instructions],
  }).compileToV0Message();
  const { header, staticAccountKeys, compiledInstructions } = message;

  const fee = config.priorityFeeLamports ?? config.priorityFee;
  const fields = [];
  let bits = 0;
  if (fee !== undefined && fee !== null) {
    bits |= MASK.priorityFee;
    fields.push(u64(BigInt(fee)));
  }
  for (const name of ['computeUnitLimit', 'loadedAccountsDataSizeLimit', 'heapSize']) {
    if (config[name] === undefined || config[name] === null) continue;
    bits |= MASK[name];
    fields.push(u32(config[name]));
  }

  const parts = [
    Uint8Array.of(0x81, header.numRequiredSignatures, header.numReadonlySignedAccounts, header.numReadonlyUnsignedAccounts),
    u32(mask ?? bits),
    new PublicKey(blockhash).toBytes(),
    Uint8Array.of(compiledInstructions.length, staticAccountKeys.length),
    ...staticAccountKeys.map((k) => k.toBytes()),
    ...fields,
    ...compiledInstructions.map((ix) => Uint8Array.of(ix.programIdIndex, ix.accountKeyIndexes.length, ix.data.length & 0xff, ix.data.length >>> 8)),
    ...compiledInstructions.flatMap((ix) => [Uint8Array.from(ix.accountKeyIndexes), ix.data]),
  ];
  const messageBytes = Buffer.concat(parts.map((p) => Buffer.from(p)));
  const wire = new Uint8Array(messageBytes.length + 64 * header.numRequiredSignatures);
  wire.set(messageBytes, 0);
  return { wire, messageLength: messageBytes.length, signers: header.numRequiredSignatures, addresses: staticAccountKeys.length };
}

/** web3.js instructions from a vector's JSON input (base58 keys, base64 data). */
export function instructionsFromJson(list) {
  return list.map(
    (ix) =>
      new TransactionInstruction({
        programId: new PublicKey(ix.programId),
        keys: ix.keys.map((k) => ({ pubkey: new PublicKey(k.pubkey), isSigner: k.isSigner, isWritable: k.isWritable })),
        data: Buffer.from(ix.data, 'base64'),
      }),
  );
}

function u32(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError(`not a u32: ${value}`);
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value);
  return out;
}

function u64(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(value);
  return out;
}
