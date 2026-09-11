#!/usr/bin/env node
// Upgrade a program whose upgrade authority is a Squads v4 vault.
//
// Rehearsal tool: every member key is a local file, so one process can
// propose, approve and execute. On mainnet the same vault transaction is
// proposed here (or in the Squads app) and each member approves from their own
// wallet — only `create`'s output and the instruction layout carry over.
//
// Needs @sqds/multisig 2.1.x and @solana/web3.js 1.x resolvable:
//   npm i --prefix "$DIR" @sqds/multisig@2.1.4 @solana/web3.js@1.98.4
//   NODE_PATH="$DIR/node_modules" node scripts/rehearse/squads-upgrade.cjs <command>
//
// Commands:
//   create                 THRESHOLD-of-N multisig over MEMBERS; prints multisig + vault
//   addresses              multisig + vault addresses, no RPC
//   status                 program authority / data length, multisig state
//   upgrade <buffer>       extend the program data if the buffer is larger —
//                          top-level ExtendProgram while the runtime feature
//                          enable_extend_program_checked is inactive, else
//                          ExtendProgramChecked inside the vault transaction —
//                          then a vault transaction: [Upgrade]
//   set-authority <key>    vault transaction: SetAuthority(program -> key)
//   resume                 finish the latest vault transaction: create its
//                          proposal if missing, collect the missing approvals,
//                          execute
//
// Env:
//   RPC_URL      default https://api.devnet.solana.com
//   PAYER        keypair file; pays fees and rent
//   PROGRAM_ID   the upgradeable program
//   MEMBERS      comma-separated keypair files; the first THRESHOLD approve
//   MULTISIG     address of an existing multisig (as shown in the Squads app)
//   CREATE_KEY   keypair file seeding a new multisig's address; needed by
//                `create`, and otherwise only when MULTISIG is not set
//   THRESHOLD    default 2
//   PROPOSE_ONLY 1 = stop once the proposal exists. For a real multisig: run with
//                the proposer's keypair as the only MEMBERS entry, then approve
//                and execute in the Squads app (or `resume` with the keys).
'use strict';
const fs = require('fs');
const {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  ComputeBudgetProgram,
  SYSVAR_RENT_PUBKEY,
  SYSVAR_CLOCK_PUBKEY,
  LAMPORTS_PER_SOL,
  sendAndConfirmTransaction,
} = require('@solana/web3.js');
const multisig = require('@sqds/multisig');

const LOADER = new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111');
// Header sizes of loader-v3 accounts: Buffer = tag(4) + Option<authority>(33);
// ProgramData = tag(4) + slot(8) + Option<authority>(33).
const BUFFER_HEADER = 37;
const PROGRAMDATA_HEADER = 45;
// The loader refuses to extend by less than this unless it reaches the maximum.
const MIN_EXTEND = 10240;
// Runtime feature `enable_extend_program_checked`. Inactive on devnet and
// mainnet as of 2026-09-11.
const EXTEND_CHECKED_FEATURE = new PublicKey('2oMRZEDWT2tqtYMofhmmfQ8SsjqUFzT6sYXppQDavxwz');

function env(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (value === undefined) throw new Error(`set ${name}`);
  return value;
}
const load = (path) => Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(path, 'utf8'))));

const connection = new Connection(env('RPC_URL', 'https://api.devnet.solana.com'), 'confirmed');
const payer = load(env('PAYER'));
const members = env('MEMBERS').split(',').map(load);
const threshold = Number(env('THRESHOLD', '2'));
const programId = new PublicKey(env('PROGRAM_ID'));
const createKey = process.env.MULTISIG ? null : load(env('CREATE_KEY'));
const multisigPda = process.env.MULTISIG
  ? new PublicKey(process.env.MULTISIG)
  : multisig.getMultisigPda({ createKey: createKey.publicKey })[0];
const [vault] = multisig.getVaultPda({ multisigPda, index: 0 });
const [programData] = PublicKey.findProgramAddressSync([programId.toBuffer()], LOADER);

const writable = (pubkey, isSigner = false) => ({ pubkey, isSigner, isWritable: true });
const readonly = (pubkey, isSigner = false) => ({ pubkey, isSigner, isWritable: false });

// UpgradeableLoaderInstruction is bincode: a u32 LE variant tag, then fields.
function loaderIx(tag, keys, fields = Buffer.alloc(0)) {
  const data = Buffer.alloc(4 + fields.length);
  data.writeUInt32LE(tag, 0);
  fields.copy(data, 4);
  return new TransactionInstruction({ programId: LOADER, keys, data });
}
// Tag 6. No authority: anyone may pay to grow a program's data. Top-level only —
// the runtime refuses it via CPI — and rejected once the feature is active.
function extendProgram(bytes) {
  const fields = Buffer.alloc(4);
  fields.writeUInt32LE(bytes, 0);
  return loaderIx(
    6,
    [writable(programData), writable(programId), readonly(SystemProgram.programId), writable(payer.publicKey, true)],
    fields,
  );
}
// Tag 9. Needs the authority's signature and, with the feature active, may be
// invoked via CPI — so it then belongs inside the vault transaction.
function extendProgramChecked(bytes) {
  const fields = Buffer.alloc(4);
  fields.writeUInt32LE(bytes, 0);
  return loaderIx(
    9,
    [
      writable(programData),
      writable(programId),
      writable(vault, true), // authority
      readonly(SystemProgram.programId),
      writable(vault, true), // payer for the extra rent
    ],
    fields,
  );
}
// Tag 3.
function upgrade(buffer, spill) {
  return loaderIx(3, [
    writable(programData),
    writable(programId),
    writable(buffer),
    writable(spill),
    readonly(SYSVAR_RENT_PUBKEY),
    readonly(SYSVAR_CLOCK_PUBKEY),
    readonly(vault, true),
  ]);
}
// Tag 4.
function setAuthority(next) {
  return loaderIx(4, [writable(programData), readonly(vault, true), readonly(next)]);
}

async function confirmed(step, signature) {
  const latest = await connection.getLatestBlockhash('confirmed');
  const { value } = await connection.confirmTransaction({ signature, ...latest }, 'confirmed');
  if (value.err) throw new Error(`${step} failed: ${JSON.stringify(value.err)} (${signature})`);
  console.log(`  ${step.padEnd(24)} ${signature}`);
  return signature;
}

async function send(step, instructions, signers) {
  const signature = await sendAndConfirmTransaction(connection, new Transaction().add(...instructions), signers, {
    commitment: 'confirmed',
  });
  console.log(`  ${step.padEnd(24)} ${signature}`);
  return signature;
}

function readAuthority(data, offset) {
  return data[offset] === 1 ? new PublicKey(data.subarray(offset + 1, offset + 33)).toBase58() : 'none (immutable)';
}

async function status() {
  const info = await connection.getAccountInfo(programData);
  console.log(`program       ${programId.toBase58()}${info ? '' : ' (not deployed)'}`);
  if (info) {
    console.log(`  authority   ${readAuthority(info.data, 12)}`);
    console.log(`  data length ${info.data.length - PROGRAMDATA_HEADER}`);
    console.log(`  last slot   ${info.data.readBigUInt64LE(4)}`);
  }
  const ms = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda).catch(() => null);
  console.log(`multisig      ${multisigPda.toBase58()}${ms ? '' : ' (not created)'}`);
  console.log(`  vault       ${vault.toBase58()}`);
  if (ms) {
    console.log(`  threshold   ${ms.threshold} of ${ms.members.length}`);
    console.log(`  tx index    ${ms.transactionIndex.toString()}`);
  }
}

async function create() {
  if (!createKey) throw new Error('create needs CREATE_KEY; MULTISIG names a multisig that already exists');
  const [programConfigPda] = multisig.getProgramConfigPda({});
  const config = await multisig.accounts.ProgramConfig.fromAccountAddress(connection, programConfigPda);
  console.log(`creation fee  ${Number(config.multisigCreationFee) / LAMPORTS_PER_SOL} SOL`);
  const signature = await multisig.rpc.multisigCreateV2({
    connection,
    treasury: config.treasury,
    createKey,
    creator: payer,
    multisigPda,
    configAuthority: null,
    threshold,
    members: members.map((m) => ({ key: m.publicKey, permissions: multisig.types.Permissions.all() })),
    timeLock: 0,
    rentCollector: null,
    memo: 'upgrade-authority rehearsal',
  });
  await confirmed('multisigCreateV2', signature);
  await status();
}

// Wrap `instructions` in a new vault transaction, then finish it.
async function propose(instructions, memo) {
  const ms = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda);
  const transactionIndex = BigInt(ms.transactionIndex.toString()) + 1n;
  const creator = members[0];
  const { blockhash } = await connection.getLatestBlockhash();
  const transactionMessage = new TransactionMessage({ payerKey: vault, recentBlockhash: blockhash, instructions });

  console.log(`vault transaction #${transactionIndex}: ${memo}`);
  await confirmed(
    'vaultTransactionCreate',
    await multisig.rpc.vaultTransactionCreate({
      connection,
      feePayer: payer,
      multisigPda,
      transactionIndex,
      creator: creator.publicKey,
      rentPayer: payer.publicKey,
      vaultIndex: 0,
      ephemeralSigners: 0,
      transactionMessage,
      memo,
      signers: [creator],
    }),
  );
  await finish(transactionIndex);
}

// Proposal, approvals, execution — each step skipped if already done, so a run
// that died halfway can be resumed.
async function finish(transactionIndex) {
  const creator = members[0];
  const [proposalPda] = multisig.getProposalPda({ multisigPda, transactionIndex });
  const readProposal = () => multisig.accounts.Proposal.fromAccountAddress(connection, proposalPda).catch(() => null);

  let proposal = await readProposal();
  if (!proposal) {
    // Built by hand: rpc.proposalCreate in @sqds/multisig 2.1.4 signs with
    // `rentPayer` but never passes it to the instruction, so the rent is taken
    // from the creator instead.
    const ix = multisig.instructions.proposalCreate({
      multisigPda,
      transactionIndex,
      creator: creator.publicKey,
      rentPayer: payer.publicKey,
    });
    await send('proposalCreate', [ix], [payer, creator]);
    proposal = await readProposal();
  }
  if (proposal.status.__kind === 'Executed') {
    console.log(`  #${transactionIndex} already executed`);
    return;
  }
  if (process.env.PROPOSE_ONLY === '1') {
    console.log(`  proposal #${transactionIndex} is open: approve and execute it in the Squads app`);
    return;
  }

  const approved = new Set(proposal.approved.map((k) => k.toBase58()));
  for (const member of members.slice(0, threshold)) {
    if (approved.has(member.publicKey.toBase58())) continue;
    await confirmed(
      `proposalApprove ${member.publicKey.toBase58().slice(0, 4)}`,
      await multisig.rpc.proposalApprove({ connection, feePayer: payer, member, multisigPda, transactionIndex }),
    );
  }

  // Built by hand rather than with rpc.vaultTransactionExecute so the compute
  // limit can be raised: the loader verifies the new ELF inside this CPI.
  const { instruction } = await multisig.instructions.vaultTransactionExecute({
    connection,
    multisigPda,
    transactionIndex,
    member: creator.publicKey,
  });
  await send(
    'vaultTransactionExecute',
    [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), instruction],
    [payer, creator],
  );
}

async function upgradeFromBuffer(bufferArg) {
  const buffer = new PublicKey(bufferArg);
  const [bufferInfo, dataInfo] = await Promise.all([
    connection.getAccountInfo(buffer),
    connection.getAccountInfo(programData),
  ]);
  if (!bufferInfo) throw new Error(`no buffer at ${buffer.toBase58()}`);
  const bufferAuthority = readAuthority(bufferInfo.data, 4);
  if (bufferAuthority !== vault.toBase58()) {
    throw new Error(`buffer authority is ${bufferAuthority}; set it to the vault ${vault.toBase58()} first`);
  }
  const shortfall = bufferInfo.data.length - BUFFER_HEADER - (dataInfo.data.length - PROGRAMDATA_HEADER);
  const instructions = [];
  if (shortfall > 0) {
    const bytes = Math.max(shortfall, MIN_EXTEND);
    console.log(`extend by ${bytes} bytes (needs ${shortfall}; loader minimum ${MIN_EXTEND})`);
    const feature = await connection.getAccountInfo(EXTEND_CHECKED_FEATURE);
    const checkedActive = !!feature && feature.data.length > 0 && feature.data[0] === 1;
    if (!checkedActive) {
      // The vault cannot do this one: the runtime refuses the loader's extend via
      // CPI. It needs no authority either, so the payer sends it directly.
      await send('extendProgram (top-level)', [extendProgram(bytes)], [payer]);
    } else {
      const rent =
        (await connection.getMinimumBalanceForRentExemption(dataInfo.data.length + bytes)) - dataInfo.lamports;
      const balance = await connection.getBalance(vault);
      if (balance < rent) {
        const top = rent - balance + 5_000_000;
        await send(`fund vault ${(top / LAMPORTS_PER_SOL).toFixed(4)} SOL`, [
          SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: vault, lamports: top }),
        ], [payer]);
      }
      instructions.push(extendProgramChecked(bytes));
    }
  }
  instructions.push(upgrade(buffer, payer.publicKey));
  await propose(instructions, 'upgrade program');
  await status();
}

async function main() {
  const [command, arg] = process.argv.slice(2);
  switch (command) {
    case 'create':
      return create();
    case 'addresses':
      console.log(`multisig      ${multisigPda.toBase58()}`);
      console.log(`  vault       ${vault.toBase58()}`);
      return;
    case 'status':
      return status();
    case 'upgrade':
      return upgradeFromBuffer(arg ?? env('BUFFER'));
    case 'set-authority':
      await propose([setAuthority(new PublicKey(arg))], `set authority -> ${arg}`);
      return status();
    case 'resume': {
      const ms = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda);
      const latest = BigInt(ms.transactionIndex.toString());
      if (latest === 0n) throw new Error('no vault transaction to resume');
      console.log(`resuming vault transaction #${latest}`);
      await finish(latest);
      return status();
    }
    default:
      throw new Error('usage: squads-upgrade.cjs create | addresses | status | upgrade <buffer> | set-authority <key> | resume');
  }
}

main().catch((e) => {
  console.error(e.message ?? e);
  if (e.logs) console.error(e.logs.join('\n'));
  process.exit(1);
});
