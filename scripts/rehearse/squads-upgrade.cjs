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
//   preflight              every invariant that must hold before the vault is
//                          given anything, as PASS/FAIL, plus the exact
//                          handover command with the addresses filled in
//   dry-run                propose a harmless memo vault transaction, to prove
//                          the members can approve and execute at all —
//                          do this BEFORE handing over a live program
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
//   MEMBERS      comma-separated keypair files; the first THRESHOLD approve.
//                With a real multisig you usually hold one of them: set it as
//                the only entry (or use PROPOSER) together with PROPOSE_ONLY=1
//                and approve in the Squads app. It must be a member with
//                Initiate permission — `preflight` checks that.
//   PROPOSER     alias for a single-key MEMBERS
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
// `ExtendProgramChecked` is never coming. Agave retired the gate by pointing it
// at a burn address — `solana feature status` on mainnet lists
// ExtendProgCheckedWi11BeDe1eted11111111111111 "Enable ExtendProgramChecked
// instruction", inactive, and nobody can hold that address's key to activate
// it. The id this script used to watch (2oMRZEDW…) is not even a known feature
// to solana-cli 4.2.2 any more. So there is one extend path: tag 6, top-level,
// any payer, no authority — which is also the only one the runtime allows,
// since it refuses the upgradeable loader via CPI for anything but Upgrade and
// SetAuthority.

function requireSigners() {
  if (!payer) throw new Error('set PAYER (a keypair file that pays fees)');
  if (!members.length) throw new Error('set MEMBERS or PROPOSER (keypair files of multisig members)');
}

function env(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (value === undefined) throw new Error(`set ${name}`);
  return value;
}
const load = (path) => Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(path, 'utf8'))));

const connection = new Connection(env('RPC_URL', 'https://api.devnet.solana.com'), 'confirmed');
// Read-only commands (`addresses`, `status`, `preflight`) must work with
// nothing but an address, so the signing material is optional until used.
const payer = process.env.PAYER ? load(process.env.PAYER) : null;
const memberList = process.env.MEMBERS ?? process.env.PROPOSER;
const members = memberList ? memberList.split(',').map(load) : [];
const threshold = Number(env('THRESHOLD', '2'));
const vaultIndex = Number(env('VAULT_INDEX', '0'));
// Upgrade refunds the buffer's rent and the programdata's excess here. It is a
// live payout of roughly a SOL, so it is worth naming rather than defaulting
// into whichever hot key happened to pay the fees.
const spill = process.env.SPILL ? new PublicKey(process.env.SPILL) : null;
const programId = new PublicKey(env('PROGRAM_ID'));
const createKey = process.env.MULTISIG ? null : load(env('CREATE_KEY'));
const multisigPda = process.env.MULTISIG
  ? new PublicKey(process.env.MULTISIG)
  : multisig.getMultisigPda({ createKey: createKey.publicKey })[0];
const [vault] = multisig.getVaultPda({ multisigPda, index: vaultIndex });
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

const MEMO_PROGRAM = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
const PERM = { Initiate: 1, Vote: 2, Execute: 4 };

function permNames(mask) {
  return Object.entries(PERM)
    .filter(([, bit]) => (mask & bit) !== 0)
    .map(([name]) => name)
    .join('+') || 'none';
}

// Everything that must hold before this vault is handed a live program, as
// PASS/FAIL. Read-only: it signs nothing and needs no keypair.
async function preflight() {
  let failed = 0;
  // true = PASS, false = FAIL (blocks the handover), 'warn' = worth a look,
  // null = context the operator needs but nothing to judge.
  const line = (ok, label, detail) => {
    if (ok === false) failed++;
    const tag = ok === false ? 'FAIL' : ok === true ? 'PASS' : ok === 'warn' ? 'WARN' : 'INFO';
    console.log(`${tag}  ${label.padEnd(22)} ${detail}`);
  };

  const ms = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda).catch(() => null);
  console.log(`multisig      ${multisigPda.toBase58()}`);
  if (!ms) {
    line(false, 'exists', 'no Squads v4 multisig at that address');
    process.exitCode = 1;
    return;
  }
  line(true, 'exists', `${ms.threshold} of ${ms.members.length}`);

  // A config authority can change members and threshold on its own, which makes
  // every approval below decorative. Squads writes the default pubkey for "none".
  const configAuthority = new PublicKey(ms.configAuthority);
  line(
    configAuthority.equals(PublicKey.default),
    'config authority',
    configAuthority.equals(PublicKey.default)
      ? 'none — only the members can change this multisig'
      : `${configAuthority.toBase58()} can rewrite members and threshold ALONE`,
  );

  const voters = ms.members.filter((m) => (m.permissions.mask & PERM.Vote) !== 0);
  const executors = ms.members.filter((m) => (m.permissions.mask & PERM.Execute) !== 0);
  line(
    voters.length >= ms.threshold,
    'voters',
    `${voters.length} member(s) may vote, threshold ${ms.threshold}` +
      (voters.length >= ms.threshold ? '' : ' — this multisig can never reach quorum'),
  );
  line(executors.length > 0, 'executors', `${executors.length} member(s) may execute`);
  for (const m of ms.members) {
    console.log(`      member       ${new PublicKey(m.key).toBase58()}  ${permNames(m.permissions.mask)}`);
  }

  const timeLock = Number(ms.timeLock);
  line(timeLock === 0 ? true : 'warn', 'time lock', timeLock === 0 ? '0' : `${timeLock}s delay on every execution`);
  const rentCollector = ms.rentCollector ? new PublicKey(ms.rentCollector).toBase58() : 'none';
  line(null, 'rent collector', rentCollector);

  const txIndex = BigInt(ms.transactionIndex.toString());
  line(
    txIndex > 0n ? true : 'warn',
    'proven',
    txIndex > 0n
      ? `${txIndex} vault transaction(s) so far`
      : 'never executed anything — run `dry-run` and execute it before handing over a live program',
  );

  // The proposer has to be a member, and needs Initiate. Approving in the app
  // is fine; proposing from this script is not, without that permission.
  if (members.length) {
    const proposer = members[0].publicKey;
    const record = ms.members.find((m) => new PublicKey(m.key).equals(proposer));
    line(
      !!record && (record.permissions.mask & PERM.Initiate) !== 0,
      'proposer',
      record
        ? `${proposer.toBase58()} ${permNames(record.permissions.mask)}`
        : `${proposer.toBase58()} is NOT a member of this multisig`,
    );
  } else {
    line('warn', 'proposer', 'no MEMBERS/PROPOSER given — set one to check it may propose');
  }

  const vaultBalance = await connection.getBalance(vault);
  line(null, `vault[${vaultIndex}]`, `${vault.toBase58()}  ${(vaultBalance / LAMPORTS_PER_SOL).toFixed(4)} SOL`);

  line(
    null,
    'extend path',
    'top-level ExtendProgram, any payer, no authority — the vault needs no SOL for it ' +
      '(ExtendProgramChecked is retired to a burn address and can never activate)',
  );

  // A spending limit lets one member move the vault's SOL with no vote. It
  // cannot touch the program, but it is the kind of thing to know about a vault
  // before trusting it with anything.
  const limits = await connection
    .getProgramAccounts(new PublicKey('SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf'), {
      dataSlice: { offset: 0, length: 0 },
      filters: [
        { memcmp: { offset: 0, bytes: '2odkUytTTsV' } }, // SpendingLimit discriminator
        { memcmp: { offset: 8, bytes: multisigPda.toBase58() } },
      ],
    })
    .catch(() => null);
  line(
    limits === null ? null : limits.length === 0 ? true : 'warn',
    'spending limits',
    limits === null
      ? 'could not scan (the RPC refused getProgramAccounts)'
      : limits.length === 0
        ? 'none'
        : `${limits.length} — a member can move vault SOL without a vote`,
  );

  const info = await connection.getAccountInfo(programData);
  if (!info) {
    line(false, 'program', `${programId.toBase58()} is not deployed`);
  } else {
    const authority = readAuthority(info.data, 12);
    const done = authority === vault.toBase58();
    line(
      done ? true : 'warn',
      'program authority',
      done ? `already the vault` : `${authority} (still a single key)`,
    );
    console.log(`      program      ${programId.toBase58()}  ${info.data.length - PROGRAMDATA_HEADER} bytes`);
    if (!done && authority !== 'none (immutable)') {
      console.log('');
      console.log('  Handover command — run it with the CURRENT authority key, and only after');
      console.log('  everything above reads PASS:');
      console.log('');
      console.log(`    solana program set-upgrade-authority ${programId.toBase58()} \\`);
      console.log(`      --new-upgrade-authority ${vault.toBase58()} \\`);
      console.log('      --skip-new-upgrade-authority-signer-check \\');
      console.log(`      --upgrade-authority <current-authority-keypair> --url ${connection.rpcEndpoint}`);
      console.log('');
      console.log('  The flag only waives the new authority\'s signature — a PDA cannot sign. It does');
      console.log('  NOT check that the address is a real vault, and nothing can undo the change');
      console.log('  afterwards except the vault itself. Re-run `preflight` to confirm.');
    }
  }

  console.log('');
  console.log(failed === 0 ? 'preflight: no failures' : `preflight: ${failed} FAIL — do not hand over`);
  if (failed > 0) process.exitCode = 1;
}

// Propose a memo signed by the vault: the cheapest transaction that still
// exercises proposal -> approvals -> execution with the vault as signer. Run
// this before the multisig has ever executed anything, so the first real
// upgrade is not also the first time these keys are used together.
async function dryRun() {
  requireSigners();
  const memo = new TransactionInstruction({
    programId: MEMO_PROGRAM,
    keys: [readonly(vault, true)],
    data: Buffer.from('lazorkit upgrade-authority dry run', 'utf8'),
  });
  await propose([memo], 'dry run: prove approve + execute');
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
      vaultIndex,
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

  // The number of approvals is the multisig's business, not an env var: a
  // THRESHOLD that disagrees with the chain either stops short of quorum or
  // spends signatures for nothing.
  const onChain = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda);
  const needed = onChain.threshold;
  const approved = new Set(proposal.approved.map((k) => k.toBase58()));
  for (const member of members.slice(0, needed)) {
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
  // Without this the script happily builds a proposal that can only ever fail:
  // the loader checks the signer against the program's authority, not the vault.
  const programAuthority = readAuthority(dataInfo.data, 12);
  if (programAuthority !== vault.toBase58()) {
    throw new Error(
      `program authority is ${programAuthority}, not the vault ${vault.toBase58()} — ` +
        'a vault transaction cannot upgrade it yet; run `preflight` for the handover command',
    );
  }
  const bufferAuthority = readAuthority(bufferInfo.data, 4);
  if (bufferAuthority !== vault.toBase58()) {
    throw new Error(`buffer authority is ${bufferAuthority}; set it to the vault ${vault.toBase58()} first`);
  }
  const shortfall = bufferInfo.data.length - BUFFER_HEADER - (dataInfo.data.length - PROGRAMDATA_HEADER);
  if (shortfall > 0) {
    // Deliberately not folded into this command. The extend is a separate
    // transaction that lands immediately, before any member has agreed to
    // anything, and it cannot be undone — a program's data only grows. It
    // belongs in its own step the operator chooses to take.
    throw new Error(
      `programdata is ${shortfall} bytes too small for this buffer — run ` +
        `\`extend ${Math.max(shortfall, MIN_EXTEND)}\` first (top-level, any payer, irreversible)`,
    );
  }
  const spillTo = spill ?? payer.publicKey;
  console.log(`spill (reclaimed rent) -> ${spillTo.toBase58()}${spill ? '' : '  [SPILL unset: the fee payer]'}`);
  await propose([upgrade(buffer, spillTo)], 'upgrade program');
  await status();
}

// Grow the programdata account. No authority, no multisig, no undo.
async function extend(bytesArg) {
  requireSigners();
  const requested = Number(bytesArg ?? env('EXTEND_BYTES'));
  if (!Number.isInteger(requested) || requested <= 0) throw new Error('extend needs a positive byte count');
  const bytes = Math.max(requested, MIN_EXTEND);
  const info = await connection.getAccountInfo(programData);
  if (!info) throw new Error('program is not deployed');
  const rent = (await connection.getMinimumBalanceForRentExemption(info.data.length + bytes)) - info.lamports;
  console.log(`extend ${programId.toBase58()} by ${bytes} bytes (loader minimum ${MIN_EXTEND})`);
  console.log(`  current      ${info.data.length - PROGRAMDATA_HEADER} bytes`);
  console.log(`  extra rent   ${rent > 0 ? (rent / LAMPORTS_PER_SOL).toFixed(6) + ' SOL' : 'none — already funded above the requirement'}`);
  await send('extendProgram', [extendProgram(bytes)], [payer]);
  await status();
}

async function main() {
  const [command, arg] = process.argv.slice(2);
  switch (command) {
    case 'preflight':
      return preflight();
    case 'dry-run':
      return dryRun();
    case 'create':
      requireSigners();
      return create();
    case 'addresses': {
      console.log(`multisig      ${multisigPda.toBase58()}`);
      console.log(`  vault[${vaultIndex}]    ${vault.toBase58()}`);
      // A vault is derived from whatever address you pass, so a typo prints a
      // perfectly confident answer for a multisig that does not exist. Say so.
      if (process.env.OFFLINE === '1') {
        console.log('  (OFFLINE — not checked against the chain)');
        return;
      }
      const ms = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda).catch(() => null);
      console.log(ms ? `  verified    ${ms.threshold} of ${ms.members.length} on ${connection.rpcEndpoint}` : '  NOT A SQUADS V4 MULTISIG at that address');
      if (!ms) process.exitCode = 1;
      return;
    }
    case 'status':
      return status();
    case 'extend':
      return extend(arg);
    case 'upgrade':
      requireSigners();
      return upgradeFromBuffer(arg ?? env('BUFFER'));
    case 'set-authority':
      requireSigners();
      // This one moves authority OUT of the vault — the opposite of the
      // handover, and just as irreversible.
      console.log(`moving the upgrade authority away from the vault, to ${arg}`);
      await propose([setAuthority(new PublicKey(arg))], `set authority -> ${arg}`);
      return status();
    case 'resume': {
      requireSigners();
      const ms = await multisig.accounts.Multisig.fromAccountAddress(connection, multisigPda);
      const latest = BigInt(ms.transactionIndex.toString());
      if (latest === 0n) throw new Error('no vault transaction to resume');
      // Whatever is newest is not necessarily yours: anyone else proposing from
      // the Squads app moves this index, and resuming blindly would approve and
      // execute their transaction with your key. Name the index instead.
      const index = arg === undefined ? null : BigInt(arg);
      if (index === null) {
        throw new Error(
          `resume needs the transaction index, e.g. \`resume ${latest}\` — the newest on this ` +
            'multisig. Check in the Squads app that it is yours before approving it.',
        );
      }
      if (index > latest) throw new Error(`vault transaction #${index} does not exist (newest is #${latest})`);
      console.log(`resuming vault transaction #${index}`);
      await finish(index);
      return status();
    }
    default:
      throw new Error(
        'usage: squads-upgrade.cjs preflight | dry-run | create | addresses | status | ' +
          'extend <bytes> | upgrade <buffer> | set-authority <key> | resume <index>',
      );
  }
}

main().catch((e) => {
  console.error(e.message ?? e);
  if (e.logs) console.error(e.logs.join('\n'));
  process.exit(1);
});
