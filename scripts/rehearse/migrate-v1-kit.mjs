// Migrate a v1 wallet with the KIT SDK, on devnet, end to end.
//
// The legacy SDK's migration has been run against a real chain three times. The
// kit SDK's has not: `@lazorkit/sdk` 1.0.0-rc.2 shipped `migrateV1Wallet` with
// unit tests and a byte-parity check against the legacy builder, which proves
// the instruction is identical but never proves the surrounding flow — the
// scan, the setup instructions, the seed it mints, the transaction it wants
// assembled — actually works.
//
// Steps, against a throwaway program id:
//   1. create a v1 wallet with @lazorkit/sdk-legacy 0.3.2 (protocol v1),
//      fund its vault and mint it a token
//   2. upgrade that program in place to v2
//   3. migrate with @lazorkit/sdk (kit), from the owner key alone — no user
//      seed, the case a returning user is actually in
//   4. read the chain back and check every claim
//
// ESM ignores NODE_PATH, so the dependencies have to be resolvable from this
// file's own directory:
//
//   DEPS=$(mktemp -d)
//   npm i --prefix "$DEPS" @solana/web3.js@1.98.4 @solana/spl-token@0.4.9 \
//     @solana/kit@6 @lazorkit/sdk@1.0.0-rc.2 sdk-v1@npm:@lazorkit/sdk-legacy@0.3.2
//   ln -sfn "$DEPS/node_modules" scripts/rehearse/node_modules
//   V1_SO=... V2_SO=... node scripts/rehearse/migrate-v1-kit.mjs
//
// Env: RPC_URL, PROGRAM_ID, PAYER (keypair file), V1_SO, V2_SO. Omitting V1_SO
// or V2_SO skips that deploy, for re-running a step against a program already
// in the right state.
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from '@solana/web3.js';
import * as spl from '@solana/spl-token';
import sdkV1 from 'sdk-v1';
import {
  LazorKit,
  findV1WalletsByOwner,
} from '@lazorkit/sdk';
import {
  address,
  appendTransactionMessageInstructions,
  compileTransaction,
  createKeyPairFromBytes,
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createTransactionMessage,
  getSignatureFromTransaction,
  pipe,
  sendAndConfirmTransactionFactory,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransaction,
} from '@solana/kit';

const RPC_URL = process.env.RPC_URL ?? 'https://api.devnet.solana.com';
const WS_URL = RPC_URL.replace('https://', 'wss://').replace('http://', 'ws://');
const PROGRAM_ID = process.env.PROGRAM_ID ?? '3AN3WnaAN6SteghykdM96qHSGUJiVAUHWFjiyz31myAA';
const PAYER_PATH = process.env.PAYER ?? 'keys/devnet-init-authority.json';
const V1_SO = process.env.V1_SO;
const V2_SO = process.env.V2_SO;

const payerBytes = Uint8Array.from(JSON.parse(fs.readFileSync(PAYER_PATH, 'utf8')));
const payer = Keypair.fromSecretKey(payerBytes);
const connection = new Connection(RPC_URL, 'confirmed');

const checks = [];
const check = (name, ok, detail = '') => {
  checks.push({ name, ok });
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}${detail ? `   ${detail}` : ''}`);
};
const sol = (n) => (Number(n) / 1e9).toFixed(6);

function deploy(so, label) {
  console.log(`\n${label}…`);
  const out = execFileSync(
    'solana',
    ['program', 'deploy', so, '--program-id', PROGRAM_ID, '--upgrade-authority', PAYER_PATH,
      '--fee-payer', PAYER_PATH, '--url', RPC_URL, '--max-sign-attempts', '60'],
    { encoding: 'utf8' },
  );
  console.log('  ', out.trim().split('\n').pop());
}

// ── 1. a real v1 wallet ────────────────────────────────────────────────
if (V1_SO) deploy(V1_SO, 'deploying the v1 binary');

const v1 = new sdkV1.LazorKitClient(connection, new PublicKey(PROGRAM_ID));
const owner = Keypair.generate();
const userSeed = crypto.getRandomValues(new Uint8Array(32));

const created = await v1.createWallet({
  payer: payer.publicKey,
  userSeed: Buffer.from(userSeed),
  owner: { type: 'ed25519', publicKey: owner.publicKey },
});
await sendAndConfirmTransaction(connection, new Transaction().add(...created.instructions), [payer], {
  commitment: 'confirmed',
});
const walletPda = created.walletPda;
const [v1Vault] = v1.findVault(walletPda);
console.log(`\nv1 wallet   ${walletPda.toBase58()}`);
console.log(`v1 vault    ${v1Vault.toBase58()}`);
console.log(`owner       ${owner.publicKey.toBase58()}  (the only thing the migration will get)`);

await sendAndConfirmTransaction(
  connection,
  new Transaction().add(
    SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: v1Vault, lamports: 30_000_000 }),
  ),
  [payer],
  { commitment: 'confirmed' },
);

const mint = await spl.createMint(connection, payer, payer.publicKey, null, 6);
const vaultAta = await spl.getOrCreateAssociatedTokenAccount(connection, payer, mint, v1Vault, true);
await spl.mintTo(connection, payer, mint, vaultAta.address, payer, 777_000);
console.log(`funded      0.03 SOL + 777,000 of ${mint.toBase58()}`);

// ── 2. the upgrade that breaks v1 ──────────────────────────────────────
if (V2_SO) deploy(V2_SO, 'upgrading in place to v2');

// ── 3. migrate, with the kit SDK, from the owner key alone ─────────────
const rpc = createSolanaRpc(RPC_URL);
const rpcSubscriptions = createSolanaRpcSubscriptions(WS_URL);
const programId = address(PROGRAM_ID);
const lk = new LazorKit(rpc, programId);

const ownerAddress = address(owner.publicKey.toBase58());
const ownerIdSeed = owner.publicKey.toBytes();

const found = await findV1WalletsByOwner(rpc, ownerIdSeed, programId, 'ed25519');
const match = found.find((w) => w.wallet === walletPda.toBase58());
check('the kit scan finds the v1 wallet with no user seed', !!match, `${found.length} result(s)`);
check(
  'the record carries the owner key read off the chain',
  !!match && Buffer.from(match.ownerPubkey).equals(Buffer.from(ownerIdSeed)),
);

const plan = await lk.migrateV1Wallet({
  payer: address(payer.publicKey.toBase58()),
  owner: { type: 'ed25519', publicKey: ownerAddress },
  v1Wallet: match.wallet,
});
check('it derives the same v1 vault', plan.v1.vault === v1Vault.toBase58());
check('it enumerates the vault token', plan.tokens.length === 1, plan.tokens[0]?.mint);
check('it minted a destination seed to persist', plan.destinationUserSeed?.length === 32);
check('the migration is a single Ed25519 instruction', plan.migrate.type === 'ed25519');

// Keypairs rather than kit "signers": the owner signs because the instruction
// lists its key as a signer, not because it is attached to the message, and
// signTransaction takes the pairs directly.
const payerKeyPair = await createKeyPairFromBytes(payerBytes);
const ownerKeyPair = await createKeyPairFromBytes(owner.secretKey);
const payerAddress = address(payer.publicKey.toBase58());
const sendAndConfirm = sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions });

async function send(label, instructions, keyPairs) {
  const { value: blockhash } = await rpc.getLatestBlockhash({ commitment: 'confirmed' }).send();
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayer(payerAddress, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(blockhash, m),
    (m) => appendTransactionMessageInstructions(instructions, m),
  );
  const signed = await signTransaction(keyPairs, compileTransaction(message));
  await sendAndConfirm(signed, { commitment: 'confirmed' });
  const signature = getSignatureFromTransaction(signed);
  console.log(`  ${label.padEnd(22)} ${signature}`);
  return signature;
}

// The v2 wallet and the destination ATA first; the migration itself second.
await send('setup', plan.setupInstructions, [payerKeyPair]);
await send('migrate', [plan.migrate.instruction], [payerKeyPair, ownerKeyPair]);

// ── 4. read the chain back ─────────────────────────────────────────────
const [v1WalletAfter, v1AuthAfter, v1VaultAfter] = (
  await rpc
    .getMultipleAccounts([plan.v1.wallet, plan.v1.authority, plan.v1.vault], { encoding: 'base64' })
    .send()
).value;
check('the v1 wallet is closed', v1WalletAfter === null);
check('the v1 authority is closed', v1AuthAfter === null);
check('the v1 vault is empty', !v1VaultAfter || Number(v1VaultAfter.lamports) === 0);

const { value: v2VaultInfo } = await rpc.getAccountInfo(plan.v2Vault, { encoding: 'base64' }).send();
check(
  'the SOL landed in the v2 vault',
  !!v2VaultInfo && Number(v2VaultInfo.lamports) >= 30_000_000,
  v2VaultInfo ? `${sol(v2VaultInfo.lamports)} SOL` : 'missing',
);

const destAta = await spl.getAssociatedTokenAddress(mint, new PublicKey(plan.v2Vault), true);
const destBalance = await connection.getTokenAccountBalance(destAta).catch(() => null);
check('the token landed too', destBalance?.value.amount === '777000', destBalance?.value.amount);

const sourceGone = await connection.getAccountInfo(vaultAta.address);
check('the emptied source token account is closed', sourceGone === null);

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exit(failed.length ? 1 : 0);
