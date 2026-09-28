// The whole two-id rollout, end to end — on devnet, or on a local validator
// with the release artifacts (see docs/mainnet-deploy-checklist.md §3).
//
//   v2  at its own program id (already deployed)
//   v1  at another id, holding an Ed25519 wallet with a token and a session,
//       and a passkey wallet with a token
//   then the v1 id is upgraded to the sunset binary, and both wallets leave:
//   MigrateWallet executes at the v1 id and delivers into a v2 vault at the v2
//   id — the Ed25519 one through the kit SDK, the passkey one through
//   sdk-legacy with the default pairing, after a relayer's attempt to swap the
//   system program is refused — and the expired v1 session is closed by a keeper.
//
// Dependencies must resolve from this directory (ESM ignores NODE_PATH):
//   DEPS=$(mktemp -d)
//   npm i --prefix "$DEPS" @solana/web3.js@1.98.4 @solana/spl-token@0.4.9 \
//     @solana/kit@6 sdk-v1@npm:@lazorkit/sdk-legacy@0.3.2
//   ln -sfn "$DEPS/node_modules" scripts/rehearse/node_modules
//   ( cd sdk/sdk-kit && npm run build )     # the kit SDK is used from source
//   V1_SO=<v1 dump> SUNSET_SO=<rehearsal-v1 build> node scripts/rehearse/two-id-rehearsal.mjs
//
// Env: RPC_URL, WS_URL, DEPLOY_RPC_URL, PAYER, V2_PROGRAM_ID, V1_PROGRAM_ID, V1_SO | V1_PRELOADED,
//      SUNSET_SO, STATE_FILE
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
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
import { LazorKit } from '../../sdk/sdk-kit/dist/index.js';

// sdk-legacy from source, with its own web3.js, so no object crosses copies.
const requireLegacy = createRequire(new URL('../../sdk/sdk-legacy/package.json', import.meta.url));
const w3 = requireLegacy('@solana/web3.js');
const legacy = requireLegacy('./dist/index.js');

const RPC_URL = process.env.RPC_URL ?? 'https://api.devnet.solana.com';
// The CLI's deploy path is separate on purpose: on 2026-09-27 the public
// api.devnet endpoint failed every `solana program show/deploy/write-buffer`
// ("error sending request") while plain RPC calls to it worked, and a second
// public endpoint served the CLI fine.
const DEPLOY_RPC_URL = process.env.DEPLOY_RPC_URL ?? RPC_URL;
// A local validator serves websockets one port above RPC; set WS_URL there.
const WS_URL = process.env.WS_URL ?? RPC_URL.replace('https://', 'wss://').replace('http://', 'ws://');
const PAYER_PATH = process.env.PAYER ?? 'keys/devnet-init-authority.json';
const V2 = process.env.V2_PROGRAM_ID ?? '57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv';
const V1 = process.env.V1_PROGRAM_ID ?? '3AN3WnaAN6SteghykdM96qHSGUJiVAUHWFjiyz31myAA';

const payerBytes = Uint8Array.from(JSON.parse(fs.readFileSync(PAYER_PATH, 'utf8')));
const payer = Keypair.fromSecretKey(payerBytes);
const connection = new Connection(RPC_URL, 'confirmed');

// Public devnet endpoints drop and rate-limit requests; retry the reads and
// sends rather than lose a run half-way (a lost run strands the owner key, and
// with it the wallet).
async function retry(label, fn, tries = 8) {
  for (let i = 1; ; i++) {
    try {
      return await fn();
    } catch (e) {
      const msg = String(e?.message ?? e) + String(e?.context?.message ?? '');
      if (i >= tries || !/fetch failed|Too Many|429|TRANSPORT|timeout|ECONNRESET|error sending/i.test(msg)) throw e;
      console.log(`   ${label}: transient (${msg.slice(0, 60)}), retry ${i}`);
      await new Promise((r) => setTimeout(r, 2000 * i));
    }
  }
}

const checks = [];
const check = (name, ok, detail = '') => {
  checks.push(ok);
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}${detail ? `   ${detail}` : ''}`);
};
const sol = (n) => (Number(n) / 1e9).toFixed(6);

function deploy(so, label) {
  console.log(`\n${label}`);
  // The public devnet RPC drops the CLI's first account lookup often enough
  // ("AccountNotFound … error sending request") that a retry is the norm.
  for (let attempt = 1; ; attempt++) {
    try {
      const out = execFileSync(
        'solana',
        ['program', 'deploy', so, '--program-id', V1, '--upgrade-authority', PAYER_PATH,
          '--fee-payer', PAYER_PATH, '--url', DEPLOY_RPC_URL, '--max-sign-attempts', '60'],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
      );
      console.log('  ', out.trim().split('\n').pop());
      return;
    } catch (e) {
      if (attempt >= 5 || !/error sending request/.test(String(e.stderr))) throw e;
      console.log(`   RPC hiccup, retrying (${attempt})`);
      execFileSync('sleep', ['5']);
    }
  }
}

// A program deployed or upgraded in slot N only runs from slot N+1 ("Program is
// not deployed" until then). Public RPCs hide that; a local validator does not.
async function settle() {
  const from = await retry('slot', () => connection.getSlot());
  while ((await retry('slot', () => connection.getSlot())) < from + 2) {
    await new Promise((r) => setTimeout(r, 400));
  }
}

// ── 1. a v1 wallet, with a token and a short-lived session ─────────────
// On a local validator the v1 dump is preloaded instead (V1_PRELOADED=1, with
// `--upgradeable-program <v1 id> <dump> <payer>`): current validators refuse to
// *deploy* its old sbpf version, though they still run it — as mainnet does.
if (!process.env.V1_PRELOADED) {
  deploy(process.env.V1_SO, `deploying the v1 binary at ${V1}`);
  await settle();
}

const v1 = new sdkV1.LazorKitClient(connection, new PublicKey(V1));
const owner = Keypair.generate();
const created = await retry('create', () => v1.createWallet({
  payer: payer.publicKey,
  userSeed: Buffer.from(crypto.getRandomValues(new Uint8Array(32))),
  owner: { type: 'ed25519', publicKey: owner.publicKey },
}));
await retry('create tx', () =>
  sendAndConfirmTransaction(connection, new Transaction().add(...created.instructions), [payer], {
    commitment: 'confirmed',
  }),
);
const [v1Vault] = v1.findVault(created.walletPda);
console.log(`\nv1 wallet   ${created.walletPda.toBase58()}`);
// Written before anything else can fail: without the owner key a v1 wallet is
// only reachable by MigrateWallet, which the owner has to sign.
if (process.env.STATE_FILE) {
  fs.writeFileSync(
    process.env.STATE_FILE,
    JSON.stringify({ wallet: created.walletPda.toBase58(), owner: Array.from(owner.secretKey) }),
    { mode: 0o600 },
  );
}

await retry('fund', () =>
  sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: v1Vault, lamports: 30_000_000 }),
    ),
    [payer],
    { commitment: 'confirmed' },
  ),
);
const mint = await retry('mint', () => spl.createMint(connection, payer, payer.publicKey, null, 6));
const vaultAta = await retry('ata', () =>
  spl.getOrCreateAssociatedTokenAccount(connection, payer, mint, v1Vault, true),
);
await retry('mintTo', () => spl.mintTo(connection, payer, mint, vaultAta.address, payer, 777_000));
console.log(`funded      0.03 SOL + 777,000 of ${mint.toBase58()}`);

const sessionKey = Keypair.generate();
const sessionExpiry = (await retry('slot', () => connection.getSlot())) + 60;
const sess = await retry('session', () => v1.createSession({
  payer: payer.publicKey,
  walletPda: created.walletPda,
  adminSigner: { type: 'ed25519', publicKey: owner.publicKey },
  sessionKey: sessionKey.publicKey,
  expiresAt: BigInt(sessionExpiry),
}));
await retry('session tx', () =>
  sendAndConfirmTransaction(connection, new Transaction().add(...sess.instructions), [payer, owner], {
    commitment: 'confirmed',
  }),
);
console.log(`v1 session  ${sess.sessionPda.toBase58()}  expires at slot ${sessionExpiry}`);

// A passkey-owned v1 wallet — how every Seedless user holds one. The
// "authenticator" is a P-256 key this process holds, producing the same
// authenticatorData / clientDataJSON / signature a real one would.
const RP_ID = 'portal.lazor.sh';
const passkeyPrivate = p256.utils.randomPrivateKey();
const compressedPubkey = p256.getPublicKey(passkeyPrivate, true);
const credentialIdHash = sha256(crypto.getRandomValues(new Uint8Array(64)));
const pkCreated = await retry('passkey create', () => v1.createWallet({
  payer: payer.publicKey,
  userSeed: Buffer.from(crypto.getRandomValues(new Uint8Array(32))),
  owner: { type: 'secp256r1', credentialIdHash, compressedPubkey, rpId: RP_ID },
}));
await retry('passkey create tx', () =>
  sendAndConfirmTransaction(connection, new Transaction().add(...pkCreated.instructions), [payer], {
    commitment: 'confirmed',
  }),
);
const [pkVault] = v1.findVault(pkCreated.walletPda);
if (process.env.STATE_FILE) {
  const state = JSON.parse(fs.readFileSync(process.env.STATE_FILE, 'utf8'));
  state.passkeyWallet = pkCreated.walletPda.toBase58();
  state.passkeyPrivateHex = Buffer.from(passkeyPrivate).toString('hex');
  fs.writeFileSync(process.env.STATE_FILE, JSON.stringify(state), { mode: 0o600 });
}
await retry('passkey fund', () =>
  sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: pkVault, lamports: 20_000_000 }),
    ),
    [payer],
    { commitment: 'confirmed' },
  ),
);
const pkAta = await retry('passkey ata', () =>
  spl.getOrCreateAssociatedTokenAccount(connection, payer, mint, pkVault, true),
);
await retry('passkey mintTo', () => spl.mintTo(connection, payer, mint, pkAta.address, payer, 555_000));
// A second token, on Token-2022: the passkey challenge binds each source
// account by its position, which only a vault with two or more can exercise.
const mint22 = await retry('mint22', () =>
  spl.createMint(connection, payer, payer.publicKey, null, 6, undefined, undefined, spl.TOKEN_2022_PROGRAM_ID),
);
const pkAta22 = await retry('passkey ata22', () =>
  spl.getOrCreateAssociatedTokenAccount(connection, payer, mint22, pkVault, true, undefined, undefined, spl.TOKEN_2022_PROGRAM_ID),
);
await retry('passkey mintTo22', () =>
  spl.mintTo(connection, payer, mint22, pkAta22.address, payer, 333_000, [], undefined, spl.TOKEN_2022_PROGRAM_ID),
);
console.log(`v1 passkey  ${pkCreated.walletPda.toBase58()}  0.02 SOL + 555,000 SPL + 333,000 Token-2022`);

// ── 2. retire the v1 id ────────────────────────────────────────────────
deploy(process.env.SUNSET_SO, `upgrading ${V1} to the sunset binary`);
await settle();

// Anything but the three ways out is refused.
try {
  const again = await v1.createWallet({
    payer: payer.publicKey,
    userSeed: Buffer.from(crypto.getRandomValues(new Uint8Array(32))),
    owner: { type: 'ed25519', publicKey: Keypair.generate().publicKey },
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(...again.instructions), [payer], {
    commitment: 'confirmed',
  });
  check('the sunset binary refuses CreateWallet', false, 'it succeeded');
} catch (e) {
  const refused = /0xfb2|4018/.test(String(e.message ?? e) + JSON.stringify(e.logs ?? []));
  check('the sunset binary refuses CreateWallet with 4018 RetiredDeployment', refused);
}

// ── 3. migrate into v2, across program ids, with the kit SDK ───────────
const rpc = createSolanaRpc(RPC_URL);
const rpcSubscriptions = createSolanaRpcSubscriptions(WS_URL);
const lk = new LazorKit(rpc, address(V2));

const found = await retry('scan', () =>
  lk.findV1WalletsByOwner(owner.publicKey.toBytes(), 'ed25519', address(V1)),
);
check('the v1 wallet is found at the v1 id from the owner key alone', found.length === 1);

const plan = await retry('plan', () =>
  lk.migrateV1Wallet({
    payer: address(payer.publicKey.toBase58()),
    owner: { type: 'ed25519', publicKey: address(owner.publicKey.toBase58()) },
    v1Wallet: found[0].wallet,
    v1ProgramId: address(V1),
  }),
);
check('the migrate instruction goes to the v1 program', plan.migrate.instruction.programAddress === V1);

const payerKeyPair = await createKeyPairFromBytes(payerBytes);
const ownerKeyPair = await createKeyPairFromBytes(owner.secretKey);
const sendAndConfirm = sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions });
async function send(label, instructions, keyPairs) {
  const { value: blockhash } = await retry('blockhash', () =>
    rpc.getLatestBlockhash({ commitment: 'confirmed' }).send(),
  );
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayer(address(payer.publicKey.toBase58()), m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(blockhash, m),
    (m) => appendTransactionMessageInstructions(instructions, m),
  );
  const signed = await signTransaction(keyPairs, compileTransaction(message));
  await retry(label, () => sendAndConfirm(signed, { commitment: 'confirmed' }));
  console.log(`  ${label.padEnd(10)} ${getSignatureFromTransaction(signed)}`);
}
await send('setup', plan.setupInstructions, [payerKeyPair]); // the v2 wallet + ATA, at the v2 id
await send('migrate', [plan.migrate.instruction], [payerKeyPair, ownerKeyPair]); // at the v1 id

const [w, a] = (
  await rpc.getMultipleAccounts([plan.v1.wallet, plan.v1.authority], { encoding: 'base64' }).send()
).value;
check('the v1 wallet and authority are closed', w === null && a === null);
const v2VaultInfo = (await rpc.getAccountInfo(plan.v2Vault, { encoding: 'base64' }).send()).value;
check('the SOL is in the v2 vault', !!v2VaultInfo && Number(v2VaultInfo.lamports) >= 30_000_000,
  v2VaultInfo ? `${sol(v2VaultInfo.lamports)} SOL at ${plan.v2Vault}` : 'missing');
const destAta = await spl.getAssociatedTokenAddress(mint, new PublicKey(plan.v2Vault), true);
const bal = await retry('balance', () => connection.getTokenAccountBalance(destAta)).catch(() => null);
check('the token is in the v2 vault', bal?.value.amount === '777000', bal?.value.amount);
const v2Wallet = (await rpc.getAccountInfo(plan.destinationWallet, { encoding: 'base64' }).send()).value;
check('the destination wallet belongs to the v2 program', v2Wallet?.owner === V2);

// ── 4. the passkey wallet leaves through sdk-legacy ────────────────────
const b64url = (bytes) =>
  Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
/** What a WebAuthn authenticator returns for `navigator.credentials.get()`. */
function authenticate(challenge) {
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(sha256(new TextEncoder().encode(RP_ID)), 0);
  authenticatorData[32] = 0x01; // user present
  const clientDataJson = new TextEncoder().encode(
    JSON.stringify({ type: 'webauthn.get', challenge: b64url(challenge), origin: `https://${RP_ID}`, crossOrigin: false }),
  );
  const clientDataJsonHash = sha256(clientDataJson);
  const signed = new Uint8Array(69);
  signed.set(authenticatorData, 0);
  signed.set(clientDataJsonHash, 37);
  let signature = p256.sign(sha256(signed), passkeyPrivate);
  if (typeof signature.normalizeS === 'function') signature = signature.normalizeS();
  return { signature: signature.toCompactRawBytes(), authenticatorData, clientDataJsonHash, clientDataJson };
}

const lconn = new w3.Connection(RPC_URL, 'confirmed');
const lpayer = w3.Keypair.fromSecretKey(payerBytes);
const lk1 = new legacy.LazorKitClient(lconn, new w3.PublicKey(V2));
// On the real ids the SDK finds the v1 program by itself; on the rehearsal
// slot (3AN3Wn…, paired with nothing) it has to be told.
const paired = legacy.legacyProgramIdFor(new w3.PublicKey(V2)).toBase58() === V1;
const pairing = paired ? {} : { v1ProgramId: new w3.PublicKey(V1) };
console.log(`\npasskey migration (${paired ? 'default pairing' : 'explicit v1 id'})`);
const pkFound = await retry('passkey scan', () =>
  lk1.findV1WalletsByOwner(credentialIdHash, 'secp256r1', ...(paired ? [] : [new w3.PublicKey(V1)])),
);
check('the passkey wallet is found from its credential alone', pkFound.length === 1);
const pkPlan = await retry('passkey plan', () =>
  lk1.migrateV1Wallet({
    payer: lpayer.publicKey,
    owner: { type: 'secp256r1', credentialIdHash, compressedPubkey: pkFound[0].ownerPubkey, rpId: RP_ID },
    v1Wallet: pkFound[0].wallet,
    ...pairing,
  }),
);
const lsend = (label, instructions) =>
  retry(label, () =>
    w3.sendAndConfirmTransaction(lconn, new w3.Transaction().add(...instructions), [lpayer], {
      commitment: 'confirmed',
    }),
  ).then((sig) => console.log(`  ${label.padEnd(10)} ${sig}`));
await lsend('setup', pkPlan.setupInstructions);

const response = authenticate(pkPlan.migrate.challenge);
const [precompile, migrateIx] = pkPlan.migrate.finalize(response);
check('the passkey migrate goes to the v1 program', migrateIx.programId.toBase58() === V1);

// The relayer is the payer and holds a valid assertion. Swapping account 6 for
// a no-op program would once have closed the wallet and stranded its SOL.
const tampered = new w3.TransactionInstruction({
  programId: migrateIx.programId,
  data: migrateIx.data,
  keys: migrateIx.keys.map((k, i) =>
    i === 6 ? { ...k, pubkey: new w3.PublicKey('ComputeBudget111111111111111111111111111111') } : k,
  ),
});
let swapRefused = false;
try {
  await w3.sendAndConfirmTransaction(lconn, new w3.Transaction().add(precompile, tampered), [lpayer], {
    commitment: 'confirmed',
  });
} catch (e) {
  swapRefused = /IncorrectProgramId|incorrect program id/i.test(String(e.message) + JSON.stringify(e.logs ?? []));
}
check('a relayer swapping the system program is refused', swapRefused);

await lsend('migrate', [precompile, migrateIx]);
const [pw, pa, pv] = await lconn.getMultipleAccountsInfo([
  pkPlan.v1.wallet,
  pkPlan.v1.authority,
  pkPlan.v1.vault,
]);
check('the passkey wallet and authority are closed, the vault empty', !pw && !pa && (pv?.lamports ?? 0) === 0);
const pkV2Vault = await lconn.getBalance(pkPlan.v2Vault);
check('its SOL is in its own v2 vault', pkV2Vault >= 20_000_000, `${sol(pkV2Vault)} SOL`);
const pkDest = await spl.getAssociatedTokenAddress(mint, new PublicKey(pkPlan.v2Vault.toBase58()), true);
const pkBal = await retry('balance', () => connection.getTokenAccountBalance(pkDest)).catch(() => null);
check('its SPL token is in its own v2 vault', pkBal?.value.amount === '555000', pkBal?.value.amount);
const pkDest22 = await spl.getAssociatedTokenAddress(mint22, new PublicKey(pkPlan.v2Vault.toBase58()), true, spl.TOKEN_2022_PROGRAM_ID);
const pkBal22 = await retry('balance22', () => connection.getTokenAccountBalance(pkDest22)).catch(() => null);
check('its Token-2022 token is in its own v2 vault', pkBal22?.value.amount === '333000', pkBal22?.value.amount);

// ── 5. the keeper closes the expired v1 session ───────────────────────
while ((await retry('slot', () => connection.getSlot())) <= sessionExpiry) await new Promise((r) => setTimeout(r, 2000));
console.log('\nsession expired; running the keeper');
const keeper = execFileSync('node', ['scripts/rehearse/close-expired-sessions.cjs', '--execute'], {
  encoding: 'utf8',
  env: { ...process.env, PROGRAM_ID: V1, KEEPER: PAYER_PATH, RPC_URL, NODE_PATH: 'tests-sdk/node_modules' },
});
console.log(keeper.trim().split('\n').slice(-3).join('\n'));
check('the v1 session is closed', (await retry('session read', () => connection.getAccountInfo(sess.sessionPda))) === null);

const failed = checks.filter((ok) => !ok).length;
console.log(`\n${checks.length - failed}/${checks.length} checks passed`);
process.exit(failed ? 1 : 0);
