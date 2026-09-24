// Step 2 — migrate that wallet with @lazorkit/sdk-legacy 1.1.0, using nothing
// but the owner key. The user seed sits in state.json and is never read: this
// is the path a user has after clearing their browser storage.
'use strict';
const fs = require('fs');
const {
  Connection, Keypair, PublicKey, Transaction, sendAndConfirmTransaction,
} = require('@solana/web3.js');
const sdk = require('sdk-v2'); // 1.1.0 — protocol v2

const RPC = process.env.RPC_URL || 'https://api.devnet.solana.com';
const state = JSON.parse(fs.readFileSync(`${__dirname}/state.json`, 'utf8'));
const PROGRAM = new PublicKey(state.programId);
const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(process.env.PAYER, 'utf8'))));
const owner = Keypair.fromSecretKey(Uint8Array.from(state.ownerSecret));

const checks = [];
const check = (name, ok, detail = '') => {
  checks.push({ name, ok, detail });
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}${detail ? `   ${detail}` : ''}`);
};

(async () => {
  const connection = new Connection(RPC, 'confirmed');
  const client = new sdk.LazorKitClient(connection, PROGRAM);

  // ── 1. find the wallet from the owner key alone ──
  const found = await client.findV1WalletsByOwner(owner.publicKey.toBytes(), 'ed25519');
  const match = found.find((w) => w.wallet.toBase58() === state.walletPda);
  check('scan finds the v1 wallet with no seed', !!match, match ? match.wallet.toBase58() : `found ${found.length}`);
  check('it is reported as Owner rank', match?.role === 0, `role=${match?.role}`);
  check('vault address matches', match?.vault.toBase58() === state.vault);

  // ── 2. build the migration by address ──
  const plan = await client.migrateV1Wallet({
    payer: payer.publicKey,
    owner: { type: 'ed25519', publicKey: owner.publicKey },
    v1Wallet: new PublicKey(state.walletPda),
  });
  check('plan targets the same v1 accounts', plan.v1.wallet.toBase58() === state.walletPda);
  check('plan found the token account', plan.tokens.length === 1, plan.tokens[0]?.ata.toBase58());
  check('a fresh v2 seed was minted for the destination', !!plan.destinationUserSeed);
  check(
    'the minted seed is not the original',
    Buffer.from(plan.destinationUserSeed ?? []).toString('hex') !== state.userSeedHex,
  );

  const send = async (label, instructions, signers) => {
    const sig = await sendAndConfirmTransaction(
      connection, new Transaction().add(...instructions), signers, { commitment: 'confirmed' },
    );
    console.log(`      ${label}: ${sig}`);
    return sig;
  };

  // ── 3. setup, then the migration itself ──
  if (plan.setupInstructions.length) await send('setup', plan.setupInstructions, [payer]);
  if (plan.migrate.type !== 'ed25519') throw new Error('expected the ed25519 path');
  await send('migrate', [plan.migrate.instruction], [payer, owner]);

  // ── 4. did the funds actually move ──
  const [v1WalletInfo, v1AuthInfo, v1VaultInfo, v2VaultInfo] =
    await connection.getMultipleAccountsInfo([
      new PublicKey(state.walletPda),
      plan.v1.authority,
      new PublicKey(state.vault),
      plan.v2Vault,
    ]);
  check('v1 wallet closed', v1WalletInfo === null);
  check('v1 authority closed', v1AuthInfo === null);
  check('v1 vault emptied', (v1VaultInfo?.lamports ?? 0) === 0, `${v1VaultInfo?.lamports ?? 0} lamports`);
  check(
    'v2 vault holds the SOL',
    (v2VaultInfo?.lamports ?? 0) >= state.vaultLamports - 5_000_000,
    `${(v2VaultInfo?.lamports ?? 0) / 1e9} SOL`,
  );

  const destAta = plan.tokens.length
    ? (await connection.getTokenAccountsByOwner(plan.v2Vault, { mint: new PublicKey(state.mint) })).value[0]
    : undefined;
  const destBalance = destAta
    ? (await connection.getTokenAccountBalance(destAta.pubkey)).value.amount
    : '0';
  check('tokens landed in the v2 vault', destBalance === state.tokenBalance, `${destBalance} of ${state.tokenBalance}`);

  const failed = checks.filter((c) => !c.ok);
  console.log(failed.length ? `\n${failed.length} CHECK(S) FAILED` : '\nMIGRATION REHEARSAL PASSED');
  process.exit(failed.length ? 1 : 0);
})().catch((e) => {
  console.error('error:', e.message);
  if (e.logs) console.error(e.logs.slice(-8).join('\n'));
  process.exit(1);
});
