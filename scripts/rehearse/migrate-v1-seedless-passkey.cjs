// Step 4 — migrate the passkey-owned wallet, with no user seed, through the
// Secp256r1 path: scan, plan, sign the challenge the way an authenticator
// would, send [precompile, migrate].
'use strict';
const fs = require('fs');
const { p256 } = require('@noble/curves/nist');
const { sha256 } = require('@noble/hashes/sha2');
const {
  Connection, Keypair, PublicKey, Transaction, sendAndConfirmTransaction,
} = require('@solana/web3.js');
const sdk = require('sdk-v2'); // 1.1.0 — protocol v2

const RPC = process.env.RPC_URL || 'https://api.devnet.solana.com';
const state = JSON.parse(fs.readFileSync(`${__dirname}/state-passkey.json`, 'utf8'));
const PROGRAM = new PublicKey(state.programId);
const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(process.env.PAYER, 'utf8'))));

const privateKey = Uint8Array.from(Buffer.from(state.privateKeyHex, 'hex'));
const compressedPubkey = Uint8Array.from(Buffer.from(state.compressedPubkeyHex, 'hex'));
const credentialIdHash = Uint8Array.from(Buffer.from(state.credentialIdHashHex, 'hex'));

const checks = [];
const check = (name, ok, detail = '') => {
  checks.push(ok);
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}${detail ? `   ${detail}` : ''}`);
};

const b64url = (bytes) =>
  Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** What a WebAuthn authenticator returns for `navigator.credentials.get()`. */
function assert(challenge) {
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(sha256(new TextEncoder().encode(state.rpId)), 0);
  authenticatorData[32] = 0x01; // user present
  // bytes 33..37 stay zero: LazorKit uses its own odometer, not this counter

  const clientDataJson = new TextEncoder().encode(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: b64url(challenge),
      origin: `https://${state.rpId}`,
      crossOrigin: false,
    }),
  );
  const clientDataJsonHash = sha256(clientDataJson);

  const signed = new Uint8Array(authenticatorData.length + clientDataJsonHash.length);
  signed.set(authenticatorData, 0);
  signed.set(clientDataJsonHash, authenticatorData.length);

  let signature = p256.sign(sha256(signed), privateKey);
  if (typeof signature.normalizeS === 'function') signature = signature.normalizeS();

  return {
    signature: signature.toCompactRawBytes(),
    authenticatorData,
    clientDataJsonHash,
    clientDataJson,
  };
}

(async () => {
  const connection = new Connection(RPC, 'confirmed');
  const client = new sdk.LazorKitClient(connection, PROGRAM);

  const found = await client.findV1WalletsByOwner(credentialIdHash, 'secp256r1');
  const match = found.find((w) => w.wallet.toBase58() === state.walletPda);
  check('scan finds the passkey wallet with no seed', !!match, match?.wallet.toBase58());
  check('reported as Owner rank', match?.role === 0);
  check('reported as a Secp256r1 authority', match?.authorityType === 1);

  const plan = await client.migrateV1Wallet({
    payer: payer.publicKey,
    owner: { type: 'secp256r1', credentialIdHash, compressedPubkey, rpId: state.rpId },
    v1Wallet: new PublicKey(state.walletPda),
  });
  check('plan takes the passkey path', plan.migrate.type === 'secp256r1');
  check('plan found the token account', plan.tokens.length === 1);

  const send = async (label, instructions) => {
    const sig = await sendAndConfirmTransaction(
      connection, new Transaction().add(...instructions), [payer], { commitment: 'confirmed' },
    );
    console.log(`      ${label}: ${sig}`);
    return sig;
  };

  if (plan.setupInstructions.length) await send('setup', plan.setupInstructions);

  // The authenticator signs the challenge; the payer is the only Solana signer.
  const response = assert(plan.migrate.challenge);
  await send('migrate', plan.migrate.finalize(response));

  const [v1WalletInfo, v1AuthInfo, v1VaultInfo, v2VaultInfo] =
    await connection.getMultipleAccountsInfo([
      new PublicKey(state.walletPda),
      plan.v1.authority,
      new PublicKey(state.vault),
      plan.v2Vault,
    ]);
  check('v1 wallet closed', v1WalletInfo === null);
  check('v1 authority closed', v1AuthInfo === null);
  check('v1 vault emptied', (v1VaultInfo?.lamports ?? 0) === 0);
  check('v2 vault holds the SOL', (v2VaultInfo?.lamports ?? 0) >= state.vaultLamports - 5_000_000,
    `${(v2VaultInfo?.lamports ?? 0) / 1e9} SOL`);

  const destAta = (
    await connection.getTokenAccountsByOwner(plan.v2Vault, { mint: new PublicKey(state.mint) })
  ).value[0];
  const destBalance = destAta
    ? (await connection.getTokenAccountBalance(destAta.pubkey)).value.amount
    : '0';
  check('tokens landed in the v2 vault', destBalance === state.tokenBalance,
    `${destBalance} of ${state.tokenBalance}`);

  // And the thing the signature is supposed to prevent: a second, tampered use.
  let replayRejected = false;
  try {
    await send('replay (must fail)', plan.migrate.finalize(response));
  } catch (e) {
    replayRejected = true;
  }
  check('the same signature cannot be replayed', replayRejected);

  const failed = checks.filter((c) => !c).length;
  console.log(failed ? `\n${failed} CHECK(S) FAILED` : '\nPASSKEY MIGRATION REHEARSAL PASSED');
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error('error:', e.message);
  if (e.logs) console.error(e.logs.slice(-10).join('\n'));
  process.exit(1);
});
