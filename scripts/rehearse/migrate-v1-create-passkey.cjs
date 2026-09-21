// Step 3 — a v1 wallet owned by a passkey, so the migration has to go through
// the Secp256r1 path. The "authenticator" here is a P-256 key this process
// holds, producing the same authenticatorData / clientDataJSON / signature a
// real one would. Nothing about the program or the SDK can tell the difference:
// that is the point, it is the cryptography being tested, not the fingerprint.
'use strict';
const fs = require('fs');
const crypto = require('crypto');
const { p256 } = require('@noble/curves/nist');
const { sha256 } = require('@noble/hashes/sha2');
const {
  Connection, Keypair, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction,
} = require('@solana/web3.js');
const spl = require('@solana/spl-token');
const sdk = require('sdk-v1'); // 0.3.2 — protocol v1

const RPC = process.env.RPC_URL || 'https://api.devnet.solana.com';
const PROGRAM = new PublicKey(process.env.PROGRAM_ID);
const RP_ID = process.env.RP_ID || 'portal.lazor.sh';
const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(process.env.PAYER, 'utf8'))));

(async () => {
  const connection = new Connection(RPC, 'confirmed');
  const client = new sdk.LazorKitClient(connection, PROGRAM);

  const privateKey = p256.utils.randomPrivateKey();
  const compressedPubkey = p256.getPublicKey(privateKey, true); // 33 bytes
  const credentialId = crypto.randomBytes(64); // what a real authenticator hands back
  const credentialIdHash = sha256(credentialId);
  const userSeed = crypto.randomBytes(32);

  const { instructions, walletPda } = await client.createWallet({
    payer: payer.publicKey,
    userSeed,
    owner: { type: 'secp256r1', credentialIdHash, compressedPubkey, rpId: RP_ID },
  });
  const createSig = await sendAndConfirmTransaction(
    connection, new Transaction().add(...instructions), [payer], { commitment: 'confirmed' },
  );
  const [vault] = client.findVault(walletPda);
  console.log('v1 wallet   ', walletPda.toBase58());
  console.log('v1 vault    ', vault.toBase58());
  console.log('create sig  ', createSig);

  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: vault, lamports: 40_000_000 }),
    ),
    [payer],
    { commitment: 'confirmed' },
  );

  const mint = await spl.createMint(connection, payer, payer.publicKey, null, 6);
  const vaultAta = await spl.getOrCreateAssociatedTokenAccount(connection, payer, mint, vault, true);
  await spl.mintTo(connection, payer, mint, vaultAta.address, payer, 777_000);

  const vaultLamports = await connection.getBalance(vault);
  const tokenBalance = (await connection.getTokenAccountBalance(vaultAta.address)).value.amount;
  console.log('vault SOL   ', vaultLamports / 1e9, '| token', tokenBalance);

  fs.writeFileSync(
    `${__dirname}/state-passkey.json`,
    JSON.stringify(
      {
        programId: PROGRAM.toBase58(),
        rpId: RP_ID,
        walletPda: walletPda.toBase58(),
        vault: vault.toBase58(),
        privateKeyHex: Buffer.from(privateKey).toString('hex'),
        compressedPubkeyHex: Buffer.from(compressedPubkey).toString('hex'),
        credentialIdHex: credentialId.toString('hex'),
        credentialIdHashHex: Buffer.from(credentialIdHash).toString('hex'),
        mint: mint.toBase58(),
        vaultAta: vaultAta.address.toBase58(),
        vaultLamports,
        tokenBalance,
        userSeedHex: Buffer.from(userSeed).toString('hex'), // never read by the migration
      },
      null,
      2,
    ),
  );
  console.log('\nstate-passkey.json written');
})();
