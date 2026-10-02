// Seed a v1 wallet owned by somebody else's passkey, so they can test the
// migration UI against real funds without ever handing over a key.
//
// Creating a v1 wallet needs no passkey signature — only the payer signs — so
// the three public values the UI prints (credential-id hash, compressed public
// key, rp id) are enough. Run this while the program is on the v1 binary.
//
//   PROGRAM_ID=… PAYER=…/devnet-init-authority.json \
//   CREDENTIAL_ID_HASH=<hex> COMPRESSED_PUBKEY=<hex> RP_ID=portal.lazor.sh \
//   NODE_PATH=<dir with sdk-v1 + spl-token> node seed-v1-wallet-for-passkey.cjs
//
// `sdk-v1` is @lazorkit/sdk-legacy 0.3.2 (protocol v1), installed under an
// alias: npm i "sdk-v1@npm:@lazorkit/sdk-legacy@0.3.2" @solana/spl-token
'use strict';
const fs = require('fs');
const crypto = require('crypto');
const {
  Connection, Keypair, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction,
} = require('@solana/web3.js');
const spl = require('@solana/spl-token');
const sdk = require('sdk-v1');

const hexBytes = (name) => {
  const raw = (process.env[name] || '').replace(/^0x/, '').trim();
  if (!/^[0-9a-fA-F]+$/.test(raw)) throw new Error(`${name} must be hex`);
  return Uint8Array.from(Buffer.from(raw, 'hex'));
};

const RPC = process.env.RPC_URL || 'https://api.devnet.solana.com';
const PROGRAM = new PublicKey(process.env.PROGRAM_ID);
const RP_ID = process.env.RP_ID || 'portal.lazor.sh';
const SOL = Number(process.env.FUND_LAMPORTS || 40_000_000);
const TOKENS = BigInt(process.env.FUND_TOKENS || 500_000);
const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(process.env.PAYER, 'utf8'))));

(async () => {
  const credentialIdHash = hexBytes('CREDENTIAL_ID_HASH');
  const compressedPubkey = hexBytes('COMPRESSED_PUBKEY');
  if (credentialIdHash.length !== 32) throw new Error('CREDENTIAL_ID_HASH must be 32 bytes');
  if (compressedPubkey.length !== 33) throw new Error('COMPRESSED_PUBKEY must be 33 bytes');

  const connection = new Connection(RPC, 'confirmed');
  const client = new sdk.LazorKitClient(connection, PROGRAM);
  const userSeed = crypto.randomBytes(32); // thrown away on purpose: the UI must not need it

  const { instructions, walletPda } = await client.createWallet({
    payer: payer.publicKey,
    userSeed,
    owner: { type: 'secp256r1', credentialIdHash, compressedPubkey, rpId: RP_ID },
  });
  const sig = await sendAndConfirmTransaction(
    connection, new Transaction().add(...instructions), [payer], { commitment: 'confirmed' },
  );
  const [vault] = client.findVault(walletPda);
  console.log('v1 wallet ', walletPda.toBase58());
  console.log('v1 vault  ', vault.toBase58());
  console.log('create    ', sig);

  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: vault, lamports: SOL }),
    ),
    [payer],
    { commitment: 'confirmed' },
  );

  if (TOKENS > 0n) {
    const mint = await spl.createMint(connection, payer, payer.publicKey, null, 6);
    const ata = await spl.getOrCreateAssociatedTokenAccount(connection, payer, mint, vault, true);
    await spl.mintTo(connection, payer, mint, ata.address, payer, TOKENS);
    console.log('mint      ', mint.toBase58(), '→', TOKENS.toString());
  }

  console.log('vault SOL ', (await connection.getBalance(vault)) / 1e9);
  console.log('\nSeeded. Upgrade the program to v2, then the passkey owner can migrate.');
})().catch((e) => {
  console.error('error:', e.message);
  process.exit(1);
});
