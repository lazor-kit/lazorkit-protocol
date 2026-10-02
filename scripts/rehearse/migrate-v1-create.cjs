// Step 1 — make a real v1 wallet on devnet: SOL in the vault and an SPL token
// account it owns. The user seed is written to state.json ONLY so the final
// check can prove the migration never used it.
'use strict';
const fs = require('fs');
const crypto = require('crypto');
const {
  Connection, Keypair, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction,
} = require('@solana/web3.js');
const spl = require('@solana/spl-token');
const sdk = require('sdk-v1'); // @lazorkit/sdk-legacy 0.3.2 — protocol v1

const RPC = process.env.RPC_URL || 'https://api.devnet.solana.com';
const PROGRAM = new PublicKey(process.env.PROGRAM_ID);
const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(process.env.PAYER, 'utf8'))));

(async () => {
  const connection = new Connection(RPC, 'confirmed');
  const client = new sdk.LazorKitClient(connection, PROGRAM);

  const owner = Keypair.generate();
  const userSeed = crypto.randomBytes(32);

  const { instructions, walletPda } = await client.createWallet({
    payer: payer.publicKey,
    userSeed,
    owner: { type: 'ed25519', publicKey: owner.publicKey },
  });
  const createSig = await sendAndConfirmTransaction(
    connection, new Transaction().add(...instructions), [payer], { commitment: 'confirmed' },
  );
  const [vault] = client.findVault(walletPda);
  console.log('v1 wallet   ', walletPda.toBase58());
  console.log('v1 vault    ', vault.toBase58());
  console.log('create sig  ', createSig);

  // Fund the vault.
  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: vault, lamports: 50_000_000 }),
    ),
    [payer],
    { commitment: 'confirmed' },
  );

  // And give it a token, so the migration has to move an SPL account too.
  const mint = await spl.createMint(connection, payer, payer.publicKey, null, 6);
  const vaultAta = await spl.getOrCreateAssociatedTokenAccount(
    connection, payer, mint, vault, true,
  );
  await spl.mintTo(connection, payer, mint, vaultAta.address, payer, 1_234_000);

  const vaultLamports = await connection.getBalance(vault);
  const tokenBalance = (await connection.getTokenAccountBalance(vaultAta.address)).value.amount;
  console.log('vault SOL   ', vaultLamports / 1e9);
  console.log('mint        ', mint.toBase58());
  console.log('vault ATA   ', vaultAta.address.toBase58(), 'balance', tokenBalance);

  fs.writeFileSync(
    `${__dirname}/state.json`,
    JSON.stringify(
      {
        programId: PROGRAM.toBase58(),
        walletPda: walletPda.toBase58(),
        vault: vault.toBase58(),
        ownerSecret: Array.from(owner.secretKey),
        ownerPubkey: owner.publicKey.toBase58(),
        mint: mint.toBase58(),
        vaultAta: vaultAta.address.toBase58(),
        vaultLamports,
        tokenBalance,
        // Written down only to prove the migration never reads it.
        userSeedHex: Buffer.from(userSeed).toString('hex'),
      },
      null,
      2,
    ),
  );
  console.log('\nstate.json written');
})();
