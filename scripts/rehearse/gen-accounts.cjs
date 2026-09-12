// Generate v1-shaped accounts to preload into a fresh solana-test-validator, so
// an in-place v1→v2 upgrade + MigrateWallet can be rehearsed without standing up
// v1's whole fee/protocol ceremony just to create one wallet. The bytes are
// exactly what v1 would have written (bare seeds, old discriminators).
const { PublicKey, Keypair } = require('@solana/web3.js');
const fs = require('node:fs');
const path = require('node:path');

const PROGRAM_ID = new PublicKey(process.env.PROGRAM_ID);
const TOKEN = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const SYSTEM = new PublicKey('11111111111111111111111111111111');
const OUT = process.env.OUT_DIR;

const acct = (pubkey, lamports, owner, data) => ({
  pubkey: pubkey.toBase58(),
  account: {
    lamports,
    data: [Buffer.from(data).toString('base64'), 'base64'],
    owner: owner.toBase58(),
    executable: false,
    rentEpoch: 0,
  },
});
const write = (name, obj) => fs.writeFileSync(path.join(OUT, name), JSON.stringify(obj, null, 1));

const owner = Keypair.generate();
const userSeed = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff));

const [wallet, walletBump] = PublicKey.findProgramAddressSync([Buffer.from('wallet'), userSeed], PROGRAM_ID);
const [vault] = PublicKey.findProgramAddressSync([Buffer.from('vault'), wallet.toBuffer()], PROGRAM_ID);
const [authority, authBump] = PublicKey.findProgramAddressSync(
  [Buffer.from('authority'), wallet.toBuffer(), owner.publicKey.toBuffer()], PROGRAM_ID);

const wdata = Buffer.alloc(8);
wdata[0] = 1; wdata[1] = walletBump; wdata[2] = 1;
write('wallet.json', acct(wallet, 1_000_000, PROGRAM_ID, wdata));

const adata = Buffer.alloc(80);
adata[0] = 2; adata[1] = 0; adata[2] = 0; adata[3] = authBump; adata[4] = 1;
owner.publicKey.toBuffer().copy(adata, 48);
wallet.toBuffer().copy(adata, 16);
write('authority.json', acct(authority, 1_000_000, PROGRAM_ID, adata));

write('vault.json', acct(vault, 2_000_000_000, SYSTEM, Buffer.alloc(0)));

const mint = Keypair.generate().publicKey;
const mintData = Buffer.alloc(82);
mintData.writeUInt32LE(0, 0);
mintData.writeBigUInt64LE(1_000_000_000n, 36);
mintData[44] = 6; mintData[45] = 1;
write('mint.json', acct(mint, 1_461_600, TOKEN, mintData));

const held = 74_000_000n;
const srcAta = Keypair.generate().publicKey;
const srcData = Buffer.alloc(165);
mint.toBuffer().copy(srcData, 0);
vault.toBuffer().copy(srcData, 32);
srcData.writeBigUInt64LE(held, 64);
srcData[108] = 1;
write('source_ata.json', acct(srcAta, 2_039_280, TOKEN, srcData));

const destination = Keypair.generate().publicKey;
write('destination.json', acct(destination, 0, SYSTEM, Buffer.alloc(0)));
const destAta = Keypair.generate().publicKey;
const destData = Buffer.alloc(165);
mint.toBuffer().copy(destData, 0);
destination.toBuffer().copy(destData, 32);
destData.writeBigUInt64LE(0n, 64);
destData[108] = 1;
write('dest_ata.json', acct(destAta, 2_039_280, TOKEN, destData));

const refundDest = Keypair.generate().publicKey;

fs.writeFileSync(path.join(OUT, 'owner.json'), JSON.stringify(Array.from(owner.secretKey)));
fs.writeFileSync(path.join(OUT, 'manifest.json'), JSON.stringify({
  programId: PROGRAM_ID.toBase58(), wallet: wallet.toBase58(), vault: vault.toBase58(),
  authority: authority.toBase58(), mint: mint.toBase58(), sourceAta: srcAta.toBase58(),
  destination: destination.toBase58(), destAta: destAta.toBase58(), refundDest: refundDest.toBase58(),
  owner: owner.publicKey.toBase58(), heldTokens: held.toString(), vaultLamports: 2_000_000_000,
}, null, 2));
console.log('generated accounts for wallet', wallet.toBase58());
