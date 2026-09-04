// Send MigrateWallet (Ed25519) against the upgraded v2 program on the local
// validator, and assert the SOL + SPL token moved and the v1 PDAs closed.
const { Connection, PublicKey, Keypair, Transaction, sendAndConfirmTransaction } = require('@solana/web3.js');
const fs = require('node:fs');
const path = require('node:path');

const REPO = process.env.REPO;
const { createMigrateWalletIx } = require(path.join(REPO, 'sdk/sdk-legacy/dist/utils/instructions.js'));
const OUT = process.env.OUT_DIR;

(async () => {
  const m = JSON.parse(fs.readFileSync(path.join(OUT, 'manifest.json'), 'utf8'));
  const owner = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(path.join(OUT, 'owner.json'), 'utf8'))));
  const programId = new PublicKey(m.programId);
  const conn = new Connection('http://127.0.0.1:8899', 'confirmed');

  const bal = (k) => conn.getBalance(new PublicKey(k));
  const tokenAmt = async (k) => {
    const info = await conn.getAccountInfo(new PublicKey(k));
    return info ? info.data.readBigUInt64LE(64) : 0n;
  };

  const payer = Keypair.generate();
  await conn.confirmTransaction(await conn.requestAirdrop(payer.publicKey, 2_000_000_000), 'confirmed');

  console.log('--- before migrate ---');
  console.log('vault SOL      ', await bal(m.vault));
  console.log('destination SOL', await bal(m.destination));
  console.log('source token   ', (await tokenAmt(m.sourceAta)).toString());
  console.log('dest token     ', (await tokenAmt(m.destAta)).toString());

  const ix = createMigrateWalletIx({
    payer: payer.publicKey,
    v1Wallet: new PublicKey(m.wallet),
    v1Authority: new PublicKey(m.authority),
    v1Vault: new PublicKey(m.vault),
    destination: new PublicKey(m.destination),
    refundDestination: new PublicKey(m.refundDest),
    authSigner: owner.publicKey,
    authSignerIsSigner: true,
    tokens: [{
      sourceAta: new PublicKey(m.sourceAta),
      destAta: new PublicKey(m.destAta),
      tokenProgram: new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'),
    }],
    programId,
  });

  const sig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [payer, owner], { commitment: 'confirmed' });
  console.log('migrate tx:', sig);

  console.log('--- after migrate ---');
  const destSol = await bal(m.destination);
  const destTok = await tokenAmt(m.destAta);
  const vaultSol = await bal(m.vault);
  const walletSol = await bal(m.wallet);
  const authSol = await bal(m.authority);
  console.log('vault SOL      ', vaultSol);
  console.log('destination SOL', destSol);
  console.log('dest token     ', destTok.toString());
  console.log('v1 wallet SOL  ', walletSol);
  console.log('v1 authority   ', authSol);

  const fail = [];
  if (destSol !== m.vaultLamports) fail.push(`destination SOL ${destSol} != ${m.vaultLamports}`);
  if (destTok.toString() !== m.heldTokens) fail.push(`dest token ${destTok} != ${m.heldTokens}`);
  if (vaultSol !== 0) fail.push(`vault not drained: ${vaultSol}`);
  if (walletSol !== 0) fail.push(`v1 wallet not closed: ${walletSol}`);
  if (authSol !== 0) fail.push(`v1 authority not closed: ${authSol}`);

  if (fail.length) { console.error('REHEARSAL FAILED:\n  ' + fail.join('\n  ')); process.exit(1); }
  console.log('\nREHEARSAL PASSED: SOL + token migrated on a real validator through an in-place upgrade.');
})().catch((e) => { console.error(e); process.exit(1); });
