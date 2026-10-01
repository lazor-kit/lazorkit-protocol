// A stub Solana JSON-RPC node and a launcher for the relayer, so the server
// tests run offline: no cluster, no funds. The stub answers the methods the
// relayer calls, records every call, and lands whatever is sent to it.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import bs58 from 'bs58';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

// A genesis hash that is neither devnet's nor mainnet's, as a local validator's.
export const LOCAL_GENESIS = '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY';
export const MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
export const STUB_BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';
export const STUB_BALANCE = 10_000_000_000;

/** The first signature of wire bytes: slot 0, wherever the format puts it. */
export function firstSignature(raw) {
  if (raw[0] === 0x81) {
    const at = raw.length - 64 * raw[1];
    return bs58.encode(raw.subarray(at, at + 64));
  }
  return bs58.encode(raw.subarray(1, 65)); // a compact-u16 count under 128, then the signatures
}

/**
 * A JSON-RPC server on 127.0.0.1. `calls` lists every { method, params };
 * `sent` every sendTransaction's bytes. A signature in `landed` is reported
 * confirmed; whatever is sent is landed. `simulate(txBase64)` may return a
 * whole JSON-RPC answer for simulateTransaction.
 */
export async function startStubRpc({ genesis = LOCAL_GENESIS } = {}) {
  const stub = { calls: [], sent: [], landed: new Map(), slot: 1000, simulate: null, url: null, close: null };
  const answer = (method, params = []) => {
    stub.calls.push({ method, params });
    const context = { context: { slot: stub.slot } };
    switch (method) {
      case 'getGenesisHash':
        return { result: genesis };
      case 'getAccountInfo':
        return { result: { ...context, value: null } };
      case 'getBalance':
        return { result: { ...context, value: STUB_BALANCE } };
      case 'getLatestBlockhash':
        return { result: { ...context, value: { blockhash: STUB_BLOCKHASH, lastValidBlockHeight: 5000 } } };
      case 'getMinimumBalanceForRentExemption':
        return { result: 890_880 };
      case 'getSlot':
        return { result: stub.slot };
      case 'isBlockhashValid':
        return { result: { ...context, value: true } };
      case 'simulateTransaction': {
        const custom = stub.simulate?.(params[0], params[1]);
        if (custom) return custom;
        const accounts = [{ lamports: STUB_BALANCE - 10_000, owner: '11111111111111111111111111111111', data: ['', 'base64'], executable: false, rentEpoch: 0, space: 0 }];
        return { result: { ...context, value: { err: null, logs: ['Program log: stub'], accounts, unitsConsumed: 13_011, innerInstructions: [], returnData: null } } };
      }
      case 'sendTransaction': {
        const raw = new Uint8Array(Buffer.from(params[0], 'base64'));
        const signature = firstSignature(raw);
        stub.sent.push({ raw, signature });
        stub.landed.set(signature, { slot: stub.slot + 1, err: null });
        return { result: signature };
      }
      case 'getSignatureStatuses': {
        const value = params[0].map((s) => {
          const l = stub.landed.get(s);
          return l ? { slot: l.slot, confirmations: null, err: l.err, status: l.err ? { Err: l.err } : { Ok: null }, confirmationStatus: 'confirmed' } : null;
        });
        return { result: { ...context, value } };
      }
      default:
        return { error: { code: -32601, message: `stub: method not found: ${method}` } };
    }
  };
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    const rpc = JSON.parse(body);
    const one = (r) => ({ jsonrpc: '2.0', id: r.id, ...answer(r.method, r.params) });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(Array.isArray(rpc) ? rpc.map(one) : one(rpc)));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  stub.url = `http://127.0.0.1:${server.address().port}`;
  stub.close = () => new Promise((resolve) => server.close(resolve));
  /** The methods called since `mark`. */
  stub.since = (mark) => stub.calls.slice(mark).map((c) => c.method);
  return stub;
}

async function freePort() {
  const s = net.createServer();
  await new Promise((resolve) => s.listen(0, '127.0.0.1', resolve));
  const { port } = s.address();
  await new Promise((resolve) => s.close(resolve));
  return port;
}

/** A keypair file for the relayer (mode 600) in a fresh temp directory. */
export function writeKeypair(keypair) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relayer-test-'));
  const file = path.join(dir, 'relayer-keypair.json');
  fs.writeFileSync(file, JSON.stringify([...keypair.secretKey]), { mode: 0o600 });
  return { file, remove: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

/**
 * Runs `node src/server.mjs` with `args` against `rpcUrl`. Resolves once it
 * listens, with { url, output(), stop() }; rejects with its output if it exits first.
 */
export async function startRelayer({ rpcUrl, keypairFile, args = [] }) {
  const port = await freePort();
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('RELAYER_')));
  const child = spawn(process.execPath, ['src/server.mjs', '--port', String(port), '--rpc', rpcUrl, '--keypair', keypairFile, ...args], {
    cwd: ROOT,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (d) => (out += d));
  child.stderr.on('data', (d) => (out += d));
  const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)));
  await new Promise((resolve, reject) => {
    const timer = setInterval(() => {
      if (/listening/.test(out)) {
        clearInterval(timer);
        resolve();
      }
    }, 20);
    exited.then((code) => {
      clearInterval(timer);
      reject(Object.assign(new Error(`relayer exited with ${code} before listening:\n${out}`), { code, output: out }));
    });
  });
  return {
    url: `http://127.0.0.1:${port}`,
    output: () => out,
    stop: async () => {
      if (child.exitCode === null) child.kill('SIGTERM');
      await exited;
    },
  };
}

/** Runs the relayer to completion (for startup refusals): { code, output }. */
export async function runRelayerToExit({ rpcUrl, keypairFile, args = [] }) {
  try {
    const r = await startRelayer({ rpcUrl, keypairFile, args });
    await r.stop();
    return { code: null, output: r.output() };
  } catch (e) {
    return { code: e.code, output: e.output ?? e.message };
  }
}

/** One JSON-RPC call to the relayer: the parsed body. */
export async function call(url, method, params) {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  return res.json();
}
