# LazorKit devnet relayer

A small local fee payer that speaks the Kora JSON-RPC the released SDKs call
(`@lazorkit/wallet` 3.0.2 on the web, `@lazorkit/wallet-mobile-adapter` 2.0.0 on
mobile), so the playground apps can run gasless transactions against LazorKit v2 on
devnet (`57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv`).

It exists because the hosted devnet Kora (`https://kora.devnet.lazorkit.com`) does
not allow the v2 program id yet. It refuses every v2 transaction. When it does allow
v2, point the apps back at it and stop running this.

```bash
npm install
npm start                  # 127.0.0.1:8787 and localhost:8787 only
npm start -- --lan         # also the Wi-Fi address, for a phone on the same network
```

By default every sponsored transaction must call LazorKit v2, and browsers can
reach the relayer only from pages served by this Mac. See "Who can reach it" below.

On start it prints the fee payer, its balance, the policy and the URLs to use:

```
  fee payer    BJRfvkLaLEgnB8dWg6QJAekgdXM4MyRbdgrdwwqap3Wq
  balance      1.986411 SOL
  program      LazorKit v2 57bTNW… (deployed; relayer is not its upgrade authority)
  listening    http://127.0.0.1:8787
               http://localhost:8787
               http://192.168.100.130:8787   <- use this one on a phone (same Wi-Fi)
```

Stop it with Ctrl-C.

## Pointing an app at it

| App runs on | `paymasterUrl` |
|---|---|
| Web app in a browser on this Mac | `http://127.0.0.1:8787` (or `http://localhost:8787`) |
| Phone (Expo / browser) on the same Wi-Fi | `http://<LAN IP printed at start>:8787`, relayer started with `--lan` |
| Hosted devnet Kora (once it allows 57bTNW…) | `https://kora.devnet.lazorkit.com` |

```tsx
// web — @lazorkit/wallet
<LazorkitProvider rpcUrl="https://api.devnet.solana.com" portalUrl="https://portal.lazor.sh"
  paymasterConfig={{ paymasterUrl: 'http://127.0.0.1:8787' }}>

// mobile — @lazorkit/wallet-mobile-adapter
<LazorKitProvider rpcUrl="https://api.devnet.solana.com" portalUrl="https://portal.lazor.sh"
  configPaymaster={{ paymasterUrl: 'http://192.168.100.130:8787' }}>
```

If the relayer runs with `--api-key <key>`, give the app the same key as `apiKey` in
that config object. Both SDKs send it as `x-api-key`.

## The fee payer key

- `relayer-keypair.json` belongs to this relayer only: `BJRfvkLaLEgnB8dWg6QJAekgdXM4MyRbdgrdwwqap3Wq`.
  It was created with `solana-keygen new --no-bip39-passphrase --silent` and has mode `600`.
  It is listed in `.gitignore`. Do not copy it anywhere.
- It was funded with 2 devnet SOL from the CLI default wallet. To top it up:
  `solana transfer BJRfvkLaLEgnB8dWg6QJAekgdXM4MyRbdgrdwwqap3Wq 1 -u devnet`.
  Each wallet creation costs it about 0.004 SOL (rent). Each execute costs about 0.00001 SOL.
- The relayer checks these at startup and refuses to run if any of them fails:
  - the keypair path is `~/.config/solana/id.json` or anything under a `keys/` directory
  - the keypair file can be read by group or others (it must be `chmod 600`)
  - the key is the LazorKit v2 program's upgrade authority (read on-chain from the ProgramData account)
  - the RPC is mainnet (always refused) or is not devnet (allowed only with `--any-cluster`, for a local validator)

## Methods

The relayer implements the four methods the two SDK builds contain, and nothing else.
The web SDK's `Paymaster` class defines all four. On the main path, both packages call
only `getPayerSigner` and then `signAndSendTransaction`.

| Method | Params | Result |
|---|---|---|
| `getPayerSigner` | `[]` | `{ signer_address, payment_address }` (both are the relayer) |
| `getBlockhash` | `[]` | `{ blockhash }` (confirmed) |
| `signTransaction` | `{ transaction: base64, signer_key? }` | `{ signed_transaction: base64, signer_pubkey }` (not sent) |
| `signAndSendTransaction` | `{ transaction: base64, signer_key?, fee_token?, respond_after? }` | `{ signature, signed_transaction, signer_pubkey }` |

Legacy and v0 transactions both work. The relayer returns a transaction in the same
format it received. `fee_token` is ignored, because sponsorship is free, as in
`price.type = "free"`.

**`signAndSendTransaction` answers only once the transaction is confirmed.** This is
Kora's default (`respond_after: "confirmed"`). The relayer sends with preflight, then
polls the signature and answers when it reaches `confirmed`. The web SDK does not
confirm on its own: `@lazorkit/wallet` 3.0.2 returns the relayer's signature as soon as it
gets it, and the app can start the next passkey action straight away. (The mobile adapter
2.0.0 does call `confirmTransaction` before it returns.) That next action reads the authority's
counter and has the passkey sign counter + 1. If the previous transaction has not
executed yet, the passkey signs a counter that transaction is about to use, and the
program refuses it with custom error 3006 (`SignatureReused`). Answering after
`confirmed` makes a signature returned by the relayer mean "on chain", so a back-to-back
second transaction reads the counter the first one advanced.

- **Timeout.** If the transaction is not confirmed within `--confirm-timeout` seconds
  (default 30), the relayer answers with its signature anyway, as `respond_after: "sent"`
  would, logs `UNCONFIRMED`, and keeps watching it. It may still land, fail or expire,
  and the caller has the signature to find out. The released mobile adapter 2.0.0
  confirms a signature it is given, but reads only `error.message` from an error, so an
  error here would leave it nothing to wait for. Wallets after 3.0.2 confirm every send,
  follow a signature whether it comes as the result or in `error.data`, and hold the
  passkey's next challenge until it settles. The timeout bounds the whole wait: every
  RPC request the relayer makes gives up after 10 s, and a status poll still running at
  the deadline is not waited for.
- **Failed or expired.** A transaction that lands with an error is answered with -32005
  (`transaction_failed`, with `signature`, `slot` and `err`). One that never shows up
  before its blockhash expires is answered with -32005 (`blockhash_expired`, with
  `signature`). It can no longer land. "Expired" takes two "blockhash not valid" answers
  2 s apart from a node at or past the slot the simulation ran at (a node behind that
  may not know the blockhash yet), then one last look in the signature history.
- **Retries of the same bytes.** A client resends the same bytes when it never got the
  first answer, and `@lazorkit/wallet` retries every error twice with them. If the first
  attempt has landed, the relayer answers as it did the first time: with that signature
  as a success, or -32005 `transaction_failed` if it landed and failed. It signs nothing
  new and sends nothing. The same goes for a send the RPC refuses as "already been
  processed". A send the RPC never answered (a timeout, a dropped connection, an HTTP
  5xx) is sent again, up to 4 more times, and whatever the cluster knows of its signature
  is then waited for as usual.
- **Opting out.** `respond_after: "sent"` answers once the RPC has accepted the
  transaction (the old behaviour of this relayer). `"signed"` answers right after signing
  and sends in the background. Any other value is -32602. Neither SDK sends this field.
- **Lagging RPC nodes.** Every simulation, and the fee payer balance read before it, is
  made at `minContextSlot` = the slot of the relayer's own last confirmed transaction. A
  node behind a load balancer that has not executed it answers -32016 instead of
  failing a transaction that depends on it (ExecuteDeferred after Authorize, an Execute
  after CreateWallet). Simulation and send are retried briefly (500 ms apart, at most
  5 times) when the answer may only mean that the RPC node is behind:
  - simulation: -32016 "minimum context slot has not been reached", `BlockhashNotFound`,
    and a LazorKit 3006 or 3007 (these two at most twice). Each retry is pinned with
    `minContextSlot` to a bank at least as new as the newest confirmed slot the RPC
    reports and the relayer's own last confirmed transaction. A 3006/3007 retry is also
    pinned to the slot the passkey signed, which the relayer reads from the secp256r1
    auth payload at the end of the LazorKit instruction: the state the wallet read its
    counter from, when the wallet's RPC is ahead of the relayer's.
  - send: -32016, "Blockhash not found", "node is behind". The send is pinned to the
    slot the simulation ran at, so its preflight never runs on an older bank.

  HTTP 429 from the RPC is backed off too. A 3006 that is still there after the retries
  is a counter the passkey really signed too early. Resending cannot fix it: it needs a
  new passkey signature, and the error says so (`data.reason = "stale_counter"`). When
  the retries run out while the RPC is still behind the slot asked for, the answer is
  -32004 with `data.reason = "rpc_behind"` instead, and the older bank's error is not
  repeated in the message (it would read as a stale counter). Nothing was signed, and the
  same bytes may pass once the RPC catches up. A Custom 3006 or 3007 raised by a program
  that LazorKit calls (Anchor's AccountNotMutable and AccountOwnedByWrongProgram have
  those numbers) is not taken for LazorKit's: the simulation logs say which program
  failed first.

`GET /health` (or `GET /`) returns the relayer address, its balance, the allowlist and
the limits as JSON. Open it in the phone's browser to check that the phone can reach
the Mac. `POST` requests must have `content-type: application/json`. Both SDKs send that.

### Who can reach it

The relayer holds real (devnet) SOL and signs for anyone it accepts, so it limits who
can talk to it. A web page open in any browser on this Mac could otherwise call
`127.0.0.1:8787`.

- **Browsers: only pages served from this machine.** CORS allows an origin only if its
  host is `localhost`, `127.0.0.1`, `::1` or one of this Mac's own IP addresses, on any
  port, over http or https. That covers the Vite app on `localhost:5173`, `:4173` or
  `https://<LAN IP>:5173`. Any other origin gets no `Access-Control-Allow-Origin` and
  no Private-Network-Access answer, so the browser never sends its request. The
  portal does not call the relayer. Only the dApp page does. `--cors-origin a,b` sets an
  exact list instead, and `--cors-origin '*'` allows any origin.
- **No preflight-free requests.** A browser sends a `text/plain` POST from any page
  without asking. The relayer refuses anything that is not `application/json` (HTTP 415),
  so every cross-origin browser call has to pass the CORS check above.
- **No DNS rebinding.** The `Host` header must be an address the relayer listens on:
  `localhost`, `127.0.0.1`, `::1`, and with `--lan` the LAN IP. Anything else gets
  HTTP 421. This stops a page whose domain later resolves to `127.0.0.1`.
- **Not a browser: whoever reaches the port.** `curl`, the phone app and anything else
  on the network need no Origin. Without `--lan` that is only this Mac. With `--lan`,
  or through the web app's `dev:lan` proxy, it is everyone on the Wi-Fi.

What such a caller can still get, with the default policy: a transaction must call
LazorKit v2, but it may also carry a System transfer out of the fee payer, because Kora
allows that for the protocol fee (`fee_payer_policy.system.allow_transfer`). So a caller
who reaches the relayer can take up to `--max-lamports` (0.05 SOL) per transaction, and
`--max-tx-per-hour` (300) transactions per hour. That is devnet SOL only, and the hosted
Kora config has the same bound. To close it on a shared network, start the relayer with
`--api-key <key>` and give the apps the same key.

Errors use JSON-RPC codes. Every rejection says which instruction and which rule
failed, and `error.data.rule` holds the machine-readable rule name:

| Code | Meaning |
|---|---|
| -32700 / -32600 / -32601 / -32602 | parse error / bad request (batches unsupported) / unknown method / bad params |
| -32003 | the policy refused to sign (`program_not_allowed`, `fee_payer`, `signer_key`, `fee_payer_policy`, `durable_nonce`, `max_allowed_lamports`, `max_signatures`, `require_one_of_programs`) |
| -32004 | simulation failed. The message includes the program error and the last log lines. A LazorKit 3006 also sets `data.reason = "stale_counter"`. `data.reason = "rpc_behind"`: the relayer's RPC stayed behind the slot it needed, and the same bytes may pass later |
| -32005 | the RPC refused to send (`send`, preflight, logs included), the transaction failed on chain (`transaction_failed`), or its blockhash expired before it landed (`blockhash_expired`). The last two carry `data.signature` |
| -32029 | the rate limit was hit |
| -32001 (HTTP 401) | `--api-key` is set and the request did not carry it |
| -32600 (HTTP 415) | the POST was not `content-type: application/json` |
| -32600 (HTTP 421) | the `Host` header is not an address the relayer listens on (DNS rebinding guard) |

## What it will sign

A transaction is signed only if **all** of the following hold. The rules mirror
`lazorkit-protocol/deploy/kora/kora.devnet.toml`.

1. **The fee payer is this relayer.** Account 0 must be the relayer. `signer_key`, if
   sent, must also be the relayer.
2. **Every top-level instruction calls an allowlisted program:**
   LazorKit v2 `57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv`, `Secp256r1SigVerify1111111111111111111111111`,
   System, SPL Token, Token-2022, Associated Token Account, ComputeBudget, and Address
   Lookup Table.
3. **Every inner (CPI) instruction calls an allowlisted program too.** The relayer
   simulates the transaction on devnet and checks what actually runs. For example, a
   LazorKit execute whose vault calls Memo is refused.
4. **The simulation succeeds**, and **the fee payer loses at most 0.05 SOL** (the fee
   plus anything moved out of it). This is Kora's `max_allowed_lamports` (`--max-lamports`).
5. **Fee-payer policy.** System instructions may use the fee payer only for Transfer or
   CreateAccount(WithSeed), never Assign, Allocate or nonce operations. Token,
   Token-2022 and ALT instructions may not include the fee payer at all.
6. **No durable nonce.** Transactions containing AdvanceNonceAccount are refused.
7. **At most 4 required signatures, and at most 300 signed transactions per rolling hour**,
   counted across all callers and kept in memory (`--max-tx-per-hour`).
8. **The transaction calls LazorKit v2 at the top level.** This is Kora's
   `require_one_of_programs`, as in `kora.devnet.toml`. It is on by default.
   `--allow-plain` turns it off, and only the smoke test's plain transfer needs that.

How it differs from `kora.devnet.toml`, and why:

- **ALT is allowlisted.** The playground brief asked for it, and the hosted devnet Kora
  allows it. `kora.devnet.toml` does not. A transaction that calls the ALT program
  passes here but will not pass the target config. Lookup tables *used* by a v0
  transaction are unaffected.
- **`--allow-plain` can turn off `require_one_of_programs`.** Every SDK flow calls
  LazorKit, so the apps never need it. It exists so that `npm run smoke` can show a plain
  ComputeBudget + System transfer being sponsored. While it is on, any caller who
  reaches the relayer can have it pay for plain System transfers of up to 0.05 SOL each,
  300 per hour. The banner warns when it is combined with `--lan` or
  `--cors-origin '*'`. Do not use it while the web app's `dev:lan` is running.
- **No reCAPTCHA, no Redis, no metrics port, no Lighthouse.** The rate limit is one
  counter in memory.

## Options

| Flag | Env | Default |
|---|---|---|
| `--port <n>` | `RELAYER_PORT` | `8787` |
| `--lan` | | off. Loopback only |
| `--lan-ip <addr>` | | auto (the first private IPv4, `en*` preferred) |
| `--rpc <url>` | `RELAYER_RPC_URL` | `https://api.devnet.solana.com` |
| `--keypair <path>` | `RELAYER_KEYPAIR` | `./relayer-keypair.json` |
| `--max-lamports <n>` | `RELAYER_MAX_LAMPORTS` | `50000000` |
| `--max-tx-per-hour <n>` | | `300` |
| `--allow-plain` | `RELAYER_ALLOW_PLAIN=1` | off. Every transaction must call LazorKit v2 |
| `--require-lazorkit` | | the default already. Still accepted, so older instructions keep working |
| `--confirm-timeout <s>` | `RELAYER_CONFIRM_TIMEOUT` | `30`. How long `signAndSendTransaction` waits for `confirmed`. Past it, it answers with the signature for the caller to confirm (1-300) |
| `--api-key <key>` | `RELAYER_API_KEY` | none |
| `--cors-origin <a,b>` or `'*'` | | pages served from this machine (localhost, 127.0.0.1, ::1, its own IPs; any port) |
| `--any-cluster` | | off. Mainnet is refused regardless |

With `npm start`, put flags after `--`, for example `npm start -- --lan --api-key <key>`.
`npm run start:lan` is `--lan` on its own.

## Log

Every request gets one line with the caller, the method, the transaction version, the
top-level programs, the inner programs, the fee payer's simulated balance change, the
compute units, and the signature or the reason for rejection. A send is logged when it is
answered, so after it has confirmed, with its slot and how long confirmation took.
`REJECTED` means nothing was sent. `FAILED` means it was sent and then failed on chain or
expired. `UNCONFIRMED` means it was not confirmed within `--confirm-timeout` and was
answered with its signature; a second line follows once it confirms or fails:

```
12:19:36.109  127.0.0.1  signAndSendTransaction  legacy  [LazorKit v2, System]  inner=[System]  payer -0.005083 SOL  20184 CU  CONFIRMED ofiP8UTC…  slot 505527438 (1.1 s after send)
12:19:39.525  127.0.0.1  signAndSendTransaction  v0  [ComputeBudget, Secp256r1, LazorKit v2]  inner=[System]  payer -0.000010 SOL  14642 CU  CONFIRMED g8xAiu2d…  slot 505527452 (1.2 s after send)
12:19:44.659  127.0.0.1  signAndSendTransaction  v0  [ComputeBudget, Secp256r1, LazorKit v2]  REJECTED  relayer rejected: instruction #2 makes an inner call to Memo (not allowed) …
12:23:12.096  127.0.0.1  signAndSendTransaction  v0  [Secp256r1, LazorKit v2]  inner=[]  payer -0.000005 SOL  5000 CU  UNCONFIRMED 56JTGcAW… after 30 s: answered with the signature, still watching
12:23:13.598  confirmed  56JTGcAW…  slot 505527901
```

A resend of bytes that had already landed is logged as `CONFIRMED … (a resend of bytes
that had landed: nothing sent again)`.

With `respond_after: "sent"` or `"signed"` the line says `SENT` or `SIGNED`, and a second
line follows once the transaction confirms or fails.

When the relayer refuses a transaction, `@lazorkit/wallet` retries twice more (after 1 s
and 2 s), so a rejection appears three times in the log.

## Tests

Run these with the relayer running:

```bash
npm run smoke              # every method, the reachability guards, one rejection per rule
npm run smoke -- --skip-send
npm run smoke:lazorkit     # a real LazorKit v2 CreateWallet + two back-to-back passkey Executes, sponsored
npm run smoke -- --url http://192.168.100.130:8787 --api-key <key>   # over the LAN / with a key
```

- `smoke` checks the reachability guards first. A preflight from `http://localhost:5173`
  is allowed. A preflight from `https://evil.example` is refused (unless the relayer runs
  with `--cors-origin '*'`). A `text/plain` POST gets 415. A foreign `Host` gets 421.
- `smoke` then tries ComputeBudget + a System transfer of the rent-exempt minimum
  (650,240 lamports on devnet today) to a fresh address. With the default policy, that
  plain transfer must be **refused** (`require_one_of_programs`). Start the relayer with
  `npm start -- --allow-plain` to see it signed and landed instead. A transfer of
  1 lamport to a fresh address cannot land, because a 1-lamport account fails the rent
  check. With `--allow-plain`, the smoke test keeps that case as an expected rejection
  from the simulation stage. There, it also checks that `signAndSendTransaction` answered
  only after the transfer was confirmed, and that the same bytes sent again after they
  landed get the same signature back and move nothing. In both modes it checks that an
  unknown `respond_after` is refused with -32602.
- `smoke:lazorkit` uses the released `@lazorkit/sdk-legacy` 1.2.0 (a dev dependency)
  and a software P-256 key that produces WebAuthn assertions for rpId `portal.lazor.sh`.
  It creates a wallet and has the relayer put 0.003 SOL in its vault. Then it executes
  a passkey-signed vault → fresh-address transfer. The moment the relayer answers, it
  prepares a second passkey Execute, which reads the authority counter, the way
  `@lazorkit/wallet` 3.0.2 does, and sends it. That one must land. Against a relayer
  that answers before confirmation it fails with 3006. Then it checks that the first
  Execute was already confirmed when the relayer answered, and that the relayer reads the
  slot the passkey signed from the SDK's Execute bytes. Then it checks that an execute
  whose inner call goes to Memo is refused. Last, it sends the first Execute's bytes
  again: the answer must be that Execute's signature, and nothing moves. It costs the
  relayer about 0.005 SOL.
  It shows
  that the relayer carries real v2 traffic (Secp256r1 precompile, wallet-bound
  challenge, protocol CPIs). It does not test the real portal or a real device passkey.
  The web and mobile apps cover those.

Results on 2026-09-30 (devnet and a scripted RPC), after the confirmation wait stopped
answering with errors for transactions that land:

- `smoke` passed 20/20 in default mode and 23/23 with `--allow-plain`. The resent
  transfer got its signature back, and the destination still held the rent minimum.
- `smoke:lazorkit` passed. The relayer read slot 505792045 from Execute #1, the slot the
  SDK signed. The back-to-back Execute landed, and the resend of Execute #1's bytes got
  its signature back with nothing moved.
- Through a test RPC proxy on devnet, with plain transfers:
  - confirmations hidden, `--confirm-timeout 3`: answered with the signature after 3.4 s,
    and it landed. The previous code answered -32006, and a resend then got
    `already_processed` as an error.
  - confirmations hidden and every blockhash reported expired: the transaction landed,
    and the answer was its signature, at the timeout. The previous code answered
    `blockhash_expired` for it.
  - a faked `BlockhashNotFound` in simulation and a faked -32016 at send: retried, then
    confirmed after 2.6 s. The resend's simulation was pinned to the slot the transfer
    confirmed in.
- Against a scripted RPC, with the wallet's own `Paymaster` and `sequence.ts` from the
  lazor-kit release branch driving the sends, the previous code and this one, scenario
  by scenario:
  - A send confirmed 0.6 s after `--confirm-timeout` (2 s, and 30 s): the wallet was told
    it failed although it landed, and its next passkey action failed with 3006. Now both
    land.
  - The same, and the user sends it again: two executions for one action before, one
    per action now.
  - A send that lands 12 s late, after every wallet retry: before, the next passkey action
    signed the same counter and the late one failed on chain with 3006. Now the wallet
    waits for it, and both land.
  - A node behind the transaction's blockhash answered "not valid" twice while the send
    was in flight: `blockhash_expired` for a transaction that then landed, before. Now it
    is answered once confirmed.
  - `getSignatureStatuses` answering after 20 s, or never: the answer came after 20.5 s,
    or not before the caller gave up at 45 s. Now it comes at the 2 s timeout.
  - A dependent transaction whose first simulation reached a node one slot behind the
    confirmation it depends on: rejected with `IllegalOwner` before, now simulated at the
    relayer's last confirmed slot and landed.
  - A passkey that signed a slot 6 ahead of the relayer's RPC: 3007 after 1 s before, now
    landed after 3.5 s. 12 ahead: `rpc_behind` instead of a 3007 that says "sign again",
    and the same bytes passed 3 s later.
  - An inner program failing with its own 3006: no longer retried or called a stale
    counter.
  - A send whose RPC answer was lost (HTTP 502) after it was forwarded, and a resend
    whose simulation ran just before the first copy landed: errors before, the landed
    signature now.

Results on 2026-09-29 (devnet), after `signAndSendTransaction` started answering at
`confirmed`:

- `smoke` passed 20/20 in default mode and 22/22 with `--allow-plain`. The plain transfer
  was already `finalized` when the relayer answered.
- `smoke:lazorkit` passed. Each Execute was answered about 1.1 s after it was sent, and
  the back-to-back Execute landed.
- The same `smoke:lazorkit`, run against the previous relayer code (answers at `sent`),
  failed at the back-to-back step. The relayer's simulation of Execute #2 passed, because
  #1 had not executed yet. The relayer returned its signature as a success, and it then
  failed on chain with `{"InstructionError":[2,{"Custom":3006}]}`. The fee payer paid
  the fee.
- A script that calls the wallet 3.0.2 way (find wallet, read counter, `getPayerSigner`,
  prepare, approve, send) landed 4 of 4 back-to-back pairs, with 3 s and 0 s approval
  delays. Its counters went 20→21, 22→23, 24→25 and 26→27.
- Edge cases checked on devnet:
  - A stale counter was refused in simulation with `reason: "stale_counter"` after about
    1.7 s of retries.
  - `respond_after` `sent` and `signed` answered before confirmation, with the same
    result shape.
  - Through a test RPC proxy that hid confirmations or made the RPC look behind (the
    first three answers were replaced on 2026-09-30, see above):
    - a -32006 timeout carried the signature;
    - sending the same bytes again once they had landed gave `already_processed` with
      that signature;
    - a blockhash reported expired gave `blockhash_expired`;
    - a faked `BlockhashNotFound` in simulation and a faked -32016 at send were retried
      with `minContextSlot` and then confirmed.

Before that, after LazorKit-required and the reachability guards became the default:

- `smoke` passed 19/19 in default mode, 20/20 with `--allow-plain --lan` over
  `192.168.100.130` (the plain transfer landed), and 19/19 with `--cors-origin '*'`.
- `smoke:lazorkit` passed in default mode.
- In a real browser, the web app on `http://localhost:5173` reached the relayer both
  directly and through `/paymaster`. A page on `http://evil.localhost:9999` could not:
  its JSON call and its `/health` read were stopped at the preflight and never reached
  the relayer, its no-cors `text/plain` POST got 415, and a request to
  `evil.localhost:8787` got 421.
- Earlier runs: the startup guards refused the CLI default keypair path, a `keys/` path,
  a mode-644 keypair and a mainnet RPC.

Example on-chain signatures:
plain transfer `2SfzUAQXYZP8XpTxUQBcVdYeKnoWwu3pWG6vYHjnJMydDJP95KJJjpHhaoURW67WMqorYC8Cb3vc8jhC4QXNouAm`,
CreateWallet `3preJc9uturSCyYxYkRzxjLL15DjZ4WVkEqjy8pzEu6nmedH4uJyWmFAhkn4pQn5TJFV6p1GMX5QSHqaD57ujSug`,
passkey Execute `5WpVEUvVHbvBiy68VAHBwr7ViqUHGzoujWPkFD45EMA4ihqhMssPVdUSAcDsVxVLJE2Zm3VVa22cyz3BGrxBvPq`.

## Troubleshooting

- **The phone can't reach it.** Start the relayer with `--lan`. Open
  `http://<LAN IP>:8787/health` in the phone's browser. If that fails, check these:
  the phone is on the same Wi-Fi and not on cellular; macOS Firewall allows incoming
  connections for `node` (System Settings → Network → Firewall); the router does not
  isolate clients (guest networks often do).
- **Plain `http://` from a native app.** iOS blocks cleartext HTTP unless the app allows
  it (`NSAllowsArbitraryLoads` / `NSAllowsLocalNetworking`). Android blocks it unless
  `usesCleartextTraffic` is set. Expo Go and development builds usually allow it. A
  release build needs the setting. iOS also asks for Local Network permission the
  first time.
- **`fee payer is X, not this relayer`.** The app got its payer from another relayer.
  Check `paymasterUrl`, and check for a v1 wallet going through `v1PaymasterConfig`.
- **`calls LazorKit v1 … not in the relayer allowlist`.** That wallet is a v1 wallet.
  v1 traffic belongs on its own relayer, not this one.
- **`simulation failed: …`.** The program itself refused the transaction. The message
  carries the program's error and the last log lines. Nothing was signed.
- **`{"Custom":3006}` / `SignatureReused` / `stale_counter`.** The passkey signed a counter
  that is not the authority's next one. With this relayer that means the wallet read the
  counter before its previous transaction confirmed, for example because that
  transaction went through another paymaster that answers early, or because the wallet's
  RPC lags behind this one. Sign again. Resending the same bytes cannot pass.
- **`UNCONFIRMED … after 30 s` in the log.** It was sent and the caller got its
  signature. It may still land, fail or expire; the next log line for that signature
  says which. A wallet newer than 3.0.2 waits for it before the passkey signs again.
  3.0.2 does not, so its next passkey action can still meet 3006 while this one is
  pending.
- **`rpc_behind`.** The relayer's RPC did not reach the slot it needed within the
  retries: its own last confirmed transaction, or the slot the passkey signed. Nothing
  was signed. Send the same transaction again in a moment. If it keeps happening, the
  wallet and the relayer are on RPCs that disagree by more than a couple of seconds.
- **`LOW` in the start banner.** Top up the fee payer (see above).
- **The browser says "Failed to fetch", and the relayer logs nothing.** The page's origin
  is not one of this machine's (see "Who can reach it"). Open the app by `localhost` or
  the Mac's own IP, use `/paymaster`, or pass `--cors-origin <that origin>`.
- **`misdirected request: Host must be one of …` (421).** Call the relayer by the
  address it prints: `127.0.0.1`, `localhost`, or the LAN IP. A hostname such as
  `mymac.local` is refused.
