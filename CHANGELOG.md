# Changelog

All notable changes to the LazorKit smart wallet protocol and SDK are
documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — the SDKs are published from CI, with provenance

**SDKs** (release process; no code change)

- `@lazorkit/sdk-legacy` and `@lazorkit/sdk` are no longer published by hand.
  Pushing a release tag (`sdk-legacy-vX.Y.Z`, `sdk-kit-vX.Y.Z`) on a commit of
  `develop` or `main` runs `.github/workflows/release-sdk.yml`: it builds,
  tests and packs the package without credentials, then, once a maintainer
  approves the `npm-publish` environment, publishes it with npm trusted
  publishing (OIDC, no npm token) and a provenance attestation, and creates the
  GitHub release.
- The dist-tags follow the current practice: `next` for both, and for
  `@lazorkit/sdk` also `latest` within its major (not from a stable version
  to a pre-release). A new major, which a protocol major brings, leaves
  `latest` to be moved by hand after the mainnet upgrade, as does
  `@lazorkit/sdk-legacy`'s `latest`, which stays on 0.3.2, the protocol v1
  line; the workflow refuses to move it. A version that would move `next`
  back is refused when the tag is pushed and again just before publishing.
- `RELEASING.md` has the flow, the one-time npm and GitHub setup (trusted
  publisher, `npm-publish` environment, tag ruleset), what to check before
  approving, and the manual fallback; `docs/upgrade-procedure.md` step 7 now
  pushes tags. Rebuilt by the workflow's steps from `develop`, both packages
  give tarballs byte-identical to the published `@lazorkit/sdk-legacy` 1.4.0
  and `@lazorkit/sdk` 1.0.0-rc.6.

### Fixed — Execute's heap: buffers sized exactly (program; needs a review before the mainnet deploy)

**Program** (both v2 artifacts change: devnet `efea949f…` → `d95e5c2b…`,
mainnet `b30ce1df…` → `67d47162…`, 152864 bytes each; both sunset artifacts are
byte-identical)

- Execute and ExecuteDeferred ran out of heap on payloads a v1 transaction
  (SIMD-0385, 4096 bytes) carries easily, and on some legacy ones. The heap is
  a 32 KiB bump allocator that never frees, and two buffers grew by doubling,
  leaving every smaller copy allocated: the accounts-hash preimage, sized for
  four accounts per inner instruction, and the account-meta and CPI-account
  buffers reused across inner instructions, sized for 32. On devnet a passkey Execute failed with "memory
  allocation failed, out of memory" at one inner instruction of 128 accounts,
  at 70 + 70 and at 100 + 30, all three shapes a legacy transaction carries
  when the accounts repeat; in litesvm also at 16 instructions of 16 accounts,
  none wider than 64. Both buffers are now sized once from the parsed
  instructions (`compact::accounts_hash_entries`, `compact::max_inner_accounts`).
  For any payload this allocates no more than before, so nothing that landed
  before can fail. As far as the heap goes, one inner instruction can now name
  all 255 accounts the compact format allows (127 before), 16 equal ones about
  41 each (15 before); a CPI of more than 128 accounts also needs SIMD-0339
  (`increase_cpi_account_info_limit`), active on devnet and mainnet.
  Nothing else changes: no account, instruction or challenge layout. A payload
  too large for the heap now fails at the first allocation rather than
  part-way through the accounts-hash walk.
- The policy path (a session with actions, or a Delegate) gains the same room.
  D13's own allocations were already sized once and are unchanged (the actions,
  parsed twice, 32 bytes each; a 192-byte copy of each vault token account; the
  mint list, reserved at 48 bytes per copy): it was the reused buffers above
  that doubled there too. With sixteen actions and the most vault token
  accounts a v1 transaction's 64 addresses leave, 15 inner instructions after a
  listed transfer can each name 89 accounts beside a session (52 vault token
  accounts; 64 on the D13 build before this fix, #48's `efea949f…`) and 24
  beside a passkey Delegate (51; 8 on `efea949f…`). On that path the heap still
  binds before a v1 transaction's bytes do, which carry 102 and 81. In a legacy
  transaction no such payload runs out of heap now; on `efea949f…` one inner
  instruction wider than 128 accounts did (124 for a passkey Delegate).
- `docs/Architecture.md` (Compact instruction format) gives the exact sum an
  Execute allocates on every path, the policy's `64a + 240t` included, and
  Transaction v1 the largest shapes before and after. A scratch build that logs
  the allocator's cursor agreed with the sum to the byte on 112 payloads over
  passkey, ExecuteDeferred, Ed25519, session and passkey-Delegate Executes (on
  79 more against `efea949f…`, with its doubling terms), and on land or out of
  memory for all 116 on both.
- The 16-inner-instruction cap is unchanged, and documented as a limit a v1
  transaction can reach.
- Compute: on the policy path's four `c1_compute_units_of_the_policy_path`
  shapes, 9 CU more than `efea949f…`. Without a policy, measured before D13 on
  identical state: within 35 CU for an inner instruction of up to two accounts,
  up to 880 CU less for wider ones, up to 575 CU more for 16 inner instructions
  of 8 accounts.
- Tests: `program/tests/heap_capacity_tests.rs` (litesvm; passkey Execute,
  also at legacy size, ExecuteDeferred, Ed25519 Execute, and on the policy path
  a session at v1's address cap and at legacy's size cap and a passkey Delegate
  at v1's address cap and past a check that leaves out the policy) fails
  against `efea949f…` with out of memory in 9 of 11, all but the
  16-instruction cap and the legacy policy shape, and passes now; a unit test
  pins the exact capacities.
- The wallet packages' v1 heap guard (`lazorkitHeapBytes`, lazor-kit) leaves
  out the policy's `64a + 240t`, so for a session with actions or a Delegate it
  can pass a payload that runs out of memory, on this build and on
  `efea949f…`: it should compute the exact sum (`docs/Architecture.md`,
  Transaction v1).
- Devnet's v2 runs the D13 build `efea949f…` (upgraded 2026-10-03) and needs
  an upgrade to get the fix; this one is not breaking. The v2 hashes in
  `scripts/release-hashes.txt` and in the deploy checklist's tables changed
  (`check-release-hashes.sh`: ok for all four). The two-id rehearsal passed
  18/18 on these artifacts on 2026-10-04, at the mainnet and the devnet ids,
  and the phase B rollback was rehearsed at the mainnet ids (deploy checklist,
  Two-id rehearsal).

### Added — ownership proofs and messages get their own passkey challenges

**SDKs** (`@lazorkit/sdk-legacy` 1.4.0, `@lazorkit/sdk` 1.0.0-rc.6)

The programs approve a transaction by the challenge in a passkey signature, and
a passkey signs whatever challenge it is handed. lazor-kit #113
(`@lazorkit/wallet` 3.3.1, `@lazorkit/wallet-mobile-adapter` 2.3.1) gave each
kind of challenge the wallet packages ask a passkey for its own shape; both
SDKs now give the same bytes. The lengths differ and so do the tags, so no
challenge of one kind can equal one of another:

| Kind | Challenge | Length |
|---|---|---|
| Transaction (unchanged) | SHA-256 of the instruction's inputs | 32 |
| Message | `tag ‖ SHA-256(tag ‖ message)`, tag = UTF-8 `LazorKit signed message v1` | 58 |
| Ownership proof | `tag ‖ 32 random bytes`, tag = UTF-8 `LazorKit ownership proof v1` | 59 |

- **New `createTaggedOwnershipChallenge()`**, with the constant
  `OWNERSHIP_PROOF_DOMAIN`: the tagged 59-byte ownership challenge, the same
  format as the wallet packages' own `createOwnershipChallenge`. Use it for
  every new ownership proof. Both READMEs' sign-in and key-recovery examples,
  the clients' JSDoc and that of `verifyOwnershipProof` and
  `resolvePasskeyPublicKey` now use it.
- **`createOwnershipChallenge()` is unchanged**: 32 bare random bytes, as in
  every release before. It is marked `@deprecated` as a passkey challenge,
  since 32 random bytes look exactly like a transaction challenge to whatever
  is asked to sign them, but it is neither removed nor changed (see
  Compatibility). `verifyOwnershipProof`, `recoverPasskeyPublicKeys`,
  `resolvePasskeyPublicKey` and `findOwnPasskeyWallet` are unchanged too: they
  check a proof over exactly the challenge it carries, from 16 bytes up, so
  proofs over either form verify.
- **New `signedMessageChallenge(message)`**, with `SIGNED_MESSAGE_DOMAIN` and
  the type `SignedMessageInput`: the challenge a passkey signs for a message,
  never the message itself. A string is signed as its UTF-8 bytes, any
  typed-array view as its bytes; anything else throws a `TypeError`. The same
  bytes as the wallet packages' `signedMessageChallenge`. Their
  `verifyWalletMessage` checks a signature over it in the shape their
  `signMessage` returns: the signature as 64-byte r‖s (low-S or not), not the
  DER that `navigator.credentials.get` returns, so convert it first; and
  clientDataJSON and authenticatorData as base64. `verifyOwnershipProof` here
  takes DER or r‖s. Neither SDK asked a passkey to sign a message before and
  neither does now; this is for apps that do.
- **Transactions only, now said where it matters.** `Secp256r1Signer.sign` is
  called only with the 32-byte challenge the SDK computed for an instruction,
  and every `prepare*` challenge is a hash of the instruction's inputs, so no
  caller bytes reach a passkey through either SDK. The JSDoc of
  `Secp256r1Signer`, `PreparedSecp256r1.challenge` and the `prepare*` results
  says so, and says not to route a message, a server nonce or a challenge from
  a URL through such a signer. Both READMEs gain "Messages and ownership
  proofs: never a transaction challenge": the table above, how to have a
  passkey sign a message, and how to check one with the key read from the
  claimed wallet on chain (`findPasskeyWalletCandidates` + `verifyOwnershipProof`
  over `signedMessageChallenge(message)`, and the wallet account still there).
- Fixed vectors in `test-vectors/challenge-domains.json`: both tags and the
  wallet packages' own message vectors (lazor-kit
  `packages/react/test/sign-message.test.mjs`). Checked once against the
  wallet's source at lazor-kit 22e0ec2 as well: the same bytes for the four
  vectors and for 4,000 random messages, lone surrogates included.
- Tests: `sdk/sdk-kit/tests/challenge-domains.test.ts` (37), on both SDKs'
  implementations — sdk-legacy's from source, since CI runs no sdk-legacy
  tests: the message vectors; UTF-8 and typed-array input; 58 bytes under the
  tag for every message length, 32 included, and never the message;
  `signedMessageChallenge`'s own `TypeError` for anything else, checked by
  its message; the tagged ownership format, fresh nonces and the wallet
  packages' layout; `resolvePasskeyPublicKey` over two tagged challenges
  (which share their first 27 bytes) and over a tagged and a bare one;
  `createOwnershipChallenge` still 32 fresh bytes and a proof over them
  still verifying; with `globalThis.crypto` removed, sdk-legacy's
  `createOwnershipChallenge` still 32 bytes and the wallet packages'
  ownership challenge (their code, run on it) made and verified, and that
  same code throwing on the tagged form; the three lengths, the
  transaction challenge from both SDKs' `buildSecp256r1Challenge`; and an
  assertion over a message's raw bytes verifying as no message signature.
  `tests-sdk/tests/17-ownership.test.ts` (sdk-legacy, the unit half): the
  tagged format, a proof over either form, the message vectors. On the 1.3.1
  / rc.5 sources, 31 of the 37 kit tests and the 3 new sdk-legacy ones fail;
  the 6 that pass pin what must not change (`createOwnershipChallenge` with
  and without `globalThis.crypto`).

**Compatibility**
- **No breaking change.** Everything above is new exports or documentation:
  a minor for sdk-legacy, the next rc for the kit SDK, and both work with the
  same programs as before. `createOwnershipChallenge()` keeps returning
  exactly 32 random bytes on purpose: `@lazorkit/wallet` 3.3.1 and
  `@lazorkit/wallet-mobile-adapter` 2.3.1 depend on sdk-legacy `^1.3.0`, so a
  fresh install of them gets 1.4.0, and when `globalThis.crypto` is missing at
  call time (Node 18 has no global WebCrypto by default) they take sdk-legacy's
  `createOwnershipChallenge` as their 32 random bytes and throw "No source of
  random bytes for an ownership challenge" on any other length. Checked: their
  `ownershipProof.ts` (lazor-kit 22e0ec2) run on this sdk-legacy's build with
  `globalThis.crypto` undefined gives its 59-byte challenge; on a build where
  `createOwnershipChallenge` returned the tagged form it throws.
- Those wallet releases need nothing from this one: their connect already
  signs the tagged form, from their own `createOwnershipChallenge`, and checks
  it with sdk-legacy's `verifyOwnershipProof`, which takes it unchanged.
- An app that makes its own ownership proofs should move from
  `createOwnershipChallenge()` to `createTaggedOwnershipChallenge()`. Every
  verifier in both SDKs accepts both forms, so the client that asks for the
  proof and the server that checks it can move in either order.
- `@lazorkit/sdk` 1.0.0-rc.6 is a prerelease, like the rcs before it; neither
  wallet package depends on it.

### Fixed — a 255-account instruction wrote past the entrypoint's array (pinocchio 0.9.3)

**Program** (all four artifacts): mainnet `c9f563e2…` → `b30ce1df…` and devnet
`384e6927…` → `efea949f…`, 152392 bytes each; mainnet-v1 `6080da9f…` →
`7a86c87c…` and devnet-v1 `2cf15c89…` → `a84a234e…`, 45936 bytes each.

- pinocchio 0.9.2's `entrypoint!` parses an instruction's accounts into a
  stack array of `MAX_TX_ACCOUNTS` (254) entries and, at that default, does not
  clamp the count it is handed. The runtime hands over up to 255 and refuses
  only more (`MaxAccountsExceeded`), so any instruction with 255 accounts, for
  instance an Execute that repeats one account, wrote one `AccountInfo` past
  the array, on every artifact. 0.9.3 makes `MAX_TX_ACCOUNTS` 255. The
  workspace now requires pinocchio 0.9.3 or later, and `entrypoint.rs` asserts
  at compile time that `MAX_TX_ACCOUNTS` covers 255. The write went unnoticed
  (a 255-account Execute returned Ok on 0.9.2), and D13's snapshot of the
  vault's token accounts stays in bounds either way.
- 0.9.3 also reads `Clock` and `Rent` through `sol_get_sysvar` (SIMD-0127)
  instead of the per-sysvar syscalls. That syscall is active on mainnet (since
  epoch 745) and devnet (since epoch 806). An Execute costs 27 CU less in the
  four shapes `c1_compute_units_of_the_policy_path` measures.
- Test: `h2_execute_at_the_runtime_account_limit` runs a 255-account Execute
  (the fee suffix's last account is read, the listed mint charged once) and
  checks that the runtime refuses 256.
- `scripts/release-hashes.txt` and the checklist's tables record all four
  (`check-release-hashes.sh` on the pinned toolchain). The two-id rehearsal
  passed 18/18 on the current four (with the heap-capacity fix above) on
  2026-10-04, at both pairs of ids, the migrations running through the 0.9.3
  sunset binaries.

### Changed — a policy bounds the vault's SOL and every token balance it owns directly (D13)

**Program** (v2 only; both sunset artifacts are byte-identical): devnet
`3584aec7…` → `384e6927…`, mainnet `4cb80304…` → `c9f563e2…`, 152264 bytes each,
on pinocchio 0.9.2; the entrypoint fix above then moves all four.

- **What a policy does not name may not leave.** For an Execute whose signer
  carries a policy — a session with actions, or a Delegate — the vault's net
  SOL may fall only if a `Sol*` action names SOL (any of `SolLimit`,
  `SolRecurringLimit`, `SolMaxPerTx`), and its net balance of a mint only if a
  `Token*` action names that mint. Otherwise the Execute fails with the new
  `ActionUnlistedSolOutflow` (3037) or `ActionUnlistedTokenOutflow` (3038).
  Before, a mint no action listed had no balance check at all, so a session
  holding `TokenLimit(USDC)` and a whitelist of SPL Token could transfer every
  other token in the vault, and a policy with no SOL action could spend all of
  its SOL. Net over the Execute, per asset, never across assets; inflows always
  pass; rent the vault pays for a new account is SOL; wSOL is a mint. There is
  no opt-out action: a signer that must move arbitrary assets is an unbounded
  one.
- **Listed-mint accounting over the pre-loop account set.** Balances are
  measured over the writable token accounts the vault owned before the CPIs,
  each counted once. "After" used to cover every account vault-owned at the
  end, so a session could move a listed mint into a token account it had just
  initialised for the vault, uncharged, and approve itself on it; that is now
  charged, and a token account that became vault-owned during the Execute may
  carry no delegate or close authority (3032). An account passed twice used to
  be counted twice.
- **More of each vault token account is frozen** (3032): besides owner,
  delegate and close authority, its mint, state, is_native and data length,
  and `delegated_amount` may only fall; its lamports may fall only with a native
  account's `amount`. This catches re-`Approve` of the same delegate for more,
  `FreezeAccount`, `WithdrawExcessLamports` and `Reallocate`. Only initialised
  token accounts count: a mint or a multisig whose bytes 32..64 match the
  vault no longer reads as one.
- **Out of reach**, listed in `docs/Architecture.md` ("What a policy bounds"):
  anything the vault controls other than its lamports and its token accounts'
  base fields — stake, nonce and seed-derived accounts, positions in other
  programs, mint and upgrade authorities it holds, confidential balances — is
  bounded only by the program whitelist, and value released from them into the
  vault during the Execute can leave again as that asset.
- Heap: a 192-byte copy per unique writable vault token account and a 48-byte
  entry per mint, sized exactly; the action buffer is parsed into a Vec sized
  from a header walk (32 bytes per action, was 896 for 16), twice per Execute
  instead of four times, and the program check no longer collects Vecs. One
  vault token account passed 201 times is copied once (develop ran out of heap
  on it).
- Compute, a session Execute measured in litesvm against develop: a SOL
  transfer 24,128 → 23,806 CU, one listed token transfer 30,083 → 29,099, with
  8 vault token accounts 32,974 → 32,863, with 24 41,195 → 45,888.
- **Breaking**: a policy with no `Sol*` action can no longer spend SOL, rent
  included, and a policy moves only the mints it names. Unrestricted sessions
  and Owner/Admin are unchanged, and ExecuteDeferred is unchanged (a
  policy-bound signer cannot reach it). Devnet's v2 runs `3584aec7…`; upgrading
  it to the D13 artifact breaks every SOL-only or whitelist-only session that
  moves tokens or pays rent, including the session lazor-kit's `SpendingLimits`
  preset builds (it names SOL only), so it waits for an SDK release and that
  preset's fix.
- The v2 hashes in `scripts/release-hashes.txt` and in the deploy checklist's
  tables changed (with the entrypoint fix above, all four did;
  `check-release-hashes.sh`: ok for all four). PR #42 (Execute's heap
  buffers), which landed after this, changed the two v2 artifacts again and
  re-recorded them; the two-id rehearsal passed 18/18 on the resulting four
  on 2026-10-04.

**SDKs** (next releases of `@lazorkit/sdk-legacy` and `@lazorkit/sdk`; versions
are picked when this lands)

- sdk-legacy `ERROR_NAMES` gains 3036 `SessionNotExpired`, 3037, 3038 and 4018
  `RetiredDeployment`; its README table covers 3032–3038 and 4008–4018.
- Both SDKs' action, `createSession` and `addAuthority` docs and READMEs say
  what a policy now bounds, and how to build a swap policy: name the mint it
  sells, and create the output ATA in a top-level instruction the fee payer
  funds, or give the policy a `SolLimit` for the rent.

**Tests**: `program/tests/policy_unlisted_assets_tests.rs` (45 litesvm tests:
positive and negative flows, the unbounded signers, heap shapes, compute units;
against develop's binary every negative flow but one lands); `actions.rs` unit
tests for the new phase, the classifier and the per-field freeze; the
`12-session-actions` suites in `tests-sdk` and `tests-sdk-kit` (three tests gain
a `solLimit`, five new ones).

### Fixed — review follow-ups: a failed fee read, the finalized lag, the deploy commands

**SDKs** (`@lazorkit/sdk-legacy` 1.3.1, `@lazorkit/sdk` 1.0.0-rc.5)

- `prepareExecute` resolves the protocol fee beside the passkey challenge
  reads. When that read failed (a 5xx, an unhealthy node) while the challenge
  reads waited for their floor, the call rejected with its error, but the
  challenge reads went on polling -32016 for the rest of their wait (10 s, or
  30 s at `finalized`): 1.3.0 / rc.4 stopped them only when one of the three
  challenge reads failed. The fee read now runs in the same read group, and a
  challenge read that has not started yet when it fails (the kit SDK derives
  the authority's address first) is never started.
- How long a slot takes to be finalized after it is confirmed is the
  cluster's: 31 slots (16.5 s) on a local test validator (Agave 4.2.2), none on
  devnet on 2026-09-30 (solana-core 4.3.0; the finalized slot was the
  confirmed one). 1.3.0 / rc.4 said "about 32 slots (13 s)" in the JSDoc, the
  READMEs and the `MinContextSlotNotReachedError` message, and at `finalized`
  the message dropped the advice about a node that is behind — on devnet the
  likelier cause. The message now names both causes (a slot not finalized
  yet, or a node behind) and adds "retry on an RPC endpoint that has caught
  up"; the docs give the measured lags instead of a figure.
- READMEs: at `finalized` the challenge carries a finalized slot, already as
  old as the cluster's finalization lag when the prompt appears, and the
  program accepts a challenge until its slot is 150 slots old: a 31-slot lag
  leaves about 119. The slot is still read at the reads' commitment, on
  purpose: the program refuses a slot newer than the one it runs in, which a
  relayer simulating at `finalized` would hit.
- Tests (unit, both packages), each failing on 1.3.0 / rc.4: a fee read that
  fails while the challenge reads wait on the floor leaves no retry timer and
  no read after the rejection (before: 40 more reads in the next 11 s, in each
  package); a read group that has already stopped starts no read and rethrows
  its failure; the `finalized` timeout message states no fixed lag and keeps
  the lagging-node advice.

**Deploy docs and CI**

- `docs/upgrade-procedure.md` §6 deployed `target/deploy/lazorkit_program.so`
  after a bare `cargo build-sbf` and never compared it with
  `scripts/release-hashes.txt`. With `CARGO_TARGET_DIR` set (the deploy
  machine's `cargo` wrapper) that build writes elsewhere and `target/deploy/`
  keeps an old file, which the v0 check and the hash print then pass: the
  2026-09-27 near-miss the checklist records. §6 now builds with
  `OUT=target/artifacts ./scripts/check-release-hashes.sh mainnet` and deploys
  that file only when the script exits 0 (it matches the record), naming
  `--program-id`, `--upgrade-authority` and `--url`. `DEVELOPMENT.md`'s devnet
  deploy builds into a fresh target dir with `--sbf-out-dir`, the checklist's
  multisig `write-buffer` example names the sunset artifact, and
  `build-all.sh` no longer prints a deploy command for `target/deploy/`. Run on
  this commit, the §6 build gives mainnet `4cb80304…` and the devnet one
  `3584aec7…`, as recorded.
- `check-release-hashes.sh` with a relative `OUT` wrote the binaries under
  `program/` and then failed to find them; it now makes `OUT` absolute.
- New `scripts/deploy-docs-lint.cjs`, in the lint workflow: every
  `solana program deploy` / `write-buffer` in a fenced block of a doc that is
  not history must name a file under `target/artifacts/`. Before this change
  it failed three commands (§6, `DEVELOPMENT.md`, the multisig example).
- The SBF cluster check also runs on changes to `.cargo/**` and
  `rust-toolchain.toml`: a repo-root `.cargo/config.toml` with
  `overflow-checks = true` alone makes the sunset 49896 bytes instead of
  45856, and no path in the filter matched it. It also runs weekly, for drift
  from outside the repository. The `release-hashes` job is a red check, not a
  required one (main requires neither it nor `cluster-check`, and develop is
  not protected), so the record and the checklist no longer say it blocks a
  merge. Making it required is a repository setting, left to the maintainers.

### Added — a passkey's public key, recovered from two assertions

**SDKs** (`@lazorkit/sdk-legacy` 1.3.0, `@lazorkit/sdk` 1.0.0-rc.4)

A returning user who signs in with an existing passkey that has no wallet yet —
every passkey, on a v2 program id that is new — could not get one unless the
app already held that passkey's public key. A WebAuthn assertion carries none,
and a key reported from somewhere else (a portal's local storage, which falls
back to another passkey's key; a deep link) is not proven to be this
passkey's. Creating the wallet with it anyway makes one the passkey can never
sign for, so whatever is sent to its vault is stuck; checking it first, as the
wallet adapter does, refused the connect. Reproduced on devnet with
`@lazorkit/wallet` 3.0.2 and the live portal.

- **`recoverPasskeyPublicKeys(proof, rpId)`**: every 33-byte compressed key an
  `OwnershipProof` verifies against — the signer's among them, almost always
  two in all (recovery ids 0..3; 2 and 3 only when r + n < p). Pure, never
  throws; `[]` unless the proof passes exactly the checks of
  `verifyOwnershipProof` (JSON clientData, `webauthn.get`, the challenge,
  at least 16 bytes of it, the rpId hash, the user-present flag). DER or
  64-byte r||s, high-S as authenticators return it half the time; every key
  returned is re-verified against the proof.
- **`resolvePasskeyPublicKey(proofs, rpId)`**: the one key common to every
  proof, or `null` — with fewer than two proofs, any two over the same
  challenge, one that fails a check, or proofs from different passkeys. Ask the
  passkey for a second assertion over a fresh challenge, pinned to the first
  one's credential, resolve, then `createWallet` with the key. It is the key
  of whoever produced the assertions. That is the passkey's only when both come
  straight from `navigator.credentials.get` in the app's own page, where the
  browser sets the rpId hash, flags and clientData: in a relayed proof those
  bytes are the signer's choice (signed, but under the key being recovered), so
  any P-256 key can make assertions that pass every check. Recovering from
  assertions relayed by a portal or over a deep link fixes an honest portal's
  wrong key (the fallback above), not a channel someone else controls.
- `verifyOwnershipProof` now shares its checks with the recovery (one helper
  computes the signed digest or refuses); its behaviour is unchanged.
- README, "Finding a returning user's wallet": what to do when the passkey has
  no wallet and you do not hold its key.
- Tests: unit (both packages, including a repeated challenge anywhere among
  the proofs and a 64-byte string that reads as both DER and r||s; in the kit
  also a parity check of the two implementations and a constructed signature
  with r + n < p that only recovery ids 2 and 3 reach), and on a local
  validator in both suites: a fresh passkey's key recovered from two
  browser-shaped assertions (one high-S), a wallet created with it, and a
  passkey `Execute` signed for it that lands — the key the program verifies
  against is the recovered one.

### Fixed — a passkey challenge built right after a send signed a spent counter (3006)

**SDKs** (`@lazorkit/sdk-legacy` 1.3.0, `@lazorkit/sdk` 1.0.0-rc.4)

Two passkey transactions from one authority, back to back, failed the second
with `SignatureReused` (3006): three pairs out of three on devnet, and on a
local validator too. The challenge signs the authority's counter + 1, and it
was read with no freshness floor and, in sdk-legacy, at the Connection's
default commitment (`finalized` for a Connection built without one). The
wallet and the playground relayer hand back tx1's signature as soon as the RPC
accepts it, so tx2's counter was read from a bank older than the slot tx1
landed in, and tx2 signed the counter tx1 was about to use. The signature
commits to the counter, so nothing can repair it after the user approves; it
fails in the relayer's simulation, or on chain after the sponsor paid the fee.

- Every read a passkey challenge is built from — the authority's counter, its
  key and the slot — now takes `{ commitment, minContextSlot }`, default
  `commitment: 'confirmed'` (in sdk-legacy `'processed'` on a Connection at
  `'processed'`: never staler than the Connection). Pass the slot the
  authority's previous transaction landed in, or any later slot a node that
  confirmed it reports (`confirmTransaction` → `context.slot`), as
  `minContextSlot`, and the reads come from a node that has executed it. Where: `Secp256r1Params` (every `prepare*`: `prepareExecute`,
  `prepareAuthorize`, `prepareAddAuthority`, `prepareRemoveAuthority`,
  `prepareTransferOwnership`, `prepareCreateSession`, `prepareRevokeSession`),
  `Secp256r1SignerConfig` and the `secp256r1(signer, opts)` helper (every
  one-shot method: `execute`, `transferSol` in sdk-legacy, `authorize`,
  `addAuthority`, `removeAuthority`, `transferOwnership`, `createSession`,
  `revokeSession`), `migrateV1Wallet` (the v1 authority's counter and the slot
  of a passkey migration), and `readCounter` / `readAuthorityCounter` /
  `readAuthorityPubkey`. `minContextSlot` is a `number` in sdk-legacy, a
  `Slot` (`bigint`) in the kit SDK.
- A node behind the floor answers -32016 ("minimum context slot has not been
  reached"); the read is retried with a short backoff (100 ms, rising to 1 s)
  for up to 10 s, then fails with the new `MinContextSlotNotReachedError`
  (`minContextSlot`, `waitedMs`, the RPC error as `cause`) rather than read
  older state. Other errors are not retried.
- sdk-legacy reads the authority with `getAccountInfoAndContext`, because
  web3.js `getAccountInfo` rethrows RPC errors without their code. A stubbed
  Connection must provide it.
- Behaviour change without the new options: sdk-legacy's challenge reads are
  at `confirmed` on a Connection built without a commitment (which read at
  `finalized`) or at `finalized`; a Connection at `processed` or `confirmed`
  reads where it did in 1.2.0. (The kit SDK asks for `confirmed` explicitly
  now, which `createSolanaRpc` already defaulted to.) A counter read after a
  send confirmed on the same node is then current; a send that is only
  accepted, or confirmed by another node behind a load-balanced RPC, still
  needs the floor: the wallet has to wait for tx1 to confirm and pass its
  slot, or have its paymaster confirm before answering. With the kit SDK, a
  caller that confirms at `processed` passes `commitment: 'processed'` too.
- The program is unchanged: 3006 is the replay protection working, and
  predicting counter + 2 would be wrong whenever tx1 fails or is dropped.
- README (sdk-legacy): a 3006 is not always LazorKit's. A program `Execute`
  calls can fail with the same custom code (Anchor's `AccountNotMutable` is
  3006), and `extractErrorCode` / `errorFromCode` read only the number; the
  first `Program <id> failed` log line names the program that raised it.
- Tests: unit tests in both packages (tests-sdk `18-counter-read-unit` and the
  migration case in `16-v1-migration-unit`; sdk-kit `counter-read`) that each
  method passes the options to all three reads, the default (per Connection
  commitment in sdk-legacy), -32016 retried then answered, retries exhausted,
  and that nothing else is retried. On a local validator in both suites
  (`19-back-to-back`, kit `18-back-to-back`), with tx1 confirmed at
  `processed` only so that `confirmed` reads lag it the way a node behind a
  load balancer does: without a floor tx2 signs the spent counter and fails
  with 3006 (the negative control); floored at tx1's slot it lands, three
  pairs in a row, where the SDK before this change fails. Also: a floor a few
  slots ahead is waited for (the node's real -32016 is recognised), one it
  never reaches ends in `MinContextSlotNotReachedError`, and, on a
  sdk-legacy Connection at `processed`, tx2 prepared with no options right
  after tx1 confirms there lands and a wallet just created is found.
- A floor at `commitment: 'finalized'` waited 10 s like the others, but where
  a slot is finalized about 32 slots after it is confirmed (a local test
  validator: 31 slots, 16.5 s; the lag is the cluster's, see the follow-up
  above), a finalized read floored at a just-confirmed tx1 — what the README
  says to pass — always ended in `MinContextSlotNotReachedError`, with a
  message blaming the RPC endpoint. A finalized read now waits up to 30 s for its floor; if the slot is
  still not finalized, the error says so and suggests waiting for tx1 to
  finalize or reading at `confirmed`. The error has a new `commitment` field,
  and names the commitment in its message at the other commitments too.
- The counter, key and slot reads run side by side. When one failed outright
  (a 5xx, an unhealthy node), the call rejected at once but the other two kept
  retrying -32016 for up to 10 s: polling the RPC after the caller had its
  answer, a new set on every retry of the prepare, and a Node process held open
  by their timers. They now stop as soon as one fails. The stop is per call;
  the SDK keeps no state between calls.
- One passkey flow per authority at a time (both READMEs and the
  `Secp256r1Params` JSDoc): two flows for one authority that overlap sign the
  same counter, and whichever lands second fails with 3006 whatever floor is
  passed. The SDK does not queue; the READMEs show a queue for the app's side,
  and say that across tabs or devices sharing a passkey the answer to that
  3006 is a new prompt.
- A landed `{ InstructionError: [i, { Custom: N }] }` names only the
  top-level (LazorKit) instruction, so it cannot be attributed to LazorKit or to
  a program `Execute` called without the transaction's logs. The sdk-legacy
  README and the `errorFromCode` / `extractErrorCode` JSDoc say so (the latter
  returns `null` for that object), and the kit README now has the same note.
- Tests for the last four, each failing on the SDKs before them: unit tests in
  both packages (a finalized floor reached after 13 s is waited for, one never
  reached gives up after about 30 s with the finalized message, `confirmed`
  still gives up at 10 s and names itself; with one read failing, no retry
  timer is left and no read reaches the RPC afterwards — before, 28 more reads
  in the next 11 s), and on a local validator in both suites: tx1 confirmed,
  tx2 floored at its slot at `finalized` waits for finalization (about 13 s)
  and lands.

### Fixed — size and capacity figures in the docs, and the litesvm CI job

**Docs** — the room a passkey Execute leaves for inner instructions is about
345 bytes (887 of the 1232 are its own; about 305 with a compute-unit limit,
under 200 when Chrome pads clientDataJSON), not ~574; a passkey MigrateWallet
without a lookup table fits 3 tokens (823 + ~100 bytes each; 4 with no
`topOrigin` in clientDataJSON) and an Ed25519 one 7, not "about five" and
"about ten". Measured with sdk-legacy 1.2.0 and cross-checked against devnet
transactions; fixed in `docs/Architecture.md`, `docs/migration-ui-flow.md`
(now a table), `docs/use-cases/eoa-with-passkey-spender.md`, the benchmark's
capacity row and the `DeferredExecAccount` doc comment. The release artifacts
rebuild to the same hashes (devnet `3584aec7…`, mainnet `4cb80304…`).

**CI** — "program litesvm integration" failed since cargo-build-sbf 4.4.0
(2026-09-22) made SBPF v3 its default: litesvm 0.6 cannot load a v3 binary and
panicked in `add_program` (`lib.rs:700`, `InvalidAccountData`) in every test
that loads the program. The fixture script, `scripts/test-program.sh` and the
workflow's sunset build now pass `--arch v0` — what the program deploys as —
and the test harness refuses a non-v0 artifact with a message saying so.

**Build** — the same default reached every other build: the release commands
in `docs/mainnet-deploy-checklist.md` §2, `docs/upgrade-procedure.md`,
`DEVELOPMENT.md`, `scripts/build-all.sh`, `scripts/start-validator.sh` (the SDK
suites' validator) and the SBF cluster check, which recorded v3 hashes
(mainnet `80e68083…`). A v3 build passes the size check and loads on a local
validator, so nothing noticed. They all pass `--arch v0` now, and the new
`scripts/assert-sbpf-v0.sh` refuses a binary whose ELF header is not v0; the
checklist, `build-all.sh`, `start-validator.sh` and the cluster check run it.
The §2 commands rebuild to the table's hashes (mainnet `4cb80304…`, sunset
`6080da9f…`, devnet `3584aec7…`).

**Toolchain pinned** — `--arch v0` was not enough. cargo-build-sbf 4.4.0 also
turns link-time optimisation off for a crate that is both `cdylib` and `lib`
(this one), with only a warning, so CI's v0 builds stopped reproducing the
release artifacts: a 140200-byte mainnet-v1 sunset instead of 45856, which
§2's size check would stop. The release toolchain is now named in one place,
`scripts/sbf-toolchain.sh`: Agave v4.2.2 (cargo-build-sbf 4.1.0) with
platform-tools v1.53 and `--arch v0`. Two more inputs turned up on the way.
`security_txt!` compiles in `GITHUB_SHA` and `GITHUB_REF_NAME`, which GitHub
Actions sets and the recorded artifacts have empty, so release builds and the
hash check unset them (a CI build with them set is 48 bytes larger; with the
same two values a local build is byte-identical to it). And the host:
platform-tools' precompiled std embeds the paths it was built under
(`/Users/runner/…` in the macOS package, `/home/runner/…` in the Linux one),
so a Linux build of the same commit hashes otherwise (mainnet `f655b300…`, a
45848-byte sunset). The record and the tables are macOS (Apple silicon)
builds, and release builds stay there.
- Both CI jobs that build SBF install that release instead of `stable`, check
  `cargo-build-sbf --version`, pass `--tools-version`, and key their cargo
  cache on the toolchain (`--tools-version` does not invalidate cargo's cache).
- New `scripts/check-release-hashes.sh` rebuilds mainnet, mainnet-v1, devnet
  and devnet-v1 in a fresh target dir, refuses any other cargo-build-sbf, and
  compares size and SHA-256 with the new `scripts/release-hashes.txt`; it
  refuses another host unless `SBF_ANY_HOST=1`. The SBF cluster check runs it
  on a `macos-15` (Apple silicon) runner, where it reproduces all four hashes,
  so a change that moves a binary fails until the record is updated, and
  toolchain drift fails in CI rather than at deploy time. It also runs on
  changes to `Cargo.lock`, `no-padding/`, the pin and the record.
- `build-all.sh`, `build-repro-fixtures.sh`, `start-validator.sh` and
  `test-program.sh` use the pin and warn on another cargo-build-sbf; §2 of the
  checklist, `DEVELOPMENT.md`, `CONTRIBUTING.md` and `upgrade-procedure.md`
  name it. Rebuilt with it in a fresh target dir, all four artifacts match the
  record (mainnet `4cb80304…`, mainnet-v1 `6080da9f…`, devnet `3584aec7…`,
  devnet-v1 `2cf15c89…`).

### Fixed — the passkey challenge names the wallet

**Program**
- **A passkey assertion no longer verifies on another wallet.** The Secp256r1
  challenge was `SHA256(discriminator ‖ auth_payload[..14] ‖ signed_payload ‖
  payer ‖ counter_le4 ‖ program_id)`. For `CreateSession`, `AddAuthority` and
  `TransferOwnership` nothing in it named the wallet — nor for `Execute` and
  `Authorize` when no inner instruction touches an account derived from the
  wallet, such as its vault — so an assertion made for wallet A verified on
  any wallet B whose authority held the same passkey (credential hash and key)
  at the same counter, within the slot window, through the same fee payer — and
  a relayer's fee payer is shared by every wallet it serves. `RevokeSession`,
  `RemoveAuthority` and `MigrateWallet` were already bound: each signs an
  account the program then checks belongs to the wallet. It is now
  `SHA256(discriminator ‖ auth_payload[..14] ‖ signed_payload ‖ payer ‖ wallet ‖
  counter_le4 ‖ program_id)`, where `wallet` is the authenticating authority's
  own header field (bytes 16..48): no new account, no instruction layout change.
  It applies to every Secp256r1 authentication, `MigrateWallet` in the sunset
  build included (a v1 authority's header carries its wallet at the same
  offset), so the instructions that were bound through their accounts are now
  bound directly as well. This closes what "A signature count can be forged by
  replay" below left open. `program/tests/wallet_binding_tests.rs` replays a
  CreateSession and an AddAuthority from one wallet onto another with the same
  passkey and counter (both now 3005), and the sunset suite migrates a v1
  passkey wallet with the new challenge and refuses the old one. Both replays
  landed before: an old-layout assertion for A, resubmitted with B's accounts,
  created the session and the Admin on B against the devnet build of 59befed,
  the commit before the binding — recorded in the test's module doc, since the
  committed tests sign the new layout and fail earlier on that build.
- **Breaking for every passkey client:** one that builds the old challenge
  fails with `InvalidMessageHash` (3005). Ship SDK and program together; on
  devnet, where v2 is already deployed, redeploying it breaks passkey signing
  in any client not yet updated.

**SDKs** (both)
- `buildSecp256r1Challenge`, `prepareSecp256r1` and `signWithSecp256r1` take a
  required `wallet` (`PublicKey` / `Address`), hashed after `payer`: the wallet
  PDA for every v2 instruction, the **v1** wallet for `MigrateWallet` (the v1
  authority signs, not the v2 destination). Every `prepare*` method, the
  one-shot methods and `migrateV1Wallet` pass it; hand-built flows must add it.
- A fixed vector pins the byte order (payer, then wallet, then counter) in both
  packages' tests and in the program's `wallet_binding_tests`, whose signing
  helper every passkey test in `program/tests` uses; unit tests pin the wallet
  `prepare*` and `migrateV1Wallet` hash.
- The ownership rule is unchanged: `pickOwnWallet` and `migrateV1Wallet` still
  treat two signed-for wallets as ambiguous, because counts raised before this
  change — on every v1 authority, and on devnet v2 — may hold replayed copies.
  The validator tests that demonstrated the replay now assert it is refused
  (3005) and that the one wallet signed for is adopted.

### Fixed — a passkey Execute or ExecuteDeferred can repay its payer

An inner instruction that pays the payer back — how a sponsored call settles
with its paymaster — made a passkey `Execute` fail with `InvalidMessageHash`
(3005) and `ExecuteDeferred` fail with `DeferredHashMismatch` (3015), then,
with the hash corrected, with `UnbalancedInstruction`.

**Program**
- **ExecuteDeferred moves the rent after its CPIs.** It used to credit the
  DeferredExec rent to the refund destination with direct lamport writes and
  then run the inner instructions. The runtime syncs a caller's lamport writes
  into a CPI only for the accounts that CPI is handed, so an inner instruction
  naming the refund destination carried the credit across without the
  DeferredExec debit, and the CPI push failed. The authorization is still
  consumed (its data zeroed) before any CPI, so nothing inside them can replay
  it; the rent moves last, added to whatever the inner instructions left.
  `program/tests/deferred_refund_tests.rs` runs Authorize with a real passkey
  assertion and then an ExecuteDeferred that repays the refund destination —
  paid by the same key, and by another — and fails on the old order.

**SDKs** (both)
- **The accounts hash uses the flags the runtime reports.** The program hashes
  each account's runtime signer/writable flags; those are per key over the
  whole message, and the SDKs hashed their own declaration instead. `Execute`
  declared the payer read-only, but as fee payer the runtime reports it
  writable. Authorize's tx2 layout lists the payer twice — as tx2's payer and
  as the refund destination, which inner references resolve to — and hashed
  that second entry as writable only, where the runtime reports the payer's
  signature there too.
- `createExecuteIx` declares the payer a writable signer, as the IDL already
  did; a payer that is not the transaction's fee payer can now be repaid and
  pay the execution fee. `prepareAuthorize` declares the wallet read-only, as
  `createExecuteDeferredIx` passes it, and a repeated key's flags are merged
  before hashing.
- **`prepareAuthorize` takes an `executor`** — who will send tx2, default the
  Authorize payer. Tx2's payer (index 0) and its refund destination (index 4,
  always the Authorize payer) hash differently depending on who sends it: the
  Authorize payer is a signer at index 4 only when it sends tx2 itself. Hashing
  it as one unconditionally, as the first cut of this fix did, broke the
  relayer hand-off whenever an inner instruction repaid the sponsor (3015). The
  deferred payload now records the executor and the refund destination
  (optional fields, serialized; payload version unchanged), and
  `executeDeferredFromPayload` defaults the refund destination to the recorded
  one — the only one the program accepts — and refuses a different sender when
  an inner instruction names either slot, rather than build a tx2 the program
  would refuse.
- **`prepareExecute` and `prepareAuthorize` take a `feePayer`** for when
  another key pays the transaction fee: the runtime reports it a writable
  signer wherever it appears, so an inner instruction that repays it is hashed
  that way (3005 before). The SDKs model the instruction's own accounts and the
  fee payer; another top-level instruction, the protocol-fee suffix and the
  runtime's read-only demotions are the caller's to account for, and the docs
  now say so.
- No format change (`test-vectors/accounts-hash.json` is untouched): the bytes
  differ only where an inner instruction names the payer, the fee payer or tx2's
  executor, or for Authorize the wallet — exactly the cases that failed. Unit
  tests pin the flags in both SDKs; both validator suites repay the payer from
  Execute (also with another key paying the fee), repay a fee payer that is not
  the Execute payer, and repay the Authorize payer from ExecuteDeferred sent by
  itself and by a relayer.

### Changed — v2 ships at its own program id; v1 is retired, not overwritten

Protocol v2 no longer replaces v1 in place. An in-place upgrade would have frozen
every v1 wallet on one day — including Seedless, which went live on v1 while v2
was being prepared. v2 now deploys fresh at its own id, the way Squads v3/v4,
Jupiter v4/v6 and Token/Token-2022 shipped, and v1 keeps running untouched until
it is retired.

| cluster | v2 | v1 (retiring) |
|---|---|---|
| mainnet | `LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8` (not yet deployed) | `LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi` |
| devnet | `57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv` (deployed) | `4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS` |

**Program**
- Cluster features are now `mainnet`, `devnet`, `staging`, `rehearsal` (full v2)
  and `mainnet-v1`, `devnet-v1`, `rehearsal-v1` (sunset). Exactly one, enforced
  at compile time. The v1 ids can only be built as sunset binaries.
- **Sunset binary.** Serves `ReclaimDeferred` (8), `MigrateWallet` (17) and
  `CloseExpiredSession` (18); everything else fails with **4018
  `RetiredDeployment`** before any processor runs. The compiler drops the
  unreachable code: 45 KB against 150 KB for full v2.
- `ReclaimDeferred` accepts a v1 DeferredExec account as well as a v2 one. Its
  rent was recoverable only before the upgrade; now it is recoverable after,
  still only by the payer that funded it.
- `lazorkit_program::ID` is re-exported, and the test harness loads at it rather
  than at a hardcoded address.
- `PROTOCOL_INIT_AUTHORITY` moved into `assertions`, inside the same cluster
  arms as the program id. It used to key off the program crate's features, so
  `--features assertions/mainnet` built the mainnet id with the committed devnet
  key as init authority — anyone could have initialised the protocol first.
- Each v1 feature asserts at compile time that it builds a sunset binary, and
  each v2 feature that it does not.

### Fixed — found in review of the two-id change

**Program**
- **`MigrateWallet` pins the system program.** Account 6 was used as the CPI
  target for the SOL sweep without a check, and the passkey challenge does not
  cover it. A relayer holding a valid assertion could swap in a no-op program:
  tokens moved, the wallet and authority closed, and the vault's SOL stranded
  for good. Now `IncorrectProgramId`, and the instruction also refuses to
  finish unless the v1 vault is empty after the sweep. Ed25519 owners were
  never exposed (their signature covers every account).
- **`MigrateWallet` moves tokens with `TransferChecked`.** Plain `Transfer` is
  refused by Token-2022 for transfer-fee mints, which made those wallets
  unmigratable. **Breaking for hand-built instructions:** each token is now
  four accounts — source, destination, **mint**, token program.
- **`ReclaimDeferred` pays only the stored payer.** The refund destination was
  free, and on a sponsored authorization the payer is the relayer's fee payer,
  which signs for anyone: a stranger could route the sponsor's rent to
  themselves. Now `UnauthorizedReclaim` unless refund == payer, as
  `ExecuteDeferred` already required.

**SDKs** (both)
- **`migrateV1Wallet` no longer delivers into a wallet someone else controls.**
  It used to reuse the first v2 wallet listing the owner's key, at any rank —
  and v2 `AddAuthority` never asks the key being added, so an attacker could
  list a victim's passkey on a wallet they control and receive the migration.
  The `userSeed` path had the same hole (v1 seeds are public). A wallet is now
  reused only if it passes `vetMigrationDestination`, and only on the terms in
  "Choosing the destination" below (the final rule, after three reviews);
  otherwise a fresh wallet is created, or, for a `userSeed` or
  `destinationUserSeed` wallet, the call throws. **Published `sdk-legacy` 1.1.x and `@lazorkit/sdk` 1.0.0-rc.2 have
  the hole** — no exposure yet, since v2 is not on mainnet, but do not use
  their `migrateV1Wallet` against it.
- **Unmovable tokens are left out and reported.** Frozen accounts and
  Token-2022 transfer-hook mints would revert the whole migration, and anyone
  can plant one in a vault. They come back as `skippedTokens`
  (`'frozen' | 'transfer-hook' | 'excluded'`); `excludeTokenAccounts` lets the
  user drop spam. New helpers: `classifyV1VaultTokens`, `mintTransferHook`.
- `createMigrateWalletIx` / `MigrateTokenPair` take the `mint`.
- `migrateV1Wallet` throws when the client is built at a retired v1 id, where
  the destination would be derived under a program that can never sign for it.

### Fixed — found in a second review, 2026-09-28

- **Passkey migrations of two or more token accounts always failed.** The
  signed payload read each source account at a 3-account stride after tokens
  became 4 accounts, so from the second token on it bound the wrong key and
  authentication failed (3005). Both loops now index by one `TOKEN_ACCOUNTS`
  constant; a three-token passkey test fails on the old stride and passes now.
  The two-id rehearsal's passkey wallet holds two tokens (SPL + Token-2022).
- **Destination vetting now checks the whole passkey.** `vetMigrationDestination`
  compared only the credential-id hash, which is public, and `CreateWallet`
  takes any owner: a wallet with the victim's hash and the attacker's public
  key passed, and received the migration. It now also requires the stored
  public key and relying-party hash to match (both SDKs). The signature is
  now `vetMigrationDestination(wallet, owner, { watchMints }?)` (see
  "Vetting a migration destination" below).
- **More Token-2022 states are recognised as unmovable**: non-transferable
  mints and accounts, paused mints, mints that freeze new accounts, withheld
  transfer fees, CPI guard. New helpers `mintBlocker` / `tokenAccountBlocker`.
- `migrateV1Wallet` takes `refundDestination` (defaults to `payer`) for the
  rent of the closed v1 accounts.
- `deploy/kora/kora.mainnet.toml` still *required* the v1 id while allowing
  only v2, so the relayer would have refused every transaction.
  `scripts/kora-config-lint.cjs` now checks both files in CI.

### Fixed — found in a third review, 2026-09-28

- **Withheld transfer fees no longer strand a token.** They only stop the
  source account from closing, and anyone may harvest them to the mint:
  `migrateV1Wallet` now puts a `HarvestWithheldTokensToMint` before the
  migration in the same transaction (ed25519: `migrate.instructions`; passkey:
  `finalize()` returns `[...harvests, precompile, migrate]`). Proven on a local
  validator with a 1% fee token: the rehearsal is 18/18.
- A token whose mint is gone or owned by another token program is left behind
  as `mint-missing` instead of reverting the migration; a destination account
  that exists and is frozen is `destination-frozen`; a default-frozen mint whose
  destination is already thawed moves.
- Mints and destinations are read in pages of 100 (the RPC limit), after
  `excludeTokenAccounts` is applied: 101 planted mints no longer make a vault
  unmigratable.
- A passkey `owner` must be exactly the v1 authority's key and relying party;
  a wrong `rpId` used to sweep funds into a wallet no assertion could satisfy.
- `kora-config-lint` also requires every required program to be allowed and
  the v1 id to be in both lists or neither.

**SDKs** (`@lazorkit/sdk-legacy` 1.2.0, `@lazorkit/sdk` 1.0.0-rc.3)
- **Breaking:** `PROGRAM_ID_MAINNET` / `PROGRAM_ID_DEVNET` are the v2 ids
  (`LazorFroiVuAjcwwQ2me83vTr5nc5NRxSaTg3pmEXC8`, `57bTNWqtYTJbWuLWASKo6GqUTAK6oFDUR5c6hEc6V8nv`).
- New: `PROGRAM_ID_MAINNET_V1`, `PROGRAM_ID_DEVNET_V1`, and
  `legacyProgramIdFor(programId)`.
- `migrateV1Wallet` and `findV1WalletsByOwner` take the v1 program id
  (defaulting to the paired v1 deployment). The migration instruction — and the
  passkey challenge, which binds the verifying program — go to the v1 id; the
  destination wallet and vault are derived at the client's v2 id.

**Operations**
- The v2 relayer does not sponsor the v1 id until it runs the sunset binary:
  full v1's Execute forwards every outer signer (H-3), so sponsoring it lets any
  v1 transaction conscript the fee payer.

### Added — finding a returning passkey's own wallet (both SDKs)

`CreateWallet` and `AddAuthority` take any key without its consent, on v1 and
v2, and a passkey's credential-id hash is public — it sits in every authority
account the passkey has. So "the first wallet that lists my credential", the
lookup the docs showed as `const [wallet] = await
client.findWalletsByAuthority(credentialIdHash)`, can be a wallet someone else
planted: the victim's hash next to the attacker's public key, or the victim's
real passkey added to the attacker's wallet. A user who funds it funds the
attacker.

The new lookup adopts a wallet only when (1) this passkey is an Owner on it,
under this relying party, and the key stored there is the one a fresh assertion
just proved; (2) nothing untrusted can spend from it — no other authority,
live session, pending deferred execution, delegate / foreign close authority on
the vault's token accounts, or vault handed to another program, apart from
Ed25519 keys the integrator declares trusted; and (3) the passkey has signed
for it before. Anything else comes back as `needsConfirmation`, for the user to
choose from. Accounts too short to read count against the wallet rather than
being skipped.

The rules, the same in both packages. Each attack below was reproduced on a
local validator; the read ordering is pinned with a stubbed RPC that serves
each read from before or after one transaction.
- **A pending deferred execution is never trusted**, whatever authority it
  names (`pendingDeferred[].trusted` is always `false`). The authority PDA is
  derived from `[lk2:authority, wallet, credentialIdHash]` and does not bind
  the public key, and `ExecuteDeferred` does not re-check who authorized it: an
  attacker can queue a drain from their own key at the victim's authority
  address, remove it, re-create it holding the victim's real key, and leave.
  The same seed can also land on a trusted Ed25519 key's address.
- **Live through the expiry slot.** Sessions and deferred executions count
  while `expiresAt >= slot`: the program refuses only once
  `current_slot > expires_at`. One too short to read counts as live.
- **`WalletFacts.tokenGrants`, and `watchMints`.** Token rights outlive every
  authority: a delegate set with `Approve`, a close authority other than the
  vault, or (SPL Token) the vault's canonical account for a watched mint whose
  owner was moved off the vault with `SetAuthority`, which senders still pay
  into. Each is reported for every SPL Token / Token-2022 account the vault
  owns (kinds `delegate`, `closeAuthority`, `owner`, `unreadable`), trusted
  when its grantee is in `trustedKeys`; an untrusted one makes
  `controlledAlone` false. The watched mints are wSOL, USDC, USDT and devnet
  USDC, plus every mint passed as `watchMints` to `describeWalletCandidates`,
  `findOwnPasskeyWallet`, `vetMigrationDestination` (third argument,
  `{ watchMints }`) and `migrateV1Wallet`. Nothing on chain leads from a moved
  account back to the vault, so only a mint named in advance can be checked:
  pass the mints your app receives. A malformed mint throws.
- **`WalletFacts.vaultIsSystemAccount`.** An Owner without a policy can
  `Execute` System `Assign` / `Allocate` on the vault (the vault signs via
  `invoke_signed`); from then on the new owner program, not LazorKit, decides
  what leaves it — then hand the wallet to the victim's passkey with
  `TransferOwnership`. `controlledAlone` requires the vault to be missing or
  owned by the System Program with no data, and no trusted key waives it.
- **Dead wallets are left out.** A candidate whose wallet account is missing,
  owned by another program or carries the wrong discriminator is dropped from
  `describeWalletCandidates` — checked before its reads and again with them.
  `MigrateWallet` closes the v1 wallet and only the authority that migrated;
  another Owner passkey's v1 authority stays behind and, as v1, would have been
  adopted ahead of the live v2 wallet, with nothing ever able to move funds
  sent to it.
- **Only a wallet the passkey has signed for is adopted; a never-used wallet
  needs confirmation** (`WalletFacts.signatureCount`, the u32 replay counter
  at offset 8 of this passkey's own authority, the same on v1: every authority
  starts at 0 and only a signature verified against its stored key advances
  it; 0 unless that authority is still intact). `TransferOwnership` hands a
  wallet to a passkey without asking it, and its earlier Owner can have moved
  the vault's canonical SPL Token account for any mint to themselves; it then
  no longer lists as the vault's and nothing leads back to it, so for an
  unwatched mint the wallet looks spotless — and a lamport more in its vault
  ranked it above the user's own, so it was adopted and later deposits of that
  mint went to the attacker. Now a wallet never signed for is only ever
  offered, even the only one and with `trustedKeys`; the user's own wallet
  before its first transaction, and the one a migration just created, are
  confirmed once. Order: signed for first, then v1, then balance, then
  address — the balance order is anyone's to change.
- **A signature count can be forged by replay, so only the one wallet signed
  for is adopted.** The program's passkey challenge binds the payer, the
  counter and the instruction's arguments but not the wallet for
  `CreateSession`, `AddAuthority`, `TransferOwnership` and `Authorize`. The
  signature from a user's first such transaction on their own wallet can be
  submitted again, within about 150 slots and through the same fee payer (the
  relayer signs for anyone), on a wallet planted for their passkey, raising
  its counter to 1 — reproduced on a local validator, where the planted wallet,
  a lamport richer, was adopted. `pickOwnWallet` now adopts only when exactly
  one wallet has `signatureCount > 0` and it is `controlledAlone`; two signed
  for (alone or not) go to the user. `migrateV1Wallet` reuses a wallet only
  when it is the one authority on the program storing this passkey that has
  signed at all (any rank: an Admin seat's signature replays onto an Owner's).
  Left open, until the program binds the wallet into the challenge: a copy of
  a signature made where the passkey is not an Owner candidate (an Admin
  seat) or on an authority since removed makes the planted wallet the only one
  signed for, and `findOwnPasskeyWallet` adopts it.
- **Consistent reads.** `describeWalletCandidates` and
  `vetMigrationDestination` read the slot first, then in the order power flows
  between accounts: the wallet's authorities; then its sessions and deferred
  executions; then the wallet account, vault, watched token accounts and the
  vault's token accounts. Each step asks the RPC for state at least as new as
  the slot the previous one was answered at (`minContextSlot`). Read
  concurrently, one transaction landing mid-read — a co-owner that opens a
  session or approves a delegate and removes itself, a deferred execution that
  runs and closes itself, a sole owner that assigns the vault away and hands
  the wallet over — could show as none of it, especially behind a
  load-balanced RPC. A node that has not reached the slot is asked again, up
  to five times; then the call throws. `migrateV1Wallet` reads a vetted
  destination's token accounts no older than its vet.
- **Vetting a migration destination.** `vetMigrationDestination(wallet, owner,
  { watchMints }?)` returns `null` or the reason, and passes only: a wallet
  account of this program (missing, foreign-owned, another discriminator, or
  only lamports: `<address> is not a wallet of program <id>`); exactly one
  authority, this whole key at Owner rank (for a passkey the credential-id
  hash, the public key and the relying party); no session or deferred
  execution with `expiresAt >= slot`; a vault that is a plain system account
  (a missing one is fine); and no token grant on the vault's token accounts —
  no key is trusted here. The reason strings are for people, not parsing.
- **Delivering a migration.** `migrateV1Wallet` refuses to deliver into an
  existing destination token account that is not the v2 vault's alone —
  another token program or owner, a delegate, a close authority other than the
  vault, too short to read — and throws naming up to three
  (`refusing to migrate into <wallet>: destination token account …`), rather
  than skipping the token, which the closing v1 vault would strand. Fresh
  destinations are unaffected; a frozen one is skipped as
  `destination-frozen`. Bare lamports at a destination address no longer count
  as an open token account, so a token whose mint freezes new accounts stays
  in `skippedTokens` instead of failing the migration on-chain.
- **Choosing the destination.** Without a `userSeed`, `migrateV1Wallet` reuses
  an existing v2 wallet only if it passes the vet **and** the passkey has
  signed for it (`signatureCount > 0`) **and** on no other authority of the
  program, at any rank (see the replay above); it used to take the first that
  passed vetting, which a planted one does. An Ed25519 owner's wallets, which record
  no signatures, are never reused this way. Otherwise the destination is
  `destinationUserSeed`'s wallet or a fresh random seed's (returned as
  `destinationUserSeed` — persist it).
- **`destinationUserSeed` is vetted.** A wallet already at the named seed is
  used only if it passes the vet, as a `userSeed` wallet is; otherwise the
  call throws `refusing to migrate into the destinationUserSeed's v2 wallet: …`
  (`userSeed's`). A wallet address holding only lamports (anyone can send
  them; a v1 `userSeed` is public) is no longer refused as a wallet with
  "0 authorities": the wallet is created there, as `CreateWallet` allows.
- **Setup and migrate in one transaction.** The owner signs the destination
  vault, not who owns its wallet. `setupInstructions` must land before the
  migrate, in the same transaction — where they succeed or fail together — or
  an earlier one that is confirmed *successful* before the migrate is sent: if
  someone else's `CreateWallet` at that seed lands first, the setup fails, and
  a migrate sent anyway pays into their vault. Both SDKs' JSDoc and READMEs say
  so.

**`@lazorkit/sdk-legacy`**
- `client.findOwnPasskeyWallet({ credentialIdHash, rpId, proof, trustedKeys?, watchMints?, includeV1? })`
  → `{ adopt, needsConfirmation, unproven }`. Both empty: the passkey provably
  owns no wallet, so create one. `unproven` counts wallets listing the
  credential with another public key.
- The steps on their own: `client.findPasskeyWalletCandidates({ credentialIdHash, rpId, includeV1? })`
  (Owner-rank passkey authorities under this rpId — v2 hits, then the paired v1
  deployment's), `verifyOwnershipProof(candidates, proof, rpId)`,
  `client.describeWalletCandidates(candidates, { trustedKeys?, watchMints? })` (vault
  balance, other authorities, live sessions, pending deferred executions,
  `vaultIsSystemAccount`, `tokenGrants`, `controlledAlone`, `signatureCount`)
  and `pickOwnWallet(facts)` (adopts only the one wallet with
  `signatureCount > 0`, when it is `controlledAlone`; order: signed for, v1,
  fullest vault, wallet address).
- `client.vetMigrationDestination(wallet, owner, { watchMints }?)`.
- `createOwnershipChallenge()` (32 random bytes) and
  `selectWalletByAddress(candidates, address)` (vault or wallet address).
- Types `PasskeyWalletCandidate`, `OwnershipProof`, `WalletFacts` (keys as
  `PublicKey`, `lamports: number`, `signatureCount: number`),
  `AuthorityRoleName`; constants `V1_DISC_SESSION`, `V1_DISC_DEFERRED_EXEC`.
- New dependency `@noble/curves` ^1.9.7 for P-256 verification. It stays on
  1.x: 2.x `verify` prehashes by default.
- The README ("Finding a returning user's wallet"), the repo-root README, the
  `findWalletsByAuthority` JSDoc, `docs/use-cases/eoa-with-passkey-spender.md`
  and the migration guides (`docs/migration-ui-flow.md`,
  `docs/migration-v1-to-v2.md`) no longer present a lookup by credential hash
  as the way to find a user's wallet, or "a wallet this key holds alone" as
  the migration's reuse rule. `findWalletsByAuthority` itself is unchanged — a
  raw lookup.

**`@lazorkit/sdk`** (kit)
- The same API and rules in `src/ownership.ts` (pure functions) and on the kit
  `LazorKit` client (`findPasskeyWalletCandidates`, `describeWalletCandidates`,
  `findOwnPasskeyWallet`, `vetMigrationDestination(wallet, owner, { watchMints }?)`),
  in kit types: `Address` strings in place of `PublicKey`, `lamports: bigint`,
  and plain `Uint8Array` bytes. `WalletFacts` has the same fields in the same
  order as sdk-legacy's, `signatureCount: number` included.
- Constants `V1_DISC_SESSION`, `V1_DISC_DEFERRED_EXEC`; new dependency
  `@noble/curves` ^1.9.7.
- `findWalletsByAuthority` gains JSDoc saying it is a raw lookup and pointing
  to `findOwnPasskeyWallet` (the kit had no `[0]` example to fix).
- The README gains "Finding a returning user's wallet", and "Migrating a v1
  wallet" now migrates the proven wallet from that flow (`version: 1`, its
  stored `publicKey` and `rpId`) instead of the first hit of
  `findV1WalletsByOwner(credentialIdHash)`. Its Ed25519 branch sends
  `migrate.instructions` (any fee harvests, then MigrateWallet), not the bare
  `migrate.instruction`, which left a transfer-fee token's source account
  unclosable.
- Brought in line with sdk-legacy: `describeWalletCandidates([], …)` throws on
  a malformed `trustedKeys` or `watchMints` entry instead of returning `[]`
  unchecked; `migrateV1Wallet` no longer reads a reused destination's wallet
  account again after its vet (the pinned vet already found it, and no v2
  instruction closes a wallet), so a lagging node cannot fail the migration
  with "is no longer on chain".

### Added — `CloseExpiredSession` (instruction 18)

A session ends two ways now. Before expiry, as before: `RevokeSession`, signed
by the wallet's own Owner or Admin. After expiry, by anyone — the account
authorises nothing at that point (`execute` refuses a session past
`expires_at`), and the only key that could free its rent belongs to a user with
no reason to come back. The caller names the refund destination and keeps the
rent, which turns cleanup from a chore nobody does into something that pays for
itself.

It accepts a **v1** session as well as a v2 one. The two headers are identical
apart from the discriminator, and this is the only way the sessions stranded by
the upgrade are ever recovered — 0.29 SOL of them on mainnet today.

The boundary matters: the close uses the same comparison `execute` does, so a
session is closable only when the slot is strictly past `expires_at`. Its final
slot still belongs to it. A live session is refused with **3036**
(`SessionNotExpired`).

Both SDKs export `createCloseExpiredSessionIx`; there is no high-level client
method, because the instruction needs no wallet, no authority and no fee
accounts.

## SDK — `@lazorkit/sdk` 1.0.0-rc.2, migration in the kit SDK

The kit SDK had no way to move a user off v1, so an app built on it had nothing
to offer its users on upgrade day. It now carries the same migration surface as
`sdk-legacy`, and `tests/instructions.test.ts` asserts the `MigrateWallet`
instruction it builds is byte-identical to the legacy one.

- **`findV1WalletsByOwner`** (module function and client method) finds a user's
  v1 wallets from their key material alone — no `userSeed`, which most users no
  longer have. Each record carries `ownerPubkey`, read off the authority
  account, because a WebAuthn assertion carries no public key.
- **`migrateV1Wallet`** takes `v1Wallet` or `userSeed` and returns the setup
  instructions, the migrate instruction (or a challenge plus `finalize` for a
  passkey), and `destinationUserSeed` when it had to mint one.
- **New modules**: `src/v1.ts` (v1 seeds, discriminators, PDA derivation,
  `readV1WalletState`, `enumerateV1VaultTokens`) and `src/spl.ts` (ATA
  derivation, idempotent ATA creation, token-account decoding).
- `LazorKitRpc` now also requires `GetMultipleAccountsApi` and
  `GetTokenAccountsByOwnerApi`. `createSolanaRpc(url)` already satisfies both.

## SDK 1.1.1 — `@lazorkit/sdk-legacy`, the owner key comes back from the scan

`migrateV1Wallet` needs the owner's 33-byte compressed key, and a returning
user's browser cannot produce it: signing in with an existing passkey returns an
assertion, and an assertion carries no public key — only registration does. Live
testing hit exactly this, as `compressedPubkey must be exactly 33 bytes, got 0`.

`findV1WalletsByOwner` now returns `ownerPubkey` from the authority account it
has already fetched (33 compressed bytes for a passkey, 32 for Ed25519).

## SDK 1.1.0 — `@lazorkit/sdk-legacy`, migrate without the user seed

Wallets created through `@lazorkit/wallet` used a random 32-byte `userSeed`
that lived in the browser's storage. `migrateV1Wallet` required it, so a user
who cleared storage or moved to another device had no way to migrate — their
funds would have been stranded in the v1 vault after the upgrade.

The program never needed the seed: `MigrateWallet` takes the v1 wallet as an
account and derives the vault from that key. Only the SDK helper insisted.

- **`findV1WalletsByOwner(connection, ownerIdSeed, programId, authorityType)`**
  and the client method of the same name find a user's v1 wallets from their
  passkey alone, by scanning v1 authority accounts (needs an RPC that allows
  `getProgramAccounts` with memcmp filters).
- **`migrateV1Wallet` now takes `v1Wallet`** as an alternative to `userSeed`,
  and returns `destinationWallet` plus, when it had to mint one,
  `destinationUserSeed`. Passing neither throws and says which to use.
- With no `userSeed`, the destination is whatever v2 wallet the owner already
  has; a fresh one is created only when there is none.

## SDK 1.0.0 — protocol v2 (`@lazorkit/sdk-legacy` 1.0.0, `@lazorkit/sdk` 1.0.0-rc.1)

The SDKs move to a new major because they speak protocol v2, which is not wire
compatible with the program running on mainnet today. **`latest` on npm stays
on `0.3.2` until the mainnet upgrade lands**; 1.x publishes under the `next`
dist-tag.

```bash
npm install @lazorkit/sdk-legacy          # 0.3.x — protocol v1, mainnet today
npm install @lazorkit/sdk-legacy@next     # 1.x   — protocol v2
npm install @lazorkit/sdk@next            # kit SDK, release candidate
```

### Breaking — what an app has to change

- **Every address moves.** PDA seeds are namespaced `lk2:`, so the same
  `userSeed` derives a different wallet and vault. No error is raised: a cached
  address, a deposit address shown to a user, or a wallet row in your own
  database all keep pointing at the v1 account, which no v2 code path reads.
  Move funds with `migrateV1Wallet` rather than re-creating.
- **`createSession` with no actions now throws** unless you pass
  `unrestricted: true`. An empty action buffer is an unbounded session key, so
  it has to be named.
- **`addAuthority` with `role: ROLE_SPENDER` requires a non-empty `policy`**,
  and a policy is refused on any other rank (3033, 3035 on-chain). Creating an
  Owner requires `allowOwner: true`.
- **All-zero key material is rejected** at the client before anything is
  signed.
- **`AddAuthority` and `RemoveAuthority` need the wallet account writable.**
  Only matters if you build those instructions by hand.
- **The signed bytes changed**: the accounts hash binds each account's
  signer/writable flags, account index bytes use bit 7 as a forward-signer
  request (so indices cap at 127), and the `AddAuthority` payload always
  carries `[policy_len u16][policy]`.
- **`buildCompactLayout` takes the payer as a third argument.**
- **Serialized `DeferredPayload`s carry a version and are refused across the
  boundary.** Drain anything in flight before upgrading both sides.
- **The protocol fee suffix is mandatory** on `CreateWallet`, `Execute` and
  `ExecuteDeferred` — the program answers 4008 without it even when it charges
  nothing. The high-level client handles this; direct callers of the low-level
  builders must pass the fee accounts.
- **The low-level `create*Ix` builders are no longer exported from the package
  root.** Use the client, or import them from the module path.

An app that only uses `LazorKitClient` and holds no cached addresses is
typically a handful of call-site changes: the session and authority guards
above, plus the migration of existing wallets.

## SDK 0.3.2 — `@lazorkit/sdk-legacy`, protocol v1

- Dropped the Node `crypto` dependency (`@noble/hashes` and the `buffer`
  package instead), so the SDK bundles for browsers and React Native with no
  polyfill configuration. No behaviour change: outputs are byte-identical to
  0.3.1 and the type declarations are unchanged. Cut from the v1 line, so
  0.3.x keeps talking to the program that is live on mainnet.

## SDK 0.3.1 — `@lazorkit/sdk-legacy`, protocol v1

- Republished 0.3.0 under a new number after that version was tombstoned on
  npm. This is the line mainnet integrators run today.

## Protocol v2 (program 2.0.0)

An audit of `program/src` produced 26 findings, five proven by reproduction
tests. The audit that already existed (Accretion / Solana Foundation, A26SFR1,
Feb 2026) covered `program-v2`, **not this repo** — this is a fork that added an
entire fee layer nobody had reviewed, and the heaviest findings all lived in that
delta.

Underneath the individual bugs was a structural problem: `role` answered two
independent questions — what may you *manage* and what may you *spend* — while
gating only the first. That is why "Spender" named a tier with full control of
the vault.

v2 ships every fix and the new permission model as one in-place upgrade at the
existing program ID. v1 wallets cross over with one Owner-signed `MigrateWallet`.

### Critical and high

- **C-1 — an admin could freeze every user's funds.** The entrypoint reverted
  every `CreateWallet`/`Execute`/`ExecuteDeferred` when the protocol config was
  disabled or its fee was zero, and those are the only paths that move funds out
  of a vault. One admin write, permanent, unrecoverable. Fee collection is now
  *skipped* rather than reverting, the config PDA address is pinned so "not
  configured" cannot be spoofed, and both fees are capped at 0.01 SOL so an
  unpayable fee cannot be a freeze in disguise.
- **H-1 — authentication could be driven from another program.** Both the
  Secp256r1 authenticator and `Execute` now refuse to run below the top level.
- **H-2 — rank governed management and nothing else.** `Execute` never read
  `role`, so a "Spender" spent exactly like an Owner. Rank and policy are now
  separate fields answering separate questions; a Delegate must carry a policy,
  and an authority that carries one may not create authorities at all.
- **H-3 — `Execute` conscripted the paymaster.** Every outer signer was forwarded
  into every inner CPI, so a session limited to 0.001 SOL could move 2 SOL out of
  the fee payer's own wallet. Forwarding is now opt-in per account, never covers
  the fee payer, and on the session path covers only the session's own key.
- **H-4 — token authority escapes** are caught by the pre/post snapshot, which
  now runs for policy-bearing authorities as well as sessions.

### Medium

- **M-2** — the program refuses to run at any address other than the one
  compiled into it.
- **M-3** — the ProtocolConfig PDA address is verified at every read site, not
  just its owner.
- **M-4** — the accounts hash binds each referenced account's
  `is_signer`/`is_writable`, not only its key. A relayer could previously take an
  account approved as read-only and submit it writable.
- **M-5** — an all-zero Secp256r1 pubkey is rejected in `TransferOwnership`.
- **M-6** — `payer.is_signer()` is explicit in the six processors that relied on
  the System Program enforcing it during a CPI that is skipped for a pre-funded
  PDA.
- **M-1, M-7** — documented rather than changed, with the reasoning: an Ed25519
  authority's transaction signature already binds strictly more than a payload
  signature would, and a program whitelist constrains one level of CPI while the
  value limits constrain the whole call graph.

### Added

- **Several Owners per wallet.** Each device holds its own passkey and passkeys
  cannot be copied, so multi-device means multi-authority — and only if they are
  all Owners can a surviving device revoke a lost one. `WalletAccount.owner_count`
  refuses the removal of the last Owner.
- **Per-authority spending policies.** The action buffer that bounded sessions
  now bounds authorities too, on the same engine.
- **Two-step protocol admin rotation** (propose / accept). `UpdateProtocol` could
  not write `admin` at all, and a one-step write would make a typo permanent.
- **Version discipline.** PDA seeds namespaced by protocol major version, account
  discriminators carrying it in their high nibble, and a validated `version` byte
  that is finally read rather than only written. See
  [`docs/upgrade-procedure.md`](docs/upgrade-procedure.md).
- **Golden vectors** for the accounts-hash wire format
  ([`test-vectors/accounts-hash.json`](test-vectors/accounts-hash.json)),
  asserted against by the program and both SDKs.
- **`MigrateWallet`** (discriminator 17). One Owner-signed transaction moves a
  v1 wallet's vault SOL and every token account it names into a v2 wallet, then
  closes the v1 wallet and authority. The signed payload binds the destination
  and the exact token-account set, so a relayer cannot redirect or drop assets.
  No operator path exists: a wallet whose owner never signs stays in v1.

### SDK

- **Both SDKs run in the browser** with no Node polyfills. Hashing and
  randomness come from `@noble/hashes`; the legacy SDK imports `Buffer` from the
  `buffer` package and the kit SDK uses `@solana/kit` codecs.
- **The fee suffix is always sent** on `CreateWallet`, `Execute` and
  `ExecuteDeferred`. The program requires it (4008) even when no fee is charged,
  and the SDK used to omit it whenever the protocol config was missing or
  disabled — which broke every client between an upgrade and
  `InitializeProtocol`. `{ protocolFees: false }` omits it, for a build without
  the fee layer.
- **`migrateV1Wallet`** and the v1 readers (`deriveV1Accounts`,
  `readV1WalletState`, `enumerateV1VaultTokens`) in `@lazorkit/sdk-legacy`; see
  [`docs/migration-ui-flow.md`](docs/migration-ui-flow.md).

### Breaking — protocol v2

- **Every PDA address changes.** Seeds are namespaced `lk2:`. v1 wallets, vaults,
  authorities, sessions and the protocol singletons are unreachable from v2 code.
  This is deliberate: the singleton seeds would otherwise collide with accounts
  that already exist, and `initialize_protocol` requires a zero-length account, so
  the protocol would have been permanently un-initialisable.
- **Account discriminators renumbered** to `0x21`–`0x27`. A v1 account fails
  immediately rather than being reinterpreted under a moved layout.
- **Account index bytes cap at 127.** Bit 7 is now the forward-signer flag. An
  index of 128 or above is rejected, not masked.
- **v1 signatures no longer verify.** The accounts hash covers privilege.
- **`AddAuthority` payload gained `[policy_len u16][policy]`** between the key
  material and the auth payload, inside the signed region.
- **`AddAuthority` and `RemoveAuthority` need the wallet account writable.** The
  instruction data is unchanged, so this fails at runtime rather than at compile
  time — and only on the paths that touch an Owner.
- **Serialized `DeferredPayload`s do not cross the version boundary.** They carry
  a version and are rejected on mismatch; re-authorize instead of replaying.

### Migration

v1 wallets still hold user funds, so the upgrade ships with a way across. After
it lands a v1 wallet can do one thing — `MigrateWallet`, signed by its Owner —
and its funds are safe in the v1 vault until then. Nobody else can move them.

**Before upgrading mainnet** work through
[`docs/mainnet-deploy-checklist.md`](docs/mainnet-deploy-checklist.md). In short:

1. Run `scripts/survey-v1.ts` and keep its report private (it lists real user
   wallets and balances — operational intel, not repo content).
2. Have the migration UI live — built on `migrateV1Wallet`, see
   [`docs/migration-ui-flow.md`](docs/migration-ui-flow.md) — and announce the
   window: a v1 wallet needs one signed migration before it transacts again.
3. Confirm `PROTOCOL_INIT_AUTHORITY` for the mainnet build. It defaults to the
   existing deployer key and gates `InitializeProtocol` permanently.
4. Rehearse with the live v1 binary (`solana program dump`), not a rebuild, and
   record both SBF SHA-256 hashes.

For clients:

```diff
- const [walletPda] = findWalletPda(userSeed, PROGRAM_ID_DEVNET);
+ // Same call — the seed prefix is internal to the SDK. The address it
+ // returns is different, and any v1 address you cached is stale.
+ const [walletPda] = findWalletPda(userSeed, PROGRAM_ID_DEVNET);
```

```diff
  await client.addAuthority({
    payer, walletPda, adminSigner,
    newAuthority: { type: 'ed25519', publicKey: delegate.publicKey },
    role: ROLE_SPENDER,
+   // A Delegate must carry a policy — this is what makes the name true.
+   policy: serializeActions([Actions.solLimit(1_000_000_000n)]),
  });
```

```diff
+ // Creating an Owner is now possible, and deliberately explicit.
+ await client.addAuthority({
+   payer, walletPda, adminSigner,
+   newAuthority: { type: 'secp256r1', credentialIdHash, compressedPubkey, rpId },
+   role: ROLE_OWNER,
+   allowOwner: true,
+ });
```

If you build instructions with the low-level builders rather than the client,
make the wallet account writable on `AddAuthority` and `RemoveAuthority`.


### Added — foundation devnet support (SDK 0.3.0)

The single source of truth for both LazorKit on-chain builds. `@lazorkit/sdk-legacy`
ships from this repo and is also consumed by the sibling `program-v2` repo
(the foundation, no-fee build that occupies the same mainnet program ID slot
during the foundation contract). These changes let one SDK serve both binaries
at the same mainnet ID and keep dApp DX uniform across the binary swap.

- **`PROGRAM_ID_FOUNDATION_DEVNET`** constant (`FLb7fyAtkfA4TSa2uYcAT8QKHd2pkoMHgmqfnXFXo7ao`)
  exported from `constants.ts`. Lets devs target the foundation devnet binary
  for testing without overriding `programId` manually. The mainnet ID
  (`LazorjRF…`) and existing commercial devnet ID (`4h3X…`) are unchanged;
  the new constant is additive.
- **Error decoding** in `utils/errors.ts` now covers the additional codes
  emitted by the two builds:
  - `3030 SessionVaultOwnerChanged`, `3031 SessionVaultDataLenChanged`,
    `3032 SessionTokenAuthorityChanged` — vault / token-authority invariant
    defenses against `System::Assign` / `SetAuthority` / `Approve` escapes.
  - `4001 ProtocolAlreadyInitialized` through `4007 InvalidTreasury` —
    protocol-fee management errors emitted by the commercial flow.
  No runtime API changes; existing callers continue to work unmodified.

### Added — dual-cluster program ID support (SDK 0.2.0)

- **Program — Pattern D feature flags.** The on-chain SBF binary now
  requires exactly one cluster feature at build time:
  - `cargo build-sbf --features mainnet` → binary embeds the mainnet vanity ID
    `LazorjRFNavitUaBu5m3WaNPjU1maipvSW2rZfAFAKi`
  - `cargo build-sbf --features devnet` → binary embeds the devnet ID
    `4h3XoNReAgEcHVxcZ8sw2aufi9MTr7BbvYYjzjWDyDxS`
  - Building with neither, or both, produces a clear `compile_error!`. Prevents
    accidental cross-cluster deploys (a binary built for one ID malfunctions if
    deployed to the other slot — internal `crate::ID` checks fail). Implemented
    via `#[cfg(...)]` on the `declare_id!` call in `assertions/src/lib.rs`.

- **SDK — `LazorKitClient` auto-infers program ID from RPC.** The constructor
  now accepts an optional `programId` argument and infers the right one from
  the connection's RPC endpoint when omitted:
  - `mainnet` in URL → `PROGRAM_ID_MAINNET`
  - `devnet` in URL → `PROGRAM_ID_DEVNET`
  - `localhost` / `127.0.0.1` → `PROGRAM_ID_DEVNET` (local-validator convention)
  - anything else → throws with a clear error pointing at the explicit-override path
- **SDK — both cluster constants exported.** `PROGRAM_ADDRESS_MAINNET`,
  `PROGRAM_ADDRESS_DEVNET`, `PROGRAM_ID_MAINNET`, `PROGRAM_ID_DEVNET`.

### Breaking — SDK 0.2.0

- **`PROGRAM_ADDRESS` / `PROGRAM_ID` removed from public exports.** They were
  cluster-ambiguous and would defeat Pattern D's "pick a cluster" intent.
  Use `PROGRAM_ADDRESS_MAINNET` / `_DEVNET` and `PROGRAM_ID_MAINNET` / `_DEVNET`
  instead. Partners on `^0.1.0` are unaffected — npm semver does not auto-pull
  `0.2.0`.
- **Low-level builders now require `programId` explicitly.** All instruction
  builders (`createCreateWalletIx`, `createExecuteIx`, etc.), all PDA helpers
  (`findWalletPda`, `findVaultPda`, etc.) and `buildSecp256r1Challenge` now
  take `programId` as a required argument. This was previously a defaulted
  parameter pointing at the devnet ID — defaults are unsafe in a multi-cluster
  world. The high-level `LazorKitClient` continues to handle this implicitly
  via `this.programId`; only direct callers of the low-level helpers need to
  pass it.

### Migration from SDK 0.1.x

Most apps need no changes:

```diff
- import { Connection } from '@solana/web3.js';
- import { LazorKitClient } from '@lazorkit/sdk-legacy';
- const client = new LazorKitClient(new Connection('https://api.devnet.solana.com'));
+ // Same call — cluster is now auto-inferred from the RPC endpoint
+ const client = new LazorKitClient(new Connection('https://api.devnet.solana.com'));
```

If you were importing `PROGRAM_ID` directly:

```diff
- import { PROGRAM_ID } from '@lazorkit/sdk-legacy';
+ import { PROGRAM_ID_DEVNET } from '@lazorkit/sdk-legacy';   // or PROGRAM_ID_MAINNET
```

If you were calling low-level builders or PDA helpers, add the explicit
`programId` argument:

```diff
- const [walletPda] = findWalletPda(userSeed);
+ const [walletPda] = findWalletPda(userSeed, PROGRAM_ID_DEVNET);

- createCreateWalletIx({ payer, walletPda, vaultPda, authorityPda, ... });
+ createCreateWalletIx({ payer, walletPda, vaultPda, authorityPda, ..., programId: PROGRAM_ID_DEVNET });
```

Partners not ready to migrate can stay on `^0.1.0` — devnet behaviour is
preserved unchanged.

### Operational

- `program/Cargo.toml` now propagates `mainnet` / `devnet` features through
  to `assertions`. The validator-start helper in `tests-sdk/package.json`
  runs `cargo build-sbf --features devnet` automatically before launching.

---

## [0.1.0] — pre-mainnet hardening

This section captures everything on `refactor/sdk-cleanup` that is not yet
in `main` but is staged for the upcoming pre-mainnet release on
`fix/audit-hardening`.

### Added

- **Program — permissionless `RegisterPayer`** (`b722874`). The admin gate
  on the `RegisterPayer` instruction has been dropped. Any payer can now
  register their own `FeeRecord` (the PDA is derived from the payer signer,
  not from instruction data, so attackers cannot register a record at
  someone else's address). Payer pays their own ~0.00112 SOL rent;
  economically self-limiting against spam. Fee collection still works for
  unregistered payers — registration only enables stats tracking.

- **SDK — auto-prepended self-registration**
  ([`client.ts:resolveProtocolFeeWithRegister`](sdk/sdk-legacy/src/utils/client.ts)).
  All four fee-eligible builders (`createWallet`, `prepareExecute`/`finalizeExecute`,
  `execute`, `executeDeferredFromPayload`) now transparently prepend a
  `RegisterPayer` instruction the first time a given payer hits a
  fee-paying transaction. Subsequent calls short-circuit through an
  in-memory cache — one extra `getAccountInfo` per cold payer per process,
  zero overhead after that. Apps no longer need to call `registerPayer`
  manually.

- **SDK — transaction-builder helpers**
  ([`sdk/sdk-legacy/src/utils/transactions.ts`](sdk/sdk-legacy/src/utils/transactions.ts), `6c4b190`).
  Three small standalone utilities so partners stop hand-rolling
  `new Transaction().add(...)` boilerplate and to make v0 + Address Lookup
  Table support trivial:
  - `buildLegacyTx({ payer, instructions, blockhash, signers })` →
    signed legacy `Transaction`
  - `buildV0Tx({ payer, instructions, blockhash, signers, lookupTables? })` →
    signed `VersionedTransaction`
  - `createAndExtendLut({ connection, authority, addresses })` → bootstrap
    a shared Address Lookup Table; handles the slot-finalization quirk,
    chunks extends in groups of 30, waits one slot before returning.
  Empty Address Lookup Tables containing system program, sysvars, the
  `protocol_config` PDA and all treasury-shard PDAs save **~88 B per
  Secp256r1 Execute** (verified in `tests-sdk/tests/benchmark-fees.ts`).

- **Docs — `docs/use-cases/` folder** (`78d83bc`). New home for end-to-end
  integration patterns. First guide
  ([`eoa-with-passkey-spender.md`](docs/use-cases/eoa-with-passkey-spender.md))
  covers the partner-team flow of attaching a passkey as Spender on a
  wallet whose Owner is an existing Ed25519 EOA. Includes role-permission
  table with file:line citations into the program code, mermaid
  end-state diagram, and a sequence diagram for enrollment + daily use +
  recovery.

- **Docs — six mermaid diagrams in Architecture.md** (`0cda41f`):
  PDA relationship map, ER diagram of the account model, RBAC permission
  flowchart with auth-type constraints on edges, Secp256r1 Execute sequence
  (challenge → precompile → counter commit), Spender-calls-Execute
  sequence demonstrating per-instruction role checks, and Deferred
  Execution flow showing the TX1 hash commitment / TX2 reveal-and-execute
  / Reclaim path.

- **Docs — SDK README updated** (`0a9203a`). New "Protocol fees &
  auto-registration" subsection explaining the on-chain fee accounts
  convention, the permissionless `registerPayer({ payer })` API, and the
  `resolveProtocolFee` / `resolveProtocolFeeWithRegister` escape hatches.
  New "Transactions (legacy + v0)" section documenting the three new
  helpers above.

- **Tests — fee-aware benchmark**
  ([`tests-sdk/tests/benchmark-fees.ts`](tests-sdk/tests/benchmark-fees.ts), `aa5050b`).
  Measures CU, legacy tx size, v0+LUT tx size, and lamport cost
  (sig fee + protocol fee + rent delta) for every non-admin LazorKit
  instruction with the protocol fee enabled at 5000/5000. Each fee-eligible
  instruction is benchmarked twice — `cold` (first fee-paying tx for the
  payer; SDK auto-prepends `RegisterPayer`) and `warm` (FeeRecord already
  exists; no auto-prepend). Uses the SDK's `buildLegacyTx` / `buildV0Tx` /
  `createAndExtendLut` helpers so the v0 column reflects the path partners
  will use.

- **Audit — pre-mainnet findings** (`32e58bb`,
  [`docs/audit-2026-04-28/findings.md`](docs/audit-2026-04-28/findings.md)).
  Re-audit of the post-2026-04-21 delta plus full re-walk of high-risk
  paths and threat-model walkthroughs. Verdict: GO with caveats — no
  code-level blockers; ship conditional on the operational checklist
  (Phase E) being completed.

### Changed

- **SDK — `client.registerPayer` signature simplified** (breaking for
  callers that called it directly; `b722874`). Was
  `registerPayer({ payer, admin, targetPayer })`, now
  `registerPayer({ payer })`. The on-chain instruction no longer takes any
  arguments, so the SDK signature reflects that. Most apps never need to
  call this directly — see auto-prepend above.

- **Tests — `12-protocol-fees.test.ts` updated for permissionless
  registration** (`b722874`). The two tests that previously required an
  admin signature now register a payer with no extra signers. The
  duplicate-registration test still expects custom error 4006
  (`IntegratorAlreadyRegistered`).

- **Tests — `devnet-setup-protocol.ts` updated** (`b722874`).
  `EXECUTION_FEE` lifted from `2000n` → `5000n` to match `CREATION_FEE`
  for a uniform 5000-lamport protocol fee. Removed the manual
  `client.registerPayer` step from the setup flow — SDK auto-prepends
  on the first fee-paying tx now.

### Known issues

- **F-1 (Low):** `tests-sdk/tests/12-protocol-fees.test.ts:230` ("charges
  fee for unregistered payer but skips FeeRecord counter update") is now
  stale. It uses the high-level `client.createWallet`, which auto-prepends
  `RegisterPayer`, so the FeeRecord *does* get created instead of staying
  null. The on-chain code path it tested is still correct ([entrypoint.rs:138-147](program/src/entrypoint.rs#L138)) — it is just no longer
  exercised by this specific test. Fix: migrate the test to use the
  lower-level `createCreateWalletIx` builder. **Non-blocking for mainnet.**

- **R-1 (Medium):** The `admin` field in `ProtocolConfig` is **not
  rotatable** via `UpdateProtocol` — only `creation_fee`, `execution_fee`,
  `enabled`, and `treasury` can be changed. Loss of the admin key means
  the protocol cannot be re-administered. **Mitigation:** initialize
  `ProtocolConfig` with `admin = <Squads multisig PDA>` from day 1, so
  signer compromise is handled by Squads governance and the on-chain
  rotation gap becomes a 1% black-swan concern. A code-level fix
  (cosign-style rotation) is recommended within 6 months as cheap
  insurance.

### Operational

These do not change the program or the public SDK, but they affect every
mainnet operator:

- **Fees default uniform 5000/5000 lamports** in the devnet setup script.
  The on-chain default values are still set at `InitializeProtocol` time;
  this only changes the recommended starting values.
- **Audit doc** at [`docs/audit-2026-04-28/findings.md`](docs/audit-2026-04-28/findings.md)
  contains the full Phase E operational checklist (key custody, deploy
  sequence, monitoring, rollback procedures). The companion private
  repo `onspeedhp/lazorkit-admin` ships scripts and runbooks for each
  Phase E item.

---

## Earlier history

For pre-`refactor/sdk-cleanup` history see commit log on `main` and the
prior security review at
[`docs/security-review-2026-04-21.md`](docs/security-review-2026-04-21.md).
