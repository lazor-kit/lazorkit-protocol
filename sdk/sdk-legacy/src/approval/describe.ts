// What a typed request approves, as structured data: amounts in base units,
// windows in seconds, times in Unix seconds, addresses in base58, and a
// screen class. No English: the portal (or an embedded sheet) words it.
//
// `approvalReadPlan` lists what to read; `describeApproval` checks the request
// against those reads (refusing what would fail on chain with
// `request-invalid`) and describes it. Every number comes from the request's
// bytes or from a read, never from the app.

import { base58Encode, base64urlDecode, bytesEqual, decodeAddress } from './bytes';
import {
  APPROVAL_MAX_SESSION_SECONDS,
  CLOCK_SYSVAR_ADDRESS,
  MAX_TRANSACTION_BYTES,
  type ApprovalCluster,
  type ApprovalFeature,
  type ApprovalKind,
} from './constants';
import { decodeActions, mintsNamedBy, readStoredActions, type DecodedAction, type StoredAction } from './actions';
import {
  decodeAuthorityAccount,
  decodeClock,
  decodeMintAccount,
  decodeSessionAccount,
  decodeWalletAccount,
  type AccountSnapshot,
  type AuthorityFacts,
  type AuthorityRole,
  type ClockFacts,
} from './accounts';
import { requestCredentialId, type ApprovalRequest, type CreateSessionRequest } from './envelope';
import { credentialIdHash, findSessionAddress, findVaultAddress } from './pda';
import { createSessionTransactionBytes } from './size';

// ─── What to read ────────────────────────────────────────────────────

export interface ApprovalReadPlan {
  clock: string;
  wallet: string;
  /** The signing authority. */
  authority: string;
  /** For "could spend all X" lines: the vault's balance and token accounts. */
  vault: string;
  /** createSession: the would-be session PDA (must be empty). revokeSession: the session. */
  session?: string;
  /** removeAuthority: the authority to remove. */
  target?: string;
  /** Mints the actions or policy name; for revoke/remove known only once `session`/`target` is read. */
  mints: string[];
}

/**
 * The accounts to read for `req`, in one `getMultipleAccounts` call. For
 * revokeSession and removeAuthority the mints are named by the session's
 * actions or the target's policy: pass those snapshots once read to get them.
 */
export function approvalReadPlan(
  req: ApprovalRequest,
  read: { session?: AccountSnapshot | null; target?: AccountSnapshot | null } = {},
): ApprovalReadPlan {
  const base = {
    clock: CLOCK_SYSVAR_ADDRESS,
    wallet: req.wallet,
    authority: req.authority,
    vault: findVaultAddress(req.wallet, req.programId),
  };
  switch (req.kind) {
    case 'createSession': {
      let mints: string[] = [];
      try {
        mints = mintsNamedBy(decodeActions(base64urlDecode(req.args.actions) ?? new Uint8Array()));
      } catch {
        mints = [];
      }
      return { ...base, session: findSessionAddress(req.wallet, req.args.sessionKey, req.programId), mints };
    }
    case 'revokeSession': {
      const s = decodeSessionAccount(read.session, req.programId);
      return { ...base, session: req.args.session, mints: s ? safeMints(s.actions) : [] };
    }
    case 'removeAuthority': {
      const t = decodeAuthorityAccount(read.target, req.programId);
      return { ...base, target: req.args.target, mints: t ? safeMints(t.policy) : [] };
    }
  }
}

function safeMints(buf: Uint8Array): string[] {
  try {
    return mintsNamedBy(readStoredActions(buf));
  } catch {
    return [];
  }
}

// ─── Inputs ──────────────────────────────────────────────────────────

/** The reads, keyed by role. `null` = read, no such account; absent = not read. */
export interface ApprovalChainView {
  clock: AccountSnapshot | null;
  wallet: AccountSnapshot | null;
  authority: AccountSnapshot | null;
  session?: AccountSnapshot | null;
  target?: AccountSnapshot | null;
  mints?: Record<string, AccountSnapshot | null>;
  /** The vault's lamports and its token balances by mint, when read. */
  vault?: { lamports: bigint; tokens?: Record<string, bigint> };
}

export interface DescribeApprovalOptions {
  /**
   * Features of the deployed binary, confirmed against the chain; `null`
   * when they could not be confirmed. Binary-dependent conclusions are drawn
   * only from these.
   */
  features: readonly (ApprovalFeature | string)[] | null;
  /** Mints the caller lists by name, with their decimals; a read that disagrees is refused. */
  knownMints?: Record<string, { decimals: number }>;
}

// ─── Outputs ─────────────────────────────────────────────────────────

export type ApprovalInvalidReason =
  | 'clock-unreadable'
  | 'wallet-missing'
  | 'authority-missing'
  | 'authority-not-passkey'
  | 'authority-wrong-wallet'
  | 'authority-wrong-credential'
  | 'authority-role'
  | 'authority-has-policy'
  | 'expiry-not-after-now'
  | 'expiry-too-far'
  | 'actions-invalid'
  | 'actions-whitelist-blacklist'
  | 'transaction-too-large'
  | 'session-exists'
  | 'session-missing'
  | 'session-wrong-wallet'
  | 'target-missing'
  | 'target-wrong-wallet'
  | 'target-is-signer'
  | 'target-not-removable'
  | 'last-owner'
  | 'payer-is-program-account'
  | 'refund-is-program-account'
  | 'mint-decimals-mismatch';

export type ApprovalCheck =
  | { ok: true; description: ApprovalDescription }
  | { ok: false; code: 'request-invalid'; reason: ApprovalInvalidReason }
  | { ok: false; code: 'wrong-network'; reason: 'features-unknown' | 'feature-missing' };

export type AssetRef = { kind: 'sol' } | { kind: 'token'; mint: string };

export interface TokenFacts {
  mint: string;
  /** From the caller's list (checked against the read) or the read; null when unreadable. */
  decimals: number | null;
  tokenProgram: 'token' | 'token-2022' | null;
  /** Whether the caller's `knownMints` lists it. */
  listed: boolean;
  /** False when the mint was read and is not an initialized token mint, or was not read. */
  readable: boolean;
}

export interface LimitRule {
  /** Lamports or token base units. For a lifetime limit on chain, what is left. */
  amount: bigint;
  /** The action's own expiry, in the policy's `timeUnit` (Unix seconds on a time-expiry binary); 0 = none. */
  expiresAt: bigint;
  /** Expired at the clock read: the program treats it as exhausted. False when the time unit is unknown. */
  expired: boolean;
  /** Ends before the session does (createSession only). */
  endsBeforeSession: boolean;
}

export interface RecurringRule extends LimitRule {
  /** The window length: seconds, or slots when the policy's `timeUnit` is `slot`. */
  windowSeconds: bigint;
  /** On chain only: spent in the current window, and when it opened (0 = never). */
  spent?: bigint;
  lastReset?: bigint;
  /** On chain only: what can still be spent in the current window. */
  leftInWindow?: bigint;
}

export interface AssetGrant {
  asset: AssetRef;
  token?: TokenFacts;
  lifetime?: LimitRule;
  recurring?: RecurringRule;
  perPayment?: LimitRule;
  /** A lifetime or recurring total bounds it. */
  hasTotal: boolean;
  /** A rule of 0 or an expired rule: nothing of it can be spent. */
  cannotSpend: boolean;
  /** The vault's balance of it, when read. */
  balance?: bigint;
}

export interface ProgramRules {
  /** `any`: no list. `only`: a whitelist. `except`: a blacklist. */
  mode: 'any' | 'only' | 'except';
  entries: { programId: string; expiresAt: bigint; expired: boolean }[];
}

/**
 * How a binary reads stored session and policy times: Unix seconds with
 * `time-expiry`, slots on a binary confirmed without it, `unknown` when the
 * features could not be confirmed.
 */
export type TimeUnit = 'seconds' | 'slot' | 'unknown';

export interface PolicyDescription {
  /**
   * The unit of every time and window in this policy on this binary. With
   * `unknown`, no rule is marked expired and `leftInWindow` is not computed.
   */
  timeUnit: TimeUnit;
  assets: AssetGrant[];
  programs: ProgramRules;
  /** Assets that can leave with no total: per-payment caps only, or (without D13) not named at all. */
  uncapped: (AssetRef | { kind: 'unnamed-tokens' })[];
  /** With D13 confirmed and at least one action: assets no action names cannot leave. */
  otherAssetsBlocked: boolean;
  /** Mints the screen must flag as unreadable. */
  unreadableMints: string[];
  actions: StoredAction[];
}

interface DescriptionBase {
  kind: ApprovalKind;
  cluster: ApprovalCluster;
  programId: string;
  wallet: string;
  vault: string;
  authority: string;
  payer: string;
  signerRole: AuthorityRole;
  /** The signer's stored counter; it signs this + 1. */
  signerCounter: number;
  clock: ClockFacts;
  /** Whether the binary's features were confirmed. */
  featuresKnown: boolean;
}

export interface CreateSessionDescription extends DescriptionBase, PolicyDescription {
  kind: 'createSession';
  sessionKey: string;
  session: string;
  expiresAt: bigint;
  /** expiresAt minus the cluster clock. */
  secondsLeft: bigint;
  screen: 'session-no-limits' | 'session-no-total' | 'session-create';
  /** For `session-create`: what the hero shows. */
  variant?: 'totals' | 'tokens-only' | 'no-spend';
  /** No limits on a binary not confirmed to hold non-Owner signers to the vault invariants. */
  canGiveAccountAway: boolean;
}

export interface RevokeSessionDescription extends DescriptionBase {
  kind: 'revokeSession';
  session: string;
  sessionKey: string;
  expiresAt: bigint;
  /**
   * How `expiresAt` reads on this binary. With `time-expiry` the program reads
   * every session's expiry as Unix seconds, so a slot left by an earlier build
   * reads as long ended.
   */
  expiresAtUnit: TimeUnit;
  /** Already past its expiry (undefined when the unit is unknown). */
  ended?: boolean;
  refund: string;
  refundIsPayer: boolean;
  /** What it may still spend; null when the stored actions do not parse. */
  policy: PolicyDescription | null;
  unrestricted: boolean;
}

export interface RemoveAuthorityDescription extends DescriptionBase {
  kind: 'removeAuthority';
  target: string;
  targetType: 'passkey' | 'ed25519';
  targetRole: AuthorityRole;
  /** Ed25519: base58 key. Passkey: undefined. */
  targetPublicKey?: string;
  targetRpIdHash?: Uint8Array;
  targetPolicy: PolicyDescription | null;
  ownerCount: number;
  ownersAfter: number;
  refund: string;
  refundIsPayer: boolean;
}

export type ApprovalDescription = CreateSessionDescription | RevokeSessionDescription | RemoveAuthorityDescription;

// ─── Checks and description ─────────────────────────────────────────

function invalid(reason: ApprovalInvalidReason): ApprovalCheck {
  return { ok: false, code: 'request-invalid', reason };
}

function tokenFacts(mint: string, view: ApprovalChainView, opts: DescribeApprovalOptions): TokenFacts | 'mismatch' {
  const listed = opts.knownMints?.[mint];
  const snap = view.mints?.[mint];
  const read = snap === undefined ? undefined : decodeMintAccount(snap);
  if (listed) {
    if (read && read.decimals !== listed.decimals) return 'mismatch';
    if (snap !== undefined && !read) return 'mismatch';
    return { mint, decimals: listed.decimals, tokenProgram: read?.tokenProgram ?? null, listed: true, readable: !!read };
  }
  return { mint, decimals: read?.decimals ?? null, tokenProgram: read?.tokenProgram ?? null, listed: false, readable: !!read };
}

/** The binary's time unit and the clock reading in it (undefined when unknown). */
interface PolicyTime {
  unit: TimeUnit;
  now: bigint | undefined;
}

/**
 * The time the program compares stored expiries and windows with: the clock's
 * Unix timestamp on a `time-expiry` binary (program: `unix_now`), its slot on
 * a binary confirmed without it, nothing when the features are unknown.
 */
function policyTime(features: DescribeApprovalOptions['features'], clock: ClockFacts): PolicyTime {
  if (features === null) return { unit: 'unknown', now: undefined };
  if (features.includes('time-expiry')) return { unit: 'seconds', now: clock.unixTimestamp };
  return { unit: 'slot', now: clock.slot };
}

function isExpired(expiresAt: bigint, now: bigint | undefined): boolean {
  return now !== undefined && expiresAt !== 0n && now > expiresAt;
}

function rule(amount: bigint, expiresAt: bigint, now: bigint | undefined, sessionEnd: bigint | undefined): LimitRule {
  return {
    amount,
    expiresAt,
    expired: isExpired(expiresAt, now),
    endsBeforeSession: sessionEnd !== undefined && expiresAt !== 0n && expiresAt < sessionEnd,
  };
}

function describePolicy(
  actions: StoredAction[],
  time: PolicyTime,
  sessionEnd: bigint | undefined,
  view: ApprovalChainView,
  opts: DescribeApprovalOptions,
): PolicyDescription | 'mismatch' {
  const now = time.now;
  const d13 = !!opts.features?.includes('d13');
  const grants = new Map<string, AssetGrant>();
  const grantFor = (ref: AssetRef): AssetGrant => {
    const key = ref.kind === 'sol' ? 'sol' : ref.mint;
    let g = grants.get(key);
    if (!g) {
      g = { asset: ref, hasTotal: false, cannotSpend: false };
      grants.set(key, g);
    }
    return g;
  };
  const programs: ProgramRules = { mode: 'any', entries: [] };

  for (const a of actions) {
    switch (a.type) {
      case 'solLimit':
        grantFor({ kind: 'sol' }).lifetime = rule(a.remaining, a.expiresAt, now, sessionEnd);
        break;
      case 'tokenLimit':
        grantFor({ kind: 'token', mint: a.mint }).lifetime = rule(a.remaining, a.expiresAt, now, sessionEnd);
        break;
      case 'solMaxPerTx':
        grantFor({ kind: 'sol' }).perPayment = rule(a.max, a.expiresAt, now, sessionEnd);
        break;
      case 'tokenMaxPerTx':
        grantFor({ kind: 'token', mint: a.mint }).perPayment = rule(a.max, a.expiresAt, now, sessionEnd);
        break;
      case 'solRecurringLimit':
      case 'tokenRecurringLimit': {
        const ref: AssetRef = a.type === 'solRecurringLimit' ? { kind: 'sol' } : { kind: 'token', mint: a.mint };
        const r: RecurringRule = { ...rule(a.limit, a.expiresAt, now, sessionEnd), windowSeconds: a.windowSeconds };
        if ('spent' in a) {
          r.spent = a.spent;
          r.lastReset = a.lastReset;
          if (now !== undefined) {
            // A window restarts once more than `window` passed since it opened
            // (program: `now.saturating_sub(last_reset) > window`).
            const reset = now > a.lastReset && now - a.lastReset > a.windowSeconds;
            r.leftInWindow = r.expired ? 0n : reset ? a.limit : a.limit > a.spent ? a.limit - a.spent : 0n;
          }
        }
        grantFor(ref).recurring = r;
        break;
      }
      case 'programWhitelist':
      case 'programBlacklist':
        programs.mode = a.type === 'programWhitelist' ? 'only' : 'except';
        programs.entries.push({ programId: a.programId, expiresAt: a.expiresAt, expired: isExpired(a.expiresAt, now) });
        break;
    }
  }

  const unreadableMints: string[] = [];
  const assets = [...grants.values()].sort((x, y) => (x.asset.kind === 'sol' ? -1 : y.asset.kind === 'sol' ? 1 : 0));
  for (const g of assets) {
    const rules = [g.lifetime, g.recurring, g.perPayment].filter((r): r is LimitRule => !!r);
    g.hasTotal = !!(g.lifetime || g.recurring);
    g.cannotSpend = rules.some((r) => r.expired || r.amount === 0n);
    if (g.asset.kind === 'token') {
      const t = tokenFacts(g.asset.mint, view, opts);
      if (t === 'mismatch') return 'mismatch';
      g.token = t;
      if (!t.readable && !t.listed) unreadableMints.push(t.mint);
      const bal = view.vault?.tokens?.[g.asset.mint];
      if (bal !== undefined) g.balance = bal;
    } else if (view.vault) {
      g.balance = view.vault.lamports;
    }
  }

  const uncapped: PolicyDescription['uncapped'] = assets
    .filter((g) => !g.hasTotal && !g.cannotSpend)
    .map((g) => g.asset);
  if (!d13 && actions.length > 0) {
    if (!grants.has('sol')) uncapped.unshift({ kind: 'sol' });
    uncapped.push({ kind: 'unnamed-tokens' });
  }

  return {
    timeUnit: time.unit,
    assets,
    programs,
    uncapped,
    otherAssetsBlocked: d13 && actions.length > 0,
    unreadableMints,
    actions,
  };
}

/**
 * Checks `req` against the chain reads and describes what it approves.
 * Refuses with `request-invalid` whatever would fail on chain, and with
 * `wrong-network` a createSession whose binary is not confirmed to read
 * expiries in Unix seconds. The caller has already checked the query
 * (`checkApprovalQuery`) and that `programId` is the configured one.
 */
export function describeApproval(
  req: ApprovalRequest,
  view: ApprovalChainView,
  opts: DescribeApprovalOptions,
): ApprovalCheck {
  if (req.kind === 'createSession') {
    if (opts.features === null) return { ok: false, code: 'wrong-network', reason: 'features-unknown' };
    if (!opts.features.includes('time-expiry')) return { ok: false, code: 'wrong-network', reason: 'feature-missing' };
  }
  const clock = view.clock ? decodeClock(view.clock.data) : null;
  if (!clock) return invalid('clock-unreadable');
  const wallet = decodeWalletAccount(view.wallet, req.programId);
  if (!wallet) return invalid('wallet-missing');
  const signer = decodeAuthorityAccount(view.authority, req.programId);
  if (!signer) return invalid('authority-missing');
  if (signer.type !== 'passkey') return invalid('authority-not-passkey');
  if (signer.wallet !== req.wallet) return invalid('authority-wrong-wallet');
  if (!signer.credentialIdHash || !bytesEqual(signer.credentialIdHash, credentialIdHash(requestCredentialId(req)))) {
    return invalid('authority-wrong-credential');
  }
  if (signer.role !== 'owner' && signer.role !== 'admin') return invalid('authority-role');

  const vault = findVaultAddress(req.wallet, req.programId);
  const base: DescriptionBase = {
    kind: req.kind,
    cluster: req.cluster,
    programId: req.programId,
    wallet: req.wallet,
    vault,
    authority: req.authority,
    payer: req.payer,
    signerRole: signer.role,
    signerCounter: signer.counter,
    clock,
    featuresKnown: opts.features !== null,
  };
  const programAccounts = [req.wallet, vault, req.authority];

  switch (req.kind) {
    case 'createSession':
      return describeCreate(req, view, opts, base, signer, programAccounts);
    case 'revokeSession': {
      if (programAccounts.includes(req.payer) || req.payer === req.args.session) return invalid('payer-is-program-account');
      if (programAccounts.includes(req.args.refund) || req.args.refund === req.args.session) {
        return invalid('refund-is-program-account');
      }
      const s = decodeSessionAccount(view.session, req.programId);
      if (!s) return invalid('session-missing');
      if (s.wallet !== req.wallet) return invalid('session-wrong-wallet');
      // The program reads the session's expiry and its actions' times in one
      // unit: Unix seconds on a time-expiry binary (where a slot an earlier
      // build stored reads as long ended), slots before it.
      const time = policyTime(opts.features, clock);
      let policy: PolicyDescription | null = null;
      try {
        const p = describePolicy(readStoredActions(s.actions), time, undefined, view, opts);
        if (p === 'mismatch') return invalid('mint-decimals-mismatch');
        policy = p;
      } catch {
        policy = null;
      }
      return {
        ok: true,
        description: {
          ...base,
          kind: 'revokeSession',
          session: req.args.session,
          sessionKey: s.sessionKey,
          expiresAt: s.expiresAt,
          expiresAtUnit: time.unit,
          ended: time.now === undefined ? undefined : time.now > s.expiresAt,
          refund: req.args.refund,
          refundIsPayer: req.args.refund === req.payer,
          policy,
          unrestricted: s.actions.length === 0,
        },
      };
    }
    case 'removeAuthority': {
      if (programAccounts.includes(req.payer) || req.payer === req.args.target) return invalid('payer-is-program-account');
      if (programAccounts.includes(req.args.refund) || req.args.refund === req.args.target) {
        return invalid('refund-is-program-account');
      }
      const t = decodeAuthorityAccount(view.target, req.programId);
      if (!t) return invalid('target-missing');
      if (t.wallet !== req.wallet) return invalid('target-wrong-wallet');
      if (req.args.target === req.authority) return invalid('target-is-signer');
      if (signer.role === 'owner' && t.role === 'owner' && wallet.ownerCount <= 1) return invalid('last-owner');
      const removable = signer.role === 'owner' || (signer.role === 'admin' && t.role === 'delegate');
      if (!removable) return invalid('target-not-removable');
      let targetPolicy: PolicyDescription | null = null;
      if (t.policy.length > 0) {
        try {
          const p = describePolicy(readStoredActions(t.policy), policyTime(opts.features, clock), undefined, view, opts);
          if (p === 'mismatch') return invalid('mint-decimals-mismatch');
          targetPolicy = p;
        } catch {
          targetPolicy = null;
        }
      }
      return {
        ok: true,
        description: {
          ...base,
          kind: 'removeAuthority',
          target: req.args.target,
          targetType: t.type,
          targetRole: t.role,
          targetPublicKey: t.type === 'ed25519' ? base58Encode(t.publicKey) : undefined,
          targetRpIdHash: t.rpIdHash,
          targetPolicy,
          ownerCount: wallet.ownerCount,
          ownersAfter: wallet.ownerCount - (t.role === 'owner' ? 1 : 0),
          refund: req.args.refund,
          refundIsPayer: req.args.refund === req.payer,
        },
      };
    }
  }
}

function describeCreate(
  req: CreateSessionRequest,
  view: ApprovalChainView,
  opts: DescribeApprovalOptions,
  base: DescriptionBase,
  signer: AuthorityFacts,
  programAccounts: string[],
): ApprovalCheck {
  if (signer.policy.length !== 0) return invalid('authority-has-policy');
  const session = findSessionAddress(req.wallet, req.args.sessionKey, req.programId);
  if (programAccounts.includes(req.payer) || req.payer === session) return invalid('payer-is-program-account');
  if (view.session && view.session.data.length > 0) return invalid('session-exists');

  const expiresAt = BigInt(req.args.expiresAt);
  const now = base.clock.unixTimestamp;
  if (now < 0n || expiresAt <= now) return invalid('expiry-not-after-now');
  if (expiresAt > now + APPROVAL_MAX_SESSION_SECONDS) return invalid('expiry-too-far');

  let actions: DecodedAction[];
  const actionsBytes = base64urlDecode(req.args.actions);
  try {
    actions = decodeActions(actionsBytes ?? new Uint8Array(1));
  } catch (e) {
    const conflict = (e as { programError?: string }).programError === 'ActionWhitelistBlacklistConflict';
    return invalid(conflict ? 'actions-whitelist-blacklist' : 'actions-invalid');
  }
  // Valid, but too large to send once signed (the SDK refuses it before
  // asking; an older or other SDK may not).
  if (createSessionTransactionBytes(actionsBytes!.length) > MAX_TRANSACTION_BYTES) return invalid('transaction-too-large');
  // createSession is described only on a time-expiry binary (checked above).
  const policy = describePolicy(actions as StoredAction[], { unit: 'seconds', now }, expiresAt, view, opts);
  if (policy === 'mismatch') return invalid('mint-decimals-mismatch');

  let screen: CreateSessionDescription['screen'];
  let variant: CreateSessionDescription['variant'];
  if (actions.length === 0) {
    screen = 'session-no-limits';
  } else if (policy.uncapped.length > 0) {
    screen = 'session-no-total';
  } else {
    screen = 'session-create';
    const spendable = policy.assets;
    if (spendable.length === 0) variant = 'no-spend';
    else if (!spendable.some((g) => g.asset.kind === 'sol')) variant = 'tokens-only';
    else variant = 'totals';
  }

  return {
    ok: true,
    description: {
      ...base,
      ...policy,
      kind: 'createSession',
      sessionKey: req.args.sessionKey,
      session,
      expiresAt,
      secondsLeft: expiresAt - now,
      screen,
      variant,
      canGiveAccountAway: actions.length === 0 && !opts.features?.includes('nonowner-invariants'),
    },
  };
}

/** Whether a base58 string is a canonical 32-byte address. */
export function isAddress(value: unknown): value is string {
  return decodeAddress(value) !== undefined;
}
