#!/usr/bin/env node
// npm and GitHub side of .github/workflows/release-sdk.yml, which publishes the two SDKs
// when a release tag is pushed. Plain Node with no dependencies, so every job can run it
// without an install. RELEASING.md describes the flow.
//
//   plan <git-tag>
//       Checks a release tag before anything is built: sdk-legacy-vX.Y.Z or sdk-kit-vX.Y.Z,
//       its version equal to the package's package.json and package-lock.json, its commit on
//       origin/develop or origin/main, and, for a version not on npm yet, a publish that does
//       not move `next` back to a lower version. Writes package, name, dir, version, test and
//       published to $GITHUB_OUTPUT, and the plan to $GITHUB_STEP_SUMMARY for the reviewer.
//   pack <package> <dir>
//       Runs the package's prepublishOnly (clean, then build) and `npm pack` into <dir>, as
//       `npm publish` does before it uploads, checks the tarball and records it in
//       <dir>/manifest.json.
//   verify-tag <dir>
//       Checks through the GitHub API that the release tag still points at the commit the
//       tarball was built from ($GITHUB_SHA). Needs GH_TOKEN and GH_REPO.
//   publish <dir> [--dry-run]
//       Runs `npm publish <tarball> --provenance --access public --tag next --ignore-scripts`
//       unless the version is on npm already, after checking again that this does not move
//       `next` back, then points the package's dist-tags at it: `next`, and `latest` for
//       @lazorkit/sdk within its major. Authentication is npm trusted publishing (OIDC); no
//       token is read. @lazorkit/sdk-legacy's `latest` is never moved.
//   github-release <dir> [--dry-run]
//       Creates the GitHub release for the tag, unless it exists. Needs GH_TOKEN and GH_REPO.
//   oidc-check [--dist-tag]
//       Proves that npm trusted publishing works in this job without publishing anything:
//       packs each package's `next` version from npm and runs `npm publish --dry-run` on it.
//       With --dist-tag, also adds and removes the scratch dist-tag `oidc-check` on each
//       package, which proves the trusted publisher may change dist-tags.
//
// The decisions (version order, which dist-tag moves) are exported for
// scripts/sdk-release.test.mjs; importing this file runs nothing.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// The release tag of a package is `<key>-v<version>`.
export const PACKAGES = {
  "sdk-legacy": {
    name: "@lazorkit/sdk-legacy",
    dir: "sdk/sdk-legacy",
    test: false, // as lint.yml: sdk-legacy has no unit tests
    // `latest` stays on the protocol v1 line (0.3.x) until the mainnet upgrade, and is moved
    // by hand then (docs/upgrade-procedure.md, step 7).
    distTags: ["next"],
  },
  "sdk-kit": {
    name: "@lazorkit/sdk",
    dir: "sdk/sdk-kit",
    test: true,
    // `latest` follows the releases of its own major, and its release candidates while it is
    // one itself; a new major moves it by hand (see distTagDecision).
    distTags: ["next", "latest"],
  },
};

// Dist-tags this script refuses to move, whatever PACKAGES says.
export const NEVER_MOVE = new Map([["@lazorkit/sdk-legacy", new Set(["latest"])]]);

// The dist-tag `npm publish` sets.
export const PUBLISH_TAG = "next";

// The dist-tag `oidc-check --dist-tag` adds and removes again.
const SCRATCH_TAG = "oidc-check";

// The files that decide what a release run does; the plan says whether they match develop's.
const RELEASE_FILES = [".github/workflows/release-sdk.yml", "scripts/sdk-release.mjs"];

// A release tag must be on one of these branches of origin.
const RELEASE_BRANCHES = ["develop", "main"];

const TAG_RE = /^(sdk-legacy|sdk-kit)-v(.+)$/;
// SemVer 2.0.0 without build metadata, which npm drops.
const SEMVER_RE =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?$/;

// How long to wait for a just-published version to show up in `npm view`.
const VISIBILITY_ATTEMPTS = 20;
const VISIBILITY_DELAY_MS = 15_000;

const MANIFEST = "manifest.json";

const log = (...args) => console.error(...args);

const readJson = (file) => JSON.parse(readFileSync(file, "utf8"));

const specOf = (pkg) => `${pkg.name}@${pkg.version}`;

const releaseTagOf = (entry) => `${entry.package}-v${entry.version}`;

function exec(cmd, args, { cwd = ROOT } = {}) {
  log(`$ ${cmd} ${args.join(" ")}${cwd === ROOT ? "" : `  (in ${path.relative(ROOT, cwd)})`}`);
  const r = spawnSync(cmd, args, { cwd, stdio: ["ignore", process.stderr, "inherit"] });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} exited with ${r.status}`);
}

function capture(cmd, args, { cwd = ROOT } = {}) {
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (r.error) throw r.error;
  return r;
}

// Like exec, but also returns the combined output and does not throw on failure.
function execTee(cmd, args) {
  log(`$ ${cmd} ${args.join(" ")}`);
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    for (const stream of [child.stdout, child.stderr]) {
      stream.on("data", (chunk) => {
        output += chunk;
        process.stderr.write(chunk);
      });
    }
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, output }));
  });
}

function npmJson(args) {
  const r = capture("npm", [...args, "--json"]);
  let data;
  try {
    data = r.stdout.trim() ? JSON.parse(r.stdout) : undefined;
  } catch {
    data = undefined;
  }
  return { status: r.status, data, stderr: r.stderr };
}

// npm 12 wraps successful `npm view --json` output in an array; npm 11 does not.
const unwrap = (data) => (Array.isArray(data) ? data[0] : data);

function setOutput(key, value) {
  log(`output: ${key}=${value}`);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`);
}

function addSummary(markdown) {
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${markdown}\n`);
}

export function parseVersion(v) {
  const m = SEMVER_RE.exec(v);
  if (!m) throw new Error(`${v} is not a SemVer version`);
  return { nums: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ? m[4].split(".") : [] };
}

export const isPrerelease = (v) => parseVersion(v).pre.length > 0;

const majorOf = (v) => parseVersion(v).nums[0];

// SemVer precedence.
export function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  for (let i = 0; i < 3; i++) {
    if (pa.nums[i] !== pb.nums[i]) return pa.nums[i] < pb.nums[i] ? -1 : 1;
  }
  if (pa.pre.length === 0 || pb.pre.length === 0) {
    if (pa.pre.length === pb.pre.length) return 0;
    return pa.pre.length === 0 ? 1 : -1;
  }
  for (let i = 0; i < Math.max(pa.pre.length, pb.pre.length); i++) {
    const x = pa.pre[i];
    const y = pb.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const xNum = /^\d+$/.test(x);
    const yNum = /^\d+$/.test(y);
    if (xNum && yNum) return Number(x) < Number(y) ? -1 : 1;
    if (xNum !== yNum) return xNum ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

// Trusted publishing needs npm 11.5.1+, and `npm dist-tag` only uses OIDC from 11.21.0
// (or 12.2.0) on. Node 24 bundles an older npm, so the workflow installs 11.21.0.
function assertNpmSupportsOidc() {
  const version = capture("npm", ["--version"]).stdout.trim();
  const [major, minor] = version.split(".").map(Number);
  const ok = major === 11 ? minor >= 21 : major === 12 ? minor >= 2 : major > 12;
  if (!ok) throw new Error(`npm ${version} cannot use trusted publishing for dist-tags (need 11.21.0+ or 12.2.0+)`);
  log(`npm ${version}`);
}

function isPublished({ name, version }) {
  const r = npmJson(["view", `${name}@${version}`, "version", "--prefer-online"]);
  if (r.status === 0) return unwrap(r.data) === version;
  // E404 covers both "no such version" and "no such package".
  if (r.data?.error?.code === "E404") return false;
  throw new Error(`npm view ${name}@${version} failed (exit ${r.status}): ${r.data?.error?.summary ?? r.stderr.trim()}`);
}

function publishedIntegrity({ name, version }) {
  const r = npmJson(["view", `${name}@${version}`, "dist.integrity", "--prefer-online"]);
  if (r.status !== 0) throw new Error(`npm view ${name}@${version} dist.integrity failed: ${r.stderr.trim()}`);
  return unwrap(r.data);
}

function hasProvenance({ name, version }) {
  const r = npmJson(["view", `${name}@${version}`, "dist.attestations", "--prefer-online"]);
  if (r.status !== 0) throw new Error(`npm view ${name}@${version} dist.attestations failed: ${r.stderr.trim()}`);
  return Boolean(unwrap(r.data)?.provenance);
}

function distTagsOf(name) {
  const r = npmJson(["view", name, "dist-tags", "--prefer-online"]);
  if (r.status === 0) return unwrap(r.data) ?? {};
  if (r.data?.error?.code === "E404") return {};
  throw new Error(`npm view ${name} dist-tags failed (exit ${r.status}): ${r.data?.error?.summary ?? r.stderr.trim()}`);
}

async function waitUntilPublished(pkg) {
  for (let attempt = 1; attempt <= VISIBILITY_ATTEMPTS; attempt++) {
    if (isPublished(pkg)) return true;
    if (attempt < VISIBILITY_ATTEMPTS) {
      log(`${specOf(pkg)} is not visible on npm yet; retrying (${attempt}/${VISIBILITY_ATTEMPTS})`);
      await new Promise((r) => setTimeout(r, VISIBILITY_DELAY_MS));
    }
  }
  return false;
}

// Whether to point dist-tag `tag` (now at `current`, or unset) at `version`. A tag is never
// moved back to a lower version. `latest` never moves to a new major: a protocol major moves
// the SDKs to a new npm major, and `latest` must keep resolving to the line that speaks to
// mainnet as it is now until the upgrade lands, which this workflow cannot know
// (docs/upgrade-procedure.md, step 7). Nor does `latest` move from a stable version to a
// pre-release: it follows @lazorkit/sdk's release candidates only while it is one itself.
export function distTagDecision(name, version, tag, current) {
  if (NEVER_MOVE.get(name)?.has(tag)) throw new Error(`refusing to move ${name}'s ${tag} dist-tag`);
  if (current === version) return { move: false, why: `${tag} is already ${version}` };
  if (current && compareVersions(current, version) > 0) {
    return { move: false, why: `${tag} is ${current}, ahead of ${version}; leaving it` };
  }
  if (tag === "latest" && current) {
    if (majorOf(version) > majorOf(current)) {
      return {
        move: false,
        why:
          `${tag} is ${current} and ${version} is a new major; leaving it: move ${tag} by hand once ` +
          "the protocol upgrade it speaks is on mainnet (docs/upgrade-procedure.md, step 7)",
      };
    }
    if (isPrerelease(version) && !isPrerelease(current)) {
      return { move: false, why: `${tag} is the stable ${current}; a pre-release does not take it` };
    }
  }
  return { move: true, why: `${tag}: ${current ?? "unset"} -> ${version}` };
}

// `npm publish --tag next` points `next` at the new version whatever `next` is now (npm only
// guards `latest`), so a version lower than `next` is refused. plan() checks it at the push and
// publish() again just before it publishes: an approval can come days later, after a higher
// version was published by another run or by hand.
export function assertPublishKeepsOrder(name, version, distTags) {
  const current = distTags[PUBLISH_TAG];
  if (current && compareVersions(current, version) > 0) {
    throw new Error(
      `${name}@${version} is lower than ${PUBLISH_TAG} (${current}): \`npm publish --tag ${PUBLISH_TAG}\` would move ` +
        `${PUBLISH_TAG} back. This workflow does not publish it; publish it by hand under another dist-tag (RELEASING.md).`,
    );
  }
}

function tarballManifest(file) {
  const r = capture("tar", ["-xzOf", file, "package/package.json"]);
  if (r.status !== 0) throw new Error(`cannot read package/package.json from ${file}: ${r.stderr.trim()}`);
  return JSON.parse(r.stdout);
}

function expectSame(what, actual, pkg) {
  if (actual.name !== pkg.name || actual.version !== pkg.version) {
    throw new Error(`${what} is ${actual.name}@${actual.version}, expected ${specOf(pkg)}`);
  }
}

function sha512(file) {
  return `sha512-${createHash("sha512").update(readFileSync(file)).digest("base64")}`;
}

function packageOf(key) {
  const pkg = PACKAGES[key];
  if (!pkg) throw new Error(`unknown package ${key}; expected one of ${Object.keys(PACKAGES).join(", ")}`);
  return pkg;
}

function readEntry(dir) {
  if (!dir) throw new Error("missing <dir>");
  dir = path.resolve(dir);
  const entry = readJson(path.join(dir, MANIFEST));
  const pkg = packageOf(entry.package);
  if (entry.name !== pkg.name) throw new Error(`${MANIFEST} is for ${entry.name}, expected ${pkg.name}`);
  parseVersion(entry.version);
  return { dir, entry, pkg, file: path.join(dir, entry.tarball) };
}

// The commit must be on a release branch of origin, so that only merged code is released.
function checkReleaseBranch() {
  const head = capture("git", ["rev-parse", "HEAD"]).stdout.trim();
  if (process.env.GITHUB_SHA && process.env.GITHUB_SHA !== head) {
    throw new Error(`checked out ${head}, but this run is for ${process.env.GITHUB_SHA}`);
  }
  const on = [];
  const missing = [];
  for (const branch of RELEASE_BRANCHES) {
    const ref = `refs/remotes/origin/${branch}`;
    if (capture("git", ["rev-parse", "--verify", "--quiet", ref]).status !== 0) {
      missing.push(ref);
      continue;
    }
    const r = capture("git", ["merge-base", "--is-ancestor", head, ref]);
    if (r.status === 0) on.push(branch);
    else if (r.status !== 1) throw new Error(`git merge-base ${head} ${ref} failed: ${r.stderr.trim()}`);
  }
  if (on.length === 0) {
    throw new Error(
      `${head} is not on ${RELEASE_BRANCHES.map((b) => `origin/${b}`).join(" or ")}; tag a commit that was merged` +
        (missing.length > 0 ? ` (not fetched: ${missing.join(", ")})` : ""),
    );
  }
  log(`${head} is on ${on.map((b) => `origin/${b}`).join(", ")}`);
  return { head, on };
}

// Whether the workflow and this script at the tagged commit are develop's. A tag-push run uses
// the copies at the tag, so this is what the reviewer of npm-publish checks (RELEASING.md).
function releaseFilesMatchDevelop() {
  const r = capture("git", ["diff", "--quiet", "HEAD", "refs/remotes/origin/develop", "--", ...RELEASE_FILES]);
  if (r.status === 0) return true;
  if (r.status === 1) return false;
  throw new Error(`git diff HEAD origin/develop failed: ${r.stderr.trim()}`);
}

function plan(tag) {
  const m = TAG_RE.exec(tag ?? "");
  if (!m) throw new Error(`${tag}: not a release tag (sdk-legacy-vX.Y.Z or sdk-kit-vX.Y.Z)`);
  const [, key, version] = m;
  if (!SEMVER_RE.test(version)) throw new Error(`${tag}: ${version} is not a SemVer version`);
  const pkg = packageOf(key);
  const spec = `${pkg.name}@${version}`;

  const manifest = readJson(path.join(ROOT, pkg.dir, "package.json"));
  if (manifest.name !== pkg.name) throw new Error(`${pkg.dir}/package.json is ${manifest.name}, expected ${pkg.name}`);
  if (manifest.private) throw new Error(`${pkg.dir}/package.json is private`);
  if (manifest.version !== version) {
    throw new Error(
      `tag ${tag} is version ${version}, but ${pkg.dir}/package.json is ${manifest.version}; ` +
        "tag the commit that bumps the version",
    );
  }
  const lock = readJson(path.join(ROOT, pkg.dir, "package-lock.json"));
  if (lock.version !== version || lock.packages?.[""]?.version !== version) {
    throw new Error(`${pkg.dir}/package-lock.json is not at ${version}; run \`npm install --package-lock-only\` there`);
  }
  const { head, on } = checkReleaseBranch();
  const sameAsDevelop = releaseFilesMatchDevelop();
  if (!sameAsDevelop) {
    // A workflow command, on stdout.
    console.log(`::warning::${RELEASE_FILES.join(" and ")} at ${head} differ from origin/develop's; check the diff before approving`);
  }

  const published = isPublished({ name: pkg.name, version });
  const distTags = distTagsOf(pkg.name);
  log(`${pkg.name} dist-tags now: ${JSON.stringify(distTags)}`);
  if (published) {
    log(`${spec} is on npm already: the publish job will not publish it again, only point its dist-tags and create the GitHub release`);
  } else {
    assertPublishKeepsOrder(pkg.name, version, distTags);
    log(`${spec} is not on npm yet: the publish job publishes it with --tag ${PUBLISH_TAG}`);
  }
  const steps = [];
  for (const t of pkg.distTags) {
    const step =
      t === PUBLISH_TAG && !published
        ? `${t}: ${distTags[t] ?? "unset"} -> ${version} (npm publish --tag ${t})`
        : distTagDecision(pkg.name, version, t, distTags[t]).why;
    log(`plan: ${step}`);
    steps.push(step);
  }
  for (const [t, v] of Object.entries(distTags)) {
    if (!pkg.distTags.includes(t)) steps.push(`${t}: stays ${v}`);
  }

  addSummary(
    [
      `### ${spec} from \`${tag}\``,
      "",
      `- Commit \`${head}\`, on ${on.map((b) => `\`origin/${b}\``).join(" and ")}`,
      `- ${RELEASE_FILES.map((f) => `\`${f}\``).join(" and ")}: ` +
        (sameAsDevelop ? "same as `origin/develop`" : "**differ from `origin/develop`**: check the diff before approving"),
      `- npm: ${published ? "already published; the publish job only checks its dist-tags" : "not published yet"}`,
      ...steps.map((s) => `- dist-tag ${s}`),
      "",
      "Approve `npm-publish` only if this is the release you expect (RELEASING.md, Approving a release).",
    ].join("\n"),
  );

  setOutput("package", key);
  setOutput("name", pkg.name);
  setOutput("dir", pkg.dir);
  setOutput("version", version);
  setOutput("test", pkg.test ? "true" : "false");
  setOutput("published", published ? "true" : "false");
}

function pack(key, outDir) {
  if (!key || !outDir) throw new Error("usage: pack <package> <dir>");
  const pkg = packageOf(key);
  outDir = path.resolve(outDir);
  mkdirSync(outDir, { recursive: true });
  if (readdirSync(outDir).length > 0) throw new Error(`${outDir} is not empty`);
  const cwd = path.join(ROOT, pkg.dir);
  const { name, version } = readJson(path.join(cwd, "package.json"));
  const entry = { package: key, name, version, dir: pkg.dir };
  expectSame(`${pkg.dir}/package.json`, entry, { name: pkg.name, version });

  // What `npm publish` runs before it packs; the publish job passes --ignore-scripts.
  exec("npm", ["run", "prepublishOnly"], { cwd });
  exec("npm", ["pack", "--pack-destination", outDir], { cwd });

  const tarball = `${name.replace(/^@/, "").replace("/", "-")}-${version}.tgz`;
  const file = path.join(outDir, tarball);
  if (!existsSync(file)) throw new Error(`npm pack did not produce ${file}`);
  expectSame(`${tarball}/package/package.json`, tarballManifest(file), entry);
  const listing = capture("tar", ["-tzf", file]).stdout.split("\n");
  for (const required of ["package/dist/index.js", "package/dist/index.d.ts", "package/LICENSE", "package/README.md"]) {
    if (!listing.includes(required)) throw new Error(`${tarball} has no ${required.slice("package/".length)}`);
  }
  const integrity = sha512(file);
  log(`${tarball}: ${listing.filter(Boolean).length} files, ${integrity}`);
  writeFileSync(path.join(outDir, MANIFEST), `${JSON.stringify({ ...entry, tarball, integrity }, null, 2)}\n`);
}

function githubRepo() {
  const repo = process.env.GH_REPO;
  if (!repo) throw new Error("GH_REPO is not set");
  return repo;
}

function ghJson(args) {
  const r = capture("gh", args);
  if (r.status !== 0) {
    const err = new Error(`gh ${args.join(" ")} failed (exit ${r.status}): ${r.stderr.trim()}`);
    err.notFound = /HTTP 404|not found/i.test(r.stderr);
    throw err;
  }
  return JSON.parse(r.stdout);
}

// The commit a tag on GitHub points at, and its annotation if it is an annotated tag.
function remoteTag(tag) {
  const repo = githubRepo();
  let ref;
  try {
    ref = ghJson(["api", `repos/${repo}/git/ref/tags/${tag}`]);
  } catch (err) {
    if (err.notFound) return undefined;
    throw err;
  }
  if (ref.object.type === "commit") return { commit: ref.object.sha, message: undefined };
  if (ref.object.type !== "tag") throw new Error(`tag ${tag} points at a ${ref.object.type}`);
  const annotated = ghJson(["api", `repos/${repo}/git/tags/${ref.object.sha}`]);
  if (annotated.object.type !== "commit") throw new Error(`tag ${tag} points at a ${annotated.object.type}`);
  return { commit: annotated.object.sha, message: annotated.message };
}

function verifyTag(dir) {
  const { entry } = readEntry(dir);
  const tag = releaseTagOf(entry);
  if (process.env.GITHUB_REF_NAME && process.env.GITHUB_REF_NAME !== tag) {
    throw new Error(`this run is for ${process.env.GITHUB_REF_NAME}, the tarball is for ${tag}`);
  }
  const sha = process.env.GITHUB_SHA;
  if (!sha) throw new Error("GITHUB_SHA is not set");
  const remote = remoteTag(tag);
  if (!remote) throw new Error(`tag ${tag} no longer exists on GitHub; not publishing`);
  if (remote.commit !== sha) {
    throw new Error(`tag ${tag} now points at ${remote.commit}, not at ${sha}, the commit built here; not publishing`);
  }
  log(`tag ${tag} points at ${sha}${remote.message === undefined ? " (lightweight tag)" : ""}`);
}

async function publish(dir, { dryRun }) {
  if (!dryRun) assertNpmSupportsOidc();
  const { entry, pkg, file } = readEntry(dir);
  const spec = specOf(entry);
  expectSame(`${pkg.dir}/package.json`, readJson(path.join(ROOT, pkg.dir, "package.json")), entry);
  expectSame(`${entry.tarball}/package/package.json`, tarballManifest(file), entry);
  if (sha512(file) !== entry.integrity) throw new Error(`${entry.tarball} does not match ${MANIFEST}`);

  let publishedHere = false;
  if (isPublished(entry)) {
    log(`${spec} is already on npm; not publishing it again`);
  } else {
    const before = distTagsOf(entry.name);
    assertPublishKeepsOrder(entry.name, entry.version, before);
    const args = ["publish", file, "--ignore-scripts", "--access", "public", "--provenance", "--tag", PUBLISH_TAG];
    if (dryRun) args.push("--dry-run");
    const { code, output } = await execTee("npm", args);
    if (code === 0) {
      publishedHere = !dryRun;
    } else if (/previously published version/i.test(output)) {
      log(`${spec} was published already (stale registry read)`);
    } else {
      throw new Error(`npm publish ${spec} failed (exit ${code})`);
    }
    if (dryRun) {
      const then = pkg.distTags
        .filter((t) => t !== PUBLISH_TAG)
        .map((t) => distTagDecision(entry.name, entry.version, t, before[t]).why);
      log(`[dry-run] ${PUBLISH_TAG} -> ${entry.version}; would wait for ${spec} on npm, then: ${then.join("; ") || "nothing else"}`);
      return;
    }
  }

  if (publishedHere && !(await waitUntilPublished(entry))) {
    throw new Error(`${spec} was published but is still not visible on npm; re-run this job to point the dist-tags`);
  }

  const onNpm = publishedIntegrity(entry);
  if (onNpm !== entry.integrity) {
    const msg = `${spec} on npm has integrity ${onNpm}, the tarball built here ${entry.integrity}`;
    if (publishedHere) throw new Error(msg);
    // Published earlier, by hand or by another run: a different build of the same version.
    log(`warning: ${msg}`);
  }

  const distTags = distTagsOf(entry.name);
  for (const tag of pkg.distTags) {
    const d = distTagDecision(entry.name, entry.version, tag, distTags[tag]);
    log(`${entry.name}: ${d.why}`);
    if (!d.move) continue;
    if (dryRun) log(`[dry-run] npm dist-tag add ${spec} ${tag}`);
    else exec("npm", ["dist-tag", "add", spec, tag]);
  }
}

function releaseNotes(entry, message, tagsAtVersion, provenance) {
  const repo = githubRepo();
  const tag = releaseTagOf(entry);
  const title = `${entry.name} ${entry.version}`;
  const lines = (message ?? "").replace(/\r\n/g, "\n").trim().split("\n");
  // The annotation conventionally starts with the title; leave that line out of the body.
  if (lines[0]?.trim() === title) lines.shift();
  const body = lines.join("\n").trim();
  const npmUrl = `https://www.npmjs.com/package/${entry.name}/v/${entry.version}`;
  const tagList = tagsAtVersion.map((t) => `\`${t}\``).join(", ");
  const tags = tagsAtVersion.length === 0 ? "" : `, dist-tag${tagsAtVersion.length > 1 ? "s" : ""} ${tagList}`;
  const attested = provenance
    ? `, with a [provenance attestation](${npmUrl}#provenance) of the commit and workflow run that built it.`
    : ".";
  const parts = [];
  if (body) parts.push(body);
  parts.push(
    `**npm:** [\`${entry.name}@${entry.version}\`](${npmUrl})${tags}${attested}`,
    `\`\`\`sh\nnpm install ${entry.name}@${entry.version}\n\`\`\``,
    `What changed: [CHANGELOG.md](https://github.com/${repo}/blob/${tag}/CHANGELOG.md) at this tag.`,
  );
  return { title, notes: `${parts.join("\n\n")}\n` };
}

function githubRelease(dir, { dryRun }) {
  const { dir: outDir, entry } = readEntry(dir);
  const tag = releaseTagOf(entry);
  const view = capture("gh", ["release", "view", tag, "--json", "url", "--jq", ".url"]);
  if (view.status === 0) {
    log(`the GitHub release for ${tag} exists: ${view.stdout.trim()}`);
    return;
  }
  if (!/release not found/i.test(view.stderr)) throw new Error(`gh release view ${tag} failed: ${view.stderr.trim()}`);

  const remote = remoteTag(tag);
  if (!remote) throw new Error(`tag ${tag} does not exist on GitHub`);
  const distTags = distTagsOf(entry.name);
  const tagsAtVersion = Object.keys(distTags).filter((t) => distTags[t] === entry.version);
  const { title, notes } = releaseNotes(entry, remote.message, tagsAtVersion, hasProvenance(entry));
  const notesFile = path.join(outDir, "release-notes.md");
  writeFileSync(notesFile, notes);
  // Not marked as the repository's latest release: it holds both SDKs and the program.
  const args = ["release", "create", tag, "--verify-tag", "--title", title, "--notes-file", notesFile, "--latest=false"];
  if (isPrerelease(entry.version)) args.push("--prerelease");
  if (dryRun) {
    log(`[dry-run] gh ${args.join(" ")}\n----- ${notesFile}\n${notes}-----`);
    return;
  }
  exec("gh", args);
}

// Adds the scratch dist-tag and removes it again. `npm dist-tag add` returns before its request
// when the tag already has that version, so pointing `next` at itself would prove nothing.
function checkDistTagPermission(name, version) {
  if (distTagsOf(name)[SCRATCH_TAG]) exec("npm", ["dist-tag", "rm", name, SCRATCH_TAG]);
  exec("npm", ["dist-tag", "add", `${name}@${version}`, SCRATCH_TAG]);
  try {
    exec("npm", ["dist-tag", "rm", name, SCRATCH_TAG]);
  } catch (err) {
    throw new Error(`${err.message}; remove the scratch tag by hand: npm dist-tag rm ${name} ${SCRATCH_TAG}`);
  }
}

async function oidcCheck({ distTag }) {
  assertNpmSupportsOidc();
  if (!process.env.ACTIONS_ID_TOKEN_REQUEST_URL) {
    throw new Error("no GitHub OIDC token available; run this in a job with `id-token: write`");
  }
  const tmp = mkdtempSync(path.join(process.env.RUNNER_TEMP ?? tmpdir(), "oidc-check-"));
  const failed = [];
  for (const { name } of Object.values(PACKAGES)) {
    const packed = npmJson(["pack", `${name}@${PUBLISH_TAG}`, "--pack-destination", tmp, "--ignore-scripts"]);
    const { filename, version } = unwrap(packed.data) ?? {};
    if (packed.status !== 0 || !filename) throw new Error(`npm pack ${name}@${PUBLISH_TAG} failed: ${packed.stderr.trim()}`);
    const spec = `${name}@${version}`;
    const { code, output } = await execTee("npm", [
      "publish", path.join(tmp, filename), "--dry-run", "--ignore-scripts", "--access", "public",
      "--provenance", "--tag", PUBLISH_TAG, "--loglevel", "verbose",
    ]);
    if (!/Successfully retrieved and set token/.test(output)) {
      log(`${spec}: the OIDC token exchange did not succeed; check the trusted publisher on npmjs.com`);
      failed.push(name);
      continue;
    } else if (/cannot publish over the previously published versions/i.test(output)) {
      log(`${spec}: OIDC token exchange succeeded, then npm refused to publish over ${version}, as expected`);
    } else if (code === 0 && isPrerelease(version)) {
      // npm only compares stable versions in this check, so a dry run of an existing
      // pre-release goes through to the end; --dry-run still uploads nothing.
      log(`${spec}: OIDC token exchange succeeded; the dry run of this pre-release completed without uploading`);
    } else {
      log(`${spec}: OIDC token exchange succeeded, but the dry run ended unexpectedly (exit ${code})`);
      failed.push(name);
      continue;
    }
    if (!distTag) continue;
    try {
      checkDistTagPermission(name, version);
      log(`${name}: added and removed the dist-tag ${SCRATCH_TAG} over OIDC`);
    } catch (err) {
      log(`${name}: changing a dist-tag over OIDC failed; enable "Allow npm dist-tag" on its trusted publisher: ${err.message}`);
      failed.push(name);
    }
  }
  if (failed.length > 0) {
    log(`trusted publishing does not work for: ${failed.join(", ")}`);
    process.exitCode = 1;
  }
}

async function main(argv) {
  const [command, ...rest] = argv;
  const flags = new Set(rest.filter((a) => a.startsWith("--")));
  const args = rest.filter((a) => !a.startsWith("--"));
  const known = { publish: ["--dry-run"], "github-release": ["--dry-run"], "oidc-check": ["--dist-tag"] }[command] ?? [];
  for (const f of flags) if (!known.includes(f)) throw new Error(`${command}: unknown option ${f}`);
  const dryRun = flags.has("--dry-run");
  switch (command) {
    case "plan":
      plan(args[0]);
      break;
    case "pack":
      pack(args[0], args[1]);
      break;
    case "verify-tag":
      verifyTag(args[0]);
      break;
    case "publish":
      await publish(args[0], { dryRun });
      break;
    case "github-release":
      githubRelease(args[0], { dryRun });
      break;
    case "oidc-check":
      await oidcCheck({ distTag: flags.has("--dist-tag") });
      break;
    default:
      throw new Error(
        "usage: sdk-release.mjs plan <git-tag> | pack <package> <dir> | verify-tag <dir> | " +
          "publish <dir> [--dry-run] | github-release <dir> [--dry-run] | oidc-check [--dist-tag]",
      );
  }
}

const invokedDirectly =
  process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));

if (invokedDirectly) {
  try {
    await main(process.argv.slice(2));
  } catch (err) {
    log(err instanceof Error ? err.message : err);
    process.exitCode = 1;
  }
}
