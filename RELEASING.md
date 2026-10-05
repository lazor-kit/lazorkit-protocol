# Releasing the SDKs

The two SDKs are published to npm by [`.github/workflows/release-sdk.yml`](.github/workflows/release-sdk.yml)
when their release tag is pushed, with [npm trusted publishing](https://docs.npmjs.com/trusted-publishers)
(OIDC, no npm token) and a [provenance attestation](https://docs.npmjs.com/generating-provenance-statements).
[`scripts/sdk-release.mjs`](scripts/sdk-release.mjs) does the work.

| Package | Path | Release tag | Dist-tags the workflow sets |
| --- | --- | --- | --- |
| `@lazorkit/sdk-legacy` | `sdk/sdk-legacy` | `sdk-legacy-vX.Y.Z` | `next` |
| `@lazorkit/sdk` | `sdk/sdk-kit` | `sdk-kit-vX.Y.Z` | `next`, and `latest` while `latest` is a release candidate too |

`@lazorkit/sdk-legacy`'s `latest` is the protocol v1 line (0.3.x), the one mainnet integrators
install today. The workflow never moves it (the script refuses to); it moves by hand after the
mainnet upgrade ([upgrade procedure](docs/upgrade-procedure.md), step 7). `@lazorkit/sdk`'s
`latest` follows the release candidates, as it does today (`next` and `latest` are both
1.0.0-rc.6); once `latest` is a stable version, a later pre-release only moves `next`.

## One-time setup (maintainers)

1. **npm**: in the settings of `@lazorkit/sdk-legacy` and of `@lazorkit/sdk`, add a trusted
   publisher: GitHub Actions, organization `lazor-kit`, repository `lazorkit-protocol`, workflow
   `release-sdk.yml`, environment `npm-publish`, with **Allow npm publish** and **Allow npm
   dist-tag** enabled.
2. **GitHub environment**: create `npm-publish` in this repository (`Settings → Environments`;
   it is not shared with lazor-kit's) with the release maintainers as required reviewers. Under
   **Deployment branches and tags** choose *Selected branches and tags* and add the tag patterns
   `sdk-legacy-v*` and `sdk-kit-v*` and the branch `develop`, so only a release tag (or the dry
   run below, from `develop`) can get an npm token.
3. **Check the setup**: `Actions → Release SDK → Run workflow` on `develop`. A manual run only
   runs `trusted-publishing-check`: after you approve `npm-publish`, it packs each package's
   `next` version from npm and runs `npm publish --dry-run --provenance` on it. npm exchanges the
   job's OIDC token, then refuses to publish over `@lazorkit/sdk-legacy`'s existing version; for
   `@lazorkit/sdk`, whose `next` is a pre-release, npm skips that check and the dry run completes.
   Either way nothing is uploaded, and the job fails if the token exchange fails. The dist-tag
   permission is only exercised by a real release.

Optional, once a release has gone through: set each package's publishing access to *Require
two-factor authentication and disallow tokens*, and add a tag ruleset that limits who can create
`sdk-*-v*` tags.

## How a release happens

1. Bump the version in a PR to `develop`, together with its CHANGELOG entry:

   ```sh
   cd sdk/sdk-kit && npm version 1.0.0-rc.7 --no-git-tag-version   # package.json and package-lock.json
   ```

2. Once it is merged, tag a commit on `develop` that has the bump (here `develop`'s tip) and
   push the tag. The annotation becomes the start of the GitHub release notes:

   ```sh
   git fetch origin
   git tag -a sdk-kit-v1.0.0-rc.7 -m "@lazorkit/sdk 1.0.0-rc.7" origin/develop
   git push origin sdk-kit-v1.0.0-rc.7
   ```

   Releasing both SDKs is two tags, often on the same commit, and two runs.

3. `build`, without credentials, refuses the tag unless its version is the one in the package's
   `package.json` and `package-lock.json`, its commit is on `origin/develop` or `origin/main`, and,
   for a version not on npm yet, it would not move `next` back to a lower version. Then it runs
   `npm ci`, the build and (for `sdk-kit`) the tests, as the `lint` workflow does, runs
   `prepublishOnly` and packs the tarball.
4. `publish` waits for a reviewer to approve `npm-publish`. It refuses if the tag has been moved
   or deleted since the push, publishes the tarball with
   `npm publish --provenance --access public --tag next --ignore-scripts`, and for `@lazorkit/sdk`
   points `latest` at it.
5. `release` creates the GitHub release for the tag (a pre-release for an `-rc` version, never
   marked as the repository's latest), linking the npm version and `CHANGELOG.md` at the tag.

## Re-running

Every step is idempotent. Re-run the failed jobs: a version already on npm is not published
again, its dist-tags are checked and moved if needed, and the GitHub release is created if it
is missing. Each run asks for an approval again; approving one with nothing left to do is
harmless.

A version published by hand can still be finished by the workflow: push its tag, and the run
publishes nothing, warns if npm's tarball differs from the one it built, and sets the
dist-tags and the release.

## By hand

- **`@lazorkit/sdk-legacy` `latest`** after the mainnet upgrade:
  `npm dist-tag add @lazorkit/sdk-legacy@<version> latest`.
- **A version the workflow refuses**, such as a 0.3.x patch of the v1 line (lower than `next`):
  publish it from its branch with an explicit `--tag`, e.g. `npm publish --tag latest` for the
  v1 line while `latest` is still that line.
- **Fallback when the workflow is unavailable**, in the package directory:

  ```sh
  npm ci
  npm publish --tag next --provenance=false   # prepublishOnly cleans and builds
  ```

  Provenance can only be generated in CI. Then push the release tag, which leaves the dist-tags
  and the GitHub release to the workflow.

`npm ci` on these lockfiles works with npm 10.8 (Node 20's, which `build` uses) and 11.6, but
npm 11.21 refuses them (`Missing: bufferutil@4.1.0 from lock file`, optional peers of `ws`); only the
`publish` job runs 11.21, and it installs nothing.
