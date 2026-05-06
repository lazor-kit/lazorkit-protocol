<!--
Keep this short. The squash-merge commit body uses the PR description, so
prose written here ends up in `git log`. Aim for what a reviewer (or your
future self bisecting) needs to understand the change.
-->

## Summary

<!-- 1–3 bullets: what this PR does and the user-visible reason. -->

## Changes

<!-- Per-file or per-area highlights. Skip if `Summary` already covers it. -->

## Test plan

<!-- Checkboxes for what was verified. Include the actual commands / counts. -->

- [ ] CI passes
- [ ] `cargo test --features devnet` passes
- [ ] `npm test` in `tests-sdk` (against a live validator) passes
- [ ] Updates docs / CHANGELOG when public behavior changes

## Audit / security notes

<!-- Skip if N/A. Otherwise: error codes touched, account layout changes,
authority/auth flow changes, anything that needs Accretion follow-up. -->

## Related

<!-- Linked issues, prior PRs, audit findings, design docs. -->
