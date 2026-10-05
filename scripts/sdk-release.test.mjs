// Tests of the decisions in scripts/sdk-release.mjs: SemVer order and which dist-tags a
// release moves. They run offline: node --test scripts/sdk-release.test.mjs
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  assertPublishKeepsOrder,
  compareVersions,
  distTagDecision,
  isPrerelease,
  NEVER_MOVE,
  PACKAGES,
  PUBLISH_TAG,
} from "./sdk-release.mjs";

const SDK = "@lazorkit/sdk";
const LEGACY = "@lazorkit/sdk-legacy";

describe("compareVersions", () => {
  // Each version is lower than the next one (the SemVer 2.0.0 precedence example, and ours).
  const ordered = [
    "0.3.2",
    "1.0.0-alpha",
    "1.0.0-alpha.1",
    "1.0.0-alpha.beta",
    "1.0.0-beta",
    "1.0.0-beta.2",
    "1.0.0-beta.11",
    "1.0.0-rc.1",
    "1.0.0-rc.6",
    "1.0.0-rc.10",
    "1.0.0",
    "1.3.5",
    "1.4.0",
    "2.0.0-rc.1",
    "2.0.0",
  ];

  it("orders versions by SemVer precedence", () => {
    for (let i = 0; i < ordered.length; i++) {
      for (let j = 0; j < ordered.length; j++) {
        const expected = Math.sign(i - j);
        assert.equal(compareVersions(ordered[i], ordered[j]), expected, `${ordered[i]} vs ${ordered[j]}`);
      }
    }
  });

  it("rejects what is not a SemVer version", () => {
    assert.throws(() => compareVersions("1.0", "1.0.0"));
    assert.throws(() => compareVersions("v1.0.0", "1.0.0"));
    assert.throws(() => compareVersions("1.0.0+build", "1.0.0"));
  });

  it("tells pre-releases apart", () => {
    assert.equal(isPrerelease("1.0.0-rc.6"), true);
    assert.equal(isPrerelease("1.4.0"), false);
  });
});

describe("distTagDecision", () => {
  const decide = (name, version, tag, current) => distTagDecision(name, version, tag, current).move;

  it("never moves @lazorkit/sdk-legacy's latest", () => {
    assert.throws(() => distTagDecision(LEGACY, "1.5.0", "latest", "0.3.2"), /refusing to move/);
    assert.ok(NEVER_MOVE.get(LEGACY).has("latest"));
    assert.deepEqual(PACKAGES["sdk-legacy"].distTags, ["next"]);
  });

  it("moves next forward, never back", () => {
    assert.equal(decide(LEGACY, "1.4.1", "next", "1.4.0"), true);
    assert.equal(decide(LEGACY, "2.0.0-rc.1", "next", "1.4.0"), true);
    assert.equal(decide(LEGACY, "1.3.5", "next", "1.4.0"), false);
    assert.equal(decide(LEGACY, "1.4.0", "next", "1.4.0"), false);
  });

  it("follows @lazorkit/sdk's release candidates with latest within the major", () => {
    assert.equal(decide(SDK, "1.0.0-rc.7", "latest", "1.0.0-rc.6"), true);
    assert.equal(decide(SDK, "1.0.0", "latest", "1.0.0-rc.6"), true);
    assert.equal(decide(SDK, "1.0.1", "latest", "1.0.0"), true);
    assert.equal(decide(SDK, "1.1.0", "latest", "1.0.1"), true);
  });

  it("does not move latest from a stable version to a pre-release", () => {
    assert.equal(decide(SDK, "1.1.0-rc.1", "latest", "1.0.0"), false);
  });

  it("does not move latest to a new major, stable or pre-release", () => {
    for (const [version, current] of [
      ["2.0.0", "1.0.0"],
      ["2.0.0-rc.1", "1.0.0-rc.6"],
      ["2.0.0-rc.1", "1.0.0"],
      ["2.0.0", "1.9.9-rc.1"],
    ]) {
      const d = distTagDecision(SDK, version, "latest", current);
      assert.equal(d.move, false, `${current} -> ${version}`);
      assert.match(d.why, /new major.*by hand/);
    }
  });

  it("moves next to a new major", () => {
    assert.equal(decide(SDK, "2.0.0-rc.1", "next", "1.0.0-rc.6"), true);
  });

  it("never moves a tag back", () => {
    assert.equal(decide(SDK, "1.0.0-rc.7", "latest", "1.0.0-rc.8"), false);
    assert.equal(decide(SDK, "1.0.0-rc.7", "next", "1.0.0-rc.8"), false);
  });

  it("sets a tag that is not there yet", () => {
    assert.equal(decide(SDK, "1.0.0-rc.7", "latest", undefined), true);
  });
});

describe("assertPublishKeepsOrder", () => {
  it("allows a version above next, or with next unset", () => {
    assert.doesNotThrow(() => assertPublishKeepsOrder(SDK, "1.0.0-rc.7", { next: "1.0.0-rc.6", latest: "1.0.0-rc.6" }));
    assert.doesNotThrow(() => assertPublishKeepsOrder(SDK, "1.0.0-rc.7", { latest: "1.0.0-rc.6" }));
  });

  it("refuses a version below next, as when a higher one was published while this run waited", () => {
    assert.equal(PUBLISH_TAG, "next");
    assert.throws(
      () => assertPublishKeepsOrder(SDK, "1.0.0-rc.7", { next: "1.0.0-rc.8", latest: "1.0.0-rc.8" }),
      /lower than next \(1\.0\.0-rc\.8\)/,
    );
    assert.throws(() => assertPublishKeepsOrder(LEGACY, "1.3.5", { next: "1.4.0", latest: "0.3.2" }), /would move next back/);
  });
});
