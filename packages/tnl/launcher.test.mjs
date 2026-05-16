import assert from "node:assert/strict";
import { test } from "node:test";
import { nativePackageName } from "./lib/launcher.mjs";

const targets = [
  ["darwin", "arm64", "@tnldotdev/tnl-darwin-arm64"],
  ["darwin", "x64", "@tnldotdev/tnl-darwin-x64"],
  ["linux", "arm64", "@tnldotdev/tnl-linux-arm64"],
  ["linux", "x64", "@tnldotdev/tnl-linux-x64"],
];

test("selects the native package for each supported target", () => {
  for (const [platform, architecture, expected] of targets) {
    assert.equal(nativePackageName(platform, architecture), expected);
  }
});

test("rejects unsupported targets", () => {
  assert.throws(
    () => nativePackageName("win32", "x64"),
    /unsupported platform win32-x64; tnl supports macOS and Linux on arm64 and x64/,
  );
});
