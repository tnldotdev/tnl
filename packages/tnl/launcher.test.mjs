import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { nativePackageName, resolveNativeBinary } from "./lib/launcher.mjs";
import { nativeTargets } from "./lib/native-targets.mjs";

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

test("catalog matches independent targets and native manifests", () => {
  assert.deepEqual(
    nativeTargets.map(({ platform, architecture, packageName }) => [
      platform,
      architecture,
      packageName,
    ]),
    targets,
  );
  assert(Object.isFrozen(nativeTargets));
  for (const [platform, architecture, name] of targets) {
    const manifest = JSON.parse(
      readFileSync(
        new URL(`./native/${platform}-${architecture}/package.json`, import.meta.url),
        "utf8",
      ),
    );
    assert.equal(manifest.name, name);
    assert.deepEqual(manifest.os, [platform]);
    assert.deepEqual(manifest.cpu, [architecture]);
  }
});

test("native binary resolution preserves installation checks", (t) => {
  const directory = mkdtempSync(path.join(tmpdir(), "tnl-launcher-test-"));
  t.after(() => rmSync(directory, { force: true, recursive: true }));
  const manifestPath = path.join(directory, "package.json");
  const options = { platform: "linux", architecture: "x64", resolve: () => manifestPath };
  assert.throws(
    () =>
      resolveNativeBinary({
        ...options,
        resolve: () => {
          throw Object.assign(new Error("missing"), { code: "MODULE_NOT_FOUND" });
        },
      }),
    /without disabling optional dependencies/,
  );
  const launcherManifest = JSON.parse(
    readFileSync(new URL("./package.json", import.meta.url), "utf8"),
  );
  writeFileSync(manifestPath, JSON.stringify({ version: "wrong-version" }));
  assert.throws(() => resolveNativeBinary(options), /does not match/);
  writeFileSync(manifestPath, JSON.stringify({ version: launcherManifest.version }));
  mkdirSync(path.join(directory, "bin"));
  const binary = path.join(directory, "bin", "tnl");
  writeFileSync(binary, "", { mode: 0o600 });
  assert.throws(() => resolveNativeBinary(options), /does not contain an executable/);
  chmodSync(binary, 0o700);
  assert.equal(resolveNativeBinary(options), binary);
});

test("rejects unsupported targets", () => {
  assert.throws(
    () => nativePackageName("win32", "x64"),
    /unsupported platform win32-x64; tnl supports macOS and Linux on arm64 and x64/,
  );
});
