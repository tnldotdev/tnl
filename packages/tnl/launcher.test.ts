import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { onTestFinished, test } from "vitest";
import { nativePackageName, resolveNativeBinary } from "./dist/internal/launcher.js";
import { nativeTargets } from "./dist/internal/native-targets.js";

const targets = [
  ["darwin", "arm64", "@tnldotdev/tnl-darwin-arm64"],
  ["darwin", "x64", "@tnldotdev/tnl-darwin-x64"],
  ["linux", "arm64", "@tnldotdev/tnl-linux-arm64"],
  ["linux", "x64", "@tnldotdev/tnl-linux-x64"],
] as const;

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
    const manifest = jsonRecord(
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

test("native binary resolution preserves installation checks", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "tnl-launcher-test-"));
  onTestFinished(() => rmSync(directory, { force: true, recursive: true }));
  const manifestPath = path.join(directory, "package.json");
  const options = {
    platform: "linux",
    architecture: "x64",
    resolve: () => manifestPath,
  } satisfies NonNullable<Parameters<typeof resolveNativeBinary>[0]>;
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
  const launcherManifest = jsonRecord(
    readFileSync(new URL("./package.json", import.meta.url), "utf8"),
  );
  rmSync(manifestPath, { force: true });
  const readError = thrownError(() => resolveNativeBinary(options));
  assert.match(readError.message, /failed to read @tnldotdev\/tnl-linux-x64 package manifest/);
  assert(readError.cause instanceof Error);
  writeFileSync(manifestPath, "{");
  const parseError = thrownError(() => resolveNativeBinary(options));
  assert.match(parseError.message, /tnl-linux-x64 package manifest is not valid JSON/);
  assert(parseError.cause instanceof SyntaxError);
  for (const manifest of [null, {}, { version: 1 }]) {
    writeFileSync(manifestPath, JSON.stringify(manifest));
    const shapeError = thrownError(() => resolveNativeBinary(options));
    assert.match(shapeError.message, /tnl-linux-x64 package manifest has an invalid shape/);
    assert(shapeError.cause instanceof TypeError);
  }
  writeFileSync(manifestPath, JSON.stringify({ version: "1.2.3" }));
  assert.throws(() => resolveNativeBinary(options), /does not match/);
  writeFileSync(manifestPath, JSON.stringify({ version: launcherManifest.version }));
  mkdirSync(path.join(directory, "bin"));
  const binary = path.join(directory, "bin", "tnl");
  writeFileSync(binary, "", { mode: 0o600 });
  assert.throws(() => resolveNativeBinary(options), /does not contain an executable/);
  chmodSync(binary, 0o700);
  assert.equal(resolveNativeBinary(options), binary);
});

test("launcher emits one safe line for a manifest value containing control characters", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "tnl-launcher-output-test-"));
  onTestFinished(() => rmSync(directory, { force: true, recursive: true }));
  const internalDirectory = path.join(directory, "dist", "internal");
  const binDirectory = path.join(directory, "dist", "bin");
  mkdirSync(internalDirectory, { recursive: true });
  mkdirSync(binDirectory, { recursive: true });
  cpSync(
    new URL("./dist/internal/launcher.js", import.meta.url),
    path.join(internalDirectory, "launcher.js"),
  );
  cpSync(
    new URL("./dist/internal/native-targets.js", import.meta.url),
    path.join(internalDirectory, "native-targets.js"),
  );
  const launcher = path.join(binDirectory, "tnl.js");
  cpSync(new URL("./dist/bin/tnl.js", import.meta.url), launcher);
  writeFileSync(
    path.join(directory, "package.json"),
    JSON.stringify({ type: "module", version: "1.0.0" }),
  );
  const packageName = nativePackageName(process.platform, process.arch);
  const nativeDirectory = path.join(directory, "node_modules", packageName);
  mkdirSync(nativeDirectory, { recursive: true });
  writeFileSync(
    path.join(nativeDirectory, "package.json"),
    JSON.stringify({ name: packageName, version: "2.0.0\ninjected output" }),
  );

  const result = spawnSync(process.execPath, [launcher], { encoding: "utf8" });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /^tnl: [^\r\n]*\n$/);
  for (const character of result.stderr.slice(0, -1)) {
    const codePoint = character.codePointAt(0);
    assert(codePoint !== undefined && codePoint > 0x1f && (codePoint < 0x7f || codePoint > 0x9f));
  }
  assert.doesNotMatch(result.stderr, /injected output/);
});

test("rejects unsupported targets", () => {
  assert.throws(
    () => nativePackageName("win32", "x64"),
    /unsupported platform win32-x64; tnl supports macOS and Linux on arm64 and x64/,
  );
});

function jsonRecord(serialized: string): Record<string, unknown> {
  const value = JSON.parse(serialized) as unknown;
  assert(value !== null && typeof value === "object" && !Array.isArray(value));
  return value as Record<string, unknown>;
}

function thrownError(callback: () => unknown): Error {
  let thrown: unknown;
  try {
    callback();
  } catch (error) {
    thrown = error;
  }
  assert(thrown instanceof Error);
  return thrown;
}
