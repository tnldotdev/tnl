import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { nativeTargets } from "../packages/tnl/src/internal/native-targets.ts";
import { npmPackageMetadataSchema } from "./npm-artifacts.ts";
import { parseJSON } from "./validation.ts";

const directoryArgument = process.argv[2];
assert(directoryArgument, "usage: node scripts/verify-tnl-install.ts PACKAGE_DIRECTORY");
const packageDirectory = path.resolve(directoryArgument);
const metadata = parseJSON(
  await readFile(path.join(packageDirectory, "tnl-npm-packages.json"), "utf8"),
  npmPackageMetadataSchema,
  "npm package metadata",
);
const target = nativeTargets.find(
  ({ platform, architecture }) => platform === process.platform && architecture === process.arch,
);
assert(target, `unsupported installation target ${process.platform}-${process.arch}`);
const launcher = metadata.packages.filter((entry) => entry.name === "@tnldotdev/tnl");
const native = metadata.packages.filter((entry) => entry.name === target.packageName);
assert.equal(launcher.length, 1, "expected one launcher package");
assert.equal(native.length, 1, `expected one ${target.packageName} package`);
assert(launcher[0]?.kind === "launcher" && native[0]?.kind === "native");

for (const manager of ["npm", "pnpm"] as const) {
  const consumer = await mkdtemp(path.join(tmpdir(), `tnl-${manager}-consumer-`));
  try {
    // packing checks the launcher dependency map; install the matching native tarball offline.
    await writeFile(
      path.join(consumer, "package.json"),
      JSON.stringify({
        private: true,
        dependencies: {
          "@tnldotdev/tnl": `file:${path.join(packageDirectory, launcher[0].tarball)}`,
        },
        optionalDependencies: {
          [native[0].name]: `file:${path.join(packageDirectory, native[0].tarball)}`,
        },
      }),
    );
    const args =
      manager === "npm"
        ? [
            "install",
            "--offline",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--cache",
            path.join(consumer, ".cache"),
          ]
        : [
            "install",
            "--offline",
            "--ignore-scripts",
            "--store-dir",
            path.join(consumer, ".store"),
          ];
    await run(manager, args, consumer);
    const { stdout } = await run(
      path.join(consumer, "node_modules", ".bin", "tnl"),
      ["version"],
      consumer,
    );
    assert.equal(stdout.trim(), `tnl ${metadata.version} (${metadata.commit})`);
    await assert.rejects(
      () => readFile(path.join(consumer, "node_modules", ".bin", "tnld")),
      /ENOENT/,
    );
    await run(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `
      const [{ tnl }, { defineConfig }, { withTnl }, { default: vite }] = await Promise.all([
        import("@tnldotdev/tnl"), import("@tnldotdev/tnl/config"),
        import("@tnldotdev/tnl/next"), import("@tnldotdev/tnl/vite"),
      ]);
      const config = { tunnel: { allowAllIPs: true } };
      if (tnl.port !== 3000 || tnl.services !== undefined || tnl.dev !== false || typeof tnl.register !== "function" ||
          defineConfig(config) !== config || typeof withTnl !== "function" || typeof vite !== "function") {
        throw new Error("release package exports are invalid");
      }
    `,
      ],
      consumer,
    );
  } finally {
    await rm(consumer, { force: true, recursive: true });
  }
}

async function run(command: string, args: readonly string[], cwd: string) {
  try {
    return await promisify(execFile)(command, args, { cwd, maxBuffer: 10 * 1024 * 1024 });
  } catch (error) {
    if (typeof error === "object" && error !== null) {
      if ("stdout" in error && error.stdout) process.stdout.write(String(error.stdout));
      if ("stderr" in error && error.stderr) process.stderr.write(String(error.stderr));
    }
    throw error;
  }
}
