import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { nativeTargets } from "../../packages/ts/src/internal/native/native-targets.ts";
import { npmPackageMetadataSchema } from "./npm-artifacts.ts";
import { verifyNpmConsumer } from "./npm-consumer.ts";
import { parseJSON } from "./validation.ts";

const directoryArgument = process.argv[2];
assert(directoryArgument, "usage: node scripts/package/verify-tnl-install.ts PACKAGE_DIRECTORY");
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
const nativeTarballs = Object.fromEntries(
  metadata.packages
    .filter((entry) => entry.kind === "native")
    .map((entry) => [entry.name, `file:${path.join(packageDirectory, entry.tarball)}`]),
);

for (const manager of ["npm", "pnpm"] as const) {
  const consumer = await mkdtemp(path.join(tmpdir(), `tnl-${manager}-consumer-`));
  try {
    // install unmodified release tarballs. all native dependencies resolve locally;
    // third-party runtime dependencies use the package manager's normal registry.
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
        overrides: nativeTarballs,
      }),
    );
    if (manager === "pnpm") {
      await writeFile(
        path.join(consumer, "pnpm-workspace.yaml"),
        JSON.stringify({ packages: [], autoInstallPeers: false, overrides: nativeTarballs }),
      );
    }
    const args =
      manager === "npm"
        ? [
            "install",
            "--ignore-scripts",
            "--legacy-peer-deps",
            "--no-audit",
            "--no-fund",
            "--cache",
            path.join(consumer, ".cache"),
          ]
        : ["install", "--ignore-scripts", "--store-dir", path.join(consumer, ".store")];
    await run(manager, args, consumer);
    const { stdout } = await run(
      path.join(consumer, "node_modules", ".bin", "tnl"),
      ["version"],
      consumer,
    );
    assert.equal(stdout, `tnl ${metadata.version} (${metadata.commit})\n`);
    await assert.rejects(
      () => readFile(path.join(consumer, "node_modules", ".bin", "tnld")),
      /ENOENT/,
    );
    await verifyNpmConsumer(consumer);
    process.stdout.write(
      `${manager}: release launcher, native version and public exports passed\n`,
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
