import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { assertExportTargets, packageManifestSchema } from "./npm-artifacts.ts";
import { verifyNpmConsumer } from "./npm-consumer.ts";
import { parseJSON } from "./validation.ts";
import * as z from "zod";
import { TnlError } from "../../packages/ts/src/errors.ts";

const run = promisify(execFile);
const root = path.resolve(import.meta.dirname, "../..");
const directory = await mkdtemp(path.join(tmpdir(), "tnl-packages-"));
const packageName = "@tnldotdev/tnl";
const workspace = parseJSON(
  await readFile(path.join(root, "package.json"), "utf8"),
  z.looseObject({ devDependencies: z.record(z.string(), z.string()) }),
  "workspace manifest",
);

try {
  await run("npm", ["pack", "--ignore-scripts", "--pack-destination", directory], {
    cwd: path.join(root, "packages", "ts"),
  });
  const filename = (await readdir(directory)).find((entry) => entry.endsWith(".tgz"));
  if (!filename) {
    throw new Error(`${packageName} did not produce a tarball`);
  }
  const tarball = path.join(directory, filename);
  const { stdout: manifestData } = await run("tar", ["-xOzf", tarball, "package/package.json"]);
  const manifest = parseJSON(manifestData, packageManifestSchema, "packed manifest");
  assert.equal(manifest.name, packageName);
  const { stdout: files } = await run("tar", ["-tzf", tarball]);
  assertExportTargets(
    manifest,
    new Set(
      files
        .trim()
        .split("\n")
        .map((file) => file.replace(/^package\//, "")),
    ),
  );
  assert(!JSON.stringify(manifest).includes("workspace:"));

  await writeFile(
    path.join(directory, "package.json"),
    JSON.stringify({
      private: true,
      dependencies: {
        [packageName]: `file:${tarball}`,
        "drizzle-kit": workspace.devDependencies["drizzle-kit"],
        "drizzle-orm": workspace.devDependencies["drizzle-orm"],
      },
    }),
  );
  await run("pnpm", ["install", "--ignore-scripts"], { cwd: directory });
  for (const filename of ["drizzle.config.ts", "installed-drizzle-diagnostics.ts"]) {
    await copyFile(
      path.join(root, "packages/ts/test/fixtures/connections", filename),
      path.join(directory, filename),
    );
  }
  const drizzle = await run(
    process.execPath,
    [
      path.join(directory, "node_modules/drizzle-kit/bin.cjs"),
      "generate",
      "--config",
      path.join(directory, "drizzle.config.ts"),
    ],
    { cwd: directory, env: { ...process.env, TNL_CONNECTION_HANDLE: undefined } },
  ).catch((error: unknown) => {
    if (
      error !== null &&
      typeof error === "object" &&
      "stdout" in error &&
      "stderr" in error &&
      typeof error.stdout === "string" &&
      typeof error.stderr === "string"
    )
      return { stdout: error.stdout, stderr: error.stderr };
    throw error;
  });
  // this package-only check has no connector owner. reaching the owned synchronous
  // diagnostic proves the real drizzle 0.31 commonjs loader evaluated the normal
  // config and package export; the native tier supplies a handle and migrates.
  assert(
    (drizzle.stdout + drizzle.stderr).includes(new TnlError("sdk.connection_unprepared").message),
  );
  await verifyNpmConsumer(directory);
} finally {
  await rm(directory, { force: true, recursive: true });
}
