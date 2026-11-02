import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { assertExportTargets, packageManifestSchema } from "./npm-artifacts.ts";
import { verifyNpmConsumer } from "./npm-consumer.ts";
import { parseJSON } from "./validation.ts";

const run = promisify(execFile);
const root = path.resolve(import.meta.dirname, "../..");
const directory = await mkdtemp(path.join(tmpdir(), "tnl-packages-"));
const packageName = "@tnldotdev/tnl";

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
      },
    }),
  );
  await run("pnpm", ["install", "--ignore-scripts"], { cwd: directory });
  await verifyNpmConsumer(directory);
} finally {
  await rm(directory, { force: true, recursive: true });
}
