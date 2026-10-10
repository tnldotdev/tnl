import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { packageManifestSchema } from "./npm-artifacts.ts";
import { parseJSON } from "./validation.ts";

const run = promisify(execFile);
const root = path.resolve(import.meta.dirname, "..");
const directory = await mkdtemp(path.join(tmpdir(), "tnl-packages-"));
const packageName = "@tnldotdev/tnl";
const entrypoints = [
  "@tnldotdev/tnl",
  "@tnldotdev/tnl/config",
  "@tnldotdev/tnl/next",
  "@tnldotdev/tnl/vite",
];

try {
  await run("npm", ["pack", "--ignore-scripts", "--pack-destination", directory], {
    cwd: path.join(root, "packages", "tnl"),
  });
  const filename = (await readdir(directory)).find((entry) => entry.endsWith(".tgz"));
  if (!filename) {
    throw new Error(`${packageName} did not produce a tarball`);
  }
  const tarball = path.join(directory, filename);
  const { stdout: manifestData } = await run("tar", ["-xOzf", tarball, "package/package.json"]);
  const manifest = parseJSON(manifestData, packageManifestSchema, "packed manifest");
  assert.equal(manifest.name, packageName);
  assert(manifest.exports, "package must define public exports");
  assert.deepEqual(Object.keys(manifest.exports).sort(), [".", "./config", "./next", "./vite"]);
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
  await run(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `const modules = await Promise.all(${JSON.stringify(entrypoints)}.map((name) => import(name)));
 if (modules[0].tnl?.port !== 3000 || typeof modules[0].tnl?.prepare !== "function") throw new Error("missing root app integration");
if (typeof modules[1].defineConfig !== "function") throw new Error("missing config export");
if (typeof modules[2].withTnl !== "function") throw new Error("missing Next.js export");
if (typeof modules[3].default !== "function") throw new Error("missing Vite export");`,
    ],
    { cwd: directory },
  );
} finally {
  await rm(directory, { force: true, recursive: true });
}
