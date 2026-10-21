import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { packageManifestSchema } from "./npm-artifacts.ts";
import { parseJSON } from "./validation.ts";
import { build } from "esbuild";
import * as z from "zod";
import { TnlError } from "../packages/ts/src/errors.ts";

const run = promisify(execFile);
const root = path.resolve(import.meta.dirname, "..");
const directory = await mkdtemp(path.join(tmpdir(), "tnl-packages-"));
const packageName = "@tnldotdev/tnl";
const entrypoints = [
  "@tnldotdev/tnl",
  "@tnldotdev/tnl/config",
  "@tnldotdev/tnl/next",
  "@tnldotdev/tnl/vite",
  "@tnldotdev/tnl/workload",
];
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
  const { stdout: licenses } = await run("tar", [
    "-xOzf",
    tarball,
    "package/dist/third-party-licenses.txt",
  ]);
  for (const name of [
    "@vercel/oidc",
    "@vercel/cli-config",
    "@vercel/cli-exec",
    "jose",
    "zod",
    "undici",
  ])
    assert(licenses.includes(`package: ${name}\n`));
  assert.equal(manifest.name, packageName);
  assert(manifest.exports, "package must define public exports");
  assert.deepEqual(Object.keys(manifest.exports).sort(), [
    ".",
    "./config",
    "./next",
    "./vite",
    "./workload",
  ]);
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
  await copyFile(
    path.join(root, "packages/ts/fixtures/connections/drizzle.config.ts"),
    path.join(directory, "drizzle.config.ts"),
  );
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
  // this package-only check has no native owner. reaching the owned synchronous
  // diagnostic proves the real drizzle 0.31 commonjs loader evaluated the normal
  // config and package export; the native tier supplies a handle and migrates.
  assert(
    (drizzle.stdout + drizzle.stderr).includes(new TnlError("sdk.connection_unprepared").message),
  );
  await run(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `const modules = await Promise.all(${JSON.stringify(entrypoints)}.map((name) => import(name)));
 if (modules[0].tnl?.port !== 3000 || typeof modules[0].tnl?.prepare !== "function" || typeof modules[0].tnl?.open !== "function") throw new Error("missing root app integration");
if (typeof modules[1].defineConfig !== "function") throw new Error("missing config export");
if (typeof modules[2].withTnl !== "function") throw new Error("missing Next.js export");
if (typeof modules[3].default !== "function") throw new Error("missing Vite export");
if (typeof modules[4].configureWorkload !== "function") throw new Error("missing server workload export");`,
    ],
    { cwd: directory },
  );
  await run(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `
    import assert from "node:assert/strict";
    import { createRequire } from "node:module";
    const require = createRequire(import.meta.url);
    const esm = await import("@tnldotdev/tnl");
    const cjs = require("@tnldotdev/tnl");
    assert.deepEqual(Object.keys(cjs).sort(), Object.keys(esm).sort());
    assert.equal(cjs.TnlError, esm.TnlError);
    const workload = require("@tnldotdev/tnl/workload");
    const workloadESM = await import("@tnldotdev/tnl/workload");
    assert.deepEqual(Object.keys(workload).sort(), Object.keys(workloadESM).sort());
    for (const root of [esm, cjs]) {
      const handle = root.tnl.connect("database");
      assert.equal(typeof handle.then, "function");
      assert.equal(Object.getOwnPropertyDescriptor(handle, "then").enumerable, false);
      assert.throws(() => ({ ...handle }), error => error instanceof root.TnlError && error.code === "sdk.connection_unprepared");
    }
    const token = async () => "request-scoped-assertion";
    workloadESM.configureWorkload({name: "worker", token});
    workload.configureWorkload({name: "worker", token});
    assert.throws(() => workload.configureWorkload({name: "worker", token: async () => "replacement"}), error => error instanceof esm.TnlError && error.code === "sdk.workload_required");
  `,
    ],
    { cwd: directory, env: { ...process.env, TNL_CONNECTION_HANDLE: undefined } },
  );
  await run(
    process.execPath,
    [
      "--conditions=browser",
      "--input-type=module",
      "--eval",
      `
    import assert from "node:assert/strict";
    import { createRequire } from "node:module";
    const require = createRequire(import.meta.url);
    const esm = await import("@tnldotdev/tnl");
    const cjs = require("@tnldotdev/tnl");
    assert.deepEqual(Object.keys(cjs).sort(), Object.keys(esm).sort());
    for (const root of [esm, cjs]) {
      const handle = root.tnl.connect("database");
      assert.throws(() => ({ ...handle }), error => error instanceof root.TnlError && error.code === "sdk.connection_server_only");
      await assert.rejects(Promise.resolve(handle), error => error instanceof root.TnlError && error.code === "sdk.connection_server_only");
    }
  `,
    ],
    { cwd: directory },
  );
  for (const contents of [
    'import {tnl} from "@tnldotdev/tnl"; globalThis.project = tnl;',
    'globalThis.project = require("@tnldotdev/tnl").tnl;',
  ]) {
    const browser = await build({
      stdin: { contents, resolveDir: directory },
      bundle: true,
      write: false,
      platform: "browser",
      format: "iife",
      metafile: true,
    });
    assert(
      Object.keys(browser.metafile.inputs).every(
        (input) =>
          !/internal\/(connection|launcher|workload)|@vercel|zod|undici|index\.cjs$/.test(input),
      ),
    );
  }
  await assert.rejects(
    build({
      stdin: {
        contents:
          'import {configureWorkload} from "@tnldotdev/tnl/workload"; configureWorkload({name:"worker", token:async()=>"secret"});',
        resolveDir: directory,
      },
      bundle: true,
      write: false,
      platform: "browser",
      logLevel: "silent",
    }),
  );
} finally {
  await rm(directory, { force: true, recursive: true });
}
