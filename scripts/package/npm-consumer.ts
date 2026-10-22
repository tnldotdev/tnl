import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { build } from "esbuild";

const run = promisify(execFile);

// exercise the public API explicitly, independently of the manifest's target checks.
// both source packs and actual release tarballs use this installed-consumer check.
export async function verifyNpmConsumer(directory: string): Promise<void> {
  const licenses = await readFile(
    path.join(directory, "node_modules/@tnldotdev/tnl/dist/third-party-licenses.txt"),
    "utf8",
  );
  for (const name of [
    "@vercel/oidc",
    "@vercel/cli-config",
    "@vercel/cli-exec",
    "jose",
    "zod",
    "undici",
  ]) {
    assert(licenses.includes(`package: ${name}\n`), `missing node dependency license: ${name}`);
  }
  await run(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `
      import assert from "node:assert/strict";
      import { createRequire } from "node:module";
      const require = createRequire(import.meta.url);
      const [esm, { defineConfig }, { withTnl }, { default: vite }, workloadESM] = await Promise.all([
        import("@tnldotdev/tnl"), import("@tnldotdev/tnl/config"),
        import("@tnldotdev/tnl/next"), import("@tnldotdev/tnl/vite"),
        import("@tnldotdev/tnl/workload"),
      ]);
      const config = { services: { web: { protocol: "http", target: { type: "app" } } } };
      assert.equal(esm.tnl.port, 3000);
      assert.throws(() => esm.tnl.services, error => error instanceof esm.TnlError && error.code === "sdk.service_unprepared");
      assert.equal(esm.tnl.dev, false);
      assert.equal(typeof esm.tnl.prepare, "function");
      assert.equal(typeof esm.tnl.open, "function");
      assert.equal(defineConfig(config), config);
      assert.equal(typeof withTnl, "function");
      assert.equal(typeof vite, "function");
      assert.equal(typeof workloadESM.configureWorkload, "function");
      const cjs = require("@tnldotdev/tnl");
      assert.deepEqual(Object.keys(cjs).sort(), Object.keys(esm).sort());
      assert.equal(cjs.TnlError, esm.TnlError);
      const workload = require("@tnldotdev/tnl/workload");
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
          !/internal\/(?:connector\/(?!awaitable_connection\.)|native\/)|@vercel|zod|undici|index\.cjs$/.test(
            input,
          ),
      ),
    );
  }
  for (const contents of [
    'import {configureWorkload} from "@tnldotdev/tnl/workload"; configureWorkload({name:"worker", token:async()=>"secret"});',
    'globalThis.workload = require("@tnldotdev/tnl/workload");',
  ]) {
    await assert.rejects(
      build({
        stdin: { contents, resolveDir: directory },
        bundle: true,
        write: false,
        platform: "browser",
        logLevel: "silent",
      }),
      /Could not resolve "@tnldotdev\/tnl\/workload"/,
    );
  }
}
