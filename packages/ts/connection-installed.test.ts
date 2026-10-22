import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { createServer as createTLSServer } from "node:https";
import { mkdir, mkdtemp, realpath, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { expect, test } from "vitest";
import { key, cert } from "./fixtures/workload_tls.js";

const run = promisify(execFile);

test("installed ESM and CommonJS connections use verified owned HTTP transport on Node and actual Bun", async () => {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), "tnl-installed-transport-")));
  const privateDirectory = path.join(directory, "private");
  await mkdir(privateDirectory, { mode: 0o700 });
  const visits: string[] = [];
  const names: string[] = [];
  const tls = createTLSServer({ key, cert }, (request, response) => {
    expect(request.headers.host).toBe("localhost:8443");
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      visits.push(Buffer.concat(chunks).toString());
      if (request.url === "/drop") response.destroy();
      else if (request.url === "/redirect")
        response.writeHead(302, { location: "https://outside.tnl.invalid/" }).end();
      else response.end(Buffer.concat(chunks));
    });
  });
  tls.on("secureConnection", (socket) => {
    if ("servername" in socket && typeof socket.servername === "string")
      names.push(socket.servername);
  });
  await new Promise<void>((resolve) => tls.listen(0, "127.0.0.1", resolve));
  const address = tls.address();
  if (address === null || typeof address === "string") throw new Error("missing TLS listener");
  const project = {
    dev: false,
    namespace: "team.example",
    services: {
      api: {
        protocol: "http",
        namespace: "team.example",
        hostname: "localhost",
        port: 8443,
        public: false,
        url: "https://localhost:8443",
      },
    },
  };
  const ipc = createServer((request, response) => {
    request.resume();
    request.on("end", () =>
      response.writeHead(200, { "content-type": "application/json" }).end(
        JSON.stringify({
          schema: 1,
          public_runtime: project,
          connection: {
            schema: 1,
            protocol: "http",
            host: "127.0.0.1",
            port: address.port,
            url: "https://localhost:8443",
            ssl: { servername: "localhost", rejectUnauthorized: true, ca: cert },
            expires_at: new Date(Date.now() + 60_000).toISOString(),
            transport_id: `ctg_${"a".repeat(22)}`,
          },
        }),
      ),
    );
  });
  await new Promise<void>((resolve) => ipc.listen(0, "127.0.0.1", resolve));
  try {
    const local = ipc.address();
    if (local === null || typeof local === "string") throw new Error("missing IPC listener");
    const handle = path.join(privateDirectory, "handle.json");
    await run("npm", ["pack", "--ignore-scripts", "--pack-destination", directory], {
      cwd: new URL("./", import.meta.url),
    });
    const tarball = (await readdir(directory)).find((file) => file.endsWith(".tgz"));
    if (tarball === undefined) throw new Error("missing package tarball");
    const { stdout: managerVersion } = await run("pnpm", ["--version"], {
      cwd: new URL("../../", import.meta.url),
    });
    expect(managerVersion.trim()).toMatch(/^\d+\.\d+\.\d+$/);
    await writeFile(
      path.join(directory, "package.json"),
      JSON.stringify({
        private: true,
        type: "module",
        packageManager: `pnpm@${managerVersion.trim()}`,
        dependencies: { "@tnldotdev/tnl": `file:${path.join(directory, tarball)}` },
      }),
    );
    await writeFile(
      path.join(directory, "pnpm-workspace.yaml"),
      "packages: []\nautoInstallPeers: false\n",
    );
    // use an empty store so developer caches cannot hide missing install inputs.
    await run(
      "pnpm",
      ["install", "--ignore-scripts", "--store-dir", path.join(directory, "store")],
      { cwd: directory, timeout: 45_000 },
    ).catch((cause: unknown) => {
      const output =
        cause !== null &&
        typeof cause === "object" &&
        "stdout" in cause &&
        typeof cause.stdout === "string"
          ? cause.stdout
          : "";
      throw new Error(`installed consumer setup failed\n${output}`, { cause });
    });
    await writeFile(
      handle,
      JSON.stringify({
        schema: 1,
        url: `http://127.0.0.1:${local.port}`,
        key: "a".repeat(64),
        directory,
        config_digest: "c".repeat(64),
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        executable: "/unused/native",
      }),
      { mode: 0o600 },
    );
    const script = `
      import assert from 'node:assert/strict';
      import {createRequire} from 'node:module';
      import {tnl as esm} from '@tnldotdev/tnl';
      const {tnl: cjs} = createRequire(import.meta.url)('@tnldotdev/tnl');
      const sdkRequire = createRequire(createRequire(import.meta.url).resolve('@tnldotdev/tnl'));
      const {Agent} = sdkRequire('undici/index.js');
      let probes = 0;
      const dispatcher = new Agent({connect(_options, callback){ probes++; callback(new Error('dispatcher probe'), null); }});
      await assert.rejects(globalThis.fetch('https://127.0.0.1:${address.port}/', {dispatcher, signal:AbortSignal.timeout(1000)}));
      assert.equal(probes, 'Bun' in globalThis ? 0 : 1);
      await dispatcher.destroy();
      for (const tnl of [esm, cjs]) {
        const handle = tnl.connect('api');
        assert.equal(Object.getOwnPropertyDescriptor(handle, 'then').enumerable, false);
        const settings = await handle;
        assert.equal(settings.then, undefined);
        assert.equal(tnl.services.api.namespace, 'team.example');
        assert.equal(tnl.services.worker?.hostname, undefined);
        assert.equal(JSON.parse(JSON.stringify(tnl.services)).api.hostname, 'localhost');
        const response = await settings.fetch('/echo', {method:'POST', body:new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('once')); c.close()}})});
        assert.equal(response.url, 'https://localhost:8443/echo');
        assert.equal(await response.text(), 'once');
        const redirect = await settings.fetch('/redirect', {redirect:'follow'});
        assert.equal(redirect.status, 302);
        await redirect.body?.cancel();
        await assert.rejects(settings.fetch('/drop', {method:'POST', body:'drop-once'}));
      }
      console.log('verified owned transport');
    `;
    const entry = path.join(directory, "consumer.mjs");
    await writeFile(entry, script);
    for (const runtime of [process.execPath, "bun"]) {
      const result = await run(runtime, [entry], {
        cwd: directory,
        timeout: 20_000,
        env: { ...process.env, TNL_CONNECTION_HANDLE: handle, TNL_PROJECT_RUNTIME: undefined },
      });
      expect(result.stdout.trim()).toBe("verified owned transport");
    }
    expect(visits).toEqual(Array.from({ length: 4 }, () => ["once", "", "drop-once"]).flat());
    expect(names.length).toBeGreaterThan(0);
    expect(names.every((name) => name === "localhost")).toBe(true);
  } finally {
    tls.closeAllConnections();
    ipc.closeAllConnections();
    await Promise.all([
      new Promise<void>((resolve) => tls.close(() => resolve())),
      new Promise<void>((resolve) => ipc.close(() => resolve())),
    ]);
    await rm(directory, { recursive: true, force: true });
  }
}, 60_000);
