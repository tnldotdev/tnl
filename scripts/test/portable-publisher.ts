import { spawn } from "node:child_process";
import { createReadStream } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer, request as httpsRequest } from "node:https";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { setTimeout as pause } from "node:timers/promises";
import { parseArgs } from "node:util";
import { build } from "esbuild";
import { chromium } from "playwright";
import * as z from "zod";
import {
  check,
  fixtureCall,
  fixtureSchema,
  type PublisherFixture,
} from "../../packages/ts/test/portable-publisher-integration/fixture.ts";
import { buildGoWasm } from "../build/go-wasm.ts";
import {
  publisherChromeArguments,
  publisherWorkerdConfiguration,
} from "./portable-publisher-config.ts";

const { values } = parseArgs({
  options: {
    fixture: { type: "string" },
    runtime: { type: "string", default: "all" },
  },
});
check(values.fixture !== undefined, "pass --fixture with the private daemon descriptor");
const runtime = z.enum(["all", "chrome", "workerd"]).parse(values.runtime);
const descriptor = await stat(values.fixture);
check(
  descriptor.isFile() && (descriptor.mode & 0o077) === 0 && descriptor.size < 4 << 20,
  "fixture must be a bounded private regular file (0600)",
);
const fixture = fixtureSchema.parse(JSON.parse(await readFile(values.fixture, "utf8")));
const root = path.resolve(import.meta.dirname, "../..");
const source = path.join(root, "packages/ts/test/portable-publisher-integration");
const productionWasm = path.join(root, "packages/ts/dist/wasm/publisher.wasm");
check((await stat(productionWasm)).size > 1, "build the actual Go/WASM artifact first");
const temporary = process.platform === "darwin" ? path.join(tmpdir(), "opencode") : tmpdir();
await mkdir(temporary, { recursive: true, mode: 0o700 });
const directory = await mkdtemp(path.join(temporary, "tnl-portable-publisher-"));
const wasm = path.join(directory, "tnl-publisher-fixture.wasm");
const connectorWasm = path.join(directory, "tnl-connector-fixture.wasm");
const lifetime = new AbortController();
const stop = () => lifetime.abort();
process.once("SIGINT", stop);
process.once("SIGTERM", stop);
// fixture HTTPS uses the disposable CA. production/public TLS is independently
// verified by the Go visitor and the connector's Go TLS implementation.
const apiFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const outgoing = new Request(input, init);
  const body = await outgoing.text();
  return new Promise<Response>((resolve, reject) => {
    const request = httpsRequest(
      outgoing.url,
      {
        method: outgoing.method,
        headers: Object.fromEntries(outgoing.headers),
        ca: fixture.control_root_pem,
        family: 4,
        signal: outgoing.signal,
      },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (bytes: Buffer) => {
          size += bytes.length;
          if (size > 16_384) response.destroy(new Error("fixture API response exceeded bound"));
          else chunks.push(bytes);
        });
        response.once("error", reject);
        response.once("end", () => {
          resolve(new Response(Buffer.concat(chunks), { status: response.statusCode ?? 502 }));
        });
      },
    );
    request.once("error", reject);
    request.end(body);
  });
};

async function chromeSmoke(configuration: PublisherFixture) {
  const output = path.join(directory, "browser");
  const bundled = await build({
    entryPoints: [path.join(source, "browser.ts")],
    outdir: output,
    bundle: true,
    write: false,
    splitting: true,
    format: "esm",
    platform: "browser",
    conditions: ["browser"],
    chunkNames: "chunks/[name]-[hash]",
    tsconfigRaw: {},
    plugins: [packagedGoRuntime()],
  });
  const assets = new Map(
    bundled.outputFiles.map((file) => [
      "/browser/" + path.relative(output, file.path).split(path.sep).join("/"),
      file.contents,
    ]),
  );
  const server = createServer(
    {
      cert: configuration.runner_certificate_pem,
      key: configuration.runner_private_key_pem,
    },
    (request, response) => {
      response.setHeader("Cache-Control", "no-store");
      if (request.url === "/") {
        response
          .writeHead(200, { "Content-Type": "text/html" })
          .end(
            '<!doctype html><script type="module">import * as fixture from "/browser/browser.js"; globalThis.publisherFixture = fixture;</script>',
          );
      } else if (
        request.url?.endsWith("/wasm/publisher.wasm") ||
        request.url?.endsWith("/wasm/connector.wasm")
      ) {
        response.writeHead(200, { "Content-Type": "application/wasm" });
        const stream = createReadStream(
          request.url.endsWith("/wasm/publisher.wasm") ? wasm : connectorWasm,
        );
        stream.on("error", () => response.destroy());
        response.on("close", () => stream.destroy());
        stream.pipe(response);
      } else {
        const asset = assets.get(request.url ?? "");
        if (asset === undefined) response.writeHead(404).end();
        else response.writeHead(200, { "Content-Type": "text/javascript" }).end(asset);
      }
    },
  );
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const browser = await chromium.launch({
      channel: "chrome",
      args: publisherChromeArguments(configuration),
    });
    const interrupted = () => {
      void browser.close();
    };
    lifetime.signal.addEventListener("abort", interrupted, { once: true });
    try {
      const page = await browser.newPage();
      page.on("console", (message) => {
        if (/^publisher fixture phase: [a-z-]+$/.test(message.text())) console.log(message.text());
      });
      const network: string[] = [];
      page.on("response", (response) => {
        if (response.url().startsWith(configuration.control_url)) {
          const url = new URL(response.url());
          network.push(`${response.status()} ${url.pathname}`);
          if (network.length > 64) network.shift();
        }
      });
      page.on("requestfailed", (request) => {
        const url = new URL(request.url());
        network.push(`failed ${request.method()} ${url.pathname}`);
        if (network.length > 64) network.shift();
      });
      page.setDefaultTimeout(180_000);
      const address = server.address();
      check(address !== null && typeof address !== "string", "HTTPS fixture listener did not bind");
      await page.goto(`https://localhost:${address.port}/`);
      await page.waitForFunction(() => "publisherFixture" in globalThis);
      const observation = new AbortController();
      try {
        return await Promise.race([
          page.evaluate(async (input) => {
            const host = globalThis as typeof globalThis & {
              publisherFixture?: { smoke(input: unknown): Promise<unknown> };
            };
            if (host.publisherFixture === undefined)
              throw new Error("publisher fixture module is missing");
            return host.publisherFixture.smoke(input);
          }, configuration),
          // playwright does not apply its default timeout to page.evaluate.
          // capture diagnostics before the outer fixture closes the browser.
          pause(120_000, undefined, { signal: observation.signal }).then(() => {
            throw new Error("browser publisher observation timed out");
          }),
        ]);
      } catch (error) {
        const diagnostics = await page.evaluate(() =>
          Reflect.get(globalThis, "__tnlWasmFixtureDiagnostics"),
        );
        throw new Error(
          `${error instanceof Error ? error.message : "publisher fixture failed"}; Go diagnostics: ${JSON.stringify(diagnostics)}; control requests: ${network.join("; ")}`,
        );
      } finally {
        observation.abort();
      }
    } finally {
      lifetime.signal.removeEventListener("abort", interrupted);
      await browser.close();
    }
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

const workerStatus = z.strictObject({
  url: z.url(),
  runtime: z.string().uuid(),
  go_runtimes: z.number().int().nonnegative(),
  identity_imports: z.number().int().nonnegative(),
});
async function startWorker(configuration: string) {
  lifetime.signal.throwIfAborted();
  const require = createRequire(import.meta.url);
  const binary = z.object({ default: z.string().min(1) }).parse(require("workerd")).default;
  const child = spawn(binary, ["serve", configuration, "--control-fd=3"], {
    cwd: root,
    stdio: ["ignore", "pipe", "pipe", "pipe"],
  });
  let diagnostics = "";
  child.stderr?.on("data", (bytes: Buffer) => {
    diagnostics = (diagnostics + bytes.toString()).slice(-16_384);
  });
  child.stdout?.resume();
  const ended = new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code === 0 || signal === "SIGTERM" || signal === "SIGKILL") resolve();
      else reject(new Error(`workerd exited with ${code}: ${redact(diagnostics)}`));
    });
  });
  void ended.catch(() => {});
  const control = child.stdio[3];
  if (control === null || control === undefined || !("read" in control)) {
    child.kill("SIGTERM");
    await ended;
    throw new Error("workerd control pipe is missing");
  }
  const lines = createInterface({ input: control });
  const listen = z.object({
    event: z.literal("listen"),
    socket: z.literal("http"),
    port: z.number().int().positive(),
  });
  const ready = new Promise<number>((resolve, reject) => {
    lines.on("line", (line) => {
      try {
        const event = listen.safeParse(JSON.parse(line));
        if (event.success) resolve(event.data.port);
      } catch {
        reject(new Error("workerd emitted malformed readiness JSON"));
      }
    });
    child.once("error", reject);
    child.once("close", () =>
      reject(new Error(`workerd stopped before readiness: ${redact(diagnostics)}`)),
    );
  });
  const interrupted = () => {
    child.kill("SIGTERM");
  };
  lifetime.signal.addEventListener("abort", interrupted, { once: true });
  const close = async (crash = false) => {
    lines.close();
    lifetime.signal.removeEventListener("abort", interrupted);
    child.kill(crash ? "SIGKILL" : "SIGTERM");
    const force = setTimeout(() => child.kill("SIGKILL"), 5_000);
    try {
      await ended;
    } finally {
      clearTimeout(force);
    }
  };
  try {
    const timeout = AbortSignal.timeout(20_000);
    const port = await Promise.race([
      ready,
      new Promise<never>((_, reject) =>
        timeout.addEventListener("abort", () => reject(new Error("workerd startup timed out")), {
          once: true,
        }),
      ),
    ]);
    return {
      close,
      async request(route: string) {
        const response = await fetch(`http://127.0.0.1:${port}${route}`, {
          method: "POST",
          signal: AbortSignal.any([lifetime.signal, AbortSignal.timeout(120_000)]),
        });
        check(
          response.ok,
          `actual Go/WASM durable publisher ${route} failed: HTTP ${response.status} ${redact((await response.clone().text()).slice(0, 500))}; ${redact(diagnostics.slice(-1500))}`,
        );
        return response;
      },
      async call(route: string) {
        return workerStatus.parse(await (await this.request(route)).json());
      },
    };
  } catch (error) {
    await close();
    throw error;
  }
}

async function workerdSmoke(configuration: PublisherFixture) {
  const output = path.join(directory, "worker");
  const storage = path.join(directory, "durable-storage");
  await mkdir(output, { mode: 0o700 });
  await mkdir(storage, { mode: 0o700 });
  await build({
    entryPoints: [path.join(source, "worker.ts")],
    outfile: path.join(output, "worker.mjs"),
    bundle: true,
    format: "esm",
    platform: "browser",
    conditions: ["workerd", "worker", "browser"],
    external: ["cloudflare:workers"],
    tsconfigRaw: {},
    plugins: [
      packagedGoRuntime(),
      {
        name: "static-sdk-wasm",
        setup(builder) {
          builder.onResolve({ filter: /\.wasm$/ }, (args) => ({
            path: path.basename(args.path),
            external: true,
            sideEffects: false,
          }));
        },
      },
    ],
  });
  const config = path.join(output, "config.capnp");
  await writeFile(
    config,
    publisherWorkerdConfiguration(
      configuration,
      path.relative(output, wasm),
      path.relative(output, connectorWasm),
      storage,
    ),
    {
      mode: 0o600,
    },
  );
  let worker = await startWorker(config);
  try {
    const privateOrigin = `https://${configuration.private_host}`;
    const first = await worker.call("/start");
    check(
      first.go_runtimes === 1 && first.identity_imports === 1,
      "durable start did not create one actual Go owner",
    );
    // /start's response has ended. no initiating request or waitUntil is held
    // open while this independent HTTPS visitor reaches the retained owner.
    const before = await fixtureCall(configuration, "/observe", first.url, apiFetch);
    check(
      before.status === 200 && before.publisher_runtime === first.runtime,
      "publication died when initiating request ended",
    );
    await worker.close(true);
    await fixtureCall(configuration, "/await-restartable", first.url, apiFetch);
    worker = await startWorker(config);
    const restored = await worker.call("/resume");
    const after = await fixtureCall(configuration, "/observe", restored.url, apiFetch);
    check(
      restored.runtime !== first.runtime &&
        restored.go_runtimes === 1 &&
        restored.identity_imports === 0,
      "restart did not reconstruct a fresh Go runtime from durable identity",
    );
    check(
      after.status === 200 &&
        after.publisher_runtime === restored.runtime &&
        after.run_number > before.run_number,
      "fresh durable owner did not publish a new service run",
    );
    check(
      before.certificate_sha256 !== "" &&
        after.certificate_sha256 === before.certificate_sha256 &&
        after.orders === before.orders,
      "restart did not reuse its persisted service certificate",
    );
    await worker.call("/stop");
    const stopped = await fixtureCall(configuration, "/state", restored.url, apiFetch);
    check(
      stopped.active_runs === 0 && !stopped.deleted,
      "durable stop did not join named publication",
    );
    await worker.close(true);
    worker = await startWorker(config);
    const resumedStop = await worker.call("/status");
    const final = await fixtureCall(configuration, "/state", restored.url, apiFetch);
    check(
      resumedStop.go_runtimes === 0 &&
        resumedStop.identity_imports === 0 &&
        final.active_runs === 0,
      "restart resurrected persisted stopped intent",
    );
    const privateRun = z
      .object({
        runtime: z.string().min(1),
        go_runtimes: z.literal(1),
        identity_imports: z.literal(1),
      })
      .parse(await (await worker.request("/private-start")).json());
    check(
      privateRun.runtime !== resumedStop.runtime,
      "private publisher did not own its own runtime",
    );
    z.object({ private: z.literal(true) }).parse(
      await (await worker.request("/private-visit")).json(),
    );
    await worker.request("/private-stop");
    const privateStopped = await fixtureCall(configuration, "/state", privateOrigin, apiFetch);
    check(
      privateStopped.active_runs === 0 && !privateStopped.deleted,
      "private durable stop did not join the saved service run",
    );
    const managed = z.strictObject({ publisher: z.string(), calls: z.number().int() });
    const managedFirst = managed.parse(await (await worker.request("/managed-start")).json());
    const managedAgain = managed.parse(await (await worker.request("/managed-reopen")).json());
    check(
      managedFirst.calls === 1 &&
        managedAgain.calls === 0 &&
        managedFirst.publisher === managedAgain.publisher,
      "managed publisher did not lazily reuse its identity",
    );
    z.object({ private: z.literal(true) }).parse(
      await (await worker.request("/managed-visit")).json(),
    );
    await worker.request("/managed-stop");
    const managedStopped = await fixtureCall(configuration, "/state", privateOrigin, apiFetch);
    check(
      managedStopped.active_runs === 0,
      "managed publisher did not join its private service run",
    );
    return {
      actualGoWasm: true,
      sqliteDurableObject: true,
      survivedInitiatingRequest: true,
      freshRuntimeAfterProcessRestart: true,
      identityReused: true,
      certificateReused: true,
      stopPersisted: true,
      connectorOnlyPublication: true,
      sdkManagedEnrollmentAndPublication: true,
    };
  } finally {
    await worker.close();
  }
}

function redact(message: string): string {
  return [
    fixture.token,
    fixture.enrollment,
    fixture.sibling_token,
    fixture.api_token,
    fixture.runner_private_key_pem,
  ].reduce((output, secret) => output.replaceAll(secret, "[redacted]"), message);
}

// the source declaration keeps fixture typechecking independent of disposable
// build output. execution always bundles the packaged, version-matched runtime.
function packagedGoRuntime() {
  return {
    name: "packaged-go-runtime",
    setup(builder: import("esbuild").PluginBuild) {
      builder.onResolve({ filter: /\/wasm\/wasm_exec\.js$/ }, () => ({
        path: path.join(root, "packages/ts/dist/wasm/wasm_exec.js"),
      }));
    },
  };
}

try {
  // the fixture variant changes only the connector's trusted service issuer.
  // production artifacts reject that private host field. publication, signing,
  // visitor TLS and both service/connector engines remain the actual Go owners.
  for (const [output, tag] of [
    [wasm, "tnlpublisher"],
    [connectorWasm, "tnlconnector"],
  ] as const) {
    await buildGoWasm({
      cwd: root,
      tags: `tnlwasmtest,tnlsdk,${tag}`,
      output,
      signal: lifetime.signal,
    });
  }
  if (runtime !== "workerd") {
    console.log(JSON.stringify({ runtime: "chrome", proof: await chromeSmoke(fixture) }));
  }
  if (runtime !== "chrome")
    console.log(JSON.stringify({ runtime: "workerd", proof: await workerdSmoke(fixture) }));
} catch (error) {
  // playwright and provider diagnostics may include source/request values.
  console.error(redact(error instanceof Error ? error.message : "portable publisher failed"));
  process.exitCode = 1;
} finally {
  process.removeListener("SIGINT", stop);
  process.removeListener("SIGTERM", stop);
  await rm(directory, { recursive: true, force: true });
}
