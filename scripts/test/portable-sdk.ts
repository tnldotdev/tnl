import { execFile, spawn } from "node:child_process";
import { createReadStream } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire, isBuiltin } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { parseArgs, promisify } from "node:util";
import { build } from "esbuild";
import { chromium } from "playwright";
import * as z from "zod";
import {
  fixtureSchema,
  type PortableFixture,
} from "../../packages/ts/test/portable-integration/fixture.ts";
import { chromeArguments, workerdConfiguration } from "./portable-sdk-config.ts";

interface BrowserFixture {
  smoke(input: unknown): Promise<unknown>;
  isolation(input: unknown, role: "first" | "second", run: string): Promise<unknown>;
}

const { values } = parseArgs({
  options: {
    fixture: { type: "string" },
    runtime: { type: "string", default: "all" },
  },
});
if (values.fixture === undefined)
  throw new Error("pass --fixture with the private Go fixture descriptor");
const runtime = z.enum(["all", "chrome", "workerd"]).parse(values.runtime);
const descriptor = await stat(values.fixture);
if (!descriptor.isFile() || (descriptor.mode & 0o077) !== 0 || descriptor.size > 4 << 20)
  throw new Error("fixture descriptor must be a bounded private regular file (mode 0600)");
const fixture = fixtureSchema.parse(JSON.parse(await readFile(values.fixture, "utf8")));
const root = path.resolve(import.meta.dirname, "../..");
const source = path.join(root, "packages/ts/test/portable-integration");
const productionWasm = path.join(root, "packages/ts/dist/wasm/tnl.wasm");
if ((await stat(productionWasm)).size < 1)
  throw new Error("build the actual SDK Go/WASM module first");
const temporary = process.platform === "darwin" ? path.join(tmpdir(), "opencode") : tmpdir();
await mkdir(temporary, { recursive: true, mode: 0o700 });
const directory = await mkdtemp(path.join(temporary, "tnl-portable-sdk-"));
const wasm = path.join(directory, "tnl-fixture.wasm");
const unoptimizedWasm = path.join(directory, ".tnl-fixture.unoptimized.wasm");
const lifetime = new AbortController();
const stop = () => lifetime.abort(new Error("portable SDK runner interrupted"));
process.once("SIGINT", stop);
process.once("SIGTERM", stop);

const smokeSchema = z.strictObject({
  protocols: z.tuple([
    z.literal("http"),
    z.literal("tcp"),
    z.literal("postgres"),
    z.literal("mysql"),
    z.literal("kubernetes"),
  ]),
  postgresBackendPID: z.number().int().positive(),
  postgresTransactionRetained: z.literal(true),
  committedRows: z.literal(1),
  interruptedCarriers: z.number().int().positive(),
  mysqlConnectionID: z.number().int().positive(),
  closed: z.literal(true),
});
const isolationSchema = z.tuple([
  z.strictObject({
    role: z.literal("first"),
    backendPID: z.number().int().positive(),
    survivedPeerClose: z.literal(false),
  }),
  z.strictObject({
    role: z.literal("second"),
    backendPID: z.number().int().positive(),
    survivedPeerClose: z.literal(true),
  }),
]);
function isolationProof(input: unknown) {
  const pair = isolationSchema.parse(input);
  if (pair[0].backendPID === pair[1].backendPID)
    throw new Error("concurrent SDK deployments shared a PostgreSQL backend");
  return pair;
}
function redact(value: string): string {
  let output = value;
  for (const secret of [
    fixture.token,
    fixture.api_token,
    fixture.postgres.password,
    fixture.mysql.password,
    fixture.kubernetes_token,
  ])
    output = output.replaceAll(secret, "[redacted]");
  return output;
}

async function chromeSmoke(configuration: PortableFixture) {
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
    // resolve the real package's conditional export, not the source-only
    // typecheck mapping used by this fixture's standalone tsconfig.
    tsconfigRaw: {},
  });
  const assets = new Map(
    bundled.outputFiles.map((file) => [
      "/browser/" + path.relative(output, file.path).split(path.sep).join("/"),
      file.contents,
    ]),
  );
  const wasmSize = (await stat(wasm)).size;
  const server = createServer((request, response) => {
    response.setHeader("Cache-Control", "no-store");
    if (request.url === "/") {
      response.setHeader("Content-Type", "text/html");
      response.end(
        '<!doctype html><script type="module">import * as fixture from "/browser/browser.js"; globalThis.portableSDKFixture = fixture;</script>',
      );
    } else if (request.url?.endsWith("/wasm/tnl.wasm")) {
      response.writeHead(200, { "Content-Type": "application/wasm", "Content-Length": wasmSize });
      const stream = createReadStream(wasm);
      stream.on("error", () => response.destroy());
      response.on("close", () => stream.destroy());
      stream.pipe(response);
    } else {
      const asset = assets.get(request.url ?? "");
      if (asset === undefined) response.writeHead(404).end();
      else response.writeHead(200, { "Content-Type": "text/javascript" }).end(asset);
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const browser = await chromium.launch({
      channel: "chrome",
      args: chromeArguments(configuration),
    });
    const interrupted = () => {
      void browser.close();
    };
    lifetime.signal.addEventListener("abort", interrupted, { once: true });
    try {
      const page = await browser.newPage();
      const network: string[] = [];
      const location = (value: string) => {
        const url = new URL(value);
        return url.origin + url.pathname;
      };
      page.on("requestfailed", (request) => {
        network.push(
          `${request.method()} ${location(request.url())}: ${request.failure()?.errorText ?? "request failed"}`,
        );
      });
      page.on("response", (response) => {
        if (response.status() >= 400 || response.url().startsWith(configuration.control_url))
          network.push(`${response.status()} ${location(response.url())}`);
      });
      page.on("websocket", (socket) => {
        network.push(`WebSocket ${location(socket.url())}`);
        socket.on("socketerror", (error) => network.push(`WebSocket error: ${redact(error)}`));
        socket.on("close", () => network.push("WebSocket closed"));
      });
      page.setDefaultTimeout(120_000);
      const address = server.address();
      if (address === null || typeof address === "string")
        throw new Error("browser fixture did not bind its loopback listener");
      await page.goto(`http://127.0.0.1:${address.port}/`);
      await page.waitForFunction(() => "portableSDKFixture" in globalThis);
      let smoke: z.output<typeof smokeSchema>;
      try {
        smoke = smokeSchema.parse(
          await page.evaluate(async (input) => {
            const host = globalThis as typeof globalThis & { portableSDKFixture?: BrowserFixture };
            if (host.portableSDKFixture === undefined)
              throw new Error("browser fixture module is missing");
            return host.portableSDKFixture.smoke(input);
          }, configuration),
        );
      } catch (error) {
        const diagnostics = await page.evaluate(() =>
          Reflect.get(globalThis, "__tnlWasmFixtureDiagnostics"),
        );
        throw new AggregateError(
          [error],
          `Chrome SDK smoke failed; Go diagnostics: ${JSON.stringify(diagnostics)}; network: ${network.join("; ") || "no failed host requests"}`,
        );
      }
      const isolation = isolationProof(
        await page.evaluate(
          async ({ input, run }) => {
            const host = globalThis as typeof globalThis & { portableSDKFixture?: BrowserFixture };
            if (host.portableSDKFixture === undefined)
              throw new Error("browser fixture module is missing");
            return Promise.all([
              host.portableSDKFixture.isolation(input, "first", run),
              host.portableSDKFixture.isolation(input, "second", run),
            ]);
          },
          { input: configuration, run: `chrome-${crypto.randomUUID()}` },
        ),
      );
      return { runtime: "chrome", smoke, isolation };
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

async function workerdSmoke(configuration: PortableFixture) {
  const output = path.join(directory, "worker");
  await mkdir(output, { mode: 0o700 });
  await build({
    entryPoints: [path.join(source, "worker.ts")],
    outfile: path.join(output, "worker.mjs"),
    bundle: true,
    format: "esm",
    platform: "browser",
    conditions: ["workerd", "worker", "browser"],
    external: ["cloudflare:*"],
    banner: {
      js: 'import { createRequire } from "node:module"; const require = createRequire("file:///worker.mjs");',
    },
    tsconfigRaw: {},
    plugins: [
      {
        name: "worker-node-compat",
        setup(builder) {
          builder.onResolve({ filter: /^[a-z]/ }, ({ path }) =>
            isBuiltin(path)
              ? { path: path.startsWith("node:") ? path : `node:${path}`, external: true }
              : undefined,
          );
        },
      },
      {
        name: "static-sdk-wasm",
        setup(builder) {
          builder.onResolve({ filter: /\.wasm$/ }, () => ({ path: "tnl.wasm", external: true }));
        },
      },
    ],
  });
  const config = path.join(output, "config.capnp");
  await writeFile(config, workerdConfiguration(configuration, path.relative(output, wasm)), {
    mode: 0o600,
  });
  const require = createRequire(import.meta.url);
  const binary = z.object({ default: z.string().min(1) }).parse(require("workerd")).default;
  const child = spawn(binary, ["serve", config, "--control-fd=3"], {
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
  try {
    const startup = AbortSignal.any([lifetime.signal, AbortSignal.timeout(20_000)]);
    const port = await Promise.race([
      ready,
      new Promise<never>((_, reject) =>
        startup.addEventListener(
          "abort",
          () => reject(new Error("workerd startup interrupted or timed out")),
          { once: true },
        ),
      ),
    ]);
    const platform = await fetch(`http://127.0.0.1:${port}/platform`, {
      signal: AbortSignal.timeout(5_000),
    });
    const capabilities = z.record(z.string(), z.string()).parse(await platform.json());
    const unsupported = Object.entries(capabilities).filter(([, value]) => value !== "supported");
    async function call(route: string): Promise<unknown> {
      const response = await fetch(`http://127.0.0.1:${port}${route}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(configuration),
        signal: AbortSignal.any([lifetime.signal, AbortSignal.timeout(120_000)]),
      });
      const body: unknown = await response.json();
      if (!response.ok) {
        const failure = z
          .object({
            network: z.array(z.string().max(500)).max(64).optional(),
            failures: z.array(
              z.object({
                phase: z.string().max(40),
                code: z.string().max(80),
                detail: z.string().max(300).optional(),
              }),
            ),
          })
          .safeParse(body);
        throw new Error(
          `workerd SDK ${route.split("?")[0]} failed: ${failure.success ? JSON.stringify(failure.data) : `HTTP ${response.status}`}${unsupported.length === 0 ? "" : `; host platform: ${JSON.stringify(Object.fromEntries(unsupported))}`}`,
        );
      }
      return body;
    }
    const smoke = smokeSchema.parse(await call("/smoke"));
    const pg = z.object({ backendPID: z.number().int().positive() }).parse(await call("/pg"));
    const run = `workerd-${crypto.randomUUID()}`;
    const isolation = isolationProof(
      await Promise.all([
        call(`/isolation?role=first&run=${run}`),
        call(`/isolation?role=second&run=${run}`),
      ]),
    );
    return { runtime: "workerd", smoke, isolation, pg };
  } finally {
    lines.close();
    child.kill("SIGTERM");
    const force = setTimeout(() => child.kill("SIGKILL"), 5_000);
    try {
      await ended;
    } finally {
      clearTimeout(force);
    }
  }
}

try {
  // compile the same connector with its private test-host root bootstrap. never
  // overwrite the shipped artifact or add a public trust override.
  await promisify(execFile)(
    "go",
    [
      "build",
      "-tags=tnlwasmtest",
      "-trimpath",
      "-ldflags=-s -w",
      "-o",
      unoptimizedWasm,
      "./packages/ts/wasm",
    ],
    {
      cwd: root,
      env: { ...process.env, GOOS: "js", GOARCH: "wasm", CGO_ENABLED: "0" },
      signal: lifetime.signal,
      maxBuffer: 4 << 20,
    },
  );
  await promisify(execFile)(
    "wasm-opt",
    [
      unoptimizedWasm,
      "-Oz",
      "--enable-bulk-memory",
      "--enable-nontrapping-float-to-int",
      "-o",
      wasm,
    ],
    { cwd: root, signal: lifetime.signal, maxBuffer: 4 << 20 },
  );
  await rm(unoptimizedWasm);
  const failures: unknown[] = [];
  if (runtime !== "workerd") {
    try {
      console.log(JSON.stringify(await chromeSmoke(fixture)));
    } catch (error) {
      failures.push(error);
    }
  }
  if (runtime !== "chrome") {
    lifetime.signal.throwIfAborted();
    try {
      console.log(JSON.stringify(await workerdSmoke(fixture)));
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0)
    throw new AggregateError(failures, "portable SDK runtime qualification failed");
} finally {
  process.removeListener("SIGINT", stop);
  process.removeListener("SIGTERM", stop);
  await rm(directory, { recursive: true, force: true });
}
