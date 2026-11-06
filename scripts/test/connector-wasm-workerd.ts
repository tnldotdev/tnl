import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire, isBuiltin } from "node:module";
import path from "node:path";
import { createInterface } from "node:readline";
import { parseArgs } from "node:util";
import { build } from "esbuild";
import * as z from "zod";

const root = path.resolve(import.meta.dirname, "../..");
const source = path.join(root, "development/connector-wasm");
const require = createRequire(import.meta.url);
const workerd = z.object({ default: z.string().min(1) }).parse(require("workerd"));
const { values } = parseArgs({
  options: {
    fixture: { type: "string" },
    preflight: { type: "boolean", default: false },
    queries: { type: "string", default: "10" },
  },
});
if (values.fixture === undefined && !values.preflight)
  throw new Error("pass --fixture with a private local fixture file, or --preflight");
const fixture: unknown = values.fixture
  ? JSON.parse(await readFile(values.fixture, "utf8"))
  : undefined;
const serviceRoot = values.preflight
  ? undefined
  : z.object({ service_root_pem: z.string().min(1) }).parse(fixture).service_root_pem;
const queries = Number(values.queries);
if (!Number.isSafeInteger(queries) || queries < 1 || queries > 10_000)
  throw new Error("--queries must be an integer between 1 and 10000");
const output = path.join(source, "dist");

await build({
  entryPoints: [path.join(source, "worker.ts")],
  outfile: path.join(output, "worker.mjs"),
  bundle: true,
  platform: "node",
  target: "es2022",
  format: "esm",
  conditions: ["workerd", "worker", "browser"],
  external: ["cloudflare:sockets", "node:*", "*.wasm"],
  banner: {
    js: 'import { createRequire as __tnlCreateRequire } from "node:module"; const require = __tnlCreateRequire("file:///worker.mjs");',
  },
  plugins: [
    {
      name: "worker-node-builtins",
      setup(builder) {
        builder.onResolve({ filter: /^[a-z_]+$/ }, ({ path: specifier }) =>
          isBuiltin(specifier) ? { path: `node:${specifier}`, external: true } : undefined,
        );
      },
    },
  ],
});

const directory = await mkdtemp(path.join(output, "workerd-"));
try {
  const config = path.join(directory, "config.capnp");
  // local-only networking is intentional; it does not establish deployed reachability.
  await writeFile(
    config,
    `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "main", worker = (
      modules = [
        (name = "worker.mjs", esModule = embed "../worker.mjs"),
        (name = "dist/connector.wasm", wasm = embed "../connector.wasm")
      ],
      compatibilityDate = "2026-10-31",
      globalOutbound = "local"
    )),
    (name = "local", network = (
      allow = ["127.0.0.0/8", "::1/128"],
      tlsOptions = (trustBrowserCas = false, trustedCertificates = ${JSON.stringify(serviceRoot ? [serviceRoot] : [])})
    ))
  ],
  sockets = [(name = "http", address = "127.0.0.1:0", http = (), service = "main")]
);
`,
    { mode: 0o600 },
  );
  const launched = performance.now();
  const child = spawn(workerd.default, ["serve", config, "--control-fd=3"], {
    cwd: root,
    stdio: ["ignore", "pipe", "pipe", "pipe"],
  });
  const closed = once(child, "close");
  let diagnostics = "";
  child.stderr?.on("data", (data: Buffer) => {
    diagnostics = (diagnostics + data.toString()).slice(-16_384);
  });
  child.stdout?.resume();
  try {
    const control = child.stdio[3];
    if (control === null || control === undefined || !("read" in control))
      throw new Error("workerd control pipe is unavailable");
    const lines = createInterface({ input: control });
    const listen = z.object({
      event: z.literal("listen"),
      socket: z.string(),
      port: z.number().int(),
    });
    const ready = new Promise<number>((resolve, reject) => {
      lines.on("line", (line) => {
        try {
          const value: unknown = JSON.parse(line);
          const parsed = listen.safeParse(value);
          if (parsed.success && parsed.data.socket === "http") resolve(parsed.data.port);
        } catch {
          reject(new Error("workerd returned an invalid readiness record"));
        }
      });
      child.once("error", reject);
      child.once("exit", () => reject(new Error(`workerd exited during startup: ${diagnostics}`)));
    });
    const startup = AbortSignal.timeout(15_000);
    const port = await Promise.race([
      ready,
      new Promise<never>((_, reject) => {
        startup.addEventListener("abort", () => reject(new Error("workerd startup timed out")), {
          once: true,
        });
      }),
    ]);
    const health = await fetch(`http://127.0.0.1:${port}/health`, {
      signal: AbortSignal.timeout(5_000),
    });
    if (!health.ok) throw new Error("workerd health check failed");
    await health.arrayBuffer();
    const processStartupMs = performance.now() - launched;
    if (values.preflight) {
      console.log(
        JSON.stringify({ workerdReady: true, postgresQualified: false, processStartupMs }),
      );
    } else {
      const result = z
        .object({
          ok: z.literal(true),
          backendPid: z.number().int().positive(),
          writeProof: z.object({
            backendPidRetained: z.literal(true),
            committedRows: z.literal(1),
          }),
        })
        .passthrough();
      const run = async (fault: boolean, holdMs: number) => {
        const response = await fetch(
          `http://127.0.0.1:${port}/run?queries=${queries}&fault=${fault}&hold_ms=${holdMs}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(fixture),
            signal: AbortSignal.timeout(90_000),
          },
        );
        if (!response.ok) {
          const failure = z
            .object({
              phase: z.enum([
                "runtime initialization",
                "fixture input",
                "assertion acquisition",
                "PostgreSQL qualification",
              ]),
              initializationError: z.string().max(500).optional(),
              error: z.string().max(200),
            })
            .safeParse(await response.json());
          if (!failure.success)
            throw new Error(`workerd qualification failed with HTTP ${response.status}`);
          const detail =
            failure.data.phase === "runtime initialization"
              ? failure.data.initializationError
              : failure.data.error;
          throw new Error(
            `workerd failed during ${failure.data.phase}: ${detail ?? "unavailable"}`,
          );
        }
        return result.parse(await response.json());
      };
      // one fault controller owns the shared proxy at a time. concurrent requests
      // then prove separate schedulers and sockets, including use after peer close.
      const faultProof = await run(true, 3_000);
      const reports = await Promise.all([run(false, 3_000), run(false, 4_000)]);
      if (reports[0]?.backendPid === reports[1]?.backendPid)
        throw new Error("concurrent Worker requests shared a PostgreSQL connection");
      console.log(
        JSON.stringify({
          processStartupMs,
          faultProof,
          concurrentRequests: reports.length,
          reports,
        }),
      );
    }
    lines.close();
  } finally {
    child.kill("SIGTERM");
    const force = setTimeout(() => child.kill("SIGKILL"), 5_000);
    try {
      await closed;
    } finally {
      clearTimeout(force);
    }
  }
} finally {
  await rm(directory, { recursive: true, force: true });
}
