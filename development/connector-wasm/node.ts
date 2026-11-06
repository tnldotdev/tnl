import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { createNodeHost } from "./host-node.ts";
import { mapFixtureHost, parseLocalFixture, prepareFixture } from "./fixture.ts";
import { startConnectorWasm } from "./loader.ts";
import { runFixture, safeFixtureError } from "./run.ts";
import { queryCount } from "./postgres.ts";
import { memorySnapshot, nodeWarmInstrumentation } from "./node-measurements.ts";

export async function main(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      fixture: { type: "string" },
      wasm: { type: "string" },
      runtime: { type: "string" },
      queries: { type: "string" },
    },
    strict: true,
    allowPositionals: false,
  });
  if (!values.fixture) throw new Error("use --fixture <private JSON file>");
  const queries = queryCount(values.queries);
  const runtimeURL = values.runtime
    ? pathToFileURL(values.runtime)
    : new URL("./dist/wasm_exec.js", import.meta.url);
  const wasmURL = values.wasm
    ? pathToFileURL(values.wasm)
    : new URL("./dist/connector.wasm", import.meta.url);
  const local = parseLocalFixture(JSON.parse(await readFile(values.fixture, "utf8")) as unknown);
  const beforeWasm = memorySnapshot();
  await import(runtimeURL.href);
  const bytes = await readFile(wasmURL);
  const compiling = performance.now();
  const module = await WebAssembly.compile(bytes);
  const compileMs = performance.now() - compiling;
  const runtime = await startConnectorWasm(module);
  const afterWasmInit = memorySnapshot();
  const signal = AbortSignal.timeout(30_000);
  const controller = new AbortController();
  const onSignal = (): void => controller.abort();
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  try {
    const combined = AbortSignal.any([signal, controller.signal]);
    const engine = process.versions.bun ? "bun" : "node";
    const fixture = await prepareFixture(
      local,
      `wasm-${engine}-${crypto.randomUUID()}`,
      combined,
      queries,
    );
    fixture.instrumentWarm = nodeWarmInstrumentation();
    const host = mapFixtureHost(createNodeHost(combined), local);
    const result = await runFixture(runtime.bridge, host, fixture, combined);
    process.stdout.write(
      `${JSON.stringify({ ...result, runtime: { engine, compileMs, instantiateAndStartMs: runtime.instantiateAndStartMs }, memory: { scope: "caller-process-only; native Go daemon excluded", gc: "not-forced", beforeWasm, afterWasmInit, afterCleanup: memorySnapshot() } })}\n`,
    );
  } finally {
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
  }
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === fileURLToPath(pathToFileURL(process.argv[1]))
) {
  try {
    await main(process.argv.slice(2));
  } catch (error) {
    // opaque go/pg errors may contain credentials; this runner never prints them.
    process.stderr.write(`${safeFixtureError(error)}\n`);
    process.exitCode = 1;
  }
}
