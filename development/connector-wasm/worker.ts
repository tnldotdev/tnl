import "./dist/wasm_exec.js";
import module from "./dist/connector.wasm";
import { createWorkerHost } from "./host-worker.ts";
import { mapFixtureHost, parseLocalFixture, prepareFixture } from "./fixture.ts";
import { startConnectorWasm } from "./loader.ts";
import { runFixture, runnerScenario, safeFixtureError } from "./run.ts";
import { queryCount, responseBytes } from "./postgres.ts";
import { parseVariant, tuning } from "./variant.ts";
import { observeBridge } from "./diagnostics.ts";
import { createPumpHost } from "./host-pump.ts";

export default {
  async fetch(request: Request): Promise<Response> {
    const { pathname, searchParams } = new URL(request.url);
    if (request.method === "GET" && pathname === "/health") {
      return Response.json({ ready: true, goRuntime: "created-per-run-request" });
    }
    if (request.method !== "POST" || pathname !== "/run") {
      return new Response("not found", { status: 404 });
    }
    let phase = "runtime initialization";
    try {
      // compiled code is shared; each request owns its go scheduler and timers.
      const { bridge, instantiateAndStartMs } = await startConnectorWasm(module);
      phase = "fixture input";
      const local = parseLocalFixture(await request.json());
      const signal = AbortSignal.any([request.signal, AbortSignal.timeout(30_000)]);
      const queries = queryCount(searchParams.get("queries"));
      const variant = parseVariant(searchParams.get("variant"));
      const settings = tuning(variant);
      const scenario = runnerScenario(searchParams);
      phase = "assertion acquisition";
      const fixture = await prepareFixture(
        local,
        `wasm-workerd-${crypto.randomUUID()}`,
        signal,
        queries,
      );
      Object.assign(fixture, scenario);
      fixture.warmupQueries = queryCount(searchParams.get("warmup"));
      fixture.options.bridge_reuse_buffers = settings.reuseBuffers;
      fixture.options.bridge_compact_promises = settings.compactPromises;
      fixture.reuseReadView = settings.reuseBuffers;
      fixture.applicationPump = settings.applicationPump;
      fixture.payloadBytes = responseBytes(searchParams.get("payload_bytes"));
      if (searchParams.get("diagnostics") === "true")
        fixture.observeWarm = (label, sample) =>
          label === "wasm" ? observeBridge(bridge, sample) : sample();
      fixture.instrumentWarm = () => {
        const started = performance.now();
        return () => ({
          scope: "caller-process-only; native Go daemon excluded",
          wallMs: performance.now() - started,
          cpuMicros: "unsupported",
          eventLoopDelayMs: "unsupported-worker",
        });
      };
      const rawHost = mapFixtureHost(createWorkerHost(signal), local);
      const host = settings.socketPump ? createPumpHost(rawHost) : rawHost;
      phase = "PostgreSQL qualification";
      const result = await runFixture(bridge, host, fixture, signal);
      return Response.json({
        ...result,
        variant,
        runtime: { engine: "workerd", compile: "precompiled-module-import", instantiateAndStartMs },
      });
    } catch (error) {
      return Response.json(
        {
          ok: false,
          phase,
          error: safeFixtureError(error),
          // no fixture input or credentials have been read during runtime startup.
          ...(phase === "runtime initialization" && error instanceof Error
            ? { initializationError: error.message.slice(0, 500) }
            : {}),
        },
        { status: 500 },
      );
    }
  },
};
