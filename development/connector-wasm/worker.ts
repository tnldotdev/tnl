import "./dist/wasm_exec.js";
import module from "./dist/connector.wasm";
import { createWorkerHost } from "./host-worker.ts";
import { mapFixtureHost, parseLocalFixture, prepareFixture } from "./fixture.ts";
import { startConnectorWasm } from "./loader.ts";
import { runFixture, runnerScenario, safeFixtureError } from "./run.ts";
import { queryCount } from "./postgres.ts";

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
      const scenario = runnerScenario(searchParams);
      phase = "assertion acquisition";
      const fixture = await prepareFixture(
        local,
        `wasm-workerd-${crypto.randomUUID()}`,
        signal,
        queries,
      );
      Object.assign(fixture, scenario);
      fixture.instrumentWarm = () => {
        const started = performance.now();
        return () => ({
          scope: "caller-process-only; native Go daemon excluded",
          wallMs: performance.now() - started,
          cpuMicros: "unsupported",
          eventLoopDelayMs: "unsupported-worker",
        });
      };
      const host = mapFixtureHost(createWorkerHost(signal), local);
      phase = "PostgreSQL qualification";
      const result = await runFixture(bridge, host, fixture, signal);
      return Response.json({
        ...result,
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
