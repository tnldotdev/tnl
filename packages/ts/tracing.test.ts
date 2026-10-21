import { createServer, type IncomingHttpHeaders } from "node:http";
import { randomBytes } from "node:crypto";
import { chmod, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AsyncLocalStorage } from "node:async_hooks";
import { afterAll, afterEach, expect, test, vi } from "vitest";
import {
  context,
  trace,
  ROOT_CONTEXT,
  type SpanContext,
  type SpanOptions,
  type Context,
  type Span,
  type Tracer,
  type ContextManager,
} from "@opentelemetry/api";
import {
  operation,
  independent,
  traceHeaders,
  launchEnvironment,
} from "./dist/internal/tracing.js";
import { runtimeRequest, startRuntime, type RuntimeEndpoint } from "./dist/internal/local.js";
import { createPreparedService } from "./dist/internal/app.js";
import { ownerIPC } from "./dist/internal/connection_ipc.js";
import { testPublicProject } from "./test-helper/project.js";

interface Recorded {
  name: string;
  sc: SpanContext;
  parent: SpanContext | undefined;
  options: SpanOptions;
  events: string[];
  ended: number;
  attributes: Record<string, unknown>;
}

const spans: Recorded[] = [];
let installed = false;
function recorder() {
  spans.length = 0;
  const tracer: Tracer = {
    startSpan(name: string, options: SpanOptions = {}, parent: Context = ROOT_CONTEXT): Span {
      const previous = trace.getSpanContext(parent);
      const sc: SpanContext = {
        traceId: previous?.traceId ?? randomBytes(16).toString("hex"),
        spanId: randomBytes(8).toString("hex"),
        traceFlags: 1,
      };
      const recorded: Recorded = {
        name,
        sc,
        parent: previous,
        options,
        events: [],
        ended: 0,
        attributes: { ...options.attributes },
      };
      spans.push(recorded);
      const span = trace.wrapSpanContext(sc);
      span.setAttribute = (key, value) => {
        recorded.attributes[key] = value;
        return span;
      };
      span.addEvent = (name) => {
        recorded.events.push(name);
        return span;
      };
      span.end = () => {
        recorded.ended++;
      };
      return span;
    },
    startActiveSpan() {
      throw new Error("use explicit SDK-local context");
    },
  };
  if (!installed) {
    trace.setGlobalTracerProvider({ getTracer: () => tracer });
    installed = true;
  }
  let caller: Context = ROOT_CONTEXT;
  vi.spyOn(context, "active").mockImplementation(() => caller);
  return {
    spans,
    caller(id: string) {
      caller = trace.setSpanContext(ROOT_CONTEXT, {
        traceId: id.repeat(32),
        spanId: id.repeat(16),
        traceFlags: 1,
      });
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.useRealTimers();
  context.disable();
});
afterAll(() => trace.disable());

class HostContextManager implements ContextManager {
  private readonly storage = new AsyncLocalStorage<Context>();
  active(): Context {
    return this.storage.getStore() ?? ROOT_CONTEXT;
  }
  with<A extends unknown[], F extends (...args: A) => ReturnType<F>>(
    scope: Context,
    fn: F,
    thisArg?: ThisParameterType<F>,
    ...args: A
  ): ReturnType<F> {
    return this.storage.run(scope, () => fn.call(thisArg, ...args));
  }
  bind<T>(_scope: Context, target: T): T {
    return target;
  }
  enable(): this {
    return this;
  }
  disable(): this {
    this.storage.disable();
    return this;
  }
}

test("host instrumentation sees SDK operations and async attempts drop app context", async () => {
  const recorded = recorder();
  vi.restoreAllMocks();
  context.setGlobalContextManager(new HostContextManager());
  const appKey = Symbol("private application state");
  const caller = trace.setSpanContext(ROOT_CONTEXT.setValue(appKey, "secret"), {
    traceId: "5".repeat(32),
    spanId: "5".repeat(16),
    traceFlags: 1,
  });
  let attempt!: () => Promise<void>;
  await context.with(caller, () =>
    operation("sdk.prepare", async () => {
      await Promise.resolve();
      expect(trace.getSpanContext(context.active())?.spanId).toBe(recorded.spans[0]?.sc.spanId);
      attempt = independent("sdk.app.renew", async () => {
        expect(context.active().getValue(appKey)).toBeUndefined();
        expect(trace.getSpanContext(context.active())?.traceId).not.toBe("5".repeat(32));
      });
    }),
  );
  await context.with(caller, attempt);
  expect(recorded.spans[1]?.options.links).toEqual([{ context: recorded.spans[0]?.sc }]);
  expect(recorded.spans.every((s) => s.ended === 1)).toBe(true);
});

test("SDK IPC uses the current caller and sends only canonical parentage", async () => {
  const recorded = recorder();
  const headers: IncomingHttpHeaders[] = [];
  const server = createServer((request, response) => {
    headers.push({ ...request.headers });
    response.writeHead(204).end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no listener");
  const endpoint: RuntimeEndpoint = {
    version: 1,
    url: `http://127.0.0.1:${address.port}`,
    capability: "a".repeat(64),
    owner_id: "b".repeat(32),
    scope: "app",
    service: "api",
  };
  try {
    recorded.caller("1");
    await runtimeRequest(endpoint, "health");
    recorded.caller("2");
    await runtimeRequest(endpoint, "health");
    expect(
      headers.map((h) =>
        typeof h.traceparent === "string" ? h.traceparent.slice(3, 35) : undefined,
      ),
    ).toEqual(["1".repeat(32), "2".repeat(32)]);
    for (const header of headers) {
      expect(header.traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
      expect(header).not.toHaveProperty("tracestate");
      expect(header).not.toHaveProperty("baggage");
    }
    expect(recorded.spans.every((s) => s.ended === 1)).toBe(true);
    expect(JSON.stringify(endpoint)).not.toContain("trace");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("warm connection IPC uses each caller's trace on its reused socket", async () => {
  const recorded = recorder();
  const directory = await realpath(await mkdtemp(join(tmpdir(), "tnl-warm-trace-")));
  const headers: IncomingHttpHeaders[] = [];
  let connections = 0;
  const server = createServer((request, response) => {
    headers.push({ ...request.headers });
    request.resume();
    request.on("end", () => {
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({ schema: 1 }));
    });
  });
  server.on("connection", () => connections++);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  let ipc: Awaited<ReturnType<typeof ownerIPC>> | undefined;
  try {
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("no listener");
    const file = join(directory, "handle.json");
    await writeFile(
      file,
      JSON.stringify({
        schema: 1,
        url: `http://127.0.0.1:${address.port}`,
        key: "a".repeat(64),
        directory,
        config_digest: "b".repeat(64),
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        executable: "/installed/tnl",
      }),
      { mode: 0o600 },
    );
    recorded.caller("3");
    ipc = await ownerIPC(file);
    for (const caller of ["1", "2"]) {
      recorded.caller(caller);
      await ipc.prepare("database", "private-assertion");
    }
    expect(connections).toBe(1);
    expect(recorded.spans).toHaveLength(2);
    for (const [index, span] of recorded.spans.entries()) {
      expect(span.name).toBe("sdk.native.request");
      expect(span.parent?.traceId).toBe(String(index + 1).repeat(32));
      expect(headers[index]?.traceparent).toBe(`00-${span.sc.traceId}-${span.sc.spanId}-01`);
      expect(headers[index]?.tracestate).toBeUndefined();
      expect(headers[index]?.baggage).toBeUndefined();
      expect(span.ended).toBe(1);
      expect(JSON.stringify(span)).not.toContain("private-assertion");
    }
  } finally {
    ipc?.close();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

test("native launch replaces stale environment and async work uses links", async () => {
  vi.stubEnv("TNL_TRACEPARENT", "stale-parent");
  const recorded = recorder();
  recorded.caller("1");
  let attempt!: () => Promise<void>;
  await operation("sdk.prepare", async () => {
    const environment = launchEnvironment();
    expect(environment.TNL_TRACEPARENT).toBe(traceHeaders().traceparent);
    attempt = independent("sdk.app.renew", async () => {
      expect(traceHeaders().traceparent?.slice(3, 35)).not.toBe("1".repeat(32));
    });
  });
  recorded.caller("2");
  await attempt();
  const renewal = recorded.spans.find((s) => s.name === "sdk.app.renew");
  expect(renewal?.parent).toBeUndefined();
  expect(renewal?.options.links).toEqual([{ context: recorded.spans[0]?.sc }]);
  expect(recorded.spans.every((s) => s.ended === 1)).toBe(true);
});

test("the SDK launches the native CLI with its current operation parent", async () => {
  const recorded = recorder();
  recorded.caller("4");
  const server = createServer((_request, response) => response.writeHead(204).end());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no listener");
  const endpoint: RuntimeEndpoint = {
    version: 1,
    url: `http://127.0.0.1:${address.port}`,
    capability: "a".repeat(64),
    owner_id: "b".repeat(32),
    scope: "app",
    service: "api",
  };
  const directory = await mkdtemp(join(tmpdir(), "tnl-trace-launch-"));
  const binary = join(directory, "native.mjs");
  try {
    await writeFile(
      binary,
      `#!${process.execPath}\nif (!/^00-${"4".repeat(32)}-[0-9a-f]{16}-01$/.test(process.env.TNL_TRACEPARENT ?? "")) process.exit(2);\nprocess.stdout.write(${JSON.stringify(JSON.stringify(endpoint))});`,
    );
    await chmod(binary, 0o700);
    await operation("sdk.prepare", async () => {
      expect(await startRuntime(directory, binary, { service: "api" })).toEqual(endpoint);
    });
    expect(recorded.spans.every((s) => s.ended === 1)).toBe(true);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

test("prepared handles use new callers; renewal is finite and linked; errors never record cause text", async () => {
  const recorded = recorder();
  vi.useFakeTimers();
  const endpoint: RuntimeEndpoint = {
    version: 1,
    url: "http://127.0.0.1:12345",
    capability: "a".repeat(64),
    owner_id: "b".repeat(32),
    scope: "app",
    service: "api",
  };
  recorded.caller("1");
  const handle = await createPreparedService({ service: "api" }, "vite", {
    start: async () => endpoint,
    request: async (_endpoint, action) =>
      action === "prepare"
        ? {
            version: 1,
            registration_id: `reg_${"a".repeat(32)}`,
            service: "api",
            hostname: "api.member.example",
            public_url: "https://api.member.example",
            project: testPublicProject(true),
          }
        : undefined,
  });
  const listener = {
    hostname: "127.0.0.1",
    port: 12345,
    url: new URL("http://127.0.0.1:12345"),
    stop() {},
  };
  recorded.caller("2");
  await handle.register(listener);
  expect(recorded.spans.find((s) => s.name === "sdk.app.register")?.sc.traceId).toBe(
    "2".repeat(32),
  );
  await vi.advanceTimersByTimeAsync(5000);
  const renewal = recorded.spans.find((s) => s.name === "sdk.app.renew");
  expect(renewal?.parent).toBeUndefined();
  expect(renewal?.ended).toBe(1);
  expect(renewal?.options.links?.[0]?.context.traceId).toBe("2".repeat(32));
  recorded.caller("3");
  await handle.close();
  expect(recorded.spans.find((s) => s.name === "vite.cleanup")?.sc.traceId).toBe("3".repeat(32));
  await expect(
    operation("sdk.connect", async () => {
      throw new Error("secret SQL payload");
    }),
  ).rejects.toThrow("secret SQL payload");
  expect(JSON.stringify(recorded.spans)).not.toMatch(/secret|SQL|payload/);
  expect(recorded.spans.filter((s) => s.events.includes("bound"))).toHaveLength(1);
  expect(JSON.stringify(handle)).not.toMatch(/trace|span|capability|registration_id/);
});
