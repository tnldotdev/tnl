import { afterEach, describe, expect, test, vi } from "vitest";
import { inspect } from "node:util";
import { createClient } from "../../src/index.browser.js";
import type { WasmByteStream, WasmConnection } from "../../src/internal/connector/wasm_abi.js";
import type { TnlStream } from "../../src/project.js";

const loader = vi.hoisted(() => ({ load: vi.fn() }));
vi.mock("../../src/internal/connector/wasm_loader.js", () => ({ loadWasm: loader.load }));

function deferred<Value>() {
  return Promise.withResolvers<Value>();
}

const services = {
  web: { protocol: "http" },
  db: { protocol: "postgres" },
  mysql: { protocol: "mysql" },
  cache: { protocol: "tcp" },
  cluster: { protocol: "kubernetes" },
} as const;

function fixture() {
  const events: string[] = [];
  const streams: ReturnType<typeof byteStream>[] = [];
  const connections = new Map<string, WasmConnection>();
  const exited = deferred<void>();
  const connect = vi.fn(async (name: keyof typeof services): Promise<unknown> => {
    let connection = connections.get(name);
    if (connection === undefined) {
      connection = {
        metadata: {
          key: `binding:${name}`,
          protocol: services[name].protocol,
          hostname: `${name}.example.test`,
        },
        open: vi.fn(async () => {
          events.push(`${name}:open`);
          const stream = byteStream(events, name);
          streams.push(stream);
          return stream;
        }),
        fetch: vi.fn(async (request: Request) => {
          events.push(`${name}:fetch`);
          return Response.json({
            method: request.method,
            url: request.url,
            redirect: request.redirect,
            body: await request.text(),
          });
        }),
        close: vi.fn(async () => {
          events.push(`${name}:close`);
        }),
      };
      connections.set(name, connection);
    }
    return connection;
  });
  const backend = { connect, close: vi.fn(async () => events.push("deployment:close")) };
  const bridge = {
    createDeployment: vi.fn(async () => backend),
    close: vi.fn(async () => {
      events.push("runtime:close");
      exited.resolve();
    }),
  };
  loader.load.mockResolvedValue({ bridge, exited: exited.promise });
  return { bridge, backend, streams, connections, events };
}

function byteStream(events: string[], name: string) {
  let data = new Uint8Array([1, 2, 3]);
  return {
    read: vi.fn(async () => {
      const value = data;
      data = new Uint8Array();
      return value.byteLength === 0 ? null : value;
    }),
    write: vi.fn(async (value: Uint8Array) => {
      events.push(`${name}:write`);
      data = value.slice();
    }),
    startTls: vi.fn(async () => {
      events.push(`${name}:tls`);
    }),
    closeWrite: vi.fn(async () => {
      events.push(`${name}:eof`);
    }),
    close: vi.fn(async () => {
      events.push(`${name}:stream-close`);
    }),
  } satisfies WasmByteStream;
}

function deployment() {
  return createClient({ project: "acme/shop", services, token: "private-credential" }).deployment(
    "production",
  );
}

afterEach(() => loader.load.mockReset());

describe("automatic browser/worker Go connector binding", () => {
  test("construction, native-only publication settings, and local rejection never load WASM", async () => {
    const app = createClient({ project: "acme/shop", services, token: "private-credential" });
    const remote = app.deployment("production");
    expect(loader.load).not.toHaveBeenCalled();
    expect(() => app.deployment("local")).toThrow(
      expect.objectContaining({ code: "sdk.capability_unsupported" }),
    );
    await expect(
      remote.publish(() => new Response(), { targetHostname: "localhost" }),
    ).rejects.toMatchObject({
      code: "sdk.capability_unsupported",
    });
    await remote.close();
    expect(loader.load).not.toHaveBeenCalled();
  });

  test("captures a portable credential only in the private Go boundary", async () => {
    const f = fixture();
    const remote = deployment();
    const db = await remote.connect("db");
    expect(loader.load).toHaveBeenCalledOnce();
    expect(f.bridge.createDeployment).toHaveBeenCalledWith(
      {
        project: "acme/shop",
        name: "production",
        credential: "private-credential",
        services: [],
      },
      { fetch: expect.any(Function), WebSocket: expect.any(Function) },
      expect.any(AbortSignal),
    );
    expect(Object.keys(db)).toEqual(["open"]);
    expect(inspect(db)).not.toContain("private-credential");
    expect(JSON.stringify(remote)).not.toContain("private-credential");
    await remote.close();
  });

  test("requires explicit remote credentials and facts without reading native environment", () => {
    vi.stubEnv("TNL_TOKEN", "ambient-secret");
    vi.stubEnv("TNL_CONNECTION_HANDLE", "/native/handle");
    expect(() => createClient({ project: "acme/shop", services }).deployment("production")).toThrow(
      expect.objectContaining({ code: "sdk.configuration_invalid" }),
    );
    const remote = deployment();
    expect(() =>
      // @ts-expect-error invalid JavaScript callers are rejected before startup.
      remote.client("missing", { create: vi.fn(), close: vi.fn() }),
    ).toThrow(expect.objectContaining({ code: "sdk.configuration_invalid" }));
    expect(loader.load).not.toHaveBeenCalled();
  });

  test.each(["", "dpl_short", `dpl_${"a".repeat(22)}\n`, "../production"])(
    "rejects invalid deployment names without startup: %j",
    (name) => {
      expect(() =>
        createClient({ project: "acme/shop", services, token: "private" }).deployment(name),
      ).toThrow(expect.objectContaining({ code: "sdk.configuration_invalid" }));
      expect(loader.load).not.toHaveBeenCalled();
    },
  );

  test("TCP portable adapter and factory own their stream and driver", async () => {
    const f = fixture();
    const remote = deployment();
    const close = vi.fn(async (stream: TnlStream) => stream.close());
    const create = vi.fn(async (connection: Awaited<ReturnType<typeof remote.connect<"cache">>>) =>
      connection.open(),
    );
    const get = remote.client("cache", { create, close });
    const first = await get();
    expect(await get()).toBe(first);
    expect(f.backend.connect).toHaveBeenCalledTimes(2);
    expect(create).toHaveBeenCalledOnce();
    const writer = first.writable.getWriter();
    const reader = first.readable.getReader();
    const bytes = new Uint8Array([0, 255, 17, 42]);
    await writer.write(bytes);
    expect((await reader.read()).value).toEqual(bytes);
    expect(f.streams[0]?.startTls).not.toHaveBeenCalled();
    await remote.close();
    expect(close).toHaveBeenCalledExactlyOnceWith(first);
    expect(f.streams[0]?.close).toHaveBeenCalledOnce();
    expect(f.events.at(-1)).toBe("runtime:close");
  });

  test("PostgreSQL portable adapter only receives a stream after Go TLS setup", async () => {
    const f = fixture();
    const remote = deployment();
    const get = remote.client("db", {
      async create(connection) {
        const stream = await connection.open();
        const writer = stream.writable.getWriter();
        // a protocol adapter supplies startup/auth bytes; tnl supplies no DB password.
        await writer.write(new Uint8Array([0, 0, 0, 8, 0, 3, 0, 0]));
        return stream;
      },
      close: (stream) => stream.close(),
    });
    await get();
    expect(f.events.slice(0, 3)).toEqual(["db:open", "db:tls", "db:write"]);
    await get.close();
    await remote.close();
  });

  test("MySQL portable adapter controls SSLRequest while Go owns TLS", async () => {
    const f = fixture();
    const remote = deployment();
    const get = remote.client("mysql", {
      async create(connection) {
        const stream = await connection.open();
        const reader = stream.readable.getReader();
        expect((await reader.read()).value).toEqual(new Uint8Array([1, 2, 3]));
        reader.releaseLock();
        const writer = stream.writable.getWriter();
        const sslRequest = new Uint8Array(36);
        sslRequest[0] = 32;
        sslRequest[5] = 8;
        await writer.write(sslRequest);
        await stream.startTls();
        await writer.write(new Uint8Array([1, 0, 0, 2, 0]));
        return stream;
      },
      close: (stream) => stream.close(),
    });
    await get();
    expect(f.events.slice(0, 4)).toEqual(["mysql:open", "mysql:write", "mysql:tls", "mysql:write"]);
    await remote.close();
  });

  test.each(["web", "cluster"] as const)(
    "%s Fetch adapter stays on the Go service transport with manual redirects",
    async (name) => {
      const f = fixture();
      const remote = deployment();
      const get = remote.client(name, {
        create: (connection) => connection.fetch,
        close() {},
      });
      const fetch = await get();
      const response = await fetch("/api?watch=true", { method: "POST", body: "payload" });
      expect(await response.json()).toEqual({
        method: "POST",
        url: `https://${name}.example.test/api?watch=true`,
        redirect: "manual",
        body: "payload",
      });
      await expect(fetch("https://elsewhere.example.test/")).rejects.toMatchObject({
        code: "sdk.configuration_invalid",
      });
      await expect(fetch(`https://user:password@${name}.example.test/`)).rejects.toMatchObject({
        code: "sdk.configuration_invalid",
      });
      expect(f.connections.get(name)?.fetch).toHaveBeenCalledOnce();
      const connection = await remote.connect(name);
      await (await connection.open()).close();
      expect(f.streams[0]?.startTls).toHaveBeenCalledOnce();
      await remote.close();
    },
  );

  test("rejects protocol drift before starting a supplied driver and retains cleanup", async () => {
    const f = fixture();
    const remote = deployment();
    f.backend.connect.mockResolvedValueOnce({
      metadata: { key: "binding:db", protocol: "mysql", hostname: "db.example.test" },
      open: vi.fn(),
      fetch: vi.fn(),
      close: vi.fn(async () => {}),
    });
    const create = vi.fn();
    await expect(remote.client("db", { create, close: vi.fn() })()).rejects.toMatchObject({
      code: "sdk.wasm_invalid",
    });
    expect(create).not.toHaveBeenCalled();
    await remote.close();
    expect(f.backend.close).toHaveBeenCalledOnce();
  });

  test("redacts arbitrary Go, host, and malformed ABI errors", async () => {
    const f = fixture();
    const remote = deployment();
    f.backend.connect.mockRejectedValueOnce(new Error("private-credential: server body"));
    let failure: unknown;
    try {
      await remote.connect("db");
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({ code: "sdk.connection_unavailable" });
    expect(inspect(failure)).not.toContain("private-credential");
    expect(JSON.stringify(failure)).not.toContain("server body");
    await remote.close();
  });

  test("abort interrupts a pending Go opening and close joins its late stream", async () => {
    const f = fixture();
    const remote = deployment();
    const connection = await remote.connect("cache");
    const opened = deferred<WasmByteStream>();
    const entered = deferred<void>();
    const raw = f.connections.get("cache");
    if (raw === undefined) throw new Error("missing fixture connection");
    raw.open = vi.fn(async () => {
      entered.resolve();
      return opened.promise;
    });
    const pending = connection.open();
    const rejected = expect(pending).rejects.toMatchObject({ code: "sdk.client_closed" });
    await entered.promise;
    let done = false;
    const cleanup = remote.close().then(() => {
      done = true;
    });
    await Promise.resolve();
    expect(done).toBe(false);
    const late = byteStream(f.events, "late");
    opened.resolve(late);
    await Promise.all([rejected, cleanup]);
    expect(late.close).toHaveBeenCalledOnce();
    expect(f.bridge.close).toHaveBeenCalledOnce();
  });

  test("deployment close joins late driver creation and never stops a sibling runtime", async () => {
    const first = fixture();
    const a = deployment();
    const creating = deferred<{ value: number }>();
    const entered = deferred<void>();
    const close = vi.fn();
    const get = a.client("cache", {
      create() {
        entered.resolve();
        return creating.promise;
      },
      close,
    });
    const pending = get();
    const rejected = expect(pending).rejects.toMatchObject({ code: "sdk.client_closed" });
    await entered.promise;
    const sibling = fixture();
    const b = deployment();
    const connection = await b.connect("cache");
    const stopped = a.close();
    creating.resolve({ value: 42 });
    await Promise.all([rejected, stopped]);
    expect(close).toHaveBeenCalledExactlyOnceWith({ value: 42 });
    expect(first.bridge.close).toHaveBeenCalledOnce();
    expect(sibling.bridge.close).not.toHaveBeenCalled();
    await (await connection.open()).close();
    await b.close();
  });

  test("failed driver cleanup stays retryable without exiting its Go runtime", async () => {
    const f = fixture();
    const remote = deployment();
    const failure = new Error("application driver cleanup failed");
    const close = vi.fn().mockRejectedValueOnce(failure).mockResolvedValue(undefined);
    const get = remote.client("cache", { create: () => ({ driver: true }), close });
    await get();
    await expect(remote.close()).rejects.toBe(failure);
    expect(f.bridge.close).not.toHaveBeenCalled();
    await remote.close();
    expect(close).toHaveBeenCalledTimes(2);
    expect(f.bridge.close).toHaveBeenCalledOnce();
  });

  test("close preserves a real operation failure that races cancellation", async () => {
    const f = fixture();
    const remote = deployment();
    const connection = await remote.connect("cache");
    const entered = deferred<void>();
    const opening = deferred<never>();
    const raw = f.connections.get("cache");
    if (raw === undefined) throw new Error("missing fixture connection");
    raw.open = vi.fn(async () => {
      entered.resolve();
      return opening.promise;
    });
    const pending = connection.open();
    const failed = expect(pending).rejects.toMatchObject({ code: "sdk.connection_unavailable" });
    await entered.promise;
    const cleanup = remote.close();
    const cleanupFailed = expect(cleanup).rejects.toMatchObject({
      code: "sdk.connection_unavailable",
    });
    opening.reject(new Error("private credential: independent network failure"));
    await Promise.all([failed, cleanupFailed]);
    expect(f.bridge.close).not.toHaveBeenCalled();
    await remote.close();
    expect(f.bridge.close).toHaveBeenCalledOnce();
  });

  test("malformed ABI handles with a close method remain owned for cleanup", async () => {
    const f = fixture();
    const remote = deployment();
    const close = vi.fn(async () => {});
    f.backend.connect.mockResolvedValueOnce({ close });
    await expect(remote.connect("db")).rejects.toMatchObject({ code: "sdk.wasm_invalid" });
    await remote.close();
    expect(close).toHaveBeenCalledOnce();
    expect(f.bridge.close).toHaveBeenCalledOnce();
  });
});
