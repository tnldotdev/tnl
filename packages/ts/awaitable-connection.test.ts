import { afterEach, beforeEach, describe, expect, onTestFinished, test, vi } from "vitest";

const native = vi.hoisted(() => ({
  async: vi.fn<(binary: string, args: string[]) => Promise<{ stdout: string }>>(),
  sync: vi.fn<(binary: string, args: string[]) => string>(),
  resolve: vi.fn(() => "/installed/matching/tnl"),
}));
vi.mock("./src/internal/launcher.js", () => ({ resolveNativeBinary: native.resolve }));
// reuse the response queue for direct async IPC; synchronous reads still use
// the installed native reader and never dispatch a prepare operation.
vi.mock("./src/internal/connection_ipc.js", () => ({
  ownerIPC: async (file: string) => ({
    async prepare(name: string) {
      const { stdout } = await native.async("/installed/matching/tnl", [
        "--no-telemetry",
        "runtime",
        "connections",
        "prepare",
        "--handle",
        file,
        "--service",
        name,
      ]);
      const value: unknown = JSON.parse(stdout);
      return value;
    },
    close() {},
  }),
}));
vi.mock("node:child_process", async () => {
  const execFile = (
    binary: string,
    args: string[],
    _options: unknown,
    callback: (error: unknown, stdout?: string) => void,
  ) => {
    void native.async(binary, args).then(
      ({ stdout }) => callback(null, stdout),
      (error) => callback(error),
    );
    return { stdin: { end() {} } };
  };
  return { execFile, execFileSync: native.sync };
});

const service = {
  protocol: "postgres",
  hostname: "database.team.example",
  namespace: "team.example",
  port: 15432,
  public: true,
};
const project = { dev: false, namespace: "team.example", services: { database: service } };
const connection = () => ({
  schema: 1,
  protocol: "postgres",
  host: "127.0.0.1",
  port: 24567,
  expires_at: new Date(Date.now() + 60_000).toISOString(),
  ssl: { servername: service.hostname, rejectUnauthorized: true },
});
const prepared = () => ({ schema: 1, public_runtime: project, connection: connection() });
const started = () => ({
  schema: 1,
  state: "ready",
  pid: 123,
  expires_at: new Date(Date.now() + 60_000).toISOString(),
  public_runtime: project,
  private_handle: "/private/prepared/handle.json",
  executable: "/installed/matching/tnl",
});

beforeEach(() => {
  const exitListeners = new Set(process.listeners("beforeExit"));
  onTestFinished(() => {
    for (const listener of process.listeners("beforeExit"))
      if (!exitListeners.has(listener)) process.removeListener("beforeExit", listener);
  });
  vi.resetModules();
  vi.stubEnv("TNL_CONNECTION_HANDLE", undefined);
  for (const name of ["TNL_WORKLOAD", "GITHUB_ACTIONS", "VERCEL", "FLY_APP_NAME"])
    vi.stubEnv(name, undefined);
  native.resolve.mockClear();
  native.async.mockReset().mockImplementation(async (_binary, args) => ({
    stdout: JSON.stringify(
      args.includes("start")
        ? started()
        : args.includes("stop")
          ? { schema: 1, state: "stopped" }
          : prepared(),
    ),
  }));
  native.sync.mockReset().mockImplementation(() => JSON.stringify(prepared()));
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

describe("awaitable root connection handles", () => {
  test("a sibling synchronous settings read dispatches only prepared read and no provider/control preparation", async () => {
    const { connectionHandle } = await import("./src/internal/connection.js");
    await connectionHandle("database", vi.fn());
    const before = native.async.mock.calls.length;
    native.sync.mockImplementation(() => {
      throw Object.assign(new Error("native prepared read failed"), {
        stderr: JSON.stringify({ reason: "TNL_CLIENT_CONNECTION_UNAVAILABLE" }),
      });
    });
    expect(() => Reflect.get(connectionHandle("sibling", vi.fn()), "port")).toThrow();
    expect(native.async).toHaveBeenCalledTimes(before);
    expect(native.sync.mock.calls.at(-1)?.[1][3]).toBe("read");
  });
  test("creation is immediate and unprepared reads fail before resolving a binary", async () => {
    const { connectionHandle } = await import("./src/internal/connection.js");
    const { TnlError } = await import("./src/errors.js");
    const handle = connectionHandle("database", vi.fn());
    expect(typeof handle.then).toBe("function");
    expect(Object.getOwnPropertyDescriptor(handle, "then")).toMatchObject({
      enumerable: false,
      writable: false,
    });
    expect(() => ({ ...handle })).toThrow(
      expect.objectContaining({ code: "sdk.connection_unprepared" }),
    );
    expect(() => Reflect.get(handle, "host")).toThrow(TnlError);
    expect(native.resolve).not.toHaveBeenCalled();
    expect(native.async).not.toHaveBeenCalled();
    expect(native.sync).not.toHaveBeenCalled();
  });

  test("Promise.resolve and concurrent awaits prepare only the requested service once", async () => {
    const { connectionHandle } = await import("./src/internal/connection.js");
    const update = vi.fn();
    const handle = connectionHandle("database", update);
    const other = connectionHandle("database", update);
    const [first, second, third] = await Promise.all([handle, Promise.resolve(handle), other]);
    expect(first).toEqual(second);
    expect(second).toEqual(third);
    expect(first).not.toHaveProperty("then");
    expect(Object.getPrototypeOf(first)).toBe(Object.prototype);
    expect(Object.isFrozen(first)).toBe(true);
    if (!("ssl" in first)) throw new Error("expected SQL options");
    expect(Object.isFrozen(first.ssl)).toBe(true);
    expect(first).toEqual({
      host: "127.0.0.1",
      port: 24567,
      ssl: { servername: service.hostname, rejectUnauthorized: true },
    });
    const starts = native.async.mock.calls.filter(([, args]) => args.includes("start"));
    expect(starts).toHaveLength(1);
    expect(starts[0]?.[1]).not.toContain("--service");
    expect(native.async).toHaveBeenCalledTimes(2);
    expect(update).toHaveBeenCalledWith(project);

    expect({ ...connectionHandle("database", update) }).toEqual(first);
    expect(native.sync).toHaveBeenCalledWith(
      "/installed/matching/tnl",
      [
        "--no-telemetry",
        "runtime",
        "connections",
        "read",
        "--handle",
        "/private/prepared/handle.json",
        "--service",
        "database",
      ],
      expect.objectContaining({
        timeout: expect.any(Number),
        maxBuffer: 128 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      }),
    );
    expect(() => Reflect.set(handle, "port", 1)).not.toThrow();
    expect(Reflect.set(handle, "port", 1)).toBe(false);
    expect(Reflect.deleteProperty(handle, "host")).toBe(false);
    expect(Object.keys(handle)).toEqual(["host", "port", "ssl"]);
    expect({ ...handle }).not.toHaveProperty("expires_at");
    expect({ ...handle }).not.toHaveProperty("protocol");
  });

  test("prepared environment handles support synchronous reads without startup", async () => {
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("TNL_WORKLOAD", "storefront");
    vi.stubEnv("TNL_CONNECTION_HANDLE", "/private/action/handle.json");
    const { connectionHandle } = await import("./src/internal/connection.js");
    const handle = connectionHandle("database", vi.fn());
    expect("ssl" in handle).toBe(true);
    expect(Reflect.get(handle, "host")).toBe("127.0.0.1");
    expect(native.async).not.toHaveBeenCalled();
    expect(native.sync).toHaveBeenCalledTimes(2);
    const spread = { ...handle };
    expect(Object.keys(spread)).toEqual(["host", "port", "ssl"]);
    expect(native.sync).toHaveBeenCalledTimes(3);
    await handle;
    expect(native.async.mock.calls.every(([, args]) => args.includes("prepare"))).toBe(true);
  });

  test("one spread reads one coherent snapshot, while later reads refresh", async () => {
    vi.stubEnv("TNL_CONNECTION_HANDLE", "/private/action/handle.json");
    let port = 20000;
    native.sync.mockImplementation(() =>
      JSON.stringify({
        ...prepared(),
        connection: {
          ...connection(),
          port: ++port,
          ssl: { ...connection().ssl, ca: String(port) },
        },
      }),
    );
    const { connectionHandle } = await import("./src/internal/connection.js");
    const handle = connectionHandle("database", vi.fn());
    const first = { ...handle };
    const second = { ...handle };
    expect(first).toMatchObject({ port: 20001, ssl: { ca: "20001" } });
    expect(second).toMatchObject({ port: 20002, ssl: { ca: "20002" } });
    expect(native.sync).toHaveBeenCalledTimes(2);
  });

  test("Kubernetes settings dial the local port and retain managed metadata", async () => {
    vi.stubEnv("TNL_CONNECTION_HANDLE", "/private/action/handle.json");
    const url = "https://database.team.example:15443";
    const metadata = { ...service, protocol: "kubernetes", port: 15443, url };
    const value = {
      schema: 1,
      public_runtime: { ...project, services: { database: metadata } },
      connection: {
        ...connection(),
        protocol: "kubernetes",
        url,
        kubeconfig: "/private/action/kubeconfig",
        context: "tnl:database",
      },
    };
    native.sync.mockReturnValue(JSON.stringify(value));
    native.async.mockResolvedValue({ stdout: JSON.stringify(value) });
    const { connectionHandle } = await import("./src/internal/connection.js");
    const update = vi.fn();
    const handle = connectionHandle("database", update);
    expect({ ...handle }).toEqual({
      server: "https://127.0.0.1:24567",
      kubeconfig: "/private/action/kubeconfig",
      context: "tnl:database",
    });
    expect(await handle).toEqual({ ...handle });
    expect(update.mock.lastCall?.[0].services.database).toEqual(metadata);
  });

  test("repeated awaits and synchronous reads reject expired snapshots", async () => {
    vi.stubEnv("TNL_CONNECTION_HANDLE", "/private/action/handle.json");
    const value = prepared();
    native.async.mockResolvedValue({ stdout: JSON.stringify(value) });
    native.sync.mockReturnValue(JSON.stringify(value));
    const { connectionHandle } = await import("./src/internal/connection.js");
    const handle = connectionHandle("database", vi.fn());
    await handle;
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 120_000);
    await expect(Promise.resolve(handle)).rejects.toMatchObject({ code: "sdk.response_invalid" });
    expect(() => ({ ...handle })).toThrow(
      expect.objectContaining({ code: "sdk.response_invalid" }),
    );
    expect(native.async).toHaveBeenCalledTimes(2);
  });

  test("metadata stays public and mismatched, widened or secret-bearing snapshots fail safely", async () => {
    vi.stubEnv("TNL_CONNECTION_HANDLE", "/private/action/handle.json");
    const { connectionHandle } = await import("./src/internal/connection.js");
    const { TnlError } = await import("./src/errors.js");
    const update = vi.fn();
    const handle = connectionHandle("database", update);
    expect({ ...handle }).toMatchObject({ host: "127.0.0.1", port: 24567 });
    expect(update.mock.lastCall?.[0].services.database).toEqual(service);
    for (const invalid of [
      { ...prepared(), extra: "private-proof" },
      {
        ...prepared(),
        connection: {
          ...connection(),
          ssl: { ...connection().ssl, key: "private-key", cert: "private-cert" },
        },
      },
      { ...prepared(), connection: { ...connection(), protocol: "mysql" } },
      {
        ...prepared(),
        connection: { ...connection(), ssl: { ...connection().ssl, servername: "other.example" } },
      },
    ]) {
      native.sync.mockReturnValue(JSON.stringify(invalid));
      try {
        Reflect.get(handle, "host");
        throw new Error("expected rejection");
      } catch (error) {
        expect(error).toBeInstanceOf(TnlError);
        expect(String(error)).not.toMatch(/private-proof|private-key|private-cert/);
        expect(error).not.toHaveProperty("cause");
      }
    }
  });

  test("failed preparation can retry and native stderr never reaches errors", async () => {
    const { connectionHandle } = await import("./src/internal/connection.js");
    native.async.mockRejectedValueOnce({ stderr: "private-secret", stdout: "private-key" });
    const handle = connectionHandle("database", vi.fn());
    await expect(Promise.resolve(handle)).rejects.toMatchObject({
      code: "sdk.connection_unavailable",
    });
    expect(await handle).toHaveProperty("host", "127.0.0.1");
  });

  test("an established owner survives failed reads and remains available to other handles", async () => {
    const { connectionHandle } = await import("./src/internal/connection.js");
    const handle = connectionHandle("database", vi.fn());
    const first = await handle;
    native.async.mockRejectedValueOnce({
      code: "ETIMEDOUT",
      stderr: JSON.stringify({ reason: "TNL_CLIENT_CONNECTION_UNAVAILABLE" }),
    });
    await expect(Promise.resolve(handle)).rejects.toMatchObject({
      code: "sdk.connection_unavailable",
    });
    expect(await connectionHandle("database", vi.fn())).toEqual(first);
    expect({ ...handle }).toEqual(first);
    expect(native.async.mock.calls.filter(([, args]) => args.includes("start"))).toHaveLength(1);
    expect(native.async.mock.calls.filter(([, args]) => args.includes("stop"))).toHaveLength(0);
  });

  test.each(["startup", "snapshot"])(
    "new-owner %s validation failures stop and join before retry",
    async (phase) => {
      const { connectionHandle } = await import("./src/internal/connection.js");
      const handle = connectionHandle("database", vi.fn());
      if (phase === "startup")
        native.async.mockResolvedValueOnce({ stdout: JSON.stringify({ ...started(), schema: 2 }) });
      else
        native.async
          .mockResolvedValueOnce({ stdout: JSON.stringify(started()) })
          .mockResolvedValueOnce({ stdout: JSON.stringify({ ...prepared(), schema: 2 }) });
      await expect(Promise.resolve(handle)).rejects.toMatchObject({ code: "sdk.response_invalid" });
      expect(native.async.mock.calls.filter(([, args]) => args.includes("stop"))).toHaveLength(1);
      expect(() => ({ ...handle })).toThrow(
        expect.objectContaining({ code: "sdk.connection_unprepared" }),
      );
      expect(await handle).toHaveProperty("port", 24567);
      const operations = native.async.mock.calls.map(([, args]) => args[3]);
      expect(operations.indexOf("stop")).toBeLessThan(operations.lastIndexOf("start"));
    },
  );

  test("failed rollback keeps its capability and typed causes until cleanup can join", async () => {
    const { connectionHandle } = await import("./src/internal/connection.js");
    const { TnlCleanupError, TnlError } = await import("./src/errors.js");
    const handle = connectionHandle("database", vi.fn());
    native.async
      .mockResolvedValueOnce({ stdout: JSON.stringify(started()) })
      .mockResolvedValueOnce({ stdout: JSON.stringify({ ...prepared(), schema: 2 }) })
      .mockRejectedValueOnce({ code: "ETIMEDOUT", stderr: "private-cleanup-detail" })
      .mockResolvedValueOnce({ stdout: JSON.stringify({ schema: 1, state: "stopping" }) });
    let failure: unknown;
    try {
      await handle;
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(TnlCleanupError);
    if (!(failure instanceof TnlCleanupError)) throw new Error("expected owned cleanup failure");
    expect(failure.cause).toMatchObject({ code: "sdk.response_invalid" });
    expect(failure.errors).toHaveLength(2);
    expect(failure.errors.every((error) => error instanceof TnlError)).toBe(true);
    expect(JSON.stringify(failure)).not.toContain("private-cleanup-detail");
    expect(() => ({ ...handle })).toThrow(
      expect.objectContaining({ code: "sdk.connection_unprepared" }),
    );
    await expect(Promise.resolve(handle)).rejects.toMatchObject({
      code: "sdk.cleanup_failed",
      cause: failure.cause,
    });
    expect(native.async.mock.calls.filter(([, args]) => args.includes("start"))).toHaveLength(1);
    expect(await handle).toHaveProperty("port", 24567);
    expect(native.async.mock.calls.map(([, args]) => args[3])).toEqual([
      "start",
      "prepare",
      "stop",
      "stop",
      "stop",
      "start",
      "prepare",
    ]);
  });

  test("a failed external preparation never stops or replaces its caller's owner", async () => {
    vi.stubEnv("TNL_CONNECTION_HANDLE", "/private/action/handle.json");
    const { connectionHandle } = await import("./src/internal/connection.js");
    const handle = connectionHandle("database", vi.fn());
    native.async.mockResolvedValueOnce({ stdout: JSON.stringify({ ...prepared(), schema: 2 }) });
    await expect(Promise.resolve(handle)).rejects.toMatchObject({ code: "sdk.response_invalid" });
    expect(await handle).toHaveProperty("port", 24567);
    expect(native.async.mock.calls.map(([, args]) => args[3])).toEqual(["prepare", "prepare"]);
  });

  test("known owner expiry requires async preparation and coalesces one joined replacement", async () => {
    const { connectionHandle } = await import("./src/internal/connection.js");
    const handle = connectionHandle("database", vi.fn());
    const first = await handle;
    const previous = JSON.stringify(first);
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 120_000);
    const calls = native.async.mock.calls.length;
    const synchronous = native.sync.mock.calls.length;
    expect(() => ({ ...handle })).toThrow(
      expect.objectContaining({ code: "sdk.connection_unprepared" }),
    );
    expect(native.async).toHaveBeenCalledTimes(calls);
    expect(native.sync).toHaveBeenCalledTimes(synchronous);
    const settings = await Promise.all(
      Array.from({ length: 8 }, () => Promise.resolve(connectionHandle("database", vi.fn()))),
    );
    expect(settings.every((value) => Object.isFrozen(value))).toBe(true);
    expect(JSON.stringify(first)).toBe(previous);
    expect(native.async.mock.calls.map(([, args]) => args[3])).toEqual([
      "start",
      "prepare",
      "stop",
      "start",
      "prepare",
    ]);
  });

  test("expired owner cleanup retains its capability until joined stop is confirmed", async () => {
    const { connectionHandle } = await import("./src/internal/connection.js");
    const handle = connectionHandle("database", vi.fn());
    await handle;
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 120_000);
    native.async
      .mockRejectedValueOnce({ code: "ETIMEDOUT" })
      .mockResolvedValueOnce({ stdout: JSON.stringify({ schema: 1, state: "stopping" }) });
    await expect(Promise.resolve(handle)).rejects.toMatchObject({
      code: "sdk.connection_unavailable",
    });
    await expect(Promise.resolve(handle)).rejects.toMatchObject({ code: "sdk.response_invalid" });
    expect(native.async.mock.calls.filter(([, args]) => args.includes("start"))).toHaveLength(1);
    expect(() => ({ ...handle })).toThrow(
      expect.objectContaining({ code: "sdk.connection_unprepared" }),
    );
    await handle;
    expect(native.async.mock.calls.map(([, args]) => args[3])).toEqual([
      "start",
      "prepare",
      "stop",
      "stop",
      "stop",
      "start",
      "prepare",
    ]);
  });

  test("snapshot expiry cannot replace a live owner or extend its validated deadline", async () => {
    const { connectionHandle } = await import("./src/internal/connection.js");
    const handle = connectionHandle("database", vi.fn());
    const now = Date.now();
    await handle;
    vi.useFakeTimers();
    vi.setSystemTime(now + 30_000);
    native.async.mockResolvedValueOnce({
      stdout: JSON.stringify({
        ...prepared(),
        connection: { ...connection(), expires_at: new Date(now - 1).toISOString() },
      }),
    });
    await expect(Promise.resolve(handle)).rejects.toMatchObject({ code: "sdk.response_invalid" });
    await handle;
    expect(native.async.mock.calls.filter(([, args]) => args.includes("start"))).toHaveLength(1);
    expect(native.async.mock.calls.filter(([, args]) => args.includes("stop"))).toHaveLength(0);
    vi.setSystemTime(now + 61_000);
    await handle;
    expect(native.async.mock.calls.filter(([, args]) => args.includes("stop"))).toHaveLength(1);
    expect(native.async.mock.calls.filter(([, args]) => args.includes("start"))).toHaveLength(2);
  });
});
