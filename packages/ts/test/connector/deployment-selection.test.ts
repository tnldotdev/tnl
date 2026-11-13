import { afterEach, beforeEach, expect, onTestFinished, test, vi } from "vitest";

const native = vi.hoisted(() => ({
  request: vi.fn<(binary: string, args: string[]) => Promise<{ stdout: string }>>(),
  resolve: vi.fn(() => "/installed/matching/tnl"),
}));
vi.mock("../../src/internal/native/launcher.js", () => ({ resolveNativeBinary: native.resolve }));
vi.mock("../../src/internal/connector/connection_ipc.js", () => ({
  ownerIPC: async (file: string) => ({
    async prepare(name: string, _assertion?: string, selection?: object) {
      const { stdout } = await native.request("/installed/matching/tnl", [
        "runtime",
        "connections",
        selection === undefined ? "prepare" : "sdk-prepare",
        "--handle",
        file,
        "--service",
        name,
      ]);
      return JSON.parse(stdout) as unknown;
    },
    close() {},
  }),
}));
vi.mock("node:child_process", () => ({
  execFile(
    binary: string,
    args: string[],
    _options: unknown,
    callback: (error: unknown, stdout?: string) => void,
  ) {
    void native.request(binary, args).then(
      ({ stdout }) => callback(null, stdout),
      (error) => callback(error),
    );
    return { stdin: { end() {} } };
  },
}));

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
  transport_id: "ctg_aaaaaaaaaaaaaaaaaaaaaa",
  ssl: { servername: service.hostname, rejectUnauthorized: true },
});
const prepared = () => ({ schema: 1, project_runtime: project, connection: connection() });
const started = () => ({
  expires_at: new Date(Date.now() + 60_000).toISOString(),
  connection_handle: "/private/prepared/handle.json",
  executable: "/installed/matching/tnl",
});
const selected = () => ({ schema: 1, owner: started(), prepared: prepared() });
const options = {
  project: "team/project",
  token: "private-credential",
  services: { database: { protocol: "postgres" } },
} as const;

beforeEach(() => {
  const listeners = new Set(process.listeners("beforeExit"));
  onTestFinished(() => {
    for (const listener of process.listeners("beforeExit"))
      if (!listeners.has(listener)) process.removeListener("beforeExit", listener);
  });
  vi.resetModules();
  vi.stubGlobal("__tnlConnectorContextV2", undefined);
  vi.stubEnv("TNL_CONNECTION_HANDLE", undefined);
  native.resolve.mockReset().mockReturnValue("/installed/matching/tnl");
  native.request.mockReset().mockImplementation(async (_binary, args) => {
    if (args.includes("--recover-handle")) throw new Error("fixture owner remains alive");
    return {
      stdout: JSON.stringify(
        args.includes("sdk-stop")
          ? { schema: 1, state: "stopped" }
          : args.includes("sdk-prepare")
            ? selected()
            : prepared(),
      ),
    };
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

test("factories retain clients across renewal and separate exact native bindings", async () => {
  const { createClient } = await import("../../src/index.js");
  let owner = "a";
  native.request.mockImplementation(async () => ({
    stdout: JSON.stringify({
      ...selected(),
      owner: { ...started(), connection_handle: `/private/${owner}/handle.json` },
    }),
  }));
  const deployment = createClient(options).deployment("production");
  const create = vi.fn((settings: object) => ({ settings }));
  const close = vi.fn();
  const get = deployment.client("database", { create, close });
  const a = await get();
  expect(await get()).toBe(a);
  owner = "b";
  const b = await get();
  expect(b).not.toBe(a);
  owner = "a";
  expect(await get()).toBe(a);
  expect(create).toHaveBeenCalledTimes(2);
  const calls = native.request.mock.calls.length;
  await get.close();
  expect(close.mock.calls.map(([client]) => client)).toEqual([a, b]);
  expect(native.request.mock.calls).toHaveLength(calls);
});

test("module copies and native executables have independent deployment lifetimes", async () => {
  const first = await import("../../src/index.js");
  const a = first.createClient(options).deployment("production");
  await a.connect("database");
  vi.resetModules();
  const second = await import("../../src/index.js");
  native.resolve.mockReturnValue("/installed/other/tnl");
  native.request.mockResolvedValueOnce({
    stdout: JSON.stringify({
      ...selected(),
      owner: { ...started(), executable: "/installed/other/tnl" },
    }),
  });
  const b = second.createClient(options).deployment("production");
  await b.connect("database");
  const calls = native.request.mock.calls;
  expect(calls[0]?.[0]).toBe("/installed/matching/tnl");
  expect(calls[1]?.[0]).toBe("/installed/other/tnl");
  expect(calls[0]?.[1]).not.toEqual(calls[1]?.[1]);
  await a.close();
  native.request.mockResolvedValueOnce({
    stdout: JSON.stringify({
      ...selected(),
      owner: { ...started(), executable: "/installed/other/tnl" },
    }),
  });
  expect(await b.connect("database")).toHaveProperty("port", 24567);
});

test("resolved settings are frozen plain driver options and never select again on spread", async () => {
  const { createClient } = await import("../../src/index.js");
  const deployment = createClient(options).deployment("production");
  const first = await deployment.connect("database");
  const calls = native.request.mock.calls.length;
  expect(Object.isFrozen(first)).toBe(true);
  expect(Object.isFrozen(first.ssl)).toBe(true);
  expect(Object.getPrototypeOf(first)).toBe(Object.prototype);
  expect({ ...first }).toEqual({
    host: "127.0.0.1",
    port: 24567,
    ssl: { servername: service.hostname, rejectUnauthorized: true },
  });
  expect(first).not.toHaveProperty("then");
  expect(first).not.toHaveProperty("expires_at");
  expect(first).not.toHaveProperty("protocol");
  expect(native.request.mock.calls).toHaveLength(calls);
});

test("malformed warm replies cannot retire an established owner or reveal private input", async () => {
  const { createClient } = await import("../../src/index.js");
  const deployment = createClient(options).deployment("production");
  const first = await deployment.connect("database");
  for (const invalid of [
    { ...selected(), prepared: { ...prepared(), schema: 2 } },
    { ...selected(), owner: { ...started(), pid: "private-invalid-pid" } },
    {
      ...selected(),
      owner: { ...started(), project_runtime: { ...project, token: "private-token" } },
    },
    { ...selected(), owner: { ...started(), extra: "private-owner-data" } },
    {
      schema: 1,
      reason: "TNL_CLIENT_AUTHENTICATION_REQUIRED",
      sdk_retained_start_failure: "private-marker",
    },
    {
      schema: 1,
      reason: "TNL_CLIENT_AUTHENTICATION_REQUIRED",
      sdk_failure_handle: { key: "private-reference" },
    },
  ]) {
    native.request.mockResolvedValueOnce({ stdout: JSON.stringify(invalid) });
    await expect(deployment.connect("database")).rejects.toMatchObject({
      code: "sdk.response_invalid",
    });
  }
  expect(await deployment.connect("database")).toEqual(first);
  expect(native.request.mock.calls.some(([, args]) => args.includes("sdk-stop"))).toBe(false);
});

test.each([
  ["TNL_CLIENT_AUTHENTICATION_REQUIRED", "sdk.authentication_required"],
  ["TNL_SERVER_RESPONSE_INVALID", "sdk.response_invalid"],
  ["TNL_CLIENT_CONNECTION_CLEANUP_FAILED", "sdk.cleanup_failed"],
])(
  "native IPC failure %s retains its classification without private data",
  async (reason, code) => {
    const { createClient } = await import("../../src/index.js");
    const deployment = createClient(options).deployment("production");
    await deployment.connect("database");
    native.request.mockResolvedValueOnce({
      stdout: JSON.stringify({
        schema: 1,
        reason,
        sdk_retained_start_failure: true,
        sdk_failure_handle: "private-failure-reference",
      }),
    });
    try {
      await deployment.connect("database");
      throw new Error("expected native failure");
    } catch (error) {
      expect(error).toMatchObject({ code });
      expect(JSON.stringify(error)).not.toContain("private-failure-reference");
    }
    expect(await deployment.connect("database")).toHaveProperty("port", 24567);
  },
);

test.each([undefined, "", "ctg_invalid"])(
  "rejects invalid transport identity %j",
  async (transport_id) => {
    vi.stubEnv("TNL_CONNECTION_HANDLE", "/private/action/handle.json");
    const { createClient } = await import("../../src/index.js");
    const deployment = createClient({
      project: options.project,
      services: options.services,
    }).deployment("production");
    native.request.mockResolvedValue({
      stdout: JSON.stringify({
        ...prepared(),
        connection: { ...connection(), transport_id },
      }),
    });
    await expect(deployment.connect("database")).rejects.toMatchObject({
      code: "sdk.response_invalid",
    });
  },
);

test("borrowed snapshots reject protocol, metadata, secret fields, and expiry changes", async () => {
  vi.stubEnv("TNL_CONNECTION_HANDLE", "/private/action/handle.json");
  const { createClient } = await import("../../src/index.js");
  const deployment = createClient({
    project: options.project,
    services: options.services,
  }).deployment("production");
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
    {
      ...prepared(),
      connection: { ...connection(), expires_at: new Date(Date.now() - 1).toISOString() },
    },
  ]) {
    native.request.mockResolvedValueOnce({ stdout: JSON.stringify(invalid) });
    await expect(deployment.connect("database")).rejects.toMatchObject({
      code: "sdk.response_invalid",
    });
  }
  expect(native.resolve).not.toHaveBeenCalled();
  expect(native.request.mock.calls.every(([, args]) => args[2] === "prepare")).toBe(true);
});

test("failed preparation can retry without exposing native stderr or triggering SDK replacement", async () => {
  const { createClient } = await import("../../src/index.js");
  const deployment = createClient(options).deployment("production");
  native.request.mockRejectedValueOnce({ stderr: "private-secret", stdout: "private-key" });
  await expect(deployment.connect("database")).rejects.toMatchObject({
    code: "sdk.connection_unavailable",
  });
  expect(await deployment.connect("database")).toHaveProperty("port", 24567);
  native.request.mockRejectedValueOnce({ code: "ETIMEDOUT" });
  await expect(deployment.connect("database")).rejects.toMatchObject({
    code: "sdk.connection_unavailable",
  });
  expect(await deployment.connect("database")).toHaveProperty("port", 24567);
  expect(native.request.mock.calls.some(([, args]) => args.includes("sdk-stop"))).toBe(false);
});

test("native cleanup failures retain typed causes and permit an explicit retry", async () => {
  const { createClient } = await import("../../src/index.js");
  const { TnlCleanupError } = await import("../../src/errors.js");
  const deployment = createClient(options).deployment("production");
  native.request.mockRejectedValueOnce({
    stderr: JSON.stringify({
      reason: "TNL_CLIENT_CONNECTION_CLEANUP_FAILED",
      message: "private-cleanup-detail",
    }),
  });
  let failure: unknown;
  try {
    await deployment.connect("database");
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(TnlCleanupError);
  expect(failure).toMatchObject({
    cause: { code: "sdk.response_invalid" },
    errors: expect.any(Array),
  });
  expect(JSON.stringify(failure)).not.toContain("private-cleanup-detail");
  expect(await deployment.connect("database")).toHaveProperty("port", 24567);
});
