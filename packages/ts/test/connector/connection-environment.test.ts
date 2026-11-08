import { context, ROOT_CONTEXT, trace } from "@opentelemetry/api";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

interface Owner {
  file: string;
  port: number;
}

const fixture = vi.hoisted(() => ({
  launches: [] as { args: string[]; environment: NodeJS.ProcessEnv; input: unknown }[],
  owners: new Map<string, Owner>(),
  scopeGate: undefined as Promise<void> | undefined,
  scopeStarted: vi.fn(),
  scopes: 0,
  workload: false,
  realWorkload: false,
  provider: undefined as
    | typeof import("../../src/internal/connector/workload/provider.js")
    | undefined,
  failIPC: false,
  acquireAssertion: vi.fn<() => Promise<string>>(),
}));
vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => "/fixture/tnl",
}));
vi.mock("node:fs/promises", async (original) => ({
  ...(await original<typeof import("node:fs/promises")>()),
  async open() {
    const manifest = Buffer.from(
      JSON.stringify({
        schema: 1,
        server: "https://a.example",
        team: "team",
        project_key: "project",
        source_fingerprint: "a".repeat(64),
        project_label: "project",
        services: { database: "postgres" },
        workloads: {
          job: {
            provider: "oidc",
            services: ["database"],
            max_duration_seconds: 3600,
            acquisition: { method: "callback", audience: "trusted-audience" },
          },
        },
      }),
    );
    let position = 0;
    return {
      stat: async () => ({ isFile: () => true, size: manifest.length }),
      async read(buffer: Buffer, offset: number, length: number) {
        const bytesRead = manifest.copy(buffer, offset, position, position + length);
        position += bytesRead;
        return { bytesRead };
      },
      async close() {},
    };
  },
  async realpath(value: string) {
    fixture.scopeStarted();
    await fixture.scopeGate;
    return value;
  },
  mkdtemp: async (prefix: string) => `${prefix}fixture-${++fixture.scopes}`,
}));
vi.mock("../../src/internal/connector/workload/provider.js", () => ({
  configureWorkload: (
    ...args: Parameters<ReturnType<typeof actualProvider>["configureWorkload"]>
  ) => actualProvider().configureWorkload(...args),
  usesWorkload: (...args: Parameters<ReturnType<typeof actualProvider>["usesWorkload"]>) =>
    fixture.realWorkload ? actualProvider().usesWorkload(...args) : fixture.workload,
  acquireAssertion: (...args: Parameters<ReturnType<typeof actualProvider>["acquireAssertion"]>) =>
    fixture.realWorkload ? actualProvider().acquireAssertion(...args) : fixture.acquireAssertion(),
  selectWorkload: async (
    ...args: Parameters<ReturnType<typeof actualProvider>["selectWorkload"]>
  ) =>
    fixture.realWorkload
      ? actualProvider().selectWorkload(...args)
      : {
          name: "job",
          directory: process.cwd(),
          selected: { services: ["database"] },
          manifest: { schema: 1 },
        },
}));

function actualProvider() {
  if (fixture.provider === undefined) throw new Error("provider not loaded");
  return fixture.provider;
}
vi.mock("../../src/internal/connector/connection_ipc.js", () => ({
  ownerIPC: async (file: string) => ({
    async prepare() {
      if (fixture.failIPC) throw new Error("owner disconnected");
      const owner = [...fixture.owners.values()].find((owner) => owner.file === file);
      if (owner === undefined) throw new Error("unknown owner");
      return prepared(owner);
    },
    close() {},
  }),
}));
vi.mock("node:child_process", () => ({
  execFile(
    _binary: string,
    args: string[],
    options: { env: NodeJS.ProcessEnv },
    callback: (error: Error | null, stdout: string) => void,
  ) {
    const environment = { ...options.env };
    return {
      stdin: {
        on() {},
        end(input: string | undefined) {
          fixture.launches.push({
            args,
            environment,
            input: input === undefined ? undefined : (JSON.parse(input) as unknown),
          });
          queueMicrotask(() => {
            if (args[3] === "sdk-stop") {
              callback(null, JSON.stringify({ schema: 1, state: "stopped" }));
              return;
            }
            const registry = args[args.indexOf("--registry") + 1];
            if (registry === undefined) throw new Error("missing registry");
            let owner = fixture.owners.get(registry);
            if (owner === undefined) {
              owner = {
                file: `/fixture/owner-${fixture.owners.size}/handle.json`,
                port:
                  environment.TNL_SERVER === "https://b.example" ||
                  environment.TNL_STATE_DIR === "/fixture/state-b"
                    ? 20002
                    : 20001,
              };
              fixture.owners.set(registry, owner);
            }
            callback(null, JSON.stringify(prepared(owner)));
          });
        },
      },
    };
  },
  execFileSync() {
    throw new Error("no synchronous read in this fixture");
  },
}));

function prepared(owner: Owner) {
  return {
    schema: 1,
    owner: {
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      connection_handle: owner.file,
      executable: "/fixture/tnl",
    },
    prepared: {
      schema: 1,
      project_runtime: {
        dev: false,
        namespace: "team.example",
        services: {
          database: {
            protocol: "postgres",
            hostname: "database.team.example",
            namespace: "team.example",
            port: 15432,
            public: true,
          },
        },
      },
      connection: {
        schema: 1,
        protocol: "postgres",
        host: "127.0.0.1",
        port: owner.port,
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        transport_id: "ctg_aaaaaaaaaaaaaaaaaaaaaa",
        ssl: { servername: "database.team.example", rejectUnauthorized: true },
      },
    },
  };
}

let originalListeners = new Set(process.listeners("beforeExit"));
beforeEach(async () => {
  vi.resetModules();
  globalThis.__tnlConnectorContextV1 = undefined;
  fixture.provider = await vi.importActual("../../src/internal/connector/workload/provider.js");
  fixture.launches.length = 0;
  fixture.owners.clear();
  fixture.scopeGate = undefined;
  fixture.scopes = 0;
  fixture.workload = false;
  fixture.realWorkload = false;
  fixture.failIPC = false;
  fixture.acquireAssertion.mockImplementation(async () => process.env.VERCEL_OIDC_TOKEN ?? "");
  vi.stubEnv("TNL_SERVER", "https://a.example");
  vi.stubEnv("TNL_STATE_DIR", "/fixture/state-a");
  vi.stubEnv("TNL_CONNECTION_HANDLE", undefined);
  for (const name of ["TNL_WORKLOAD", "VERCEL", "FLY_APP_NAME", "GITHUB_ACTIONS"])
    vi.stubEnv(name, undefined);
  originalListeners = new Set(process.listeners("beforeExit"));
});
afterEach(() => {
  globalThis.__tnlConnectorContextV1 = undefined;
  for (const listener of process.listeners("beforeExit"))
    if (!originalListeners.has(listener)) process.removeListener("beforeExit", listener);
});

test.each([
  { name: "TNL_SERVER", initial: "https://a.example", changed: "https://b.example" },
  { name: "TNL_SERVER", initial: undefined, changed: "https://b.example" },
  { name: "TNL_STATE_DIR", initial: "/fixture/state-a", changed: "/fixture/state-b" },
  { name: "TNL_STATE_DIR", initial: undefined, changed: "/fixture/state-b" },
])("cold scopes pin $name=$initial before yielding", async ({ name, initial, changed }) => {
  const { connectionHandle } = await import("../../src/internal/connector/connection.js");
  const gate = Promise.withResolvers<void>();
  fixture.scopeGate = gate.promise;
  vi.stubEnv(name, initial);
  // call then directly so preparation captures A before switching to B.
  const first = connectionHandle("database", vi.fn()).then((value) => value);
  expect(fixture.scopeStarted).toHaveBeenCalledOnce();
  vi.stubEnv(name, changed);
  const second = connectionHandle("database", vi.fn()).then((value) => value);
  expect(fixture.scopeStarted).toHaveBeenCalledTimes(2);
  gate.resolve();

  const settings = await Promise.all([first, second]);
  expect(settings).toMatchObject([{ port: 20001 }, { port: 20002 }]);
  expect(fixture.launches.map((launch) => launch.environment[name])).toEqual([initial, changed]);
  vi.stubEnv(name, initial);
  expect(await connectionHandle("database", vi.fn())).toHaveProperty("port", 20001);
  expect(fixture.launches).toHaveLength(2);
});

test("a handle selected while a cold scope yields cannot enter that scope", async () => {
  const { connectionHandle } = await import("../../src/internal/connector/connection.js");
  const gate = Promise.withResolvers<void>();
  fixture.scopeGate = gate.promise;
  const pending = connectionHandle("database", vi.fn()).then((value) => value);
  expect(fixture.scopeStarted).toHaveBeenCalledOnce();
  vi.stubEnv("TNL_CONNECTION_HANDLE", "/fixture/other/handle.json");
  gate.resolve();

  await pending;
  expect(fixture.launches[0]?.environment.TNL_CONNECTION_HANDLE).toBeUndefined();
});

test.each([
  { name: "TNL_SERVER", changed: "https://b.example" },
  { name: "TNL_STATE_DIR", changed: "/fixture/state-b" },
])(
  "pending preparations keep same-name callbacks in their captured $name context",
  async ({ name, changed }) => {
    fixture.realWorkload = true;
    const { connectionHandle, configureWorkload } =
      await import("../../src/internal/connector/connection.js");
    const callbackA = vi.fn(async () => "assertion-a");
    const callbackB = vi.fn(async () => "assertion-b");
    const initial = process.env[name];
    const gate = Promise.withResolvers<void>();
    fixture.scopeGate = gate.promise;
    configureWorkload({ name: "job", token: callbackA });
    const first = connectionHandle("database", vi.fn()).then((value) => value);
    expect(fixture.scopeStarted).toHaveBeenCalledOnce();
    vi.stubEnv(name, changed);
    configureWorkload({ name: "job", token: callbackB });
    const second = connectionHandle("database", vi.fn()).then((value) => value);
    expect(fixture.scopeStarted).toHaveBeenCalledTimes(2);
    expect(callbackA).not.toHaveBeenCalled();
    expect(callbackB).not.toHaveBeenCalled();
    gate.resolve();

    expect(await Promise.all([first, second])).toMatchObject([{ port: 20001 }, { port: 20002 }]);
    expect(fixture.launches.map((launch) => [launch.environment[name], launch.input])).toEqual([
      [initial, { schema: 1, assertion: "assertion-a" }],
      [changed, { schema: 1, assertion: "assertion-b" }],
    ]);
    expect(callbackA).toHaveBeenCalledOnce();
    expect(callbackB).toHaveBeenCalledOnce();
  },
);

test("pending workload detection does not switch to an unconfigured context", async () => {
  fixture.realWorkload = true;
  const { connectionHandle, configureWorkload } =
    await import("../../src/internal/connector/connection.js");
  const callback = vi.fn(async () => "assertion-a");
  configureWorkload({ name: "job", token: callback });
  const gate = Promise.withResolvers<void>();
  fixture.scopeGate = gate.promise;
  const pending = connectionHandle("database", vi.fn()).then((value) => value);
  expect(fixture.scopeStarted).toHaveBeenCalledOnce();
  vi.stubEnv("TNL_SERVER", "https://b.example");
  gate.resolve();

  await pending;
  expect(fixture.launches[0]?.input).toEqual({ schema: 1, assertion: "assertion-a" });
  expect(callback).toHaveBeenCalledOnce();
});

test("workload recovery and cleanup keep scope selection but refresh launch inputs", async () => {
  fixture.workload = true;
  vi.stubEnv("VERCEL_OIDC_TOKEN", "first-assertion");
  vi.stubEnv("TNL_TRACEPARENT", "stale-parent");
  const caller = (id: string) =>
    trace.setSpanContext(ROOT_CONTEXT, {
      traceId: id.repeat(32),
      spanId: id.repeat(16),
      traceFlags: 1,
    });
  const active = vi.spyOn(context, "active").mockReturnValue(caller("1"));
  const { connectionHandle } = await import("../../src/internal/connector/connection.js");
  await connectionHandle("database", vi.fn());
  expect(fixture.launches[0]?.input).toEqual({ schema: 1, assertion: "first-assertion" });
  expect(fixture.launches[0]?.environment.TNL_TRACEPARENT).toBe(
    `00-${"1".repeat(32)}-${"1".repeat(16)}-01`,
  );

  fixture.failIPC = true;
  active.mockReturnValue(caller("2"));
  const recovery = connectionHandle("database", vi.fn()).then((value) => value);
  vi.stubEnv("TNL_SERVER", "https://b.example");
  vi.stubEnv("TNL_STATE_DIR", "/fixture/state-b");
  vi.stubEnv("VERCEL_OIDC_TOKEN", "current-assertion");
  await recovery;
  expect(fixture.launches[1]?.args).toContain("--recover-handle");
  expect(fixture.launches[1]?.args).toContain("--workload");
  expect(fixture.launches[1]?.input).toEqual({ schema: 1, assertion: "current-assertion" });
  expect(fixture.launches[1]?.environment).toMatchObject({
    TNL_SERVER: "https://a.example",
    TNL_STATE_DIR: "/fixture/state-a",
    VERCEL_OIDC_TOKEN: "current-assertion",
    TNL_TRACEPARENT: `00-${"2".repeat(32)}-${"2".repeat(16)}-01`,
  });

  for (const listener of process.listeners("beforeExit"))
    if (!originalListeners.has(listener)) listener(0);
  await vi.waitFor(() => expect(fixture.launches).toHaveLength(3));
  expect(fixture.launches[2]?.args[3]).toBe("sdk-stop");
  expect(fixture.launches[2]?.environment).toMatchObject({
    TNL_SERVER: "https://a.example",
    TNL_STATE_DIR: "/fixture/state-a",
    VERCEL_OIDC_TOKEN: "current-assertion",
  });
  expect(fixture.launches[2]?.environment.TNL_TRACEPARENT).toBeUndefined();
});
