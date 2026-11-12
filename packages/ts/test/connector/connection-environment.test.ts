import { context, ROOT_CONTEXT, trace } from "@opentelemetry/api";
import { realpathSync } from "node:fs";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import {
  workloadSelectionSchema,
  type SelectionOptions,
  type WorkloadRequest,
} from "../../src/internal/connector/workload/contract.js";

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
}));
vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => "/fixture/tnl",
}));
vi.mock("node:fs/promises", async (original) => ({
  ...(await original<typeof import("node:fs/promises")>()),
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
  async selectWorkload(
    ...args: Parameters<ReturnType<typeof actualProvider>["selectWorkload"]>
  ): Promise<SelectionOptions> {
    if (fixture.realWorkload) return actualProvider().selectWorkload(...args);
    return mockSelection(args[0]);
  },
}));

function actualProvider() {
  if (fixture.provider === undefined) throw new Error("provider not loaded");
  return fixture.provider;
}

async function mockSelection(
  preview: (request: WorkloadRequest) => Promise<unknown>,
): Promise<SelectionOptions> {
  const request: WorkloadRequest = { name: "job", runtime: {} };
  const selection = workloadSelectionSchema.parse(await preview(request));
  return {
    sdk_workload: request,
    sdk_workload_policy: selection.policy,
    sdk_environment: {
      github_actions: process.env.GITHUB_ACTIONS ?? "",
      github_request_url: process.env.ACTIONS_ID_TOKEN_REQUEST_URL ?? "",
      github_request_token: process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ?? "",
      vercel_token_file: process.env.VERCEL_OIDC_TOKEN_FILE ?? "",
      vercel_token: process.env.VERCEL_OIDC_TOKEN ?? "",
    },
  };
}
vi.mock("../../src/internal/connector/connection_ipc.js", () => ({
  ownerIPC: async (file: string) => ({
    async prepare() {
      if (fixture.failIPC) throw new Error("owner disconnected");
      const owner = [...fixture.owners.values()].find((owner) => owner.file === file);
      if (owner === undefined) throw new Error("unknown owner");
      return prepared(owner);
    },
    async workload() {
      if (fixture.failIPC) throw new Error("owner disconnected");
      return workloadSelection();
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
            if (args[2] === "sdk-workload") {
              callback(null, JSON.stringify(workloadSelection()));
              return;
            }
            if (args[2] === "sdk-stop") {
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

function workloadSelection() {
  return {
    schema: 1,
    name: "job",
    directory: process.cwd(),
    manifest: `${process.cwd()}/.tnl/generated/workloads.json`,
    policy: "a".repeat(64),
    source: fixture.realWorkload ? "callback" : "native",
  };
}

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
  vi.stubGlobal("__tnlConnectorContextV2", undefined);
  fixture.provider = await vi.importActual("../../src/internal/connector/workload/provider.js");
  fixture.launches.length = 0;
  fixture.owners.clear();
  fixture.scopeGate = undefined;
  fixture.scopes = 0;
  fixture.workload = false;
  fixture.realWorkload = false;
  fixture.failIPC = false;
  vi.stubEnv("TNL_SERVER", "https://a.example");
  vi.stubEnv("TNL_STATE_DIR", "/fixture/state-a");
  vi.stubEnv("TNL_CONNECTION_HANDLE", undefined);
  for (const name of ["TNL_WORKLOAD", "VERCEL", "FLY_APP_NAME", "GITHUB_ACTIONS"])
    vi.stubEnv(name, undefined);
  originalListeners = new Set(process.listeners("beforeExit"));
});
afterEach(() => {
  vi.unstubAllGlobals();
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
    const launches = fixture.launches.filter((launch) => launch.args[2] === "sdk-prepare");
    expect(launches.map((launch) => launch.environment[name])).toEqual([initial, changed]);
    expect(launches.map((launch) => launch.input)).toMatchObject([
      { assertion: "assertion-a", sdk_workload: { name: "job", callback: true } },
      { assertion: "assertion-b", sdk_workload: { name: "job", callback: true } },
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
  const launch = fixture.launches.find((launch) => launch.args[2] === "sdk-prepare");
  expect(launch?.input).toMatchObject({ assertion: "assertion-a" });
  expect(callback).toHaveBeenCalledOnce();
});

test.each([false, true])(
  "incompatible scopes stay isolated while current copies share (workload=%s)",
  async (workload) => {
    fixture.workload = workload;
    const key = JSON.stringify([
      realpathSync(process.cwd()),
      process.env.TNL_STATE_DIR,
      process.env.TNL_SERVER,
      process.env.TNL_CONNECTION_HANDLE,
    ]);
    const nativeKey = JSON.stringify([key, "/fixture/tnl"]);
    // the previous ABI had neither directory nor workload on its native scopes.
    const legacyScope = {
      registry: "/fixture/legacy-registry",
      binary: "/fixture/tnl",
      environment: {},
      requests: new Map<string, Promise<unknown>>(),
      open: vi.fn(async () => ({ close() {} })),
      select: vi.fn(async () => prepared({ file: "/fixture/legacy/handle.json", port: 20003 })),
    };
    const legacyContext = {
      scopes: new Map([[nativeKey, Promise.resolve(legacyScope)]]),
      selectedScopes: new Map([[key, new Map([["/fixture/tnl", legacyScope]])]]),
      fetches: new Map(),
      external: new Map(),
      workloads: new Map(),
    };
    vi.stubGlobal("__tnlConnectorContextV1", legacyContext);
    const first = await import("../../src/internal/connector/connection.js");
    const firstContext = await import("../../src/internal/connector/context.js");
    expect(await first.connectionHandle("database", vi.fn())).toHaveProperty("port", 20001);

    vi.resetModules();
    const second = await import("../../src/internal/connector/connection.js");
    const secondContext = await import("../../src/internal/connector/context.js");
    expect(first.connectionHandle).not.toBe(second.connectionHandle);
    expect(secondContext.context).toBe(firstContext.context);
    expect(secondContext.context).not.toBe(legacyContext);
    expect(Reflect.get(globalThis, "__tnlConnectorContextV1")).toBe(legacyContext);
    expect(await second.connectionHandle("database", vi.fn())).toHaveProperty("port", 20001);
    expect(fixture.scopeStarted).toHaveBeenCalledOnce();
    expect(fixture.owners.size).toBe(1);
    expect(fixture.launches.filter((launch) => launch.args[2] === "sdk-prepare")).toHaveLength(1);
    expect(fixture.launches.every((launch) => launch.args.includes(process.cwd()))).toBe(true);
    expect(legacyContext.scopes.size).toBe(1);
    expect(legacyScope.select).not.toHaveBeenCalled();
    expect(legacyScope.open).not.toHaveBeenCalled();
    expect(legacyScope.requests.size).toBe(0);
  },
);

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
  expect(fixture.launches.map((launch) => launch.args[2])).toEqual(["sdk-workload", "sdk-prepare"]);
  expect(fixture.launches[0]?.input).toEqual({
    schema: 1,
    sdk_workload: { name: "job", runtime: {} },
  });
  expect(fixture.launches[1]?.input).toMatchObject({
    schema: 1,
    sdk_workload: { name: "job", runtime: {} },
    sdk_workload_policy: "a".repeat(64),
    sdk_environment: { vercel_token: "first-assertion" },
  });
  for (const launch of fixture.launches)
    expect(launch.environment.TNL_TRACEPARENT).toBe(`00-${"1".repeat(32)}-${"1".repeat(16)}-01`);

  fixture.failIPC = true;
  active.mockReturnValue(caller("2"));
  const recovery = connectionHandle("database", vi.fn()).then((value) => value);
  vi.stubEnv("TNL_SERVER", "https://b.example");
  vi.stubEnv("TNL_STATE_DIR", "/fixture/state-b");
  vi.stubEnv("VERCEL_OIDC_TOKEN", "current-assertion");
  await recovery;
  expect(fixture.launches[2]?.args[2]).toBe("sdk-workload");
  expect(fixture.launches[3]?.args).toContain("--recover-handle");
  expect(fixture.launches[3]?.input).toMatchObject({
    schema: 1,
    sdk_workload: { name: "job", runtime: {} },
    sdk_workload_policy: "a".repeat(64),
    sdk_environment: { vercel_token: "current-assertion" },
  });
  for (const launch of fixture.launches.slice(2))
    expect(launch.environment).toMatchObject({
      TNL_SERVER: "https://a.example",
      TNL_STATE_DIR: "/fixture/state-a",
      VERCEL_OIDC_TOKEN: "current-assertion",
      TNL_TRACEPARENT: `00-${"2".repeat(32)}-${"2".repeat(16)}-01`,
    });

  for (const listener of process.listeners("beforeExit"))
    if (!originalListeners.has(listener)) listener(0);
  await vi.waitFor(() => expect(fixture.launches).toHaveLength(5));
  expect(fixture.launches[4]?.args[2]).toBe("sdk-stop");
  expect(fixture.launches[4]?.environment).toMatchObject({
    TNL_SERVER: "https://a.example",
    TNL_STATE_DIR: "/fixture/state-a",
    VERCEL_OIDC_TOKEN: "current-assertion",
  });
  expect(fixture.launches[4]?.environment.TNL_TRACEPARENT).toBeUndefined();
});
