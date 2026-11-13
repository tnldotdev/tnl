import { context, ROOT_CONTEXT, trace } from "@opentelemetry/api";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

const fixture = vi.hoisted(() => ({
  launches: [] as { args: string[]; environment: NodeJS.ProcessEnv; input: unknown }[],
  owners: new Map<string, { file: string; port: number }>(),
  gate: undefined as Promise<void> | undefined,
  starting: vi.fn(),
  failIPC: false,
}));
vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => "/fixture/tnl",
}));
vi.mock("node:fs/promises", async (original) => ({
  ...(await original<typeof import("node:fs/promises")>()),
  async realpath(value: string) {
    fixture.starting();
    await fixture.gate;
    return value;
  },
}));
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
}));
function workloadSelection() {
  return {
    schema: 1,
    name: "job",
    directory: process.cwd(),
    manifest: `${process.cwd()}/.tnl/generated/workloads.json`,
    policy: "a".repeat(64),
    source: "callback",
  };
}
function prepared(owner: { file: string; port: number }) {
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
const options = {
  project: "team/project",
  services: { database: { protocol: "postgres" } },
} as const;
let listeners: Set<(...args: never[]) => unknown>;
beforeEach(() => {
  vi.resetModules();
  vi.stubGlobal("__tnlConnectorContextV2", undefined);
  fixture.launches.length = 0;
  fixture.owners.clear();
  fixture.gate = undefined;
  fixture.starting.mockClear();
  fixture.failIPC = false;
  vi.stubEnv("TNL_SERVER", "https://a.example");
  vi.stubEnv("TNL_STATE_DIR", "/fixture/state-a");
  for (const name of [
    "TNL_TOKEN",
    "TNL_CONNECTION_HANDLE",
    "TNL_WORKLOAD",
    "VERCEL",
    "FLY_APP_NAME",
    "GITHUB_ACTIONS",
  ])
    vi.stubEnv(name, undefined);
  listeners = new Set(process.listeners("beforeExit"));
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  for (const listener of process.listeners("beforeExit"))
    if (!listeners.has(listener)) process.removeListener("beforeExit", listener);
});

test.each([
  { name: "TNL_SERVER", initial: "https://a.example", changed: "https://b.example" },
  { name: "TNL_SERVER", initial: undefined, changed: "https://b.example" },
  { name: "TNL_STATE_DIR", initial: "/fixture/state-a", changed: "/fixture/state-b" },
  { name: "TNL_STATE_DIR", initial: undefined, changed: "/fixture/state-b" },
])("deployment scopes pin $name=$initial before yielding", async ({ name, initial, changed }) => {
  const { createClient } = await import("../../src/index.js");
  const gate = Promise.withResolvers<void>();
  fixture.gate = gate.promise;
  vi.stubEnv(name, initial);
  const a = createClient({ ...options, token: "private" }).deployment("production");
  const first = a.connect("database");
  expect(fixture.starting).toHaveBeenCalledOnce();
  vi.stubEnv(name, changed);
  const b = createClient({ ...options, token: "private" }).deployment("production");
  const second = b.connect("database");
  gate.resolve();
  expect(await Promise.all([first, second])).toMatchObject([{ port: 20001 }, { port: 20002 }]);
  expect(fixture.launches.map((launch) => launch.environment[name])).toEqual(
    expect.arrayContaining([initial, changed]),
  );
  expect(await a.connect("database")).toHaveProperty("port", 20001);
  expect(fixture.launches).toHaveLength(2);
  await a.close();
  await b.close();
});

test("a borrowed handle appearing during startup cannot enter an owned scope", async () => {
  const { createClient } = await import("../../src/index.js");
  const gate = Promise.withResolvers<void>();
  fixture.gate = gate.promise;
  const deployment = createClient({ ...options, token: "private" }).deployment("production");
  const pending = deployment.connect("database");
  vi.stubEnv("TNL_CONNECTION_HANDLE", "/fixture/other/handle.json");
  gate.resolve();
  await pending;
  expect(fixture.launches[0]?.environment.TNL_CONNECTION_HANDLE).toBeUndefined();
  await deployment.close();
});

test.each(["TNL_SERVER", "TNL_STATE_DIR"])(
  "same-name callbacks stay in the captured %s context",
  async (name) => {
    const { createClient } = await import("../../src/index.js");
    const { configureWorkload } = await import("../../src/workload.js");
    const callbackA = vi.fn(async () => "assertion-a");
    const callbackB = vi.fn(async () => "assertion-b");
    const gate = Promise.withResolvers<void>();
    fixture.gate = gate.promise;
    const initial = process.env[name];
    configureWorkload({ name: "job", token: callbackA });
    const a = createClient(options).deployment("production");
    const first = a.connect("database");
    vi.stubEnv(name, name === "TNL_SERVER" ? "https://b.example" : "/fixture/state-b");
    configureWorkload({ name: "job", token: callbackB });
    const b = createClient(options).deployment("production");
    const second = b.connect("database");
    expect(callbackA).not.toHaveBeenCalled();
    expect(callbackB).not.toHaveBeenCalled();
    gate.resolve();
    await Promise.all([first, second]);
    const launches = fixture.launches.filter((launch) => launch.args[2] === "sdk-prepare");
    const launchA = launches.find((launch) => launch.environment[name] === initial);
    const launchB = launches.find((launch) => launch.environment[name] !== initial);
    expect(launchA?.input).toMatchObject({
      assertion: "assertion-a",
      sdk_workload: { selection: { project: "team/project", name: "production" } },
    });
    expect(launchB?.input).toMatchObject({
      assertion: "assertion-b",
      sdk_workload: { selection: { project: "team/project", name: "production" } },
    });
    expect(callbackA).toHaveBeenCalledOnce();
    expect(callbackB).toHaveBeenCalledOnce();
    await a.close();
    await b.close();
  },
);

test("recovery and cleanup keep captured selection but use current tracing", async () => {
  const { createClient } = await import("../../src/index.js");
  const { configureWorkload } = await import("../../src/workload.js");
  let assertion = "first-assertion";
  configureWorkload({ name: "job", token: async () => assertion });
  const caller = (id: string) =>
    trace.setSpanContext(ROOT_CONTEXT, {
      traceId: id.repeat(32),
      spanId: id.repeat(16),
      traceFlags: 1,
    });
  const active = vi.spyOn(context, "active").mockReturnValue(caller("1"));
  const deployment = createClient(options).deployment("production");
  await deployment.connect("database");
  expect(fixture.launches.map((launch) => launch.args[2])).toEqual(["sdk-workload", "sdk-prepare"]);
  for (const launch of fixture.launches)
    expect(launch.environment.TNL_TRACEPARENT).toBe(`00-${"1".repeat(32)}-${"1".repeat(16)}-01`);
  fixture.failIPC = true;
  active.mockReturnValue(caller("2"));
  assertion = "current-assertion";
  vi.stubEnv("TNL_SERVER", "https://b.example");
  vi.stubEnv("TNL_STATE_DIR", "/fixture/state-b");
  await deployment.connect("database");
  expect(fixture.launches[3]?.args).toContain("--recover-handle");
  expect(fixture.launches[3]?.input).toMatchObject({ assertion: "current-assertion" });
  for (const launch of fixture.launches.slice(2))
    expect(launch.environment).toMatchObject({
      TNL_SERVER: "https://a.example",
      TNL_STATE_DIR: "/fixture/state-a",
      TNL_TRACEPARENT: `00-${"2".repeat(32)}-${"2".repeat(16)}-01`,
    });
  await deployment.close();
  expect(fixture.launches.at(-1)?.args[2]).toBe("sdk-stop");
  expect(fixture.launches.at(-1)?.environment.TNL_TRACEPARENT).toBeUndefined();
});
