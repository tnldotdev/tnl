import { afterEach, beforeEach, expect, test, vi } from "vitest";

const transport = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock("undici/index.js", async (original) => ({
  ...(await original<typeof import("undici/index.js")>()),
  fetch: transport.fetch,
}));

const fixture = vi.hoisted(() => ({
  assertion: "first",
  owners: new Map<string, string>(),
  calls: [] as { args: string[]; input: unknown }[],
  denied: new Set<string>(),
  dead: new Set<string>(),
  recoveries: 0,
  ipc: [] as { file: string; name: string; assertion: string | undefined }[],
  proofs: new Map<string, Set<string>>(),
  prepared: new Set<string>(),
  control: { identity: 0, exchange: 0, inventory: 0, attach: 0, authorization: 0 },
  binding: (assertion: string) =>
    assertion === "other"
      ? "b".repeat(64)
      : ["first", "rotated"].includes(assertion)
        ? "a".repeat(64)
        : undefined,
}));
vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => "/fixture/tnl",
}));
vi.mock("../../src/internal/connector/connection_ipc.js", async () => {
  const { createHash } = await import("node:crypto");
  return {
    ownerIPC: async (file: string) => ({
      async prepare(name: string, assertion?: string) {
        fixture.ipc.push({ file, name, assertion });
        const binding = assertion === undefined ? undefined : fixture.binding(assertion);
        if (fixture.dead.has(file) || binding === undefined || fixture.owners.get(file) !== binding)
          throw new Error("attachment rejected");
        const proofs = fixture.proofs.get(file);
        if (!proofs?.has(assertion ?? "")) {
          fixture.control.attach++;
          proofs?.add(assertion ?? "");
        }
        const serviceKey = JSON.stringify([file, name]);
        if (!fixture.prepared.has(serviceKey)) {
          fixture.control.authorization++;
          fixture.prepared.add(serviceKey);
        }
        const raw = response(
          ["--no-telemetry", "runtime", "connections", "read", "--handle", file, "--service", name],
          undefined,
        ) as object;
        return {
          ...raw,
          verification: {
            digest: createHash("sha256")
              .update(assertion ?? "")
              .digest("hex"),
            binding,
            expires_at: new Date(Date.now() + 300_000).toISOString(),
          },
        };
      },
      close() {},
    }),
  };
});
vi.mock("../../src/internal/connector/workload/provider.js", () => ({
  usesWorkload: () => true,
  acquireAssertion: async () => fixture.assertion,
  selectWorkload: async () => ({
    name: "job",
    directory: process.cwd(),
    selected: { services: ["api", "db", "mysql", "raw", "cluster"] },
    manifest: { schema: 1 },
  }),
}));
vi.mock("node:child_process", () => ({
  execFile(
    _binary: string,
    args: string[],
    _options: unknown,
    callback: (error: Error | null, value?: string) => void,
  ) {
    return {
      stdin: {
        end(input: string | undefined) {
          const complete = () => {
            try {
              const body: unknown = input === undefined ? undefined : JSON.parse(input);
              fixture.calls.push({ args, input: body });
              callback(null, JSON.stringify(response(args, body)));
            } catch {
              callback(new Error("native operation rejected"));
            }
          };
          if (args[3] === "recover" && fixture.dead.size > 0 && ++fixture.recoveries > 1)
            setTimeout(complete, 25);
          else queueMicrotask(complete);
        },
      },
    };
  },
  execFileSync() {
    throw new Error("not prepared synchronously in this fixture");
  },
}));

function response(args: string[], input: unknown): unknown {
  const operation = args[3];
  const body = input as { assertion?: string };
  if (operation === "context") return { schema: 1, config_digest: "c".repeat(64) };
  const binding = body?.assertion === undefined ? undefined : fixture.binding(body.assertion);
  if (operation === "identity") {
    fixture.control.identity++;
    if (binding === undefined) throw new Error("control rejected assertion");
    return {
      schema: 1,
      binding,
      assertion_expires_at: new Date(Date.now() + 300_000).toISOString(),
    };
  }
  if (operation === "start") {
    if (binding === undefined) throw new Error("control rejected assertion");
    const file = `/fixture/owner-${fixture.owners.size}/handle.json`;
    fixture.owners.set(file, binding);
    fixture.proofs.set(file, new Set(body?.assertion === undefined ? [] : [body.assertion]));
    fixture.control.identity++;
    fixture.control.exchange++;
    fixture.control.inventory++;
    return {
      schema: 1,
      state: "ready",
      pid: 1,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      project_runtime: project(),
      connection_handle: file,
      executable: "/fixture/tnl",
    };
  }
  const file = args[args.indexOf("--handle") + 1] ?? "";
  if (operation === "attach") {
    if (fixture.dead.has(file) || binding === undefined || fixture.owners.get(file) !== binding)
      throw new Error("attachment rejected");
    return { schema: 1, state: "attached" };
  }
  if (operation === "recover") {
    if (fixture.dead.has(file)) return { schema: 1, state: "stopped" };
    throw new Error("owner remains alive");
  }
  if (operation === "read") {
    const name = args[args.indexOf("--service") + 1] ?? "";
    if (fixture.denied.has(name)) throw new Error("service denied");
    const metadata = project().services[name];
    if (metadata === undefined) throw new Error("service missing");
    return {
      schema: 1,
      project_runtime: project(),
      connection: {
        schema: 1,
        protocol: metadata.protocol,
        host: "127.0.0.1",
        port: 12345 + [...fixture.owners.keys()].indexOf(file),
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        transport_id: `ctg_${"a".repeat(21)}${[...fixture.owners.keys()].indexOf(file)}`,
        ...(metadata.protocol === "tcp"
          ? {}
          : { ssl: { servername: metadata.hostname, rejectUnauthorized: true } }),
        ...(metadata.url === undefined ? {} : { url: metadata.url }),
        ...(metadata.protocol === "kubernetes"
          ? { kubeconfig: "/fixture/kubeconfig", context: "tnl:cluster" }
          : {}),
      },
    };
  }
  if (operation === "stop") return { schema: 1, state: "stopped" };
  throw new Error("unexpected native operation");
}

function project() {
  const protocols = {
    api: "http",
    db: "postgres",
    mysql: "mysql",
    raw: "tcp",
    cluster: "kubernetes",
  };
  const services: Record<
    string,
    {
      protocol: string;
      hostname: string;
      namespace: string;
      port: number;
      public: boolean;
      url?: string;
    }
  > = {};
  for (const [name, protocol] of Object.entries(protocols))
    services[name] = {
      protocol,
      hostname: `${name}.example.test`,
      namespace: "example.test",
      port: 15443,
      public: false,
      ...(["http", "kubernetes"].includes(protocol)
        ? { url: `https://${name}.example.test:15443` }
        : {}),
    };
  return { dev: false, namespace: "example.test", services };
}

let originalListeners = new Set(process.listeners("beforeExit"));
beforeEach(() => {
  vi.resetModules();
  fixture.assertion = "first";
  fixture.owners.clear();
  fixture.calls.length = 0;
  fixture.denied.clear();
  fixture.dead.clear();
  fixture.recoveries = 0;
  fixture.ipc.length = 0;
  fixture.proofs.clear();
  fixture.prepared.clear();
  fixture.control = { identity: 0, exchange: 0, inventory: 0, attach: 0, authorization: 0 };
  originalListeners = new Set(process.listeners("beforeExit"));
});
afterEach(() => {
  vi.unstubAllGlobals();
  for (const listener of process.listeners("beforeExit"))
    if (!originalListeners.has(listener)) process.removeListener("beforeExit", listener);
});

test("all protocols share a verified native identity owner and assertions travel only through private stdin", async () => {
  const { connectionHandle } = await import("../../src/internal/connector/connection.js");
  const snapshots = await Promise.all(
    ["api", "db", "mysql", "raw", "cluster"].map((name) =>
      Promise.resolve(connectionHandle(name, vi.fn())),
    ),
  );
  expect(snapshots).toHaveLength(5);
  expect(fixture.owners.size).toBe(1);
  expect(fixture.calls.filter((c) => c.args[3] === "start")).toHaveLength(1);
  expect(fixture.calls.filter((c) => c.args[3] === "start")[0]?.args).not.toContain("--service");
  expect(fixture.calls.every((c) => !c.args.includes("first"))).toBe(true);
  fixture.assertion = "rotated";
  await connectionHandle("db", vi.fn());
  expect(fixture.owners.size).toBe(1);
  expect(fixture.ipc.some((c) => c.assertion === "rotated")).toBe(true);
});

test("control rejection cannot select a cached owner, and one service denial leaves another usable", async () => {
  const { connectionHandle } = await import("../../src/internal/connector/connection.js");
  await connectionHandle("db", vi.fn());
  fixture.assertion = "forged";
  const reads = fixture.ipc.length;
  await expect(Promise.resolve(connectionHandle("db", vi.fn()))).rejects.toMatchObject({
    code: "sdk.connection_unavailable",
  });
  expect(fixture.ipc).toHaveLength(reads);
  fixture.assertion = "rotated";
  fixture.denied.add("api");
  await expect(Promise.resolve(connectionHandle("api", vi.fn()))).rejects.toThrow();
  await expect(Promise.resolve(connectionHandle("db", vi.fn()))).resolves.toHaveProperty(
    "port",
    12345,
  );
  expect(fixture.owners.size).toBe(1);
  expect(fixture.calls.some((c) => c.args[3] === "stop")).toBe(false);
});

test("a returned fetch resolves the caller's current verified owner rather than capturing its original file", async () => {
  const dispatch = transport.fetch.mockResolvedValue(new Response("bytes"));
  const { connectionHandle } = await import("../../src/internal/connector/connection.js");
  const initial = await connectionHandle("api", vi.fn());
  if (!("fetch" in initial)) throw new Error("missing HTTP settings");
  fixture.assertion = "other";
  const response = await initial.fetch("/echo", {
    method: "POST",
    body: "once",
    redirect: "follow",
  });
  expect(await response.text()).toBe("bytes");
  expect(fixture.owners.size).toBe(2);
  expect(fixture.ipc.at(-1)?.file).toBe("/fixture/owner-1/handle.json");
  expect(dispatch).toHaveBeenCalledOnce();
  expect(dispatch.mock.calls[0]?.[1]).toMatchObject({ redirect: "manual" });
});

test("a module-shared workload handle cannot synchronously select the last caller's identity", async () => {
  const { connectionHandle } = await import("../../src/internal/connector/connection.js");
  const handle = connectionHandle("db", vi.fn());
  const first = await handle;
  fixture.assertion = "other";
  const second = await handle;
  expect(first).toHaveProperty("port", 12345);
  expect(second).toHaveProperty("port", 12346);
  expect(first).not.toHaveProperty("then");
  expect(() => ({ ...handle })).toThrow(
    expect.objectContaining({ code: "sdk.connection_unprepared" }),
  );
  fixture.assertion = "forged";
  await expect(Promise.resolve(handle)).rejects.toMatchObject({
    code: "sdk.connection_unavailable",
  });
  expect(first).toHaveProperty("port", 12345);
});

test("a late concurrent death proof adopts the recovered owner instead of starting a second native process", async () => {
  const { connectionHandle } = await import("../../src/internal/connector/connection.js");
  await connectionHandle("db", vi.fn());
  fixture.dead.add("/fixture/owner-0/handle.json");
  const current = await Promise.all([
    connectionHandle("db", vi.fn()),
    connectionHandle("mysql", vi.fn()),
  ]);
  expect(current).toMatchObject([{ port: 12346 }, { port: 12346 }]);
  expect(fixture.calls.filter((c) => c.args[3] === "start")).toHaveLength(2);
});

test("cold and warm helper/control budgets are explicit; rotation revalidates before reuse", async () => {
  const { connectionHandle } = await import("../../src/internal/connector/connection.js");
  await connectionHandle("api", vi.fn());
  expect(fixture.calls.map((c) => c.args[3])).toEqual(["context", "identity", "start"]);
  expect(Object.values(fixture.control).reduce((a, b) => a + b, 0)).toBe(5);
  for (let i = 0; i < 10; i++) await connectionHandle("api", vi.fn());
  expect(fixture.calls).toHaveLength(3);
  expect(Object.values(fixture.control).reduce((a, b) => a + b, 0)).toBe(5);
  fixture.assertion = "rotated";
  await connectionHandle("api", vi.fn());
  expect(fixture.calls.map((c) => c.args[3])).toEqual(["context", "identity", "start", "identity"]);
  expect(fixture.control.attach).toBe(1);
  expect(fixture.control.identity).toBe(3);
});
