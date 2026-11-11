import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { readFile } from "node:fs/promises";
import type { TnlGroupConnection } from "../../src/internal/connector/group_client.js";
import type { SelectionOptions } from "../../src/internal/connector/workload/contract.js";

const transport = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock("undici/index.js", async (original) => ({
  ...(await original<typeof import("undici/index.js")>()),
  fetch: transport.fetch,
}));

const fixture = vi.hoisted(() => ({
  assertion: "first",
  owners: new Map<string, string>(),
  manifests: new Map<string, string>(),
  registries: new Map<string, string>(),
  calls: [] as { args: string[]; input: unknown }[],
  denied: new Set<string>(),
  dead: new Set<string>(),
  recoveries: 0,
  ipc: [] as { file: string; name: string; assertion: string | undefined }[],
  selections: [] as SelectionOptions[],
  proofs: new Map<string, Set<string>>(),
  approvals: new Set<string>(),
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
      async prepare(name: string, assertion?: string, selection?: SelectionOptions) {
        if (selection !== undefined) {
          fixture.selections.push(selection);
          return response(
            [
              "--no-telemetry",
              "runtime",
              "connections",
              "sdk-prepare",
              "--selected-service",
              name,
              "--registry",
              fixture.registries.get(file) ?? "",
            ],
            { ...selection, assertion },
          );
        }
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
vi.mock("../../src/internal/connector/workload/provider.js", async (original) => ({
  ...(await original<typeof import("../../src/internal/connector/workload/provider.js")>()),
  usesWorkload: () => true,
  selectWorkload: async () => ({
    sdk_workload: { name: "job", callback: true, runtime: {} },
    sdk_workload_policy: "a".repeat(64),
    assertion: fixture.assertion,
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
  const body = input as { assertion?: string; manifest?: string };
  if (operation === "context") return { schema: 1, config_digest: "c".repeat(64) };
  const binding = body?.assertion === undefined ? undefined : fixture.binding(body.assertion);
  if (operation === "sdk-prepare") {
    const manifest = args.includes("--workload-manifest")
      ? (args[args.indexOf("--workload-manifest") + 1] ?? "")
      : (body?.manifest ?? "");
    const registry = args[args.indexOf("--registry") + 1] ?? "";
    if (
      args.includes("--recover-handle") &&
      !fixture.dead.has(args[args.indexOf("--recover-handle") + 1] ?? "")
    )
      throw new Error("owner remains alive");
    if (!fixture.approvals.has(body?.assertion ?? "")) {
      fixture.control.identity++;
      if (binding === undefined) throw new Error("control rejected assertion");
      fixture.approvals.add(body?.assertion ?? "");
    }
    let file = [...fixture.owners].find(
      ([file, owner]) =>
        owner === binding &&
        !fixture.dead.has(file) &&
        fixture.manifests.get(file) === manifest &&
        fixture.registries.get(file) === registry,
    )?.[0];
    if (file === undefined) {
      const started = response(["--no-telemetry", "runtime", "connections", "start"], input) as {
        connection_handle: string;
      };
      file = started.connection_handle;
      fixture.manifests.set(file, manifest);
      fixture.registries.set(file, registry);
    }
    const name = args[args.indexOf("--selected-service") + 1] ?? "";
    fixture.ipc.push({ file, name, assertion: body?.assertion });
    const proofs = fixture.proofs.get(file);
    if (!proofs?.has(body?.assertion ?? "")) {
      fixture.control.attach++;
      proofs?.add(body?.assertion ?? "");
    }
    const serviceKey = JSON.stringify([file, name]);
    if (!fixture.prepared.has(serviceKey)) {
      fixture.control.authorization++;
      fixture.prepared.add(serviceKey);
    }
    return {
      schema: 1,
      owner: {
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        executable: "/fixture/tnl",
        connection_handle: file,
      },
      prepared: response(
        ["--no-telemetry", "runtime", "connections", "read", "--handle", file, "--service", name],
        undefined,
      ),
    };
  }
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
  if (operation === "sdk-stop") {
    const registry = args[args.indexOf("--registry") + 1];
    for (const [file, selected] of fixture.registries)
      if (selected === registry) fixture.dead.add(file);
    return { schema: 1, state: "stopped" };
  }
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
  vi.stubGlobal("__tnlConnectorContextV2", undefined);
  fixture.assertion = "first";
  fixture.owners.clear();
  fixture.manifests.clear();
  fixture.registries.clear();
  fixture.calls.length = 0;
  fixture.denied.clear();
  fixture.dead.clear();
  fixture.recoveries = 0;
  fixture.ipc.length = 0;
  fixture.selections.length = 0;
  fixture.proofs.clear();
  fixture.approvals.clear();
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
  expect(fixture.calls.every((c) => c.args[3] === "sdk-prepare")).toBe(true);
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
  expect(fixture.owners.size).toBe(2);
});

test("cold and warm helper/control budgets are explicit; rotation revalidates before reuse", async () => {
  const { connectionHandle } = await import("../../src/internal/connector/connection.js");
  await connectionHandle("api", vi.fn());
  expect(fixture.calls.map((c) => c.args[3])).toEqual(["sdk-prepare"]);
  expect(Object.values(fixture.control).reduce((a, b) => a + b, 0)).toBe(5);
  for (let i = 0; i < 10; i++) await connectionHandle("api", vi.fn());
  expect(fixture.calls).toHaveLength(1);
  expect(Object.values(fixture.control).reduce((a, b) => a + b, 0)).toBe(5);
  fixture.assertion = "rotated";
  await connectionHandle("api", vi.fn());
  expect(fixture.calls.map((c) => c.args[3])).toEqual(["sdk-prepare"]);
  expect(fixture.control.attach).toBe(1);
  expect(fixture.control.identity).toBe(3);
});

function groupConnection(character: string): TnlGroupConnection {
  return {
    schema: 1,
    server: "https://control.example",
    team_id: `tm_${"a".repeat(22)}`,
    project_key: "tractors",
    source_fingerprint: "a".repeat(64),
    project_label: "tractors",
    group_id: `pgrp_${character.repeat(22)}`,
    group_name: `tractor-${character}`,
    services: { api: "http", raw: "tcp" },
    workloads: {
      monitor: { provider: "oidc", services: ["api", "raw"], max_duration_seconds: 3600 },
    },
  };
}

test("group clients isolate concurrent owners, callbacks, manifests and cleanup without changing global selection", async () => {
  const { groupClient } = await import("../../src/internal/connector/connection.js");
  let assertion = "first";
  const firstToken = vi.fn(async () => assertion);
  const otherToken = vi.fn(async () => "first");
  const first = groupClient({
    connection: groupConnection("a"),
    workload: { name: "monitor", token: firstToken },
  });
  const other = groupClient({
    connection: groupConnection("b"),
    workload: { name: "monitor", token: otherToken },
  });
  try {
    const [a, b] = await Promise.all([first.connect("raw"), other.connect("raw")]);
    expect([a, b]).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ port: 12345 }),
        expect.objectContaining({ port: 12346 }),
      ]),
    );
    const otherPort = "port" in b ? b.port : undefined;
    expect(otherPort).toBeTypeOf("number");
    const starts = fixture.calls.filter((call) => call.args[3] === "sdk-prepare");
    expect(starts).toHaveLength(2);
    const manifests = await Promise.all(
      starts.map(async (call) => {
        const filename = call.args[call.args.indexOf("--workload-manifest") + 1];
        if (filename === undefined) throw new Error("missing scoped manifest");
        const source = await readFile(filename, "utf8");
        expect(source).not.toContain('"first"');
        return JSON.parse(source) as unknown;
      }),
    );
    expect(manifests).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ publisher_group_id: groupConnection("a").group_id }),
        expect.objectContaining({ publisher_group_id: groupConnection("b").group_id }),
      ]),
    );
    assertion = "rotated";
    await first.connect("raw");
    expect(fixture.owners.size).toBe(2);
    expect(fixture.ipc.at(-1)?.assertion).toBe("rotated");
    expect(fixture.selections.at(-1)).toMatchObject({
      workload: "monitor",
      manifest: expect.any(String),
    });
    await first.close();
    expect(() => first.connect("raw")).toThrow(
      expect.objectContaining({ code: "sdk.connection_unavailable" }),
    );
    await expect(Promise.resolve(other.connect("raw"))).resolves.toHaveProperty("port", otherPort);
    expect(fixture.calls.filter((call) => call.args[3] === "sdk-stop")).toHaveLength(1);
    expect(otherToken).toHaveBeenCalledTimes(2);
    expect(() => other.connect("db")).toThrow(
      expect.objectContaining({ code: "sdk.workload_denied" }),
    );
  } finally {
    await Promise.all([first.close(), other.close()]);
  }
});

test.each(["google", "kubernetes", "gitlab"] as const)(
  "group descriptors retain %s and optional hard session limits",
  async (provider) => {
    const { groupClient } = await import("../../src/internal/connector/connection.js");
    for (const max_duration_seconds of [0, 86400]) {
      const connection = groupConnection("a");
      const client = groupClient({
        connection: {
          ...connection,
          workloads: { monitor: { provider, services: ["api"], max_duration_seconds } },
        },
        workload: { name: "monitor", token: async () => "first" },
      });
      await client.close();
    }
  },
);

function groupConnectionWithServices(count: number): TnlGroupConnection {
  return {
    ...groupConnection("a"),
    services: {
      raw: "tcp",
      ...Object.fromEntries(
        Array.from({ length: count - 1 }, (_, index) => [`service-${index}`, "tcp" as const]),
      ),
    },
    workloads: { monitor: { provider: "oidc", services: ["raw"], max_duration_seconds: 0 } },
  };
}

test.each([33, 128])(
  "group descriptors with %i services prepare a one-service workload",
  async (count) => {
    const { groupClient } = await import("../../src/internal/connector/connection.js");
    const connection = groupConnectionWithServices(count);
    const client = groupClient({
      connection,
      workload: { name: "monitor", token: async () => "first" },
    });
    try {
      await expect(Promise.resolve(client.connect("raw"))).resolves.toHaveProperty("port", 12345);
      const start = fixture.calls.find((call) => call.args[3] === "sdk-prepare");
      if (start === undefined) throw new Error("missing scoped preparation");
      const filename = start.args[start.args.indexOf("--workload-manifest") + 1];
      if (filename === undefined) throw new Error("missing scoped manifest");
      const manifest: unknown = JSON.parse(await readFile(filename, "utf8"));
      expect(manifest).toMatchObject({
        services: connection.services,
        workloads: { monitor: { services: ["raw"] } },
      });
    } finally {
      await client.close();
    }
  },
);

test("group descriptor capacity and workload selection capacity are independent", async () => {
  const { groupClient } = await import("../../src/internal/connector/connection.js");
  const connection = groupConnectionWithServices(128);
  const token = vi.fn(async () => "first");
  const selected = Object.keys(connection.services);
  const client = groupClient({
    connection: {
      ...connection,
      workloads: {
        monitor: { provider: "oidc", services: selected.slice(0, 32), max_duration_seconds: 0 },
      },
    },
    workload: { name: "monitor", token },
  });
  await client.close();
  expect(() =>
    groupClient({
      connection: {
        ...connection,
        workloads: {
          monitor: { provider: "oidc", services: selected.slice(0, 33), max_duration_seconds: 0 },
        },
      },
      workload: { name: "monitor", token },
    }),
  ).toThrow(expect.objectContaining({ code: "sdk.configuration_invalid" }));
  expect(() =>
    groupClient({
      connection: groupConnectionWithServices(129),
      workload: { name: "monitor", token },
    }),
  ).toThrow(expect.objectContaining({ code: "sdk.configuration_invalid" }));
  expect(token).not.toHaveBeenCalled();
  expect(fixture.calls).toHaveLength(0);
});

test("invalid group descriptors and missing workload credentials fail before native startup", async () => {
  const { groupClient } = await import("../../src/internal/connector/connection.js");
  expect(() =>
    groupClient({
      connection: { ...groupConnection("a"), group_id: "tractor-a" },
      workload: { name: "monitor", token: async () => "first" },
    }),
  ).toThrow(expect.objectContaining({ code: "sdk.configuration_invalid" }));
  const client = groupClient({
    connection: groupConnection("a"),
    workload: { name: "monitor", token: async () => "" },
  });
  try {
    await expect(Promise.resolve(client.connect("raw"))).rejects.toMatchObject({
      code: "sdk.workload_assertion_unavailable",
    });
    expect(fixture.calls).toHaveLength(0);
  } finally {
    await client.close();
  }
});
