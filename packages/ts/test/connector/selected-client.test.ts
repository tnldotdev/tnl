import { expect, expectTypeOf, test, vi } from "vitest";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import type { TnlConnectionRegistry } from "../../src/project.js";
import {
  clientFromSelection,
  type ResolvedService,
  type ServiceSelection,
} from "../../src/internal/connector/selected_client.js";
import { captureServiceFacts } from "../../src/internal/project/service_facts.js";

type Protocol = keyof TnlConnectionRegistry;
const services = Object.freeze({
  api: Object.freeze({ protocol: "http" }),
  db: Object.freeze({ protocol: "postgres" }),
  mysql: Object.freeze({ protocol: "mysql" }),
  raw: Object.freeze({ protocol: "tcp" }),
  cluster: Object.freeze({ protocol: "kubernetes" }),
});

function wire(protocol: Protocol) {
  return {
    schema: 1,
    protocol,
    host: "127.0.0.1",
    port: 12345,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    transport_id: `ctg_${"a".repeat(22)}`,
    ...(protocol === "tcp"
      ? {}
      : { ssl: { servername: "service.example", rejectUnauthorized: true } }),
    ...(["http", "kubernetes"].includes(protocol) ? { url: "https://service.example" } : {}),
    ...(protocol === "kubernetes"
      ? { kubeconfig: "/private/fixture/kubeconfig", context: "tnl:cluster" }
      : {}),
  };
}

function runtime(identity: string) {
  const owned = {
    resolve: vi.fn(async (service: string, _signal: AbortSignal) => {
      const fact = Object.hasOwn(services, service)
        ? Object.entries(services).find(([name]) => name === service)?.[1]
        : undefined;
      if (fact === undefined) throw new Error("service denied");
      return { service, protocol: fact.protocol, identity };
    }),
    prepare: vi.fn(
      async (resolution: ResolvedService & { identity: string }, _signal: AbortSignal) => {
        if (resolution.identity !== identity) throw new Error("selection crossed clients");
        return wire(resolution.protocol);
      },
    ),
    close: vi.fn(async () => {}),
    http: vi.fn(() => async () => new Response(identity)),
    mysql: vi.fn(() => () => {
      throw new Error("unit test must not dial a database");
    }),
  } satisfies ServiceSelection<ResolvedService & { identity: string }>;
  return owned;
}

test("actual client infers and constructs all five protocol settings from captured generated facts", async () => {
  const owner = runtime("a");
  const client = clientFromSelection(services, owner);
  try {
    const api = await client.connect("api");
    expectTypeOf(api).toEqualTypeOf<TnlConnectionRegistry["http"]>();
    expect(await (await api.fetch("/health")).text()).toBe("a");
    const db = await client.connect("db");
    expectTypeOf(db).toEqualTypeOf<TnlConnectionRegistry["postgres"]>();
    expect(db).toMatchObject({ host: "127.0.0.1", port: 12345 });
    const mysql = await client.connect("mysql");
    expectTypeOf(mysql).toEqualTypeOf<TnlConnectionRegistry["mysql"]>();
    expect(mysql.host).toBe("service.example");
    expect(mysql.ssl.verifyIdentity).toBe(true);
    expect(mysql.stream).toBeTypeOf("function");
    const raw = await client.connect("raw");
    expectTypeOf(raw).toEqualTypeOf<TnlConnectionRegistry["tcp"]>();
    expect(raw).toEqual({ host: "127.0.0.1", port: 12345 });
    const cluster = await client.connect("cluster");
    expectTypeOf(cluster).toEqualTypeOf<TnlConnectionRegistry["kubernetes"]>();
    expect(cluster).toMatchObject({
      kubeconfig: "/private/fixture/kubeconfig",
      context: "tnl:cluster",
    });
    for (const settings of [api, db, mysql, raw, cluster])
      expect(Object.isFrozen(settings)).toBe(true);
  } finally {
    await client.close();
  }
});

test("PostgreSQL build facts reject valid HTTP discovery before any native preparation", async () => {
  const owner = runtime("a");
  owner.resolve.mockResolvedValue({ service: "db", protocol: "http", identity: "a" });
  const client = clientFromSelection(services, owner);
  try {
    await expect(client.connect("db")).rejects.toMatchObject({ code: "sdk.response_invalid" });
    expect(owner.resolve).toHaveBeenCalledOnce();
    expect(owner.prepare).not.toHaveBeenCalled();
    expect(owner.http).not.toHaveBeenCalled();
  } finally {
    await client.close();
  }
});

test("self-consistent HTTP native settings cannot escape a PostgreSQL typed result", async () => {
  const owner = runtime("a");
  owner.prepare.mockResolvedValue(wire("http"));
  const client = clientFromSelection(services, owner);
  try {
    await expect(client.connect("db")).rejects.toMatchObject({ code: "sdk.response_invalid" });
    expect(owner.prepare).toHaveBeenCalledOnce();
    expect(owner.http).not.toHaveBeenCalled();
  } finally {
    await client.close();
  }
});

test("discovery cannot substitute another logical service even when its protocol matches", async () => {
  const owner = runtime("a");
  owner.resolve.mockResolvedValue({ service: "other", protocol: "postgres", identity: "a" });
  const client = clientFromSelection(services, owner);
  try {
    await expect(client.connect("db")).rejects.toMatchObject({ code: "sdk.response_invalid" });
    expect(owner.prepare).not.toHaveBeenCalled();
  } finally {
    await client.close();
  }
});

test("later caller changes cannot rewrite a client's build protocol facts", async () => {
  const input: { db: { protocol: Protocol } } = { db: { protocol: "postgres" } };
  const owner = runtime("a");
  const client = clientFromSelection(input, owner);
  input.db.protocol = "http";
  try {
    await expect(client.connect("db")).resolves.toHaveProperty("port", 12345);
  } finally {
    await client.close();
  }
  const captured = captureServiceFacts(input);
  expect(Object.isFrozen(captured)).toBe(true);
  expect(Object.isFrozen(captured.db)).toBe(true);
});

test("parallel client selections and cleanup remain isolated without changing process selection", async () => {
  const directory = process.cwd();
  const environment = { ...process.env };
  const a = runtime("a");
  const b = runtime("b");
  const first = clientFromSelection(services, a);
  const other = clientFromSelection(services, b);
  try {
    const [one, two] = await Promise.all([first.connect("api"), other.connect("api")]);
    expect(await (await one.fetch("/a")).text()).toBe("a");
    expect(await (await two.fetch("/b")).text()).toBe("b");
    const mysql = await first.connect("mysql");
    await first.close();
    expect(() => mysql.stream()).toThrow(
      expect.objectContaining({ code: "sdk.connection_unavailable" }),
    );
    await expect(one.fetch("/closed")).rejects.toMatchObject({
      code: "sdk.connection_unavailable",
    });
    expect(await (await two.fetch("/still-open")).text()).toBe("b");
    await expect(first.connect("db")).rejects.toMatchObject({ code: "sdk.connection_unavailable" });
    await expect(other.connect("db")).resolves.toHaveProperty("port", 12345);
    expect(a.close).toHaveBeenCalledOnce();
    expect(b.close).not.toHaveBeenCalled();
    expect(process.cwd()).toBe(directory);
    expect(process.env).toEqual(environment);
  } finally {
    await Promise.all([first.close(), other.close()]);
  }
});

test("close cancels and joins owned preparation before cleanup", async () => {
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<ReturnType<typeof wire>>();
  const owner = runtime("a");
  owner.prepare.mockImplementation(async (_resolution, signal) => {
    entered.resolve();
    const result = await release.promise;
    expect(signal.aborted).toBe(true);
    return result;
  });
  const client = clientFromSelection(services, owner);
  const work = client.connect("db");
  await entered.promise;
  const closing = client.close();
  expect(owner.close).not.toHaveBeenCalled();
  release.resolve(wire("postgres"));
  await expect(work).rejects.toMatchObject({ code: "sdk.connection_unavailable" });
  await closing;
  expect(owner.close).toHaveBeenCalledOnce();
});

test("cleanup failure remains retryable and never reopens selection", async () => {
  const owner = runtime("a");
  const cleanup = new Error("owned cleanup failed");
  owner.close.mockRejectedValueOnce(cleanup).mockResolvedValue(undefined);
  const client = clientFromSelection(services, owner);
  await client.connect("db");
  await expect(client.close()).rejects.toBe(cleanup);
  await expect(client.connect("db")).rejects.toMatchObject({ code: "sdk.connection_unavailable" });
  expect(owner.resolve).toHaveBeenCalledOnce();
  await client.close();
  await client.close();
  expect(owner.close).toHaveBeenCalledTimes(2);
});

test("an undefined cleanup rejection is still a failure and remains retryable", async () => {
  const owner = runtime("a");
  owner.close.mockRejectedValueOnce(undefined).mockResolvedValue(undefined);
  const client = clientFromSelection(services, owner);
  const first = await Promise.allSettled([client.close()]);
  expect(first).toEqual([{ status: "rejected", reason: undefined }]);
  await client.close();
  expect(owner.close).toHaveBeenCalledTimes(2);
});

test("selection files survive failed close and are removed only after joined retry succeeds", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "tnl-owned-selection-"));
  const registry = path.join(directory, "registry.json");
  const selected = path.join(directory, "selection.json");
  await Promise.all([
    writeFile(registry, "owned registry", { mode: 0o600 }),
    writeFile(selected, "nonsecret exact selection", { mode: 0o600 }),
  ]);
  const owner = runtime("a");
  let failing = true;
  owner.close.mockImplementation(async () => {
    if (failing) throw new Error("owned cleanup unavailable");
    await rm(directory, { recursive: true });
  });
  const client = clientFromSelection(services, owner);
  try {
    await client.connect("db");
    await expect(client.close()).rejects.toThrow("owned cleanup unavailable");
    expect(await readFile(registry, "utf8")).toBe("owned registry");
    await expect(stat(selected)).resolves.toBeDefined();
    failing = false;
    await client.close();
    await expect(stat(directory)).rejects.toMatchObject({ code: "ENOENT" });
    await client.close();
    expect(owner.close).toHaveBeenCalledTimes(2);
  } finally {
    failing = false;
    await client.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("source rotation stays with its owner, and one service denial leaves another usable", async () => {
  const owner = runtime("a");
  let assertion = "first proof";
  const source = vi.fn(async () => assertion);
  owner.resolve.mockImplementation(async (service) => {
    await source();
    if (service !== "db") throw new Error("service denied");
    return { service, protocol: "postgres", identity: "a" };
  });
  const other = runtime("b");
  const a = clientFromSelection(services, owner);
  const b = clientFromSelection(services, other);
  try {
    await a.connect("db");
    assertion = "rotated proof";
    await expect(a.connect("api")).rejects.toThrow("service denied");
    await a.connect("db");
    await b.connect("db");
    expect(source).toHaveBeenCalledTimes(3);
    expect(owner.prepare.mock.calls.every(([selection]) => selection.identity === "a")).toBe(true);
    expect(other.prepare.mock.calls.every(([selection]) => selection.identity === "b")).toBe(true);
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test("each client bounds pending preparations independently", async () => {
  const release = Promise.withResolvers<ResolvedService & { identity: string }>();
  const owner = runtime("a");
  owner.resolve.mockImplementation(async () => release.promise);
  const client = clientFromSelection(services, owner);
  const pending = Array.from({ length: 64 }, () => client.connect("db"));
  await expect(client.connect("db")).rejects.toMatchObject({ code: "sdk.connection_unavailable" });
  expect(owner.resolve).toHaveBeenCalledTimes(64);
  release.resolve({ service: "db", protocol: "postgres", identity: "a" });
  await Promise.all(pending);
  await client.close();
});

test("independent operation failure survives cancellation and a later successful cleanup retry", async () => {
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<ReturnType<typeof wire>>();
  const owner = runtime("a");
  const operation = new Error("independent preparation failure");
  const cleanup = new Error("owned cleanup failure");
  owner.prepare.mockImplementation(async () => {
    entered.resolve();
    return release.promise;
  });
  owner.close.mockRejectedValueOnce(cleanup).mockResolvedValue(undefined);
  const client = clientFromSelection(services, owner);
  const work = client.connect("db");
  await entered.promise;
  const closing = client.close();
  release.reject(operation);
  await expect(work).rejects.toBe(operation);
  await expect(closing).rejects.toMatchObject({ errors: [operation, cleanup] });
  await expect(client.close()).rejects.toBe(operation);
  expect(owner.close).toHaveBeenCalledTimes(2);
});

test.each([33, 128])("a %i-service build prepares only the requested service", async (count) => {
  const facts = Object.fromEntries(
    Array.from({ length: count }, (_, index) => [`service-${index}`, { protocol: "tcp" }]),
  );
  // validate dynamic input through the same constructor; no project/global lookup.
  const validated = Object.fromEntries(
    Object.keys(facts).map((name) => [name, Object.freeze({ protocol: "tcp" })]),
  );
  const owner = runtime("a");
  owner.resolve.mockResolvedValue({ service: "service-0", protocol: "tcp", identity: "a" });
  const client = clientFromSelection(validated, owner);
  try {
    await expect(client.connect("service-0")).resolves.toHaveProperty("port", 12345);
    expect(owner.resolve).toHaveBeenCalledOnce();
    expect(owner.prepare).toHaveBeenCalledOnce();
  } finally {
    await client.close();
  }
});

test.each([
  null,
  { db: { protocol: "unknown" } },
  { "bad/name": { protocol: "postgres" } },
  { db: { protocol: "postgres", target: "private-target" } },
  Object.fromEntries(Array.from({ length: 129 }, (_, i) => [`service-${i}`, { protocol: "tcp" }])),
])("invalid build facts fail before discovery (%j)", (input) => {
  const owner = runtime("a");
  expect(() => Reflect.apply(clientFromSelection, undefined, [input, owner])).toThrow(
    expect.objectContaining({ code: "sdk.configuration_invalid" }),
  );
  expect(owner.resolve).not.toHaveBeenCalled();
  expect(owner.prepare).not.toHaveBeenCalled();
});

test.each(["missing", null, 1, "bad/name"])(
  "invalid runtime service %j fails before discovery",
  async (name) => {
    const owner = runtime("a");
    const client = clientFromSelection(services, owner);
    try {
      await expect(Reflect.apply(client.connect, undefined, [name])).rejects.toMatchObject({
        code: "sdk.configuration_invalid",
      });
      expect(owner.resolve).not.toHaveBeenCalled();
    } finally {
      await client.close();
    }
  },
);
