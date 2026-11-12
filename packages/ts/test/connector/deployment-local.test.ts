import { beforeEach, describe, expect, test, vi } from "vitest";
import { createClient } from "../../src/internal/connector/local_client.js";

const native = vi.hoisted(() => ({
  reply: {
    schema: 1,
    protocol: "postgres",
    host: "127.0.0.1",
    port: 15432,
    binding: "a".repeat(64),
  } as Record<string, unknown>,
  calls: [] as string[][],
  error: null as Error | null,
  wait: false,
  queued: [] as (() => void)[],
}));
vi.mock("node:child_process", () => ({
  execFile: (
    _binary: string,
    args: string[],
    _options: unknown,
    callback: (error: Error | null, stdout: string) => void,
  ) => {
    native.calls.push(args);
    const reply = () => callback(native.error, JSON.stringify(native.reply));
    if (native.wait) native.queued.push(reply);
    else reply();
  },
}));
vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => "/fixture/tnl",
}));

const services = { db: { protocol: "postgres" }, app: { protocol: "http" } } as const;
beforeEach(() => {
  native.calls = [];
  native.error = null;
  native.wait = false;
  native.queued = [];
  native.reply = {
    schema: 1,
    protocol: "postgres",
    host: "127.0.0.1",
    port: 15432,
    binding: "a".repeat(64),
  };
});

describe("explicit local deployment", () => {
  test.each([
    null,
    {},
    { services: null },
    { services: { db: { protocol: "invalid" } } },
    { services: { db: { protocol: "postgres", target: "private address" } } },
  ])("rejects invalid or deployment-specific service facts (%j)", (options) => {
    expect(() => Reflect.apply(createClient, undefined, [options])).toThrow(
      expect.objectContaining({ code: "sdk.configuration_invalid" }),
    );
    expect(native.calls).toHaveLength(0);
  });
  test("returns ordinary PostgreSQL settings with no credentials or tunnel state", async () => {
    const local = createClient({ services }).deployment("local");
    expect(await local.connect("db")).toEqual({ host: "127.0.0.1", port: 15432, ssl: false });
    expect(native.calls).toEqual([
      [
        "runtime",
        "connections",
        "local",
        "--directory",
        process.cwd(),
        "--service",
        "db",
        "--protocol",
        "postgres",
      ],
    ]);
    await local.close();
    expect(native.calls).toHaveLength(1);
    await expect(local.connect("db")).rejects.toMatchObject({ code: "sdk.client_closed" });
  });

  test("preserves target TLS and freezes its settings", async () => {
    native.reply.ssl = { servername: "database.local", rejectUnauthorized: true };
    const local = createClient({ services }).deployment("local");
    const connection = await local.connect("db");
    expect(connection.ssl).toEqual(native.reply.ssl);
    expect(Object.isFrozen(connection)).toBe(true);
    expect(Object.isFrozen(connection.ssl)).toBe(true);
    await local.close();
  });

  test("caches ordinary driver clients by native binding and closes only its own clients", async () => {
    const tnl = createClient({ services });
    const first = tnl.deployment("local");
    const second = tnl.deployment("local");
    const create = vi.fn((connection) => ({ connection }));
    const close = vi.fn();
    const one = first.client("db", { create, close });
    const two = second.client("db", { create, close });
    expect(await one()).toBe(await one());
    const sibling = await two();
    expect(create).toHaveBeenCalledTimes(2);
    native.reply.binding = "b".repeat(64);
    await one();
    expect(create).toHaveBeenCalledTimes(3);
    await first.close();
    expect(close).toHaveBeenCalledTimes(2);
    native.reply.binding = "a".repeat(64);
    expect(await two()).toBe(sibling);
    await second.close();
    expect(close).toHaveBeenCalledTimes(3);
  });

  test("retries failed driver cleanup without recreating or losing the driver", async () => {
    const local = createClient({ services }).deployment("local");
    const failure = new Error("driver close failed");
    const close = vi.fn().mockRejectedValueOnce(failure).mockResolvedValue(undefined);
    const driver = local.client("db", { create: () => ({}), close });
    await driver();
    await expect(local.close()).rejects.toBe(failure);
    await local.close();
    expect(close).toHaveBeenCalledTimes(2);
  });

  test("close joins an in-flight native selection and does not create a late pool", async () => {
    native.wait = true;
    const local = createClient({ services }).deployment("local");
    const create = vi.fn();
    const driver = local.client("db", { create, close: vi.fn() });
    const getting = driver();
    const observed = expect(getting).rejects.toMatchObject({ code: "sdk.client_closed" });
    await Promise.resolve();
    expect(native.queued).toHaveLength(1);
    let joined = false;
    const closing = local.close().then(() => {
      joined = true;
    });
    await Promise.resolve();
    expect(joined).toBe(false);
    native.queued[0]?.();
    await observed;
    await closing;
    expect(create).not.toHaveBeenCalled();
  });

  test("close preserves an independent native failure while joining selection", async () => {
    native.wait = true;
    const local = createClient({ services }).deployment("local");
    const getting = local.connect("db");
    const observed = expect(getting).rejects.toMatchObject({
      code: "sdk.local_connection_unavailable",
    });
    const closing = local.close();
    const closeFailure = expect(closing).rejects.toMatchObject({
      code: "sdk.local_connection_unavailable",
    });
    native.error = new Error("independent native failure");
    native.queued[0]?.();
    await observed;
    await closeFailure;
  });

  test("manually closed driver factories release their capacity", async () => {
    const local = createClient({ services }).deployment("local");
    for (let index = 0; index < 65; index++) {
      const factory = local.client("db", { create: () => ({}), close: () => {} });
      await factory.close();
    }
    await local.close();
  });

  test("captures service facts instead of following later object mutations", async () => {
    const mutable: { db: { protocol: "postgres" | "mysql" } } = { db: { protocol: "postgres" } };
    const tnl = createClient({ services: mutable });
    mutable.db.protocol = "mysql";
    const local = tnl.deployment("local");
    await expect(local.connect("db")).resolves.toMatchObject({ port: 15432 });
    await local.close();
  });

  test("does not fall back to authenticated tunnel setup when local resolution fails", async () => {
    const local = createClient({ services }).deployment("local");
    native.error = new Error("native private diagnostic");
    await expect(local.connect("db")).rejects.toMatchObject({
      code: "sdk.local_connection_unavailable",
    });
    expect(native.calls).toHaveLength(1);
    await local.close();
  });

  test.each([
    { host: "database.internal" },
    { host: "192.0.2.1" },
    { host: "0.0.0.0" },
    { port: 0 },
    { protocol: "mysql" },
    { binding: "invalid" },
    { ssl: null },
    { ssl: { servername: "database.local", rejectUnauthorized: false } },
    { password: "never accepted" },
  ])("rejects invalid local native output: %j", async (change) => {
    Object.assign(native.reply, change);
    const local = createClient({ services }).deployment("local");
    await expect(local.connect("db")).rejects.toMatchObject({ code: "sdk.response_invalid" });
    await local.close();
  });
});
