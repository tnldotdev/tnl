import { createServer } from "node:http";
import { createServer as createSecureServer } from "node:https";
import { connect as connectTCP, createServer as createTCPServer } from "node:net";
import { createSecureContext } from "node:tls";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { createClient } from "../../src/internal/connector/local_client.js";
import { cert, key } from "../fixtures/local-tls.js";

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

const services = {
  db: { protocol: "postgres" },
  app: { protocol: "http" },
  mysql: { protocol: "mysql" },
  cache: { protocol: "tcp" },
  cluster: { protocol: "kubernetes" },
} as const;
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

  test("returns protocol-specific settings without authenticating or starting a connector", async () => {
    const local = createClient({ services }).deployment("local");
    native.reply.protocol = "tcp";
    const tcp = await local.connect("cache");
    expect(tcp).toEqual({ host: "127.0.0.1", port: 15432 });
    native.reply.protocol = "mysql";
    native.reply.ssl = { servername: "mysql.local", rejectUnauthorized: true };
    const mysql = await local.connect("mysql");
    expect(mysql).toMatchObject({
      host: "mysql.local",
      port: 15432,
      ssl: { servername: "mysql.local", rejectUnauthorized: true, verifyIdentity: true },
    });
    expect(mysql.stream).toBeTypeOf("function");
    native.reply.protocol = "kubernetes";
    native.reply.ssl = { servername: "cluster.local", rejectUnauthorized: true };
    native.reply.server = "https://127.0.0.1:15432";
    native.reply.kubeconfig = "/home/user/.kube/config";
    native.reply.context = "local-cluster";
    expect(await local.connect("cluster")).toEqual({
      server: "https://127.0.0.1:15432",
      kubeconfig: "/home/user/.kube/config",
      context: "local-cluster",
    });
    expect(native.calls.map((call) => call.at(-1))).toEqual(["tcp", "mysql", "kubernetes"]);
    await local.close();
  });

  test("HTTP uses only the resolved loopback origin and never follows remote redirects", async () => {
    const listener = createServer((request, response) => {
      if (request.url === "/redirect") {
        response.writeHead(302, { location: "https://remote.invalid/" }).end();
      } else {
        response.end("local");
      }
    });
    await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
    try {
      const address = listener.address();
      if (address === null || typeof address === "string") throw new Error("missing listener");
      native.reply.protocol = "http";
      native.reply.port = address.port;
      native.reply.url = `http://127.0.0.1:${address.port}`;
      const local = createClient({ services }).deployment("local");
      const app = await local.connect("app");
      expect(app.url).toBe(native.reply.url);
      expect(await (await app.fetch("/")).text()).toBe("local");
      const redirect = await app.fetch("/redirect", { redirect: "follow" });
      expect(redirect.status).toBe(302);
      await expect(app.fetch("https://remote.invalid/")).rejects.toMatchObject({
        code: "sdk.configuration_invalid",
      });
      await local.close();
      await expect(app.fetch("/")).rejects.toMatchObject({ code: "sdk.client_closed" });
    } finally {
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    }
  });

  test("HTTPS verifies the configured hostname and CA while dialing only loopback", async () => {
    const sni: string[] = [];
    const listener = createSecureServer(
      {
        key,
        cert,
        SNICallback(hostname, callback) {
          sni.push(hostname);
          callback(null, createSecureContext({ key, cert }));
        },
      },
      (_request, response) => response.end("verified local"),
    );
    await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
    try {
      const address = listener.address();
      if (address === null || typeof address === "string") throw new Error("missing listener");
      native.reply.protocol = "http";
      native.reply.port = address.port;
      native.reply.url = `https://api.tnl.invalid:${address.port}`;
      native.reply.ssl = {
        servername: "api.tnl.invalid",
        rejectUnauthorized: true,
        ca: cert,
      };
      const local = createClient({ services }).deployment("local");
      const app = await local.connect("app");
      expect(await (await app.fetch("/")).text()).toBe("verified local");
      expect(sni).toEqual(["api.tnl.invalid"]);
      await local.close();
      await expect(app.fetch("/")).rejects.toMatchObject({ code: "sdk.client_closed" });

      native.reply.ssl = { servername: "api.tnl.invalid", rejectUnauthorized: true };
      const untrusted = createClient({ services }).deployment("local");
      const settings = await untrusted.connect("app");
      await expect(settings.fetch("/")).rejects.toThrow();
      await untrusted.close();
      expect(sni).toHaveLength(2);
    } finally {
      const stopped = new Promise<void>((resolve) => listener.close(() => resolve()));
      listener.closeAllConnections();
      await stopped;
    }
  });

  test("TCP and MySQL stream settings dial the selected listener directly", async () => {
    const listener = createTCPServer((socket) => socket.end("local tcp"));
    await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
    try {
      const address = listener.address();
      if (address === null || typeof address === "string") throw new Error("missing listener");
      native.reply.protocol = "tcp";
      native.reply.port = address.port;
      const local = createClient({ services }).deployment("local");
      const settings = await local.connect("cache");
      const text = await new Promise<string>((resolve, reject) => {
        const socket = connectTCP(settings.port, settings.host);
        const chunks: Buffer[] = [];
        socket.on("data", (chunk: Buffer) => chunks.push(chunk));
        socket.once("end", () => resolve(Buffer.concat(chunks).toString()));
        socket.once("error", reject);
      });
      expect(text).toBe("local tcp");
      native.reply.protocol = "mysql";
      native.reply.ssl = { servername: "mysql.local", rejectUnauthorized: true };
      const mysql = await local.connect("mysql");
      const greeting = await new Promise<string>((resolve, reject) => {
        const socket = mysql.stream();
        const chunks: Buffer[] = [];
        socket.on("data", (chunk: Buffer) => chunks.push(chunk));
        socket.once("end", () => resolve(Buffer.concat(chunks).toString()));
        socket.once("error", reject);
      });
      expect(greeting).toBe("local tcp");
      await local.close();
    } finally {
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    }
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

  test("rejects native HTTP and Kubernetes settings that could leave loopback", async () => {
    const local = createClient({ services }).deployment("local");
    native.reply.protocol = "http";
    native.reply.url = "http://remote.invalid:15432";
    await expect(local.connect("app")).rejects.toMatchObject({ code: "sdk.response_invalid" });
    native.reply.protocol = "kubernetes";
    native.reply.ssl = { servername: "cluster.local", rejectUnauthorized: true };
    native.reply.server = "https://remote.invalid:15432";
    native.reply.kubeconfig = "/home/user/.kube/config";
    native.reply.context = "local";
    await expect(local.connect("cluster")).rejects.toMatchObject({
      code: "sdk.response_invalid",
    });
    await local.close();
  });
});
