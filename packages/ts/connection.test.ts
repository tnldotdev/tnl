import { describe, expect, test } from "vitest";
import { managedFetch, parseConnection } from "./src/internal/connection.js";

const database = {
  schema: 1,
  protocol: "postgres",
  host: "127.0.0.1",
  port: 15432,
  expires_at: new Date(Date.now() + 60_000).toISOString(),
  ssl: { servername: "database.team.example", rejectUnauthorized: true },
};

describe("private connection snapshots", () => {
  test("fetch cancellation includes native credential acquisition", async () => {
    const abort = new AbortController();
    const fetch = managedFetch(
      "https://api.example",
      (signal) =>
        new Promise<never>((_resolve, reject) => {
          if (signal === undefined) throw new Error("missing lifetime signal");
          signal.addEventListener("abort", () => reject(signal.reason), { once: true });
        }),
    );
    const pending = fetch("/", { signal: abort.signal });
    abort.abort();
    await expect(pending).rejects.toBe(abort.signal.reason);
  });
  test("fetch bounds requests waiting for native credentials", async () => {
    const abort = new AbortController();
    const fetch = managedFetch(
      "https://api.example",
      (signal) =>
        new Promise<never>((_resolve, reject) => {
          if (signal === undefined) throw new Error("missing lifetime signal");
          signal.addEventListener("abort", () => reject(signal.reason), { once: true });
        }),
    );
    const pending = Array.from({ length: 64 }, () =>
      fetch("/", { signal: abort.signal }).catch(() => {}),
    );
    await expect(fetch("/")).rejects.toMatchObject({ code: "sdk.connection_unavailable" });
    abort.abort();
    await Promise.all(pending);
  });
  test.each(["postgres", "mysql"])(
    "keeps %s private admission independent of application TLS credentials",
    (protocol) => {
      const connection = parseConnection({ ...database, protocol });
      expect(connection.ssl).toEqual(database.ssl);
      expect(connection.ssl).not.toHaveProperty("ca");
      expect(connection.ssl).not.toHaveProperty("cert");
      expect(connection.ssl).not.toHaveProperty("key");
    },
  );
  test.each(["postgres", "mysql"])(
    "rejects application credentials in %s connector options",
    (protocol) => {
      const ssl = { ...database.ssl, cert: "current-certificate", key: "current-key" };
      expect(() => parseConnection({ ...database, protocol, ssl })).toThrow();
      for (const partial of [
        { ...database.ssl, cert: "cert" },
        { ...database.ssl, key: "key" },
      ])
        expect(() => parseConnection({ ...database, protocol, ssl: partial })).toThrow();
    },
  );
  test("rejects stale, widened, unverified, malformed, and credential-bearing endpoint data", () => {
    for (const value of [
      { ...database, schema: 2 },
      { ...database, host: "database.team.example" },
      { ...database, expires_at: new Date(0).toISOString() },
      { ...database, expires_at: "invalid" },
      { ...database, port: "15432" },
      { ...database, user: "never-gathered" },
      { ...database, ssl: { ...database.ssl, rejectUnauthorized: false } },
      { ...database, ssl: { ...database.ssl, servername: "127.0.0.1" } },
      { ...database, ssl: { ...database.ssl, ca: { secret: true } } },
      { ...database, ssl: { ...database.ssl, key: "x".repeat(128 * 1024) } },
      { ...database, ssl: { ...database.ssl, unexpected: true } },
    ])
      expect(() => parseConnection(value)).toThrow();
  });
  test("freezes local snapshots and keeps HTTP URLs on the managed origin", () => {
    const snapshot = parseConnection({
      ...database,
      protocol: "http",
      url: "https://database.team.example:8443",
    });
    expect(snapshot).toMatchObject({
      host: "127.0.0.1",
      port: 15432,
      url: "https://database.team.example:8443",
    });
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.ssl)).toBe(true);
    for (const url of [
      "http://database.team.example",
      "https://127.0.0.1:15432",
      "https://database.team.example/secret",
      "https://database.team.example/?token=secret",
      "https://user:secret@database.team.example",
    ])
      expect(() => parseConnection({ ...database, protocol: "http", url })).toThrow();
  });
  test("opaque TCP returns only the outer-TLS helper, with no application TLS options", () => {
    const { ssl: _ssl, ...endpoint } = database;
    expect(parseConnection({ ...endpoint, protocol: "tcp", host: "127.0.0.1" })).toMatchObject({
      protocol: "tcp",
      host: "127.0.0.1",
    });
    expect(() => parseConnection({ ...database, protocol: "tcp", host: "127.0.0.1" })).toThrow();
  });
  test("browser connect rejects with an owned server-only diagnostic", async () => {
    const { tnl } = await import("./src/index.browser.js");
    const handle = tnl.connect("database");
    expect(Object.getOwnPropertyDescriptor(handle, "then")?.enumerable).toBe(false);
    expect(() => ({ ...handle })).toThrow(
      expect.objectContaining({ code: "sdk.connection_server_only" }),
    );
    await expect(handle).rejects.toMatchObject({
      code: "sdk.connection_server_only",
    });
    await expect(Promise.resolve(handle)).rejects.toMatchObject({
      code: "sdk.connection_server_only",
    });
  });
});
