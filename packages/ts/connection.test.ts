import { describe, expect, test } from "vitest";
import { managedFetch, parseConnection } from "./src/internal/connection.js";

const database = {
  schema: 1,
  protocol: "postgres",
  host: "database.team.example",
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
    "accepts a fresh %s public credential snapshot only as a pair",
    (protocol) => {
      const ssl = { ...database.ssl, cert: "current-certificate", key: "current-key" };
      expect(parseConnection({ ...database, protocol, ssl }).ssl).toEqual(ssl);
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
      { ...database, expires_at: new Date(0).toISOString() },
      { ...database, expires_at: "invalid" },
      { ...database, port: "15432" },
      { ...database, user: "never-gathered" },
      { ...database, ssl: { ...database.ssl, rejectUnauthorized: false } },
      { ...database, ssl: { ...database.ssl, servername: "other.example" } },
      { ...database, ssl: { ...database.ssl, ca: { secret: true } } },
      { ...database, ssl: { ...database.ssl, key: "x".repeat(128 * 1024) } },
      { ...database, ssl: { ...database.ssl, unexpected: true } },
    ])
      expect(() => parseConnection(value)).toThrow();
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
    await expect(tnl.connect("database" as never)).rejects.toMatchObject({
      code: "sdk.connection_server_only",
    });
  });
});
