import { describe, expect, test } from "vitest";
import { managedFetch, parseConnection } from "../../src/internal/connector/connection.js";

const database = {
  schema: 1,
  protocol: "postgres",
  host: "127.0.0.1",
  port: 15432,
  expires_at: new Date(Date.now() + 60_000).toISOString(),
  ssl: { servername: "database.team.example", rejectUnauthorized: true },
};
const { ssl: _ssl, ...endpoint } = database;
const origin = "https://database.team.example:8443";
const kubernetes = { kubeconfig: "/private/fixture/kubeconfig", context: "tnl:cluster" };

describe("private connection snapshots", () => {
  test.each([
    { ...endpoint, protocol: "tcp" },
    database,
    { ...database, protocol: "mysql" },
    { ...database, protocol: "http", url: origin },
    { ...database, protocol: "kubernetes", url: origin, ...kubernetes },
  ])("returns only the validated fields for $protocol", (wire) => {
    const snapshot = parseConnection(wire);
    const { schema: _schema, expires_at, ...fields } = wire;
    expect(snapshot).toEqual({ ...fields, expires: Date.parse(expires_at) });
    expect(Object.isFrozen(snapshot)).toBe(true);
    if (snapshot.protocol !== "tcp") expect(Object.isFrozen(snapshot.ssl)).toBe(true);
    expect(
      parseConnection({
        ...wire,
        transport_id: "ctg_aaaaaaaaaaaaaaaaaaaaaa",
      }),
    ).toEqual({ ...snapshot, transportID: "ctg_aaaaaaaaaaaaaaaaaaaaaa" });
  });
  test.each(["postgres", "mysql", "http", "kubernetes"])(
    "%s requires verified application TLS options",
    (protocol) => {
      for (const fields of [{}, { ssl: undefined }, { ssl: null }])
        expect(() =>
          parseConnection({
            ...endpoint,
            protocol,
            ...(["http", "kubernetes"].includes(protocol) ? { url: origin } : {}),
            ...(protocol === "kubernetes" ? kubernetes : {}),
            ...fields,
          }),
        ).toThrow();
    },
  );
  test.each([
    { wire: { ...endpoint, protocol: "tcp" }, forbidden: ["ssl", "url", "kubeconfig", "context"] },
    { wire: database, forbidden: ["url", "kubeconfig", "context"] },
    { wire: { ...database, protocol: "mysql" }, forbidden: ["url", "kubeconfig", "context"] },
    { wire: { ...database, protocol: "http", url: origin }, forbidden: ["kubeconfig", "context"] },
  ])(
    "$wire.protocol rejects fields owned by other protocols, even when undefined",
    ({ wire, forbidden }) => {
      for (const field of forbidden)
        for (const value of [undefined, null, "not-allowed"])
          expect(() => parseConnection({ ...wire, [field]: value })).toThrow(
            expect.objectContaining({ code: "sdk.response_invalid" }),
          );
    },
  );
  test("kubernetes requires a private kubeconfig path and a bounded tnl context", () => {
    const wire = { ...database, protocol: "kubernetes", url: origin, ...kubernetes };
    const { kubeconfig: _kubeconfig, context: _context, ...missing } = wire;
    for (const fields of [
      missing,
      { ...missing, kubeconfig: kubernetes.kubeconfig },
      { ...missing, context: kubernetes.context },
    ])
      expect(() => parseConnection(fields)).toThrow();
    for (const kubeconfig of [
      undefined,
      null,
      "relative/kubeconfig",
      "/private/\0kubeconfig",
      `/${"x".repeat(4096)}`,
    ])
      expect(() => parseConnection({ ...wire, kubeconfig })).toThrow();
    for (const context of [undefined, null, "cluster", `tnl:${"x".repeat(1021)}`])
      expect(() => parseConnection({ ...wire, context })).toThrow();
  });
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
      { ...database, protocol: "unknown" },
      { ...database, host: "database.team.example" },
      { ...database, expires_at: new Date(0).toISOString() },
      { ...database, expires_at: "invalid" },
      { ...database, port: "15432" },
      { ...database, port: 0 },
      { ...database, port: 65536 },
      { ...database, port: 1.5 },
      ...[undefined, null, "", "ctg_short", "ctg_aaaaaaaaaaaaaaaaaaaaa_"].map((transport_id) => ({
        ...database,
        transport_id,
      })),
      { ...database, user: "never-gathered" },
      { ...database, ssl: { ...database.ssl, rejectUnauthorized: false } },
      { ...database, ssl: { ...database.ssl, servername: "127.0.0.1" } },
      { ...database, ssl: { ...database.ssl, ca: { secret: true } } },
      { ...database, ssl: { ...database.ssl, key: "x".repeat(128 * 1024) } },
      { ...database, ssl: { ...database.ssl, unexpected: true } },
    ])
      expect(() => parseConnection(value)).toThrow();
  });
  test.each(["http", "kubernetes"])("keeps %s URLs on the managed origin", (protocol) => {
    const fields = protocol === "kubernetes" ? kubernetes : {};
    const snapshot = parseConnection({
      ...database,
      protocol,
      url: origin,
      ...fields,
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
      "https://database.team.example/",
      "https://database.team.example:443",
      "https://DATABASE.team.example",
      undefined,
      null,
    ])
      expect(() => parseConnection({ ...database, protocol, ...fields, url })).toThrow();
    expect(() => parseConnection({ ...database, protocol, ...fields })).toThrow();
  });
  test("managed fetch rejects non-HTTP snapshots and a different managed origin", async () => {
    for (const wire of [
      database,
      { ...database, protocol: "mysql" },
      { ...endpoint, protocol: "tcp" },
      { ...database, protocol: "http", url: origin },
    ]) {
      const fetch = managedFetch("https://api.example", async () => parseConnection(wire));
      await expect(fetch("/")).rejects.toMatchObject({ code: "sdk.response_invalid" });
    }
  });
  test("opaque TCP returns only the outer-TLS helper, with no application TLS options", () => {
    expect(parseConnection({ ...endpoint, protocol: "tcp", host: "127.0.0.1" })).toMatchObject({
      protocol: "tcp",
      host: "127.0.0.1",
    });
    expect(() => parseConnection({ ...database, protocol: "tcp", host: "127.0.0.1" })).toThrow();
  });
  test("browser connect rejects with an owned server-only diagnostic", async () => {
    const { tnl } = await import("../../src/index.browser.js");
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
