import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { rootCertificates } from "node:tls";
import { tnl, TnlError } from "@tnldotdev/tnl";
import { sql as statement } from "drizzle-orm";
import { drizzle as drizzlePG } from "drizzle-orm/node-postgres";
import { drizzle as drizzleJS } from "drizzle-orm/postgres-js";
import { drizzle as drizzleMySQL } from "drizzle-orm/mysql2";
import mysql from "mysql";
import mysql2 from "mysql2/promise";
import pg from "pg";
import postgres from "postgres";
import * as z from "zod";

// this file is copied into an isolated consumer with the packed SDK and exact
// workspace driver versions. only the prepared owner's native IPC is inherited.
const require = createRequire(import.meta.url);
const commonjs: typeof import("@tnldotdev/tnl") = require("@tnldotdev/tnl");
assert.equal(commonjs.TnlError, TnlError);
const wrongCA = z.string().min(1).parse(rootCertificates[0]);
const credentials = { user: "tnl_client", password: "testpass", database: "tnl_fixture" };
const pgRows = z
  .array(z.object({ username: z.literal("tnl_client"), secure: z.literal(true), pid: z.number() }))
  .min(1);
const mysqlRows = z
  .array(z.object({ username: z.string().startsWith("tnl_client@"), pid: z.number() }))
  .min(1);
const pgQuery =
  "SELECT current_user AS username, ssl AS secure, pg_backend_pid() AS pid FROM pg_stat_ssl WHERE pid=pg_backend_pid()";
const mysqlQuery = "SELECT CURRENT_USER() AS username, CONNECTION_ID() AS pid";
let phase = "startup";
let queries = 0;
let negatives = 0;
let lifetimes = 0;
let nativeCancel = "not-tested";
const sessions = new Set<number>();

function version(name: string): string {
  const manifest: unknown =
    name === "postgres"
      ? JSON.parse(
          readFileSync(
            path.resolve(path.dirname(require.resolve(name)), "../../package.json"),
            "utf8",
          ),
        )
      : require(`${name}/package.json`);
  return z.object({ version: z.string() }).parse(manifest).version;
}
function errorCode(error: unknown): string | undefined {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof error.code === "string"
  )
    return error.code;
  return undefined;
}
async function rejects(operation: () => Promise<unknown>, codes: readonly string[]) {
  await assert.rejects(operation, (error: unknown) => codes.includes(errorCode(error) ?? ""));
  negatives++;
}
function recordPG(rows: unknown): number {
  const row = pgRows.parse(rows)[0];
  assert(row);
  queries++;
  sessions.add(row.pid);
  return row.pid;
}
function recordMySQL(rows: unknown): number {
  const row = mysqlRows.parse(rows)[0];
  assert(row);
  queries++;
  sessions.add(row.pid);
  return row.pid;
}
function report(driver: string, runtime: string, status = "qualified") {
  process.stdout.write(
    JSON.stringify({
      driver,
      version: version(driver),
      runtime,
      status,
      queries,
      sessions: sessions.size,
      negatives,
      lifetimes,
      nativeCancel,
    }) + "\n",
  );
  queries = 0;
  negatives = 0;
  lifetimes = 0;
  nativeCancel = "not-tested";
  sessions.clear();
}

async function qualifyPostgres(runtime: typeof tnl, kind: string) {
  phase = "pg settings";
  const options = { ...runtime.connect("database") };
  assert("ssl" in options && !("stream" in options));
  assert.equal(options.host, "127.0.0.1");
  assert.equal(options.ssl.rejectUnauthorized, true);
  const awaited = await runtime.connect("database");
  assert.deepEqual(awaited, options);
  const invalidName = { ...runtime.connect("wrong-name") };
  assert("ssl" in invalidName && !("stream" in invalidName));
  const queryPG = async (overrides: pg.ClientConfig = {}) => {
    const client = new pg.Client({
      ...options,
      ...credentials,
      connectionTimeoutMillis: 5_000,
      ...overrides,
    });
    try {
      await client.connect();
      return recordPG((await client.query(pgQuery)).rows);
    } finally {
      await client.end();
    }
  };
  phase = "pg query and tls negatives";
  await queryPG();
  await rejects(() => queryPG({ ...invalidName }), ["ERR_TLS_CERT_ALTNAME_INVALID"]);
  await rejects(
    () => queryPG({ ssl: { ...options.ssl, ca: wrongCA } }),
    ["SELF_SIGNED_CERT_IN_CHAIN"],
  );
  await rejects(() => queryPG({ password: "incorrect" }), ["28P01"]);
  // the publisher terminates TLS, so a backend PLUS proof cannot bind to the
  // frontend certificate. pg defaults to non-PLUS; opt-in PLUS must fail closed.
  await rejects(() => queryPG({ enableChannelBinding: true }), ["0A000"]);
  phase = "pg pool";
  const pool = new pg.Pool({
    ...options,
    ...credentials,
    max: 2,
    idleTimeoutMillis: 1_000,
    connectionTimeoutMillis: 5_000,
  });
  try {
    const first = await pool.connect();
    const second = await pool.connect();
    const a = recordPG((await first.query(pgQuery)).rows);
    const b = recordPG((await second.query(pgQuery)).rows);
    assert.notEqual(a, b);
    first.release();
    second.release();
    const reused = recordPG((await pool.query(pgQuery)).rows);
    assert([a, b].includes(reused));
    await delay(1_400);
    const fresh = recordPG((await pool.query(pgQuery)).rows);
    assert(![a, b].includes(fresh));
    recordPG((await drizzlePG(pool).execute(statement.raw(pgQuery))).rows);
  } finally {
    await pool.end();
  }

  phase = "pg selected connection lifetimes";
  await pgLifetimes(runtime);
  phase = "pg native cancel limit and sql cancellation";
  const sleeping = new pg.Client({ ...options, ...credentials });
  const independent = new pg.Client({ ...options, ...credentials });
  const bystander = new pg.Client({ ...options, ...credentials });
  const cancelClient = new pg.Client({ ...options, ...credentials });
  cancelClient.connection.on("error", () => {});
  try {
    await sleeping.connect();
    await independent.connect();
    await bystander.connect();
    const bystanderPID = recordPG((await bystander.query(pgQuery)).rows);
    const pid = recordPG((await sleeping.query(pgQuery)).rows);
    await sleeping.query("CREATE TEMP SEQUENCE cancel_attempt; SET statement_timeout='1800ms'");
    let complete!: (error: Error | null) => void;
    const result = new Promise<Error | null>((resolve) => {
      complete = resolve;
    });
    const query = sleeping.query(
      new pg.Query("SELECT nextval('cancel_attempt'); SELECT pg_sleep(10)", (error) =>
        complete(error ?? null),
      ),
    );
    await waitSleep(independent, pid);
    // pg's ordinary cancellation API opens a second socket and sends a plaintext
    // CancelRequest even when the original session has verified TLS settings.
    assert("cancel" in cancelClient && typeof cancelClient.cancel === "function");
    cancelClient.cancel(sleeping, query);
    await delay(100);
    await waitSleep(independent, pid);
    const error = await result;
    assert.equal(errorCode(error), "57014");
    assert(error instanceof Error && error.message.includes("statement timeout"));
    const attempts = z
      .array(z.object({ last_value: z.literal("1") }))
      .parse((await sleeping.query("SELECT last_value FROM cancel_attempt")).rows);
    assert.equal(attempts.length, 1);
    assert.equal(recordPG((await sleeping.query(pgQuery)).rows), pid);
    // authenticated SQL is a separate, provider-authorized cancellation option.
    await sleeping.query("SET statement_timeout='5s'");
    const canceled = sleeping
      .query("SELECT nextval('cancel_attempt'); SELECT pg_sleep(10)")
      .catch((error: unknown) => error);
    await waitSleep(independent, pid);
    const otherQuery = bystander.query("SELECT pg_sleep(0.5), 42 AS value");
    await waitSleep(independent, bystanderPID);
    const canceledAt = Date.now();
    const decision = await independent.query("SELECT pg_cancel_backend($1) AS canceled", [pid]);
    assert.equal(z.array(z.object({ canceled: z.literal(true) })).parse(decision.rows).length, 1);
    const sqlError: unknown = await canceled;
    assert.equal(errorCode(sqlError), "57014");
    assert(sqlError instanceof Error && sqlError.message.includes("user request"));
    assert(Date.now() - canceledAt < 2_000, "SQL cancellation must beat statement_timeout");
    assert.equal(
      z.array(z.object({ value: z.literal(42) })).parse((await otherQuery).rows).length,
      1,
    );
    assert.equal(
      z
        .array(z.object({ last_value: z.literal("2") }))
        .parse((await sleeping.query("SELECT last_value FROM cancel_attempt")).rows).length,
      1,
    );
    assert.equal(recordPG((await sleeping.query(pgQuery)).rows), pid);
    recordPG((await independent.query(pgQuery)).rows);
    nativeCancel = "unsupported-plaintext-rejected; sql-cancel-and-statement-timeout-qualified";
  } finally {
    await sleeping.end();
    await independent.end();
    await bystander.end();
    // cancel() opens only the raw cancellation socket; it never connects this
    // Client's SQL lifecycle. end() would wait for an already-consumed end event.
    cancelClient.connection.stream.destroy();
  }
  report("pg", kind);

  phase = "postgres js accounts options";
  // these are the real accounts adapter's max/prepare options. Postgres.js
  // accepts user/password/database and native ssl directly; no connection-level
  // channel_binding parameter or tnl wrapper belongs in this constructor.
  const client = postgres({
    ...options,
    ...credentials,
    max: 5,
    prepare: false,
    idle_timeout: 1,
    connect_timeout: 5,
  });
  try {
    const first = await client.reserve();
    const second = await client.reserve();
    const a = recordPG(await first.unsafe(pgQuery));
    const b = recordPG(await second.unsafe(pgQuery));
    assert.notEqual(a, b);
    first.release();
    second.release();
    const reused = recordPG(await client.unsafe(pgQuery));
    assert([a, b].includes(reused));
    await delay(1_400);
    const fresh = recordPG(await client.unsafe(pgQuery));
    assert(![a, b].includes(fresh));
    recordPG(await drizzleJS({ client }).execute(statement.raw(pgQuery)));
  } finally {
    await client.end({ timeout: 1 });
  }
  const queryJS = async (overrides: postgres.Options<{}>) => {
    const client = postgres({
      ...options,
      ...credentials,
      max: 1,
      prepare: false,
      connect_timeout: 5,
      ...overrides,
    });
    try {
      recordPG(await client.unsafe(pgQuery));
    } finally {
      await client.end({ timeout: 1 });
    }
  };
  phase = "postgres js tls negatives";
  await rejects(() => queryJS(invalidName), ["ERR_TLS_CERT_ALTNAME_INVALID"]);
  await rejects(
    () => queryJS({ ssl: { ...options.ssl, ca: wrongCA } }),
    ["SELF_SIGNED_CERT_IN_CHAIN"],
  );
  await rejects(() => queryJS({ password: "incorrect" }), ["28P01"]);
  phase = "postgres js selected connection lifetimes";
  await postgresLifetimes(runtime);
  phase = "postgres js native cancel limit";
  const cancelSQL = postgres({ ...options, ...credentials, max: 1, prepare: false });
  const observer = new pg.Client({ ...options, ...credentials });
  try {
    await observer.connect();
    const pid = recordPG(await cancelSQL.unsafe(pgQuery));
    await cancelSQL.unsafe("CREATE TEMP SEQUENCE cancel_attempt");
    await cancelSQL.unsafe("SET statement_timeout='1800ms'");
    const query = cancelSQL
      .unsafe("SELECT nextval('cancel_attempt'); SELECT pg_sleep(10)")
      .simple();
    const outcome = query.catch((error: unknown) => error);
    await waitSleep(observer, pid);
    query.cancel();
    await delay(100);
    await waitSleep(observer, pid);
    const error: unknown = await outcome;
    assert.equal(errorCode(error), "57014");
    assert(error instanceof Error && error.message.includes("statement timeout"));
    assert.equal(recordPG(await cancelSQL.unsafe(pgQuery)), pid);
    assert.equal(
      z
        .array(z.object({ last_value: z.literal("1") }))
        .parse(await cancelSQL.unsafe("SELECT last_value FROM cancel_attempt")).length,
      1,
    );
    recordPG((await observer.query(pgQuery)).rows);
    nativeCancel = "unsupported-unbound-tls-rejected; statement-timeout-qualified";
  } finally {
    await observer.end();
    await cancelSQL.end({ timeout: 1 });
  }
  report("postgres", kind);
}

async function waitSleep(observer: pg.Client, pid: number) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const result = await observer.query(
      "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep') AS sleeping",
      [pid],
    );
    if (z.array(z.object({ sleeping: z.boolean() })).parse(result.rows)[0]?.sleeping) return;
    await delay(10);
  }
  assert.fail("native query never reached PgSleep");
}

async function pgLifetimes(runtime: typeof tnl) {
  const expiring = new pg.Client({ ...(await runtime.connect("expiring")), ...credentials });
  const renewing = new pg.Client({ ...(await runtime.connect("renewing")), ...credentials });
  let expired = false;
  expiring.on("error", () => {
    expired = true;
  });
  try {
    await expiring.connect();
    await renewing.connect();
    recordPG((await expiring.query(pgQuery)).rows);
    const pid = recordPG((await renewing.query(pgQuery)).rows);
    await delay(1_600);
    assert(expired, "the original connector decision must expire an idle pg socket");
    await assert.rejects(() => expiring.query(pgQuery));
    assert.equal(recordPG((await renewing.query(pgQuery)).rows), pid);
    lifetimes += 2;
  } finally {
    await expiring.end();
    await renewing.end();
  }
}

async function postgresLifetimes(runtime: typeof tnl) {
  // reserve one physical connection so the driver's automatic reconnection cannot
  // turn an expired session into an apparently successful lifetime assertion.
  const client = postgres({
    ...(await runtime.connect("renewing")),
    ...credentials,
    max: 1,
    prepare: false,
  });
  try {
    const connection = await client.reserve();
    const pid = recordPG(await connection.unsafe(pgQuery));
    await delay(1_600);
    assert.equal(recordPG(await connection.unsafe(pgQuery)), pid);
    connection.release();
    lifetimes++;
  } finally {
    await client.end({ timeout: 1 });
  }
  const expiring = postgres({
    ...(await runtime.connect("expiring")),
    ...credentials,
    max: 1,
    prepare: false,
  });
  try {
    recordPG(await expiring.unsafe(pgQuery));
    await rejects(
      () => Promise.resolve(expiring.unsafe("SELECT pg_sleep(10)")),
      ["CONNECTION_CLOSED"],
    );
    lifetimes++;
  } finally {
    await expiring.end({ timeout: 1 });
  }
}

async function qualifyMySQL(runtime: typeof tnl, kind: string) {
  phase = "mysql2 settings";
  const options = { ...runtime.connect("database") };
  assert("stream" in options);
  assert.equal(options.host, options.ssl.servername);
  assert.equal(options.ssl.rejectUnauthorized, true);
  assert.equal(options.ssl.verifyIdentity, true);
  assert(!Object.isFrozen(options.ssl));
  assert.equal(Object.keys(options).includes("then"), false);
  const awaited = await runtime.connect("database");
  assert("stream" in awaited);
  assert.notEqual(awaited.ssl, options.ssl);
  assert.notEqual(awaited.stream, options.stream);
  const invalidName = { ...runtime.connect("wrong-name") };
  assert("stream" in invalidName);
  const query = async (overrides: mysql2.ConnectionOptions = {}) => {
    const client = await mysql2.createConnection({
      ...options,
      ...credentials,
      connectTimeout: 5_000,
      ...overrides,
    });
    try {
      const [rows] = await client.query(mysqlQuery);
      recordMySQL(rows);
      const [secure] = await client.query("SHOW SESSION STATUS LIKE 'Ssl_cipher'");
      const cipher = z
        .array(z.object({ Value: z.string().min(1) }))
        .length(1)
        .parse(secure);
      assert(cipher[0]);
      queries++;
    } finally {
      await client.end();
    }
  };
  phase = "mysql2 frozen ssl repro";
  await assert.rejects(() => query({ ssl: Object.freeze({ ...options.ssl }) }), TypeError);
  negatives++;
  phase = "mysql2 query and tls negatives";
  await query();
  // mysql2 replaces the Node certificate error code at its handshake boundary.
  await rejects(() => query(invalidName), ["HANDSHAKE_SSL_ERROR"]);
  await rejects(() => query({ ssl: { ...options.ssl, ca: wrongCA } }), ["HANDSHAKE_SSL_ERROR"]);
  await rejects(() => query({ password: "incorrect" }), ["ER_ACCESS_DENIED_ERROR"]);
  phase = "mysql2 pool";
  const pool = mysql2.createPool({
    ...options,
    ...credentials,
    connectionLimit: 2,
    maxIdle: 1,
    idleTimeout: 500,
    connectTimeout: 5_000,
  });
  try {
    const first = await pool.getConnection();
    const second = await pool.getConnection();
    const a = recordMySQL((await first.query(mysqlQuery))[0]);
    const b = recordMySQL((await second.query(mysqlQuery))[0]);
    assert.notEqual(a, b);
    first.release();
    second.release();
    const reused = recordMySQL((await pool.query(mysqlQuery))[0]);
    assert([a, b].includes(reused));
    // retain an idle pooled socket, then evict all idle sockets. a subsequent
    // connection must call the supplied stream factory again, not reuse a socket.
    await delay(1_600);
    const fresh = recordMySQL((await pool.query(mysqlQuery))[0]);
    assert(![a, b].includes(fresh));
    const orm = drizzleMySQL({ client: pool });
    recordMySQL((await orm.execute(statement.raw(mysqlQuery)))[0]);
  } finally {
    await pool.end();
  }
  phase = "mysql2 selected connection lifetimes";
  const expiring = await mysql2.createConnection({
    ...(await runtime.connect("expiring")),
    ...credentials,
  });
  const renewing = await mysql2.createConnection({
    ...(await runtime.connect("renewing")),
    ...credentials,
  });
  let expired = false;
  expiring.on("error", () => {
    expired = true;
  });
  try {
    recordMySQL((await expiring.query(mysqlQuery))[0]);
    const pid = recordMySQL((await renewing.query(mysqlQuery))[0]);
    await delay(1_600);
    assert(expired, "the original connector decision must expire an idle mysql2 socket");
    await assert.rejects(() => expiring.query(mysqlQuery));
    assert.equal(recordMySQL((await renewing.query(mysqlQuery))[0]), pid);
    lifetimes += 2;
  } finally {
    expiring.destroy();
    await renewing.end();
  }
  report("mysql2", kind);

  phase = "mysql unsupported auth and identity repro";
  // mysql 2.18.1 ignores stream, ssl.servername and verifyIdentity. its supported
  // options cannot separate dial address from verified identity. a loopback
  // override exposes its auth and hostname limits against a real TLS MySQL.
  const queryLegacy = async (port: number, user: string, ca = options.ssl.ca) => {
    const connection = mysql.createConnection({
      ...options,
      ...credentials,
      host: "127.0.0.1",
      port,
      user,
      ssl: { ...options.ssl, ca },
      connectTimeout: 5_000,
    });
    try {
      const rows = await new Promise<unknown>((resolve, reject) =>
        connection.query(mysqlQuery, (error, rows: unknown) =>
          error ? reject(error) : resolve(rows),
        ),
      );
      const row = z
        .array(z.object({ username: z.string().startsWith("tnl_legacy@"), pid: z.number() }))
        .length(1)
        .parse(rows)[0];
      assert(row);
      sessions.add(row.pid);
      queries++;
    } finally {
      connection.destroy();
    }
  };
  await rejects(() => queryLegacy(options.port, "tnl_client"), ["ER_NOT_SUPPORTED_AUTH_MODE"]);
  await queryLegacy(options.port, "tnl_legacy");
  await queryLegacy(invalidName.port, "tnl_legacy");
  await rejects(() => queryLegacy(options.port, "tnl_legacy", wrongCA), ["HANDSHAKE_SSL_ERROR"]);
  report("mysql", kind, "unsupported-auth-and-hostname-verification");
}

try {
  assert.equal(
    process.versions.node,
    "22.23.2",
    "use pinned Node for database driver qualification",
  );
  for (const [kind, runtime] of [
    ["esm", tnl],
    ["commonjs", commonjs.tnl],
  ] as const) {
    if (process.argv[2] === "postgres-drivers") await qualifyPostgres(runtime, kind);
    else if (process.argv[2] === "mysql-drivers") await qualifyMySQL(runtime, kind);
    else assert.fail("select postgres-drivers or mysql-drivers");
  }
} catch (error) {
  // only authored phases and bounded machine codes leave this fixture. never
  // print a driver error, SQL statement, account input, or subprocess diagnostic.
  const code = errorCode(error);
  process.stdout.write(
    JSON.stringify({
      phase,
      code: code && /^(?:[A-Z0-9_]{1,64}|sdk\.[a-z_]{1,64})$/.test(code) ? code : "CHECK_FAILED",
    }) + "\n",
  );
  process.exitCode = 1;
}
