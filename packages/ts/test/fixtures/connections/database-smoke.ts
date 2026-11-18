import assert from "node:assert/strict";
import {
  deployment,
  connect,
  client as driverClient,
  type TnlClientFactory,
} from "@tnldotdev/tnl/node";
import { pg as pgAdapter } from "@tnldotdev/tnl/adapters/node-postgres";
import { postgres } from "@tnldotdev/tnl/adapters/postgres-js";
import { createInterface } from "node:readline";
import { sql as query } from "drizzle-orm";
import { drizzle as mysqlDrizzle } from "drizzle-orm/mysql2";
import { drizzle as pgDrizzle } from "drizzle-orm/node-postgres";
import { drizzle as postgresDrizzle } from "drizzle-orm/postgres-js";
import mysql from "mysql2/promise";
import pg from "pg";
import { checkPostgresORMs } from "./postgres-orm.ts";

const protocol = process.argv[2];
assert(protocol === "postgres" || protocol === "mysql");
const selectedDeployment = deployment("production", {
  project: "fixture/driver-fixture",
  services: { database: { protocol } },
});
const credentials = { user: "tnl_client", password: "testpass", database: "tnl_fixture" };
const input = createInterface({ input: process.stdin });
const lines = input[Symbol.asyncIterator]();

async function exercise<Client>(
  get: TnlClientFactory<Client>,
  pid: (client: Client) => Promise<number>,
  closed: Client[],
) {
  const first = await get();
  const original = await pid(first);
  for (const client of await Promise.all(Array.from({ length: 8 }, () => get())))
    assert.equal(client, first);
  assert.equal(await pid(first), original);
  assert.equal(closed.length, 0);
  console.log("binding-a");
  assert.equal((await lines.next()).value, "next");
  const second = await get();
  assert.notEqual(second, first);
  assert.notEqual(await pid(second), original);
  assert.equal(await pid(first), original);
  assert.equal(closed.length, 0);
  console.log("binding-b");
  assert.equal((await lines.next()).value, "next");
  assert.equal(await get(), first);
  assert.equal(await pid(first), original);
  await Promise.all([get.close(), get.close()]);
  assert.equal(closed.length, 2);
  assert(closed.includes(first) && closed.includes(second));
  await get.close();
  assert.equal(closed.length, 2);
  await assert.rejects(get(), { code: "sdk.client_closed" });
  await assert.rejects(pid(first));
  console.log("closed");
}

try {
  const options = await connect(selectedDeployment, "database");
  if (protocol === "postgres") {
    assert(!("stream" in options));
    assert.equal(options.ssl.rejectUnauthorized, true);
    const client = new pg.Client({ ...options, ...credentials, connectionTimeoutMillis: 5_000 });
    try {
      await client.connect();
      const result = await client.query(
        "SELECT current_user AS username, ssl AS secure FROM pg_stat_ssl WHERE pid=pg_backend_pid()",
      );
      assert.equal(result.rows[0]?.username, credentials.user);
      assert.equal(result.rows[0]?.secure, true);
    } finally {
      await client.end();
    }
    const create = postgres({ ...credentials, max: 1, connect_timeout: 5 });
    const sql = await create.create(options);
    try {
      const [row] = await sql.begin(
        (tx) => tx<{ answer: number }[]>`select ${41}::int + 1 as answer`,
      );
      assert.equal(row?.answer, 42);
      const [result] = await postgresDrizzle({ client: sql }).execute<{ answer: number }>(
        query`select ${41}::int + 1 as answer`,
      );
      assert.equal(result?.answer, 42);
    } finally {
      await create.close(sql);
    }
    const closed: pg.Pool[] = [];
    const adapter = pgAdapter({ ...credentials, max: 1, connectionTimeoutMillis: 5_000 });
    const get = driverClient(selectedDeployment, "database", {
      create(connection) {
        assert(!("stream" in connection));
        return adapter.create(connection);
      },
      async close(pool) {
        await adapter.close(pool);
        closed.push(pool);
      },
    });
    await checkPostgresORMs(await get(), assert);
    await exercise(
      get,
      async (pool) => {
        const db = pgDrizzle({ client: pool });
        const { rows } = await db.execute<{ answer: number }>(
          query`select ${41}::int + 1 as answer`,
        );
        assert.equal(rows[0]?.answer, 42);
        const result = await pool.query<{ pid: number; secure: boolean }>(
          "SELECT pg_backend_pid() AS pid, ssl AS secure FROM pg_stat_ssl WHERE pid=pg_backend_pid()",
        );
        assert.equal(result.rows[0]?.secure, true);
        const pid = result.rows[0]?.pid;
        assert(typeof pid === "number");
        return pid;
      },
      closed,
    );
  } else {
    assert("stream" in options);
    const { host, port, ssl, stream } = options;
    assert.equal(ssl.rejectUnauthorized, true);
    const client = await mysql.createConnection({
      ...credentials,
      host,
      port,
      ssl: { ...ssl },
      stream,
      connectTimeout: 5_000,
    });
    try {
      const [rows] = await client.query<mysql.RowDataPacket[]>("SELECT CURRENT_USER() AS username");
      assert(typeof rows[0]?.username === "string" && rows[0].username.startsWith("tnl_client@"));
      const [status] = await client.query<mysql.RowDataPacket[]>(
        "SHOW SESSION STATUS LIKE 'Ssl_cipher'",
      );
      assert(status[0]?.Value);
    } finally {
      await client.end();
    }
    const closed: mysql.Pool[] = [];
    const get = driverClient(selectedDeployment, "database", {
      create(connection) {
        assert("stream" in connection);
        const { host, port, ssl, stream } = connection;
        return mysql.createPool({
          ...credentials,
          host,
          port,
          ssl: { ...ssl },
          stream,
          connectionLimit: 1,
          connectTimeout: 5_000,
        });
      },
      async close(pool) {
        await pool.end();
        closed.push(pool);
      },
    });
    await exercise(
      get,
      async (pool) => {
        const [result] = await mysqlDrizzle({ client: pool }).execute(
          query`select ${41} + 1 as answer`,
        );
        assert(Array.isArray(result));
        assert.equal(result[0]?.answer, 42);
        const [rows] = await pool.query<mysql.RowDataPacket[]>("SELECT CONNECTION_ID() AS pid");
        const pid: unknown = rows[0]?.pid;
        assert(typeof pid === "number");
        return pid;
      },
      closed,
    );
  }
} finally {
  input.close();
  await selectedDeployment.close();
}
