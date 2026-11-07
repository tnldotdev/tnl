import assert from "node:assert/strict";
import { tnl, type TnlClientFactory } from "@tnldotdev/tnl";
import { createInterface } from "node:readline";
import mysql from "mysql2/promise";
import pg from "pg";

// run with a prepared owner and the disposable TLS database provider.
const protocol = process.argv[2];
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

if (protocol === "postgres") {
  const options = await tnl.connect("database");
  assert("ssl" in options && !("stream" in options));
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
  const closed: pg.Pool[] = [];
  const get = tnl.client("database", {
    create(connection) {
      assert("ssl" in connection && !("stream" in connection));
      return new pg.Pool({ ...connection, ...credentials, max: 1, connectionTimeoutMillis: 5_000 });
    },
    async close(pool) {
      await pool.end();
      closed.push(pool);
    },
  });
  try {
    await exercise(
      get,
      async (pool) => {
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
  } finally {
    await get.close();
  }
} else if (protocol === "mysql") {
  const options = await tnl.connect("database");
  assert("ssl" in options && "stream" in options);
  assert.equal(options.ssl.rejectUnauthorized, true);
  const client = await mysql.createConnection({
    ...options,
    ...credentials,
    connectTimeout: 5_000,
  });
  try {
    const [rows] = await client.query("SELECT CURRENT_USER() AS username");
    assert(Array.isArray(rows) && rows.length === 1);
    const row: unknown = rows[0];
    assert(
      typeof row === "object" &&
        row !== null &&
        "username" in row &&
        typeof row.username === "string" &&
        row.username.startsWith("tnl_client@"),
    );
    const [status] = await client.query("SHOW SESSION STATUS LIKE 'Ssl_cipher'");
    assert(Array.isArray(status) && status.length === 1);
    assert(
      typeof status[0] === "object" &&
        status[0] !== null &&
        "Value" in status[0] &&
        status[0].Value,
    );
  } finally {
    await client.end();
  }
  const closed: mysql.Pool[] = [];
  const get = tnl.client("database", {
    create(connection) {
      assert("ssl" in connection && "stream" in connection);
      return mysql.createPool({
        ...connection,
        ...credentials,
        connectionLimit: 1,
        connectTimeout: 5_000,
      });
    },
    async close(pool) {
      await pool.end();
      closed.push(pool);
    },
  });
  try {
    await exercise(
      get,
      async (pool) => {
        const [rows] = await pool.query<mysql.RowDataPacket[]>("SELECT CONNECTION_ID() AS pid");
        const pid: unknown = rows[0]?.pid;
        assert.equal(typeof pid, "number");
        assert(typeof pid === "number");
        return pid;
      },
      closed,
    );
  } finally {
    await get.close();
  }
} else {
  assert.fail("select postgres or mysql");
}
input.close();
