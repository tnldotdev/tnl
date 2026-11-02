import assert from "node:assert/strict";
import { tnl } from "@tnldotdev/tnl";
import mysql from "mysql2/promise";
import pg from "pg";

// run with a prepared owner and the disposable TLS database provider.
const protocol = process.argv[2];
const credentials = { user: "tnl_client", password: "testpass", database: "tnl_fixture" };
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
} else {
  assert.fail("select postgres or mysql");
}
