import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { defineEventHandler, getQuery, setResponseStatus } from "h3";
import pg from "pg";
import { tnl, TnlError } from "@tnldotdev/tnl";

const instance = randomUUID();
let calls = 0;
let active = 0;
let peak = 0;

export default defineEventHandler(async (event) => {
  const call = ++calls;
  peak = Math.max(peak, ++active);
  try {
    const { protocol } = getQuery(event);
    const http = async () => {
      const connection = await tnl.connect("api");
      assert("fetch" in connection);
      const response = await connection.fetch("/answer", {
        headers: { authorization: "Bearer application-only" },
        signal: AbortSignal.timeout(10_000),
      });
      assert.equal(response.status, 200);
      assert.equal(await response.text(), "artifact HTTP target");
    };
    const postgres = async () => {
      const connection = await tnl.connect("database");
      assert("ssl" in connection && "host" in connection);
      assert.equal(connection.host, "127.0.0.1");
      assert.equal(connection.ssl.rejectUnauthorized, true);
      assert.notEqual(connection.ssl.servername, "localhost");
      const client = new pg.Client({
        ...connection,
        // no database URL or target address is available to the function;
        // PGHOST/PGPORT are deliberately unusable in the invocation environment.
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        connectionTimeoutMillis: 10_000,
        query_timeout: 10_000,
      });
      try {
        await client.connect();
        const result = await client.query<{ answer: number }>("select $1::integer as answer", [
          call,
        ]);
        assert.equal(result.rows[0]?.answer, call);
      } finally {
        await client.end();
      }
    };
    if (protocol === "prepare") await Promise.all([tnl.connect("api"), tnl.connect("database")]);
    else if (protocol === "both") await Promise.all([http(), postgres()]);
    else if (protocol === "http") await http();
    else {
      assert.equal(protocol, "postgres");
      await postgres();
    }
    return { ok: true, instance, call, peak };
  } catch (error) {
    setResponseStatus(event, 503);
    return {
      ok: false,
      code: error instanceof TnlError ? error.code : "fixture.unexpected",
      instance,
      call,
      peak,
    };
  } finally {
    active--;
  }
});
