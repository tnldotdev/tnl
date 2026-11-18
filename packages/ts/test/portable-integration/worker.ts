import { ioredis } from "@tnldotdev/tnl/adapters/ioredis";
import { pg } from "@tnldotdev/tnl/adapters/node-postgres";
import { postgres } from "@tnldotdev/tnl/adapters/postgres-js";
import { sql as query } from "drizzle-orm";
import { drizzle as pgDrizzle } from "drizzle-orm/node-postgres";
import { drizzle as postgresDrizzle } from "drizzle-orm/postgres-js";
import { PortableSmokeError, deployment, runPortableIsolation, runPortableSmoke } from "./smoke.ts";
import { check, fixtureSchema } from "./fixture.ts";
import { installFixtureHost } from "./host.ts";

interface Fetcher {
  fetch(request: Request): Promise<Response>;
}
interface Environment {
  CONTROL: Fetcher;
  RELAY0: Fetcher;
  RELAY1: Fetcher;
}
const nativeFetch = globalThis.fetch.bind(globalThis);
const hostRequests: string[] = [];

export default {
  async fetch(request: Request, environment: Environment): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") return new Response("ready");
    if (request.method === "GET" && url.pathname === "/platform") {
      const checks: Record<string, string> = {};
      for (const [name, options] of Object.entries({
        credentials: { credentials: "omit" },
        redirect: { redirect: "error" },
        body: { method: "POST", body: new Uint8Array([1]), signal: new AbortController().signal },
      } satisfies Record<string, RequestInit>)) {
        try {
          new Request("https://fixed-input.invalid/", options);
          checks[name] = "supported";
        } catch (error) {
          // all inputs above are fixed and contain no fixture data.
          checks[name] = error instanceof Error ? `${error.name}: ${error.message}` : "unsupported";
        }
      }
      return Response.json(checks);
    }
    if (request.method !== "POST") return new Response("POST required", { status: 405 });
    try {
      const fixture = fixtureSchema.parse(await request.json());
      installFixtureHost(fixture, async (input, init) => {
        const outgoing = new Request(input, init);
        const target = new URL(outgoing.url);
        try {
          const index = fixture.relays.findIndex((relay) => relay.address === target.host);
          const response = await (target.origin === fixture.control_url
            ? environment.CONTROL.fetch(outgoing)
            : index !== -1
              ? (index === 0 ? environment.RELAY0 : environment.RELAY1).fetch(outgoing)
              : nativeFetch(outgoing));
          hostRequests.push(`${outgoing.method} ${target.pathname}: ${response.status}`);
          if (hostRequests.length > 64) hostRequests.shift();
          return response;
        } catch {
          hostRequests.push(`${outgoing.method} ${target.pathname}: host fetch failed`);
          if (hostRequests.length > 64) hostRequests.shift();
          throw new Error("fixture host fetch failed");
        }
      });
      if (url.pathname === "/smoke") return Response.json(await runPortableSmoke(fixture));
      if (url.pathname === "/redis") {
        const app = deployment(fixture);
        try {
          const getRedis = app.client(
            "redis",
            ioredis({ password: fixture.redis_password, connectTimeout: 15_000 }),
          );
          const redis = await getRedis();
          const peer = redis.duplicate();
          const key = `tnl:${crypto.randomUUID()}`;
          const result = await redis.pipeline().set(key, "ready", "EX", 30).get(key).exec();
          check(result?.[0]?.[1] === "OK" && result[1]?.[1] === "ready", "Redis pipeline failed");
          check((await peer.get(key)) === "ready", "Redis duplicate missed the saved value");
          await getRedis.close();
          check(
            !redis.stream?.writable && !peer.stream?.writable,
            "Redis adapter retained a socket",
          );
          return Response.json({ redis: true });
        } catch (error) {
          throw new PortableSmokeError("redis-adapter", error);
        } finally {
          await app.close();
        }
      }
      if (url.pathname === "/pg") {
        const app = deployment(fixture);
        try {
          const getPool = app.client(
            "postgres",
            pg({ ...fixture.postgres, max: 1, connectionTimeoutMillis: 15_000 }),
          );
          const pool = await getPool();
          const session = await pool.connect();
          let backendPID: number | undefined;
          try {
            await session.query("BEGIN");
            const { rows } = await session.query<{ pid: number }>({
              name: "portable-adapter-pid",
              text: "SELECT pg_backend_pid() AS pid WHERE 1 = $1",
              values: [1],
            });
            await session.query("COMMIT");
            backendPID = rows[0]?.pid;
          } finally {
            session.release();
          }
          const db = pgDrizzle({ client: pool });
          const { rows } = await db.execute<{ answer: number }>(
            query`select ${41}::int + 1 as answer`,
          );
          check(rows[0]?.answer === 42, "Drizzle with pg returned the wrong result");
          await getPool.close();
          const getSql = app.client(
            "postgres",
            postgres({ ...fixture.postgres, max: 1, connect_timeout: 15 }),
          );
          const sql = await getSql();
          const [row] = await sql.begin(
            (tx) => tx<{ answer: number }[]>`select ${41}::int + 1 as answer`,
          );
          check(row?.answer === 42, "Postgres.js query returned the wrong result");
          const [result] = await postgresDrizzle({ client: sql }).execute<{ answer: number }>(
            query`select ${41}::int + 1 as answer`,
          );
          check(result?.answer === 42, "Drizzle with Postgres.js returned the wrong result");
          await getSql.close();
          return Response.json({ backendPID });
        } catch (error) {
          throw new PortableSmokeError("pg-adapter", error);
        } finally {
          await app.close();
        }
      }
      const role = url.searchParams.get("role");
      const run = url.searchParams.get("run");
      if (
        url.pathname === "/isolation" &&
        (role === "first" || role === "second") &&
        run !== null
      ) {
        return Response.json(await runPortableIsolation(fixture, role, run));
      }
      return new Response("unknown fixture operation", { status: 404 });
    } catch (error) {
      // fixture bodies contain credentials. do not include them or driver errors
      // in the HTTP reply; the runner reports the failing runtime/operation.
      const failures = error instanceof AggregateError ? error.errors : [error];
      const phases = failures.flatMap((failure: unknown) =>
        failure instanceof PortableSmokeError
          ? [{ phase: failure.phase, code: failure.code, detail: failure.detail }]
          : [],
      );
      return Response.json(
        { error: "portable SDK integration failed", failures: phases, network: [...hostRequests] },
        { status: 500 },
      );
    }
  },
};
