import { createClient, type LocalPostgresConnection } from "@tnldotdev/tnl";
import { assertType, expectTypeOf, test } from "vitest";
import type { PoolConfig } from "pg";

const services = Object.freeze({
  db: Object.freeze({ protocol: "postgres" as const }),
  app: Object.freeze({ protocol: "http" as const }),
});

test("local service names and ordinary PostgreSQL settings are inferred", async () => {
  const local = createClient({ services }).deployment("local");
  const database = await local.connect("db");
  assertType<PoolConfig>({ ...database, user: "local", database: "orders" });
  expectTypeOf(database).toEqualTypeOf<LocalPostgresConnection>();
  local.client("db", { create: (connection) => ({ port: connection.port }), close: () => {} });
  // @ts-expect-error generated service names are exact.
  await local.connect("missing");
  const remote = createClient({ project: "acme/shop", token: "private", services }).deployment(
    "production",
  );
  assertType<string>((await remote.connect("app")).url);
  await local.close();
});
