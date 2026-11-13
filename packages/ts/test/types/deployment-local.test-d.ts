import {
  createClient,
  type LocalConnectionRegistry,
  type LocalPostgresConnection,
} from "@tnldotdev/tnl";
import { assertType, expectTypeOf, test } from "vitest";
import type { PoolConfig } from "pg";

const services = Object.freeze({
  db: Object.freeze({ protocol: "postgres" as const }),
  app: Object.freeze({ protocol: "http" as const }),
  mysql: Object.freeze({ protocol: "mysql" as const }),
  cache: Object.freeze({ protocol: "tcp" as const }),
  cluster: Object.freeze({ protocol: "kubernetes" as const }),
});

test("local service names and protocol-specific driver settings are inferred", async () => {
  const local = createClient({ services }).deployment("local");
  const database = await local.connect("db");
  assertType<PoolConfig>({ ...database, user: "local", database: "orders" });
  expectTypeOf(database).toEqualTypeOf<LocalPostgresConnection>();
  local.client("db", { create: (connection) => ({ port: connection.port }), close: () => {} });
  expectTypeOf(await local.connect("app")).toEqualTypeOf<LocalConnectionRegistry["http"]>();
  expectTypeOf(await local.connect("mysql")).toEqualTypeOf<LocalConnectionRegistry["mysql"]>();
  expectTypeOf(await local.connect("cache")).toEqualTypeOf<LocalConnectionRegistry["tcp"]>();
  expectTypeOf(await local.connect("cluster")).toEqualTypeOf<
    LocalConnectionRegistry["kubernetes"]
  >();
  local.client("app", { create: ({ fetch }) => fetch, close: () => {} });
  // @ts-expect-error generated service names are exact.
  await local.connect("missing");
  const remote = createClient({ project: "acme/shop", token: "private", services }).deployment(
    "production",
  );
  assertType<string>((await remote.connect("app")).url);
  await local.close();
});
