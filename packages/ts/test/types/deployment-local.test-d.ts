import {
  deployment,
  connect,
  client,
  type LocalConnectionRegistry,
  type LocalPostgresConnection,
} from "@tnldotdev/tnl/node";
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
  const local = deployment("local", { services });
  const database = await connect(local, "db");
  assertType<PoolConfig>({ ...database, user: "local", database: "orders" });
  expectTypeOf(database).toEqualTypeOf<LocalPostgresConnection>();
  client(local, "db", { create: (connection) => ({ port: connection.port }), close: () => {} });
  expectTypeOf(await connect(local, "app")).toEqualTypeOf<LocalConnectionRegistry["http"]>();
  expectTypeOf(await connect(local, "mysql")).toEqualTypeOf<LocalConnectionRegistry["mysql"]>();
  expectTypeOf(await connect(local, "cache")).toEqualTypeOf<LocalConnectionRegistry["tcp"]>();
  expectTypeOf(await connect(local, "cluster")).toEqualTypeOf<
    LocalConnectionRegistry["kubernetes"]
  >();
  client(local, "app", { create: ({ fetch }) => fetch, close: () => {} });
  // @ts-expect-error generated service names are exact.
  await connect(local, "missing");
  const remote = deployment("production", { project: "acme/shop", token: "private", services });
  assertType<string>((await connect(remote, "app")).url);
  await local.close();
});
