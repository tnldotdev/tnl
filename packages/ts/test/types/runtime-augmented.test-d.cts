import type * as SDK from "@tnldotdev/tnl/node";
import type * as Vitest from "vitest";
declare const test: typeof Vitest.test;
declare const expectTypeOf: typeof Vitest.expectTypeOf;

declare const tnlModule: typeof SDK;

test("CommonJS keeps deployment driver settings typed", async () => {
  const deployment = tnlModule.deployment("production", {
    project: "team/project",
    token: "private",
    services: { api: { protocol: "http" }, db: { protocol: "postgres" } },
  });
  const inventory = await tnlModule.connect(deployment, "api");
  expectTypeOf(inventory.fetch("/stock")).toEqualTypeOf<Promise<Response>>();
  // @ts-expect-error CommonJS HTTP options have no SQL connection properties.
  void inventory.ssl;

  const database = await tnlModule.connect(deployment, "db");
  expectTypeOf(database.host).toEqualTypeOf<"127.0.0.1">();
  database.ssl.servername satisfies string;
  expectTypeOf(tnlModule.connect(deployment, "db")).toEqualTypeOf<
    Promise<SDK.TnlConnectionRegistry["postgres"]>
  >();
  ({ ...database, user: "app", database: "app" }) satisfies import("pg").PoolConfig;
  // @ts-expect-error CommonJS uses the same exact generated service registry.
  tnlModule.connect(deployment, "missing");
  // @ts-expect-error CommonJS SQL settings have no HTTP fetch method.
  void database.fetch;
  // @ts-expect-error CommonJS settings are read-only too.
  database.port = 5432;
});
