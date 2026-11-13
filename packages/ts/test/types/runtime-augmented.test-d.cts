import type * as SDK from "@tnldotdev/tnl";
import type * as Vitest from "vitest";
declare const test: typeof Vitest.test;
declare const expectTypeOf: typeof Vitest.expectTypeOf;

declare const tnlModule: typeof SDK;

test("CommonJS keeps deployment driver settings typed", async () => {
  const deployment = tnlModule
    .createClient({
      project: "team/project",
      token: "private",
      services: { api: { protocol: "http" }, db: { protocol: "postgres" } },
    })
    .deployment("production");
  const inventory = await deployment.connect("api");
  expectTypeOf(inventory.fetch("/stock")).toEqualTypeOf<Promise<Response>>();
  // @ts-expect-error CommonJS HTTP options have no SQL connection properties.
  void inventory.ssl;

  const database = await deployment.connect("db");
  expectTypeOf(database.host).toEqualTypeOf<"127.0.0.1">();
  database.ssl.servername satisfies string;
  expectTypeOf(deployment.connect("db")).toEqualTypeOf<
    Promise<SDK.TnlConnectionRegistry["postgres"]>
  >();
  ({ ...database, user: "app", database: "app" }) satisfies import("pg").PoolConfig;
  // @ts-expect-error CommonJS uses the same exact generated service registry.
  deployment.connect("missing");
  // @ts-expect-error CommonJS SQL settings have no HTTP fetch method.
  void database.fetch;
  // @ts-expect-error CommonJS settings are read-only too.
  database.port = 5432;
});
