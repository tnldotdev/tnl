import { createClient, tnl, type TnlConnectionRegistry } from "@tnldotdev/tnl";
import { assert, assertType, expectTypeOf, test } from "vitest";
// @ts-expect-error there is no separate server entrypoint.
import type * as RemovedServer from "@tnldotdev/tnl/server";

declare const database: TnlConnectionRegistry["postgres"];
declare const mysql: TnlConnectionRegistry["mysql"];

test("SQL settings compose with application-owned credentials in real drivers", () => {
  const credentials = { user: "app", database: "app", password: "application-owned" };
  assertType<import("pg").PoolConfig>({ ...database, ...credentials });
  assertType<import("drizzle-kit").Config>({
    dialect: "postgresql",
    dbCredentials: { ...database, ...credentials },
  });
  assertType<import("postgres").Options<{}>>({
    ...database,
    ...credentials,
    max: 5,
    prepare: false,
  });
  assertType<import("mysql2").ConnectionOptions>({ ...mysql, ...credentials });
});

test("connections require declared service facts", () => {
  expectTypeOf(tnl.port).toEqualTypeOf<number>();
  expectTypeOf(tnl.dev).toEqualTypeOf<boolean>();
  const deployment = createClient({ project: "team/project", token: "private" }).deployment(
    "production",
  );
  // @ts-expect-error service names must come from portable service facts.
  deployment.connect("any-service");
});

test("ungenerated metadata stays readonly, optional, and browser-safe", () => {
  const service = tnl.services.anyService;
  // @ts-expect-error ungenerated metadata is read-only too.
  tnl.services.anyService = undefined;
  assert(service !== undefined);
  expectTypeOf(service.hostname).toEqualTypeOf<string>();
  expectTypeOf(service.port).toEqualTypeOf<number>();
  expectTypeOf(service.public).toEqualTypeOf<boolean>();
  // @ts-expect-error browser-safe metadata never contains native TLS keys.
  void service.ssl;
  assert(service.protocol === "http" || service.protocol === "kubernetes");
  expectTypeOf(service.url).toEqualTypeOf<`https://${string}`>();
  expectTypeOf<typeof RemovedServer>().toBeAny();
});
