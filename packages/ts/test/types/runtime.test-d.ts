import { tnl, type TnlConnectionRegistry } from "@tnldotdev/tnl";
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

test("ungenerated connections require narrowing and never become any", () => {
  expectTypeOf(tnl.port).toEqualTypeOf<number>();
  expectTypeOf(tnl.dev).toEqualTypeOf<boolean>();
  const connection = tnl.connect("any-service");
  expectTypeOf(connection).not.toBeAny();
  // @ts-expect-error an ungenerated service has a protocol union.
  void connection.ssl;
  assert("ssl" in connection);
  assertType<string>(connection.host);
  expectTypeOf(connection.ssl.rejectUnauthorized).toEqualTypeOf<true>();
  // @ts-expect-error narrowing a SQL connection does not add HTTP settings.
  void connection.fetch;
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
