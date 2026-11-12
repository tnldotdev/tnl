import type * as SDK from "@tnldotdev/tnl";
import type * as Selected from "../../src/internal/connector/selected_client.js";
import type * as Vitest from "vitest";
declare const test: typeof Vitest.test;
declare const expectTypeOf: typeof Vitest.expectTypeOf;
declare const create: typeof Selected.clientFromSelection;
declare const owner: Selected.ServiceSelection<Selected.ResolvedService>;

const client = create(
  Object.freeze({
    api: Object.freeze({ protocol: "http" }),
    db: Object.freeze({ protocol: "postgres" }),
  }),
  owner,
);

test("CommonJS selected clients use the same runtime-bound names and protocol settings", async () => {
  const api = await client.connect("api");
  expectTypeOf(api.fetch("/stock")).toEqualTypeOf<Promise<Response>>();
  const db = await client.connect("db");
  expectTypeOf(db).toEqualTypeOf<SDK.TnlConnectionRegistry["postgres"]>();
  ({ ...db, user: "app", database: "app" }) satisfies import("pg").PoolConfig;
  // @ts-expect-error the build facts do not declare this service.
  client.connect("missing");
  // @ts-expect-error SQL settings have no HTTP operation.
  void db.fetch;
});
