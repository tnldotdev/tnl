import { Pool } from "pg";
import { assert, assertType, expectTypeOf, test } from "vitest";
import {
  tnl,
  type TnlClientFactory,
  type TnlConnectionHandle,
  type TnlConnectionRegistry,
  type TnlProjectFromConfig,
  type TnlResolvedConfig,
} from "@tnldotdev/tnl";
import { defineConfig } from "@tnldotdev/tnl/config";

type Settings = TnlConnectionRegistry[keyof TnlConnectionRegistry];

test("local client factories infer ordinary sync and async client results", async () => {
  const getDb = tnl.client("db", {
    create(connection) {
      expectTypeOf(connection).toEqualTypeOf<Settings>();
      if (!("ssl" in connection)) throw new Error("SQL settings required");
      return new Pool({ ...connection, user: "app", database: "app" });
    },
    close(client) {
      expectTypeOf(client).toEqualTypeOf<Pool>();
      return client.end();
    },
  });
  expectTypeOf(getDb).toEqualTypeOf<TnlClientFactory<Pool>>();
  expectTypeOf(getDb()).toEqualTypeOf<Promise<Pool>>();
  expectTypeOf(await getDb()).toEqualTypeOf<Pool>();
  expectTypeOf(getDb.close()).toEqualTypeOf<Promise<void>>();

  const getAsync = tnl.client("db", {
    async create(connection) {
      expectTypeOf(connection).toEqualTypeOf<Settings>();
      if (!("ssl" in connection)) throw new Error("SQL settings required");
      return new Pool({ ...connection, user: "app", database: "app" });
    },
    close(client) {
      expectTypeOf(client).toEqualTypeOf<Pool>();
      return client.end();
    },
  });
  expectTypeOf(getAsync()).toEqualTypeOf<Promise<Pool>>();
});

declare const immediate: TnlConnectionHandle<TnlConnectionRegistry["postgres"]>;

test("spreading an awaitable handle copies driver settings but not then", async () => {
  assertType<PromiseLike<TnlConnectionRegistry["postgres"]>>(immediate);
  ({ ...immediate, user: "app", database: "app" }) satisfies import("pg").PoolConfig;
  const plain = { ...immediate };
  expectTypeOf(plain.host).toEqualTypeOf<"127.0.0.1">();
  expectTypeOf(plain.ssl.rejectUnauthorized).toEqualTypeOf<true>();
  // @ts-expect-error the non-enumerable preparation method is not copied by spread.
  void plain.then;
  const awaited = await plain;
  expectTypeOf(awaited.port).toEqualTypeOf<number>();
  // @ts-expect-error awaiting plain settings does not restore the preparation handle.
  void awaited.then;
});

const configuration = defineConfig(({ worktree }) => {
  expectTypeOf(worktree.label.project).toEqualTypeOf<string>();
  expectTypeOf(worktree.label.checkout).toEqualTypeOf<string | undefined>();
  return {
    services: {
      api: { protocol: "http", publicURL: {} },
      db: { protocol: "postgres", target: { type: "address", address: "db.internal:5432" } },
      ...(worktree.label.checkout
        ? {
            worker: {
              protocol: "tcp" as const,
              target: { type: "address" as const, address: "worker.internal:9000" },
            },
          }
        : {}),
    },
  };
});

declare const project: TnlProjectFromConfig<TnlResolvedConfig<typeof configuration>>;

test("pure configuration projection preserves exact names and optional factory services", () => {
  expectTypeOf(project.services.api.url).toEqualTypeOf<`https://${string}`>();
  expectTypeOf(project.services.db.protocol).toEqualTypeOf<"postgres">();
  expectTypeOf(project.services.db.hostname).toEqualTypeOf<string>();
  expectTypeOf(project.services.db.port).toEqualTypeOf<number>();
  expectTypeOf(project.services.db.public).toEqualTypeOf<boolean>();
  expectTypeOf(project.services.db.namespace).toEqualTypeOf<string>();
  // @ts-expect-error optional factory services stay optional.
  void project.services.worker.protocol;
  assert(project.services.worker !== undefined);
  expectTypeOf(project.services.worker.protocol).toEqualTypeOf<"tcp">();
  // @ts-expect-error this pure projection has exact service names.
  void project.services.missing;
  // @ts-expect-error database metadata does not have an HTTP URL.
  void project.services.db.url;
  // @ts-expect-error browser-safe metadata has no native connection credentials.
  void project.services.db.ssl;
  // @ts-expect-error projected service metadata is readonly.
  project.services.db.port = 5432;
});

type Union = TnlProjectFromConfig<{
  services: { choice: { protocol: "postgres" } | { protocol: "mysql" } };
}>;
declare const union: Union;

test("pure service projections preserve protocol unions", () => {
  expectTypeOf(union.services.choice.protocol).toEqualTypeOf<"postgres" | "mysql">();
});

type Optional = TnlProjectFromConfig<{
  services: { database: { protocol: "postgres" } | undefined };
  aliases: { dashboard: { service: "api" } | undefined };
  webhooks: { events?: { service: "api"; path: "/events"; methods: readonly ["POST"] } };
}>;
declare const optional: Optional;

test("optional projections require narrowing and keep nested values readonly", () => {
  // @ts-expect-error an explicitly undefined service stays optional.
  void optional.services.database.protocol;
  assert(optional.services.database !== undefined);
  expectTypeOf(optional.services.database.protocol).toEqualTypeOf<"postgres">();
  // @ts-expect-error an explicitly undefined origin stays optional.
  void optional.aliases.dashboard.url;
  assert(optional.aliases.dashboard !== undefined);
  expectTypeOf(optional.aliases.dashboard.service).toEqualTypeOf<"api">();
  assert(optional.webhooks.events !== undefined);
  expectTypeOf(optional.webhooks.events.methods).toEqualTypeOf<readonly ["POST"]>();
  // @ts-expect-error nested projected metadata is readonly.
  optional.webhooks.events.methods[0] = "POST";
});
