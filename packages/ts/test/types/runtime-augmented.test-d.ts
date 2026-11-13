import {
  createClient,
  tnl,
  type TnlProjectFromConfig,
  type TnlConnectionRegistry,
} from "@tnldotdev/tnl";
import { defineConfig } from "@tnldotdev/tnl/config";
import { assert, assertType, expectTypeOf, test } from "vitest";
import { Pool } from "pg";

const configuration = defineConfig(({ worktree }) => ({
  services: {
    api: { protocol: "http" },
    db: { protocol: "postgres" },
    mysql: { protocol: "mysql" },
    cluster: { protocol: "kubernetes" },
    ...(worktree.label.checkout
      ? {
          worker: {
            protocol: "tcp" as const,
          },
        }
      : {}),
  },
  deployments: {
    production: {
      targets: {
        api: { address: "api.internal:3000" },
        db: { type: "rds", instance: "orders", region: "us-east-1" },
        mysql: { address: "db.internal:3306" },
        cluster: { type: "eks", cluster: "development", region: "us-east-1" },
      },
    },
  },
}));

declare module "@tnldotdev/tnl" {
  interface TnlProjectConfig {
    config: typeof configuration;
  }
}

const deployment = createClient({
  project: "team/project",
  token: "private",
  services: {
    api: { protocol: "http" },
    db: { protocol: "postgres" },
    mysql: { protocol: "mysql" },
    cluster: { protocol: "kubernetes" },
  },
}).deployment("production");

test("augmentation preserves exact service names and optional factory entries", () => {
  defineConfig(({ worktree }) => {
    expectTypeOf(worktree.label.project).toEqualTypeOf<string>();
    expectTypeOf(worktree.label.checkout).toEqualTypeOf<string | undefined>();
    return {};
  });
  expectTypeOf(tnl.services.api.url).toEqualTypeOf<`https://${string}`>();
  expectTypeOf(tnl.services.db.protocol).toEqualTypeOf<"postgres">();
  expectTypeOf(tnl.services.db.hostname).toEqualTypeOf<string>();
  expectTypeOf(tnl.services.db.port).toEqualTypeOf<number>();
  expectTypeOf(tnl.services.db.public).toEqualTypeOf<boolean>();
  expectTypeOf(tnl.services.db.namespace).toEqualTypeOf<string>();
  expectTypeOf(tnl.services.cluster.url).toEqualTypeOf<`https://${string}`>();
  // @ts-expect-error optional factory services stay optional in every checkout.
  void tnl.services.worker.protocol;
  assert(tnl.services.worker !== undefined);
  expectTypeOf(tnl.services.worker.protocol).toEqualTypeOf<"tcp">();
  // @ts-expect-error service names are exact.
  void tnl.services.missing;
  // @ts-expect-error database metadata has no URL.
  void tnl.services.db.url;
  // @ts-expect-error service metadata is exposed directly, without a wrapper.
  void tnl.services.db.metadata;
  // @ts-expect-error unknown connection name.
  deployment.connect("missing");
});
test("deployment connections expose protocol-owned readonly driver settings", async () => {
  const db = await deployment.connect("db");
  expectTypeOf(db.host).toEqualTypeOf<"127.0.0.1">();
  expectTypeOf(db.port).toEqualTypeOf<number>();
  expectTypeOf(db.ssl.rejectUnauthorized).toEqualTypeOf<true>();
  expectTypeOf(db.ssl.servername).toEqualTypeOf<string>();
  expectTypeOf(db.ssl.ca).toEqualTypeOf<string | undefined>();
  // @ts-expect-error the connector owns application certificates.
  void db.ssl.cert;
  // @ts-expect-error the connector owns application keys.
  void db.ssl.key;
  // @ts-expect-error native settings are read-only.
  db.port = 5432;
  // @ts-expect-error TLS verification is read-only.
  db.ssl.servername = "other.example";
  const mysql = await deployment.connect("mysql");
  assertType<string>(mysql.host);
  expectTypeOf(mysql.ssl.servername).toEqualTypeOf<string>();
  expectTypeOf(mysql.ssl.rejectUnauthorized).toEqualTypeOf<true>();
  expectTypeOf(mysql.ssl.verifyIdentity).toEqualTypeOf<true>();
  ({
    ...mysql,
    user: "app",
    password: "application-owned",
    database: "app",
  }) satisfies import("mysql2").ConnectionOptions;
  const cluster = await deployment.connect("cluster");
  expectTypeOf(cluster.server).toEqualTypeOf<`https://${string}`>();
  expectTypeOf(cluster.kubeconfig).toEqualTypeOf<string>();
  expectTypeOf(cluster.context).toEqualTypeOf<string>();
  const api = await deployment.connect("api");
  assertType<typeof fetch>(api.fetch);
  expectTypeOf(api.fetch("/stock")).toEqualTypeOf<Promise<Response>>();
  // @ts-expect-error HTTP options are read-only.
  api.url = "https://other.example";
  // @ts-expect-error HTTP options never expose a local driver port.
  void api.port;
  // @ts-expect-error HTTP clients do not expose TLS keys as metadata.
  void api.ssl;
  // @ts-expect-error SQL account credentials belong to the application.
  void db.password;
  const privateTLS = { servername: "db.example", rejectUnauthorized: true } as const;
  ({ host: "127.0.0.1", port: 5432, ssl: privateTLS }) satisfies TnlConnectionRegistry["postgres"];
  ({
    host: "db.example",
    port: 3306,
    ssl: { ...privateTLS, verifyIdentity: true },
    stream: mysql.stream,
  }) satisfies TnlConnectionRegistry["mysql"];
});

test("client factories infer ordinary clients and exact protocol callback settings", async () => {
  const getDb = deployment.client("db", {
    create(connection) {
      expectTypeOf(connection).toEqualTypeOf<TnlConnectionRegistry["postgres"]>();
      return new Pool({
        ...connection,
        user: "app",
        password: "application-owned",
        database: "app",
      });
    },
    close(client) {
      expectTypeOf(client).toEqualTypeOf<Pool>();
      return client.end();
    },
  });
  expectTypeOf(getDb()).toEqualTypeOf<Promise<Pool>>();
  expectTypeOf(await getDb()).toEqualTypeOf<Pool>();
  expectTypeOf(getDb.close()).toEqualTypeOf<Promise<void>>();
  const getAsync = deployment.client("db", {
    async create(connection) {
      return new Pool({ ...connection, user: "app", database: "app" });
    },
    close(client) {
      expectTypeOf(client).toEqualTypeOf<Pool>();
      return client.end();
    },
  });
  expectTypeOf(getAsync()).toEqualTypeOf<Promise<Pool>>();
  // @ts-expect-error factory service names come from the generated project.
  deployment.client("missing", { create: () => ({}), close: () => {} });
});

type Union = TnlProjectFromConfig<{
  services: { choice: { protocol: "postgres" } | { protocol: "mysql" } };
}>;
declare const union: Union;
test("a service protocol union remains a union", () => {
  expectTypeOf(union.services.choice.protocol).toEqualTypeOf<"postgres" | "mysql">();
});

test("connection settings compose with ordinary driver options", async () => {
  const settings = await deployment.connect("db");
  expectTypeOf(settings.host).toEqualTypeOf<"127.0.0.1">();
  ({ ...settings, user: "app", database: "app" }) satisfies import("pg").PoolConfig;
  const plain = { ...settings };
  // @ts-expect-error resolved driver settings are not preparation handles.
  void plain.then;
  const plainAwaited = await plain;
  expectTypeOf(plainAwaited.port).toEqualTypeOf<number>();
  // @ts-expect-error awaiting settings does not turn them into a handle.
  void plainAwaited.then;
  // @ts-expect-error metadata is read-only.
  tnl.services.db.port = 5432;
});

type Optional = TnlProjectFromConfig<{
  services: { database: { protocol: "postgres" } | undefined };
  aliases: { dashboard: { service: "api" } | undefined };
  webhooks: { events?: { service: "api"; path: "/events"; methods: readonly ["POST"] } };
}>;
declare const optional: Optional;
test("optional metadata needs assertions before use and remains deeply readonly", () => {
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
  // @ts-expect-error nested metadata is read-only.
  optional.webhooks.events.methods[0] = "POST";
});
