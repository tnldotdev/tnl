import { tnl, type TnlProjectFromConfig, type TnlConnectionRegistry } from "@tnldotdev/tnl";
import { defineConfig } from "@tnldotdev/tnl/config";

const configuration = defineConfig(({ worktree }) => ({
  services: {
    api: { protocol: "http", publicURL: {} },
    db: { protocol: "postgres", target: { type: "rds", instance: "orders", region: "us-east-1" } },
    mysql: { protocol: "mysql", target: { type: "address", address: "db.internal:3306" } },
    cluster: {
      protocol: "kubernetes",
      target: { type: "eks", cluster: "development", region: "us-east-1" },
    },
    ...(worktree.label.checkout
      ? {
          worker: {
            protocol: "tcp" as const,
            target: { type: "address" as const, address: "worker:9000" },
          },
        }
      : {}),
  },
}));

declare module "@tnldotdev/tnl" {
  interface TnlProjectConfig {
    config: typeof configuration;
  }
}

defineConfig(({ worktree }) => {
  worktree.label.project satisfies string;
  worktree.label.checkout satisfies string | undefined;
  return {};
});
tnl.services.api.url satisfies `https://${string}`;
tnl.services.db.protocol satisfies "postgres";
tnl.services.db.hostname satisfies string;
tnl.services.db.port satisfies number;
tnl.services.db.public satisfies boolean;
tnl.services.cluster.url satisfies `https://${string}`;
// @ts-expect-error optional factory services stay optional in every checkout.
void tnl.services.worker.protocol;
if (tnl.services.worker) tnl.services.worker.protocol satisfies "tcp";
// @ts-expect-error service names are exact.
void tnl.services.missing;
// @ts-expect-error database metadata has no URL.
void tnl.services.db.url;
// @ts-expect-error service metadata is exposed directly, without a wrapper.
void tnl.services.db.metadata;
// @ts-expect-error unknown connection name.
tnl.connect("missing");
const db = await tnl.connect("db");
db.host satisfies "127.0.0.1";
db.port satisfies number;
db.ssl.rejectUnauthorized satisfies true;
db.ssl.servername satisfies string;
db.ssl.ca satisfies string | undefined;
// @ts-expect-error the connector owns application certificates.
void db.ssl.cert;
// @ts-expect-error the connector owns application keys.
void db.ssl.key;
// @ts-expect-error native settings are read-only.
db.port = 5432;
// @ts-expect-error TLS verification is read-only.
db.ssl.servername = "other.example";
const mysql = await tnl.connect("mysql");
mysql.ssl.servername satisfies string;
mysql.ssl.rejectUnauthorized satisfies true;
const cluster = await tnl.connect("cluster");
cluster.server satisfies `https://${string}`;
cluster.kubeconfig satisfies string;
cluster.context satisfies string;
const api = await tnl.connect("api");
api.fetch satisfies typeof fetch;
// @ts-expect-error HTTP clients do not expose TLS keys as metadata.
void api.ssl;
// @ts-expect-error SQL account credentials belong to the application.
void db.password;
const privateTLS = { servername: "db.example", rejectUnauthorized: true } as const;
({ host: "127.0.0.1", port: 5432, ssl: privateTLS }) satisfies TnlConnectionRegistry["postgres"];
({ host: "127.0.0.1", port: 3306, ssl: privateTLS }) satisfies TnlConnectionRegistry["mysql"];

type Union = TnlProjectFromConfig<{
  services: { choice: { protocol: "postgres" } | { protocol: "mysql" } };
}>;
declare const union: Union;
union.services.choice.protocol satisfies "postgres" | "mysql";

const immediate = tnl.connect("db");
immediate.host satisfies "127.0.0.1";
immediate satisfies PromiseLike<TnlConnectionRegistry["postgres"]>;
({ ...immediate, user: "app", database: "app" }) satisfies import("pg").PoolConfig;
// @ts-expect-error metadata is read-only.
tnl.services.db.port = 5432;

type Optional = TnlProjectFromConfig<{
  services: { database: { protocol: "postgres" } | undefined };
  aliases: { dashboard: { service: "api" } | undefined };
  webhooks: { events?: { service: "api"; path: "/events"; methods: readonly ["POST"] } };
}>;
declare const optional: Optional;
// @ts-expect-error an explicitly undefined service stays optional.
void optional.services.database.protocol;
if (optional.services.database) optional.services.database.protocol satisfies "postgres";
// @ts-expect-error an explicitly undefined origin stays optional.
void optional.aliases.dashboard.url;
if (optional.aliases.dashboard) optional.aliases.dashboard.service satisfies "api";
if (optional.webhooks.events) {
  optional.webhooks.events.methods satisfies readonly ["POST"];
  // @ts-expect-error nested metadata is read-only.
  optional.webhooks.events.methods[0] = "POST";
}
