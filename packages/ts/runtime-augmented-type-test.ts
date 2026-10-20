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
db.host satisfies string;
db.port satisfies number;
db.ssl.rejectUnauthorized satisfies true;
db.ssl.servername satisfies string;
db.ssl.ca satisfies string | undefined;
db.ssl.cert satisfies string | undefined;
db.ssl.key satisfies string | undefined;
// @ts-expect-error private admission does not promise a client certificate.
db.ssl.cert satisfies string;
const mysql = await tnl.connect("mysql");
mysql.ssl.key satisfies string | undefined;
mysql.ssl.servername satisfies string;
mysql.ssl.rejectUnauthorized satisfies true;
const privateTLS = { servername: "db.example", rejectUnauthorized: true } as const;
({ host: "127.0.0.1", port: 5432, ssl: privateTLS }) satisfies TnlConnectionRegistry["postgres"];
({ host: "127.0.0.1", port: 3306, ssl: privateTLS }) satisfies TnlConnectionRegistry["mysql"];

type Union = TnlProjectFromConfig<{
  services: { choice: { protocol: "postgres" } | { protocol: "mysql" } };
}>;
declare const union: Union;
union.services.choice.protocol satisfies "postgres" | "mysql";
