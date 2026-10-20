import { tnl, type TnlProjectFromConfig } from "@tnldotdev/tnl";
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
tnl.services.api.metadata.url satisfies `https://${string}`;
tnl.services.db.metadata.protocol satisfies "postgres";
tnl.services.db.metadata.hostname satisfies string;
tnl.services.db.metadata.port satisfies number;
tnl.services.db.metadata.public satisfies boolean;
tnl.services.cluster.metadata.url satisfies `https://${string}`;
// @ts-expect-error optional factory services stay optional in every checkout.
void tnl.services.worker.metadata;
if (tnl.services.worker) tnl.services.worker.metadata.protocol satisfies "tcp";
// @ts-expect-error service names are exact.
void tnl.services.missing;
// @ts-expect-error database metadata has no URL.
void tnl.services.db.metadata.url;
// @ts-expect-error unknown connection name.
tnl.connect("missing");
const db = await tnl.connect("db");
db.host satisfies string;
db.port satisfies number;
db.ssl.rejectUnauthorized satisfies true;
const mysql = await tnl.connect("mysql");
mysql.ssl.key satisfies string;

type Union = TnlProjectFromConfig<{
  services: { choice: { protocol: "postgres" } | { protocol: "mysql" } };
}>;
declare const union: Union;
union.services.choice.metadata.protocol satisfies "postgres" | "mysql";
