import {
  deployment,
  connect,
  client,
  type TnlStreamConnectionRegistry,
} from "@tnldotdev/tnl/browser";

const selectedDeployment = deployment("production", {
  project: "acme/shop",
  token: "private",
  services: {
    db: { protocol: "postgres" },
    mysql: { protocol: "mysql" },
    api: { protocol: "http" },
    tcp: { protocol: "tcp" },
    cluster: { protocol: "kubernetes" },
  },
});

const db: TnlStreamConnectionRegistry["postgres"] = await connect(selectedDeployment, "db");
await (await db.open()).close();
// @ts-expect-error portable connections must not claim a native loopback port.
void db.port;
const mysql: TnlStreamConnectionRegistry["mysql"] = await connect(selectedDeployment, "mysql");
const stream = await mysql.open();
await stream.startTls();
await stream.close();
const get = client(selectedDeployment, "tcp", {
  create: ({ open }) => open(),
  close: (connection) => connection.close(),
});
await get.close();
const api: TnlStreamConnectionRegistry["http"] = await connect(selectedDeployment, "api");
await api.fetch("/");
const cluster: TnlStreamConnectionRegistry["kubernetes"] = await connect(
  selectedDeployment,
  "cluster",
);
await cluster.fetch("/api");
// @ts-expect-error portable Kubernetes access is Fetch, not a filesystem config.
void cluster.kubeconfig;
// @ts-expect-error the selected portable service facts still constrain names.
connect(selectedDeployment, "missing");
await selectedDeployment.close();
