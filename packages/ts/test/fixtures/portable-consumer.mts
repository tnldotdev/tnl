import {
  createClient,
  type TnlConnectionRegistry,
  type TnlStreamConnectionRegistry,
} from "@tnldotdev/tnl";

const deployment = createClient({
  project: "acme/shop",
  token: "private",
  services: {
    db: { protocol: "postgres" },
    mysql: { protocol: "mysql" },
    api: { protocol: "http" },
    tcp: { protocol: "tcp" },
    cluster: { protocol: "kubernetes" },
  },
}).deployment("production");

const db: TnlStreamConnectionRegistry["postgres"] = await deployment.connect("db");
const checkedRegistry: TnlConnectionRegistry["postgres"] = db;
void checkedRegistry;
await (await db.open()).close();
// @ts-expect-error portable connections must not claim a native loopback port.
void db.port;
const mysql: TnlStreamConnectionRegistry["mysql"] = await deployment.connect("mysql");
const stream = await mysql.open();
await stream.startTls();
await stream.close();
const get = deployment.client("tcp", {
  create: ({ open }) => open(),
  close: (connection) => connection.close(),
});
await get.close();
const api: TnlStreamConnectionRegistry["http"] = await deployment.connect("api");
await api.fetch("/");
const cluster: TnlStreamConnectionRegistry["kubernetes"] = await deployment.connect("cluster");
await cluster.fetch("/api");
// @ts-expect-error portable Kubernetes access is Fetch, not a filesystem config.
void cluster.kubeconfig;
// @ts-expect-error the selected portable service facts still constrain names.
deployment.connect("missing");
await deployment.close();
