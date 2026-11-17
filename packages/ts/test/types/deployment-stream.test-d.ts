import { createClient, type Deployment } from "../../dist/index.browser.js";
import {
  type TnlConnectionRegistry,
  type TnlStream,
  type TnlStreamConnectionRegistry,
} from "@tnldotdev/tnl";
import { assertType, expectTypeOf, test } from "vitest";

test("portable connections preserve logical names without claiming native driver settings", async () => {
  const app = createClient({
    project: "acme/shop",
    token: "private",
    services: {
      web: { protocol: "http" },
      db: { protocol: "postgres" },
      mysql: { protocol: "mysql" },
      cache: { protocol: "tcp" },
      cluster: { protocol: "kubernetes" },
    },
  });
  const remote = app.deployment("production");
  assertType<
    Deployment<{
      web: { protocol: "http" };
      db: { protocol: "postgres" };
      mysql: { protocol: "mysql" };
      cache: { protocol: "tcp" };
      cluster: { protocol: "kubernetes" };
    }>
  >(remote);
  const db = await remote.connect("db");
  assertType<TnlStreamConnectionRegistry["postgres"]>(db);
  assertType<TnlStream>(await db.open());
  // @ts-expect-error portable settings are not native pg loopback options.
  assertType<TnlConnectionRegistry["postgres"]>(db);
  // @ts-expect-error no fake local port exists in a browser or worker.
  void db.port;
  const mysql = await remote.connect("mysql");
  expectTypeOf((await mysql.open()).startTls).toEqualTypeOf<() => Promise<void>>();
  const web = await remote.connect("web");
  assertType<TnlStreamConnectionRegistry["http"]>(web);
  const cluster = await remote.connect("cluster");
  assertType<TnlStreamConnectionRegistry["kubernetes"]>(cluster);
  // @ts-expect-error portable Kubernetes clients use Fetch, not a file on disk.
  void cluster.kubeconfig;
  remote.client("cache", {
    create: (connection) => connection.open(),
    close: (stream) => stream.close(),
  });
  // @ts-expect-error logical names remain checked in the browser entry.
  remote.connect("missing");
  await remote.close();
});
