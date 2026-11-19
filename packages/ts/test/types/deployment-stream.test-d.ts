import { deployment, connect, client, type Deployment } from "@tnldotdev/tnl/browser";
import {
  type TnlConnectionRegistry,
  type TnlStream,
  type TnlStreamConnectionRegistry,
} from "@tnldotdev/tnl";
import { assertType, expectTypeOf, test } from "vitest";

test("portable connections preserve logical names without claiming native driver settings", async () => {
  const remote = deployment("production", {
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
  assertType<
    Deployment<
      {
        web: { protocol: "http" };
        db: { protocol: "postgres" };
        mysql: { protocol: "mysql" };
        cache: { protocol: "tcp" };
        cluster: { protocol: "kubernetes" };
      },
      TnlStreamConnectionRegistry
    >
  >(remote);
  const db = await connect(remote, "db");
  assertType<TnlStreamConnectionRegistry["postgres"]>(db);
  assertType<TnlStream>(await db.open());
  // @ts-expect-error portable settings are not native pg loopback options.
  assertType<TnlConnectionRegistry["postgres"]>(db);
  // @ts-expect-error no fake local port exists in a browser or worker.
  void db.port;
  const mysql = await connect(remote, "mysql");
  expectTypeOf((await mysql.open()).startTls).toEqualTypeOf<() => Promise<void>>();
  const web = await connect(remote, "web");
  assertType<TnlStreamConnectionRegistry["http"]>(web);
  const cluster = await connect(remote, "cluster");
  assertType<TnlStreamConnectionRegistry["kubernetes"]>(cluster);
  // @ts-expect-error portable Kubernetes clients use Fetch, not a file on disk.
  void cluster.kubeconfig;
  client(remote, "cache", {
    create: (connection) => connection.open(),
    close: (stream) => stream.close(),
  });
  // @ts-expect-error logical names remain checked in the browser entry.
  connect(remote, "missing");
  await remote.close();
});
