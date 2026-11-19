import { deployment, connect, client, type TnlConnectionRegistry } from "@tnldotdev/tnl/node";
import { assertType, test } from "vitest";

test("remote selections preserve every supported protocol and exact logical names", async () => {
  const production = deployment("production", {
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
  assertType<TnlConnectionRegistry["http"]>(await connect(production, "web"));
  assertType<TnlConnectionRegistry["mysql"]>(await connect(production, "mysql"));
  assertType<TnlConnectionRegistry["tcp"]>(await connect(production, "cache"));
  assertType<TnlConnectionRegistry["kubernetes"]>(await connect(production, "cluster"));
  client(production, "web", { create: (connection) => connection.fetch, close: () => {} });
  // @ts-expect-error facts never approve an undeclared logical name.
  connect(production, "other");
  await production.close();
});
