import { createClient, type TnlConnectionRegistry } from "@tnldotdev/tnl";
import { assertType, test } from "vitest";

test("remote selections preserve every supported protocol and exact logical names", async () => {
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
  const production = app.deployment("production");
  assertType<TnlConnectionRegistry["http"]>(await production.connect("web"));
  assertType<TnlConnectionRegistry["mysql"]>(await production.connect("mysql"));
  assertType<TnlConnectionRegistry["tcp"]>(await production.connect("cache"));
  assertType<TnlConnectionRegistry["kubernetes"]>(await production.connect("cluster"));
  production.client("web", { create: (connection) => connection.fetch, close: () => {} });
  // @ts-expect-error facts never approve an undeclared logical name.
  production.connect("other");
  // @ts-expect-error runtime management creation needs an original request key.
  app.deployments.create({ name: "customer", targets: { db: { address: "db:5432" } } });
  // @ts-expect-error runtime updates need an explicit strong revision condition.
  app.deployments.update("production", { targets: { db: { address: "db:5432" } } });
  // @ts-expect-error runtime management cannot administer its own credentials.
  app.credentials.create();
  await production.close();
});
