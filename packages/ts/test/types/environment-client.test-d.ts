import { expectTypeOf, test } from "vitest";
import {
  tnl,
  type EnvironmentReference,
  type IdentitySource,
  type TnlConnectionRegistry,
} from "@tnldotdev/tnl";

const services = Object.freeze({
  api: Object.freeze({ protocol: "http" as const }),
  db: Object.freeze({ protocol: "postgres" as const }),
  mysql: Object.freeze({ protocol: "mysql" as const }),
  raw: Object.freeze({ protocol: "tcp" as const }),
  cluster: Object.freeze({ protocol: "kubernetes" as const }),
});
const environment: EnvironmentReference = {
  server: "https://control.example",
  project_key: "project",
  environment_id: `env_${"a".repeat(22)}`,
};
const identity: IdentitySource & { readonly permission_id: string } = {
  kind: "oidc",
  machine_id: `mci_${"a".repeat(22)}`,
  permission_id: `mwp_${"a".repeat(22)}`,
  async assertion(signal) {
    signal.throwIfAborted();
    return { token: "oidc.jwt", expiresAt: new Date(Date.now() + 60_000) };
  },
};
test("normal environment constructor infers all protocols from generated facts", () => {
  const client = tnl.client({ services, environment, identity });
  expectTypeOf(client.connect("api")).toEqualTypeOf<Promise<TnlConnectionRegistry["http"]>>();
  expectTypeOf(client.connect("db")).toEqualTypeOf<Promise<TnlConnectionRegistry["postgres"]>>();
  expectTypeOf(client.connect("mysql")).toEqualTypeOf<Promise<TnlConnectionRegistry["mysql"]>>();
  expectTypeOf(client.connect("raw")).toEqualTypeOf<Promise<TnlConnectionRegistry["tcp"]>>();
  expectTypeOf(client.connect("cluster")).toEqualTypeOf<
    Promise<TnlConnectionRegistry["kubernetes"]>
  >();
  // @ts-expect-error generated names are exact
  client.connect("missing");
  // @ts-expect-error public callers cannot supply a protocol
  client.connect("db", "http");
  // @ts-expect-error identities are explicit checked sources
  tnl.client({ services, environment, identity: {} });
  // @ts-expect-error a manager client cannot override visitor discovery
  tnl.client({ services, environment, identity, authority: {} });
  tnl.client({
    services,
    // @ts-expect-error environment refs cannot select a mutable default by name
    environment: { server: environment.server, project_key: "project", name: "production" },
    identity,
  });
});
