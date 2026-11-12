import { expectTypeOf, test } from "vitest";
import { Pool } from "pg";
import { tnl, type TnlConnectionRegistry } from "@tnldotdev/tnl";
import {
  clientFromSelection,
  type ResolvedService,
  type ServiceSelection,
} from "../../src/internal/connector/selected_client.js";

const services = Object.freeze({
  api: Object.freeze({ protocol: "http" }),
  db: Object.freeze({ protocol: "postgres" }),
  mysql: Object.freeze({ protocol: "mysql" }),
  raw: Object.freeze({ protocol: "tcp" }),
  cluster: Object.freeze({ protocol: "kubernetes" }),
});
declare const selection: ServiceSelection<ResolvedService>;
const client = clientFromSelection(services, selection);

test("actual selected-client implementation derives protocol types from the passed literal data", async () => {
  const db = await client.connect("db");
  expectTypeOf(db).toEqualTypeOf<TnlConnectionRegistry["postgres"]>();
  expectTypeOf(db.host).toEqualTypeOf<"127.0.0.1">();
  expectTypeOf(db.ssl.rejectUnauthorized).toEqualTypeOf<true>();
  new Pool({ ...db, user: "app", database: "app" });
  // @ts-expect-error the connector does not supply application database credentials.
  void db.password;
  // @ts-expect-error a prepared connection has no application client key.
  void db.ssl.key;
  // @ts-expect-error a prepared connection has no application client certificate.
  void db.ssl.cert;
  // @ts-expect-error prepared settings remain readonly.
  db.port = 5432;
  const api = await client.connect("api");
  expectTypeOf(api.fetch("/health")).toEqualTypeOf<Promise<Response>>();
  // @ts-expect-error HTTP settings do not expose database TLS options.
  void api.ssl;
  const mysql = await client.connect("mysql");
  expectTypeOf(mysql.ssl.verifyIdentity).toEqualTypeOf<true>();
  ({ ...mysql, user: "app", database: "app" }) satisfies import("mysql2").ConnectionOptions;
  const raw = await client.connect("raw");
  expectTypeOf(raw).toEqualTypeOf<TnlConnectionRegistry["tcp"]>();
  // @ts-expect-error opaque TCP has no application TLS settings.
  void raw.ssl;
  const cluster = await client.connect("cluster");
  expectTypeOf(cluster.server).toEqualTypeOf<`https://${string}`>();
  expectTypeOf(cluster.kubeconfig).toEqualTypeOf<string>();
  // @ts-expect-error exact names come from these runtime facts, not ambient augmentation.
  client.connect("missing");
  // @ts-expect-error there is no caller protocol argument.
  client.connect("api", "http");
  // @ts-expect-error asynchronous preparation does not expose immediate driver settings.
  void client.connect("db").port;
});

test("the independent root local API does not claim a generated project it did not receive", () => {
  expectTypeOf(tnl.connect("db")).toEqualTypeOf<
    import("@tnldotdev/tnl").TnlConnectionHandle<TnlConnectionRegistry[keyof TnlConnectionRegistry]>
  >();
  // @ts-expect-error a root local connection has no runtime-bound exact protocol contract.
  tnl.connect("db") satisfies PromiseLike<TnlConnectionRegistry["postgres"]>;
});
