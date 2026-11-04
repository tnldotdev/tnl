import { assert, assertType, expectTypeOf, test } from "vitest";
import type { ConnectionSnapshot as Snapshot } from "../../src/internal/connector/snapshot.js";
import type { ServiceProtocol } from "../../src/internal/project/runtime.js";
import type { TnlNativeTLSOptions } from "../../src/project.js";

declare const snapshot: Snapshot;
test("snapshots cover every supported protocol", () => {
  expectTypeOf<Snapshot["protocol"]>().toEqualTypeOf<ServiceProtocol>();
});
test("TCP has only a loopback address", () => {
  assert(snapshot.protocol === "tcp");
  expectTypeOf(snapshot.host).toEqualTypeOf<"127.0.0.1">();
  expectTypeOf(snapshot).not.toHaveProperty("ssl");
  expectTypeOf(snapshot).not.toHaveProperty("url");
  expectTypeOf(snapshot).not.toHaveProperty("kubeconfig");
  expectTypeOf(snapshot).not.toHaveProperty("context");
});
test("SQL requires verified TLS without HTTP or Kubernetes fields", () => {
  assert(snapshot.protocol === "postgres" || snapshot.protocol === "mysql");
  assertType<TnlNativeTLSOptions>(snapshot.ssl);
  expectTypeOf(snapshot.ssl.rejectUnauthorized).toEqualTypeOf<true>();
  expectTypeOf(snapshot).not.toHaveProperty("url");
  expectTypeOf(snapshot).not.toHaveProperty("kubeconfig");
  expectTypeOf(snapshot).not.toHaveProperty("context");
});
test("HTTP requires a managed origin and verified TLS", () => {
  assert(snapshot.protocol === "http");
  assertType<TnlNativeTLSOptions>(snapshot.ssl);
  expectTypeOf(snapshot.url).toEqualTypeOf<`https://${string}`>();
  expectTypeOf(snapshot).not.toHaveProperty("kubeconfig");
  expectTypeOf(snapshot).not.toHaveProperty("context");
});
test("Kubernetes requires its origin, TLS, file, and context", () => {
  assert(snapshot.protocol === "kubernetes");
  assertType<TnlNativeTLSOptions>(snapshot.ssl);
  expectTypeOf(snapshot.url).toEqualTypeOf<`https://${string}`>();
  expectTypeOf(snapshot.kubeconfig).toEqualTypeOf<string>();
  expectTypeOf(snapshot.context).toEqualTypeOf<`tnl:${string}`>();
});

declare const address: Pick<Snapshot, "host" | "port" | "expires" | "transportID">;
declare const ssl: TnlNativeTLSOptions;
declare const url: `https://${string}`;
declare const kubeconfig: string;
declare const context: `tnl:${string}`;
declare const databaseProtocol: "postgres" | "mysql";
test("each snapshot variant requires its fields and rejects foreign fields", () => {
  ({ ...address, protocol: "tcp" }) satisfies Snapshot;
  ({ ...address, protocol: databaseProtocol, ssl }) satisfies Snapshot;
  ({ ...address, protocol: "http", ssl, url }) satisfies Snapshot;
  ({ ...address, protocol: "kubernetes", ssl, url, kubeconfig, context }) satisfies Snapshot;

  // @ts-expect-error tcp snapshots cannot contain application TLS settings.
  ({ ...address, protocol: "tcp", ssl }) satisfies Snapshot;
  // @ts-expect-error forbidden optional fields cannot be explicitly undefined either.
  ({ ...address, protocol: "tcp", ssl: undefined }) satisfies Snapshot;
  // @ts-expect-error tcp snapshots cannot contain an HTTP origin.
  ({ ...address, protocol: "tcp", url }) satisfies Snapshot;
  // @ts-expect-error tcp snapshots cannot contain a kubeconfig path.
  ({ ...address, protocol: "tcp", kubeconfig }) satisfies Snapshot;
  // @ts-expect-error tcp snapshots cannot contain a kubernetes context.
  ({ ...address, protocol: "tcp", context }) satisfies Snapshot;
  // @ts-expect-error database snapshots require verified TLS settings.
  ({ ...address, protocol: databaseProtocol }) satisfies Snapshot;
  // @ts-expect-error database snapshots cannot contain an HTTP origin.
  ({ ...address, protocol: databaseProtocol, ssl, url }) satisfies Snapshot;
  // @ts-expect-error database snapshots cannot contain a kubeconfig path.
  ({ ...address, protocol: databaseProtocol, ssl, kubeconfig }) satisfies Snapshot;
  // @ts-expect-error database snapshots cannot contain a kubernetes context.
  ({ ...address, protocol: databaseProtocol, ssl, context }) satisfies Snapshot;
  // @ts-expect-error HTTP snapshots require verified TLS settings.
  ({ ...address, protocol: "http", url }) satisfies Snapshot;
  // @ts-expect-error HTTP snapshots require a managed origin.
  ({ ...address, protocol: "http", ssl }) satisfies Snapshot;
  // @ts-expect-error HTTP snapshots cannot contain a kubeconfig path.
  ({ ...address, protocol: "http", ssl, url, kubeconfig }) satisfies Snapshot;
  // @ts-expect-error HTTP snapshots cannot contain a kubernetes context.
  ({ ...address, protocol: "http", ssl, url, context }) satisfies Snapshot;

  // @ts-expect-error kubernetes snapshots require verified TLS settings.
  ({ ...address, protocol: "kubernetes", url, kubeconfig, context }) satisfies Snapshot;
  // @ts-expect-error kubernetes snapshots require a managed origin.
  ({ ...address, protocol: "kubernetes", ssl, kubeconfig, context }) satisfies Snapshot;
  // @ts-expect-error kubernetes snapshots require a kubeconfig path.
  ({ ...address, protocol: "kubernetes", ssl, url, context }) satisfies Snapshot;
  // @ts-expect-error kubernetes snapshots require a context.
  ({ ...address, protocol: "kubernetes", ssl, url, kubeconfig }) satisfies Snapshot;
  // @ts-expect-error validated snapshots remain read-only.
  snapshot.port = 12345;
});
