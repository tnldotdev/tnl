import { parseConnection } from "../../src/internal/connector/connection.js";
import type { ServiceProtocol } from "../../src/internal/project/runtime.js";
import type { TnlNativeTLSOptions } from "../../src/project.js";

type Snapshot = ReturnType<typeof parseConnection>;
declare const snapshot: Snapshot;
declare const protocol: ServiceProtocol;
snapshot.protocol satisfies ServiceProtocol;
protocol satisfies Snapshot["protocol"];

switch (snapshot.protocol) {
  case "tcp":
    snapshot.ssl satisfies undefined;
    snapshot.url satisfies undefined;
    snapshot.kubeconfig satisfies undefined;
    snapshot.context satisfies undefined;
    break;
  case "postgres":
  case "mysql":
    snapshot.ssl satisfies TnlNativeTLSOptions;
    snapshot.ssl.rejectUnauthorized satisfies true;
    snapshot.url satisfies undefined;
    snapshot.kubeconfig satisfies undefined;
    snapshot.context satisfies undefined;
    break;
  case "http":
    snapshot.ssl satisfies TnlNativeTLSOptions;
    snapshot.url satisfies `https://${string}`;
    snapshot.kubeconfig satisfies undefined;
    snapshot.context satisfies undefined;
    break;
  case "kubernetes":
    snapshot.ssl satisfies TnlNativeTLSOptions;
    snapshot.url satisfies `https://${string}`;
    snapshot.kubeconfig satisfies string;
    snapshot.context satisfies string;
    break;
  default:
    snapshot satisfies never;
}

declare const address: Pick<Snapshot, "host" | "port" | "expires" | "transportID">;
declare const ssl: TnlNativeTLSOptions;
declare const url: `https://${string}`;
declare const kubeconfig: string;
declare const context: string;
declare const databaseProtocol: "postgres" | "mysql";
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
