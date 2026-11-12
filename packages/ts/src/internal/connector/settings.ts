import type { Socket } from "node:net";
import { TnlError } from "../../errors.js";
import type { TnlConnectionRegistry, TnlFetch } from "../../project.js";
import { parseConnectionSnapshot, type ConnectionSnapshot } from "./snapshot.js";

type Protocol = keyof TnlConnectionRegistry;
type Snapshot<Kind extends Protocol> = Extract<ConnectionSnapshot, { protocol: Kind }>;

// transport creation belongs to the connection owner, never to a wire value.
// these required mechanics carry no authorization decisions or optional grants.
export interface SettingsTransports {
  http(snapshot: Snapshot<"http">): TnlFetch;
  mysql(snapshot: Snapshot<"mysql">): () => Socket;
}

type Decoders = {
  readonly [Kind in Protocol]: (input: unknown) => TnlConnectionRegistry[Kind];
};

export function settingsDecoders(transports: SettingsTransports): Decoders {
  return {
    http(input) {
      const snapshot = parseConnectionSnapshot(input);
      if (snapshot.protocol !== "http") throw new TnlError("sdk.response_invalid");
      return Object.freeze({ url: snapshot.url, fetch: transports.http(snapshot) });
    },
    postgres(input) {
      const snapshot = parseConnectionSnapshot(input);
      if (snapshot.protocol !== "postgres") throw new TnlError("sdk.response_invalid");
      return Object.freeze({ host: snapshot.host, port: snapshot.port, ssl: snapshot.ssl });
    },
    mysql(input) {
      const snapshot = parseConnectionSnapshot(input);
      if (snapshot.protocol !== "mysql") throw new TnlError("sdk.response_invalid");
      // mysql drivers mutate their TLS options; detach them from the wire facts.
      const ssl: TnlConnectionRegistry["mysql"]["ssl"] = {
        ...snapshot.ssl,
        verifyIdentity: true,
      };
      return Object.freeze({
        host: snapshot.ssl.servername,
        port: snapshot.port,
        ssl,
        stream: transports.mysql(snapshot),
      });
    },
    tcp(input) {
      const snapshot = parseConnectionSnapshot(input);
      if (snapshot.protocol !== "tcp") throw new TnlError("sdk.response_invalid");
      return Object.freeze({ host: snapshot.host, port: snapshot.port });
    },
    kubernetes(input) {
      const snapshot = parseConnectionSnapshot(input);
      if (snapshot.protocol !== "kubernetes") throw new TnlError("sdk.response_invalid");
      const server: `https://${string}` = `https://${snapshot.host}:${snapshot.port}`;
      return Object.freeze({ server, kubeconfig: snapshot.kubeconfig, context: snapshot.context });
    },
  };
}

// the expected protocol is captured from generated facts, not supplied at connect.
// indexed dispatch preserves its exact result type without casting a union.
export function decodeSettings<Kind extends Protocol>(
  decoders: Decoders,
  protocol: Kind,
  input: unknown,
): TnlConnectionRegistry[Kind] {
  return decoders[protocol](input);
}
