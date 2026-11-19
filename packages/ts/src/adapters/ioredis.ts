import type { Socket } from "node:net";
import { AbstractConnector, Redis, type RedisOptions } from "ioredis";
import { TnlError } from "../errors.js";
import { DriverSocket } from "../internal/connector/driver_socket.js";
import type { TnlClientOptions, TnlStreamConnectionRegistry } from "../project.js";

type TransportOption =
  | "Connector"
  | "host"
  | "port"
  | "path"
  | "family"
  | "tls"
  | "sentinels"
  | "name"
  | "connector";
const forbidden = [
  "Connector",
  "host",
  "port",
  "path",
  "family",
  "tls",
  "sentinels",
  "name",
  "connector",
] satisfies TransportOption[];
export type IoredisOptions = Omit<RedisOptions, TransportOption>;

/** creates an ordinary standalone ioredis client over a selected TCP service. */
export function ioredis(
  options: IoredisOptions = {},
): TnlClientOptions<TnlStreamConnectionRegistry["tcp"], Redis> {
  if (typeof options !== "object" || options === null || forbidden.some((key) => key in options))
    throw new TnlError("sdk.configuration_invalid");
  const config = { ...options };
  const closes = new WeakMap<Redis, () => Promise<void>>();
  return {
    create(connection) {
      let closed = false;
      const sockets = new Set<DriverSocket>();
      const clients = new Set<Redis>();
      class Connector extends AbstractConnector {
        #socket?: DriverSocket;
        #timeout: number;

        constructor(options: unknown) {
          super(2_000);
          this.#timeout =
            typeof options === "object" &&
            options !== null &&
            "connectTimeout" in options &&
            typeof options.connectTimeout === "number"
              ? options.connectTimeout
              : 10_000;
        }

        override async connect(): Promise<Socket> {
          if (closed) throw new TnlError("sdk.client_closed");
          const socket = new DriverSocket(connection.open);
          this.#socket = socket;
          sockets.add(socket);
          socket.once("close", () => sockets.delete(socket));
          await socket.ready(this.#timeout);
          // ioredis uses the Socket type, but only calls stream methods on
          // an already connected socket through this hook.
          return socket as unknown as Socket;
        }

        override disconnect(): void {
          this.#socket?.destroy();
        }
      }
      class ScopedRedis extends Redis {
        constructor(settings: IoredisOptions) {
          super({ ...settings, Connector });
          clients.add(this);
        }

        override duplicate(override: Partial<RedisOptions> = {}): Redis {
          if (closed) throw new TnlError("sdk.client_closed");
          if (clients.size >= 64) throw new TnlError("sdk.client_capacity");
          if (forbidden.some((key) => key in override))
            throw new TnlError("sdk.configuration_invalid");
          return new ScopedRedis({ ...config, ...override });
        }
      }
      const redis = new ScopedRedis(config);
      closes.set(redis, async () => {
        closed = true;
        for (const client of clients) client.disconnect();
        clients.clear();
        await Promise.all(
          [...sockets].map(
            (socket) =>
              new Promise<void>((resolve) => {
                socket.once("close", resolve);
                socket.destroy();
              }),
          ),
        );
      });
      return redis;
    },
    async close(redis) {
      await closes.get(redis)?.();
    },
  };
}
