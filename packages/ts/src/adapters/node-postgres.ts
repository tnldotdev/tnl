import driver, { type Pool, type PoolConfig } from "pg";
import { TnlError } from "../errors.js";
import { DriverSocket } from "../internal/connector/driver_socket.js";
import type {
  TnlClientOptions,
  TnlConnectionRegistry,
  TnlStreamConnectionRegistry,
} from "../project.js";

type Connection = TnlConnectionRegistry["postgres"] | TnlStreamConnectionRegistry["postgres"];
type TransportOption = "connectionString" | "host" | "port" | "ssl" | "stream" | "Client";
export type PgOptions = Omit<PoolConfig, TransportOption>;

/** creates an ordinary pg pool scoped to the selected tnl service. */
export function pg(options: PgOptions): TnlClientOptions<Connection, Pool> {
  if (["connectionString", "host", "port", "ssl", "stream", "Client"].some((key) => key in options))
    throw new TnlError("sdk.configuration_invalid");
  const config = { ...options };
  const sockets = new WeakMap<Pool, Set<DriverSocket>>();
  return {
    create(connection) {
      if ("host" in connection) {
        return new driver.Pool({
          ...config,
          host: connection.host,
          port: connection.port,
          ssl: connection.ssl,
        });
      }
      // Go already verified visitor TLS, so pg must start with application bytes.
      const active = new Set<DriverSocket>();
      const pool = new driver.Pool({
        ...config,
        ssl: false,
        stream() {
          const socket = new DriverSocket(connection.open);
          active.add(socket);
          socket.once("close", () => active.delete(socket));
          return socket;
        },
      });
      sockets.set(pool, active);
      return pool;
    },
    async close(pool) {
      await pool.end();
      // pg-pool can remove a client from its inventory before its socket closes.
      await Promise.all(
        [...(sockets.get(pool) ?? [])].map(
          (socket) => new Promise<void>((resolve) => socket.once("close", resolve)),
        ),
      );
    },
  };
}
