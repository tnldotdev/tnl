import driver from "postgres";
import { TnlError } from "../errors.js";
import { DriverSocket } from "../internal/connector/driver_socket.js";
import type { TnlClientOptions, TnlStreamConnectionRegistry } from "../project.js";

type TransportOption = "host" | "port" | "ssl" | "path" | "hostname" | "socket" | "shared";
export type PostgresOptions = Omit<driver.Options<{}>, TransportOption>;

/** creates an ordinary Postgres.js client over the selected service. */
export function postgres(
  options: PostgresOptions,
): TnlClientOptions<TnlStreamConnectionRegistry["postgres"], driver.Sql> {
  if (
    typeof options !== "object" ||
    options === null ||
    ["host", "port", "ssl", "path", "hostname", "socket", "shared"].some((key) => key in options)
  )
    throw new TnlError("sdk.configuration_invalid");
  const config = { ...options };
  const owners = new WeakMap<driver.Sql, () => Promise<void>>();
  return {
    create(connection) {
      const sockets = new Map<DriverSocket, Promise<void>>();
      let closed = false;
      // Postgres.js's socket hook expects an established socket, unlike pg.
      const settings = {
        ...config,
        host: "localhost",
        port: 5432,
        ssl: false,
        async socket() {
          if (closed) throw new TnlError("sdk.client_closed");
          const socket = new DriverSocket(connection.open);
          sockets.set(
            socket,
            new Promise<void>((resolve) => {
              socket.once("close", () => {
                sockets.delete(socket);
                resolve();
              });
            }),
          );
          await socket.ready((config.connect_timeout ?? 30) * 1000);
          return socket;
        },
      };
      const sql = driver(settings);
      owners.set(sql, async () => {
        closed = true;
        try {
          await sql.end({ timeout: 5 });
        } finally {
          const pending = [...sockets];
          for (const [socket] of pending) socket.destroy();
          await Promise.all(pending.map(([, joined]) => joined));
        }
      });
      return sql;
    },
    async close(sql) {
      await owners.get(sql)?.();
    },
  };
}
