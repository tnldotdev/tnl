import driver, { type Pool, type PoolOptions } from "mysql2/promise";
import { TnlError } from "../errors.js";
import type { TnlClientOptions, TnlConnectionRegistry } from "../project.js";

type TransportOption = "host" | "port" | "ssl" | "stream" | "socketPath" | "uri";
export type MysqlOptions = Omit<PoolOptions, TransportOption>;

/** creates an ordinary mysql2 pool using the native connector and verified TLS. */
export function mysql2(
  options: MysqlOptions,
): TnlClientOptions<TnlConnectionRegistry["mysql"], Pool> {
  if (
    typeof options !== "object" ||
    options === null ||
    ["host", "port", "ssl", "stream", "socketPath", "uri"].some((key) => key in options)
  )
    throw new TnlError("sdk.configuration_invalid");
  const config = { ...options };
  return {
    create({ host, port, ssl, stream }) {
      if (stream === undefined || ssl?.verifyIdentity !== true)
        throw new TnlError("sdk.capability_unsupported");
      return driver.createPool({ ...config, host, port, ssl: { ...ssl }, stream });
    },
    close(pool) {
      return pool.end();
    },
  };
}
