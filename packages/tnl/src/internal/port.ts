import { TnlError } from "../errors.js";
/** Selects a free port under tnl dev, or the runtime's usual local port. */
export function developmentPort(
  environment: Record<string, string | undefined>,
  bun: boolean,
): number {
  if (environment.TNL_DEV_PROTOCOL !== undefined) {
    if (environment.TNL_DEV_PROTOCOL !== "1") {
      throw new TnlError("sdk.protocol_unsupported");
    }
    const forced = environment.TNL_DEV_PORT;
    return forced === undefined ? 0 : parsePort(forced, "TNL_DEV_PORT");
  }
  const configured = bun
    ? (environment.BUN_PORT ?? environment.PORT ?? environment.NODE_PORT)
    : environment.PORT;
  return configured === undefined ? 3000 : parsePort(configured, "development port");
}

function parsePort(value: string, _name: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || String(port) !== value) {
    throw new TnlError("sdk.target_invalid");
  }
  return port;
}
