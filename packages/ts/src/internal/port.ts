import { TnlError } from "../errors.js";
/** selects the app's configured listener port, defaulting to 3000. */
export function developmentPort(
  environment: Record<string, string | undefined>,
  bun: boolean,
): number {
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
