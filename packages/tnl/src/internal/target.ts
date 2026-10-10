import { isIP } from "node:net";
import { TnlError } from "../errors.js";

export type CanonicalTarget = `http://${string}` | `https://${string}`;

export function canonicalListenerTarget(
  host: string,
  port: number,
  scheme: "http" | "https" = "http",
): CanonicalTarget {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TnlError("sdk.target_invalid");
  }
  const hostname = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  const lowerHostname = hostname.toLowerCase();
  if (hostname === "0.0.0.0") {
    return `${scheme}://127.0.0.1:${port}`;
  }
  if (hostname === "::") {
    return `${scheme}://[::1]:${port}`;
  }
  if (lowerHostname === "localhost") {
    return `${scheme}://${scheme === "http" ? "127.0.0.1" : "localhost"}:${port}`;
  }
  if (isIP(hostname) === 4) {
    return `${scheme}://${hostname}:${port}`;
  }
  if (isIP(hostname) === 6) {
    return `${scheme}://[${hostname.toLowerCase()}]:${port}`;
  }
  if (
    lowerHostname.length <= 253 &&
    lowerHostname
      .split(".")
      .every((label) => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))
  ) {
    return `${scheme}://${lowerHostname}:${port}`;
  }
  throw new TnlError("sdk.target_invalid");
}

export function canonicalLoopbackTarget(host: string, port: number): `http://${string}` {
  return canonicalListenerTarget(host, port, "http") as `http://${string}`;
}

/** parses a decimal listener port from 1 through 65535. */
export function parseListenerPort(value: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new TnlError("sdk.target_invalid");
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TnlError("sdk.target_invalid");
  }
  return port;
}
