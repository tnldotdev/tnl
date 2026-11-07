import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";

const credentialHeader = "x-tnl-proxy-token";

function reservedHeader(name: string): boolean {
  const normalized = name.toLowerCase().replaceAll("_", "-");
  return (
    normalized === credentialHeader ||
    normalized === "forwarded" ||
    normalized === "x-real-ip" ||
    normalized.startsWith("x-forwarded-")
  );
}

function keepHeader(name: string, verified: boolean): boolean {
  if (!reservedHeader(name)) return true;
  return (
    verified &&
    ["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"].includes(name.toLowerCase())
  );
}

function sameToken(actual: string | string[] | undefined, expected: string): boolean {
  if (typeof actual !== "string" || !/^[a-f0-9]{64}$/.test(actual)) return false;
  const left = Buffer.from(actual, "hex");
  const right = Buffer.from(expected, "hex");
  return right.length === 32 && timingSafeEqual(left, right);
}

/** verifies and sanitizes a Fetch request before it reaches an application handler. */
export function verifyProxyHeaders(
  headers: Headers,
  token: string,
  publicHosts: ReadonlySet<string>,
): boolean {
  const supplied = headers.get(credentialHeader);
  const verified = sameToken(supplied ?? undefined, token);
  const host = headers.get("host")?.toLowerCase().replace(/:\d+$/, "") ?? "";
  const allowed = verified || (supplied === null && !publicHosts.has(host));
  for (const name of headers.keys()) {
    if (!keepHeader(name, verified)) headers.delete(name);
  }
  return allowed;
}

/** verifies the private local publisher hop and removes untrusted forwarding headers. */
export function verifyProxyRequest(
  request: IncomingMessage,
  token: string,
  publicHosts: ReadonlySet<string>,
): boolean {
  const supplied = request.headers[credentialHeader];
  const verified = sameToken(supplied, token);
  // even local requests must not be able to impersonate tnl by supplying
  // forwarding headers. a request claiming the public hostname must be verified.
  const host = request.headers.host?.toLowerCase().replace(/:\d+$/, "") ?? "";
  const allowed = verified || (supplied === undefined && !publicHosts.has(host));
  for (const name of Object.keys(request.headers)) {
    if (!keepHeader(name, verified)) delete request.headers[name];
  }
  const raw = request.rawHeaders;
  for (let index = raw.length - 2; index >= 0; index -= 2) {
    const name = raw[index];
    if (name !== undefined && !keepHeader(name, verified)) raw.splice(index, 2);
  }
  return allowed;
}
