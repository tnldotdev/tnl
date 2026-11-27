import { createHash, randomBytes } from "node:crypto";

// Make one tag per fresh HTTPS connection, not per retry group. Keep the
// normal HTTP/1.1 offer; the tag is not a protocol the publisher selects.
export function newVisitorProbeTag() {
  const nonce = randomBytes(16);
  return {
    ALPNProtocols: ["http/1.1", `tnl-probe-${nonce.toString("hex")}`],
    clientHelloId: createHash("sha256").update(nonce).digest("hex").slice(0, 32),
  };
}
