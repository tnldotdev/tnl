import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { newVisitorProbeTag } from "./connection-diagnostics.ts";

it("keeps HTTP/1.1 and derives a new log ID for each connection", () => {
  const { ALPNProtocols, clientHelloId } = newVisitorProbeTag();
  const [normal, probe] = ALPNProtocols;
  expect(normal).toBe("http/1.1");
  expect(probe).toMatch(/^tnl-probe-[a-f0-9]{32}$/);
  const nonce = Buffer.from(probe?.slice("tnl-probe-".length) ?? "", "hex");
  expect(clientHelloId).toBe(createHash("sha256").update(nonce).digest("hex").slice(0, 32));
  expect(newVisitorProbeTag().clientHelloId).not.toBe(clientHelloId);
});
