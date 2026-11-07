import { IncomingMessage } from "node:http";
import { Socket } from "node:net";
import { describe, expect, test } from "vitest";
import {
  verifyProxyHeaders,
  verifyProxyRequest,
} from "../../dist/internal/publisher/proxy_request.js";

const token = "a".repeat(64);
const hosts = new Set(["app.example", "alias.example"]);

function request(host: string, headers: [string, string][]): IncomingMessage {
  const message = new IncomingMessage(new Socket());
  message.rawHeaders = ["Host", host, ...headers.flat()];
  message.headers = { host };
  for (const [name, value] of headers) message.headers[name.toLowerCase()] = value;
  return message;
}

describe("publisher request verification", () => {
  test("Fetch headers keep the observed source only after a valid publisher hop", () => {
    const verified = new Headers({
      Host: "app.example",
      "X-Tnl-Proxy-Token": token,
      "X-Forwarded-For": "203.0.113.9",
    });
    expect(verifyProxyHeaders(verified, token, hosts)).toBe(true);
    expect(verified.get("x-forwarded-for")).toBe("203.0.113.9");
    expect(verified.has("x-tnl-proxy-token")).toBe(false);

    const local = new Headers({ Host: "localhost", "X-Forwarded-For": "198.51.100.1" });
    expect(verifyProxyHeaders(local, token, hosts)).toBe(true);
    expect(local.has("x-forwarded-for")).toBe(false);
  });
  test("retains forwarding headers only for a matching credential and removes the credential", () => {
    const incoming = request("app.example", [
      ["X-Tnl-Proxy-Token", token],
      ["X-Forwarded-For", "203.0.113.9"],
      ["X-Forwarded-Proto", "https"],
    ]);
    expect(verifyProxyRequest(incoming, token, hosts)).toBe(true);
    expect(incoming.headers["x-forwarded-for"]).toBe("203.0.113.9");
    expect(incoming.headers["x-tnl-proxy-token"]).toBeUndefined();
    expect(incoming.rawHeaders.join(" ")).not.toContain(token);
  });

  test.each(["app.example", "alias.example"])("rejects an unverified public host %s", (host) => {
    const incoming = request(host, [["X-Forwarded-For", "203.0.113.9"]]);
    expect(verifyProxyRequest(incoming, token, hosts)).toBe(false);
    expect(incoming.headers["x-forwarded-for"]).toBeUndefined();
  });

  test("strips forwarded identity on local requests without rejecting them", () => {
    const incoming = request("localhost", [
      ["X-Forwarded-For", "203.0.113.9"],
      ["X_Forwarded_Host", "attacker.example"],
      ["Forwarded", "for=attacker"],
      ["X-Real-IP", "203.0.113.9"],
    ]);
    expect(verifyProxyRequest(incoming, token, hosts)).toBe(true);
    expect(incoming.headers).toEqual({ host: "localhost" });
    expect(incoming.rawHeaders).toEqual(["Host", "localhost"]);
  });

  test("rejects forged and repeated credentials even for local hosts", () => {
    for (const value of ["b".repeat(64), `${token}, ${token}`, "invalid"]) {
      const incoming = request("localhost", [
        ["X-Tnl-Proxy-Token", value],
        ["X-Forwarded-For", "203.0.113.9"],
      ]);
      expect(verifyProxyRequest(incoming, token, hosts)).toBe(false);
      expect(incoming.headers["x-tnl-proxy-token"]).toBeUndefined();
      expect(incoming.headers["x-forwarded-for"]).toBeUndefined();
      expect(incoming.rawHeaders.join(" ")).not.toContain(value);
    }
  });
});
