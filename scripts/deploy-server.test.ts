import { describe, expect, it } from "vitest";
import { checkPorts, deploymentOrder } from "./deploy-server.js";

const control = {
  app: "tnl-control-staging",
  env: { TNLD_TCP_PORTS: "1024-65535", TNLD_REQUIRE_PROXY_HEADER: "true" },
  services: [],
};
const httpPort = { port: 443, handlers: ["proxy_proto"], proxy_proto_options: { version: "v2" } };
const tcpPort = {
  start_port: 1024,
  end_port: 65535,
  handlers: ["proxy_proto"],
  proxy_proto_options: { version: "v2" },
};
const service = { protocol: "tcp", internal_port: 8443, ports: [httpPort, tcpPort] };
const ingress = {
  app: "tnl-ingress-staging",
  env: { TNLD_REQUIRE_PROXY_HEADER: "true" },
  services: [service],
};

describe("split ingress port qualification", () => {
  it("requires the whole TCP inventory and a trusted outer PROXY v2 header", () => {
    expect(() => checkPorts(control, ingress)).not.toThrow();
    expect(() =>
      checkPorts({ ...control, env: { ...control.env, TNLD_TCP_PORTS: "" } }, ingress),
    ).toThrow();
    expect(() =>
      checkPorts(control, { ...ingress, env: { TNLD_REQUIRE_PROXY_HEADER: "false" } }),
    ).toThrow();
    expect(() =>
      checkPorts(control, {
        ...ingress,
        services: [{ ...service, ports: [httpPort] }],
      }),
    ).toThrow();
    expect(() =>
      checkPorts(control, {
        ...ingress,
        services: [
          {
            ...service,
            ports: [httpPort, { ...tcpPort, proxy_proto_options: { version: "v1" } }],
          },
        ],
      }),
    ).toThrow();
  });
});

describe("selected-image rollout order", () => {
  it("updates the ingress port range before an existing control can advertise it", () => {
    expect(deploymentOrder(true)).toEqual(["ingress", "control", "relay-a", "relay-b"]);
    expect(deploymentOrder(false)).toEqual(["control", "ingress", "relay-a", "relay-b"]);
  });
});
