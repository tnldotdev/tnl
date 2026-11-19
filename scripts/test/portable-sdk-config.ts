import type { PortableFixture } from "../../packages/ts/test/portable-integration/fixture.ts";

export function chromeArguments(fixture: PortableFixture): string[] {
  const control = new URL(fixture.control_url);
  return [
    `--ignore-certificate-errors-spki-list=${fixture.spki_pins.join(",")}`,
    `--host-resolver-rules=MAP ${control.hostname}:${control.port || "443"} ${fixture.control_dial_address}, MAP localhost 127.0.0.1`,
  ];
}

export function workerdConfiguration(fixture: PortableFixture, wasm: string): string {
  const tls = (root: string) =>
    `(trustBrowserCas = false, trustedCertificates = [${JSON.stringify(root)}])`;
  const external = (name: string, address: string, hostname: string, root: string) =>
    `(name = ${JSON.stringify(name)}, external = (
      address = ${JSON.stringify(address)},
      https = (certificateHost = ${JSON.stringify(hostname)}, tlsOptions = ${tls(root)})
    ))`;
  const relays = fixture.relays.map((relay, index) =>
    external(`relay${index}`, relay.dial_address, relay.tls_server_name, fixture.relay_root_pem),
  );
  return `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "main", worker = (
      modules = [
        (name = "worker.mjs", esModule = embed "worker.mjs"),
        (name = "tnl.wasm", wasm = embed ${JSON.stringify(wasm)})
      ],
      compatibilityDate = "2026-10-31",
      bindings = [
        (name = "CONTROL", service = "control"),
        (name = "RELAY0", service = "relay0"),
        (name = "RELAY1", service = "relay1")
      ],
      globalOutbound = "local"
    )),
    ${external("control", fixture.control_dial_address, new URL(fixture.control_url).hostname, fixture.control_root_pem)},
    ${relays.join(",\n    ")},
    (name = "local", network = (
      allow = ["127.0.0.0/8", "::1/128"],
      tlsOptions = ${tls(fixture.relay_root_pem)}
    ))
  ],
  sockets = [(name = "http", address = "127.0.0.1:0", http = (), service = "main")]
);
`;
}
