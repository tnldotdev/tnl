import { expect, test } from "vitest";
import { fixtureSchema } from "../../packages/ts/test/portable-integration/fixture.ts";
import { chromeArguments, workerdConfiguration } from "./portable-sdk-config.ts";

const services = ["http", "tcp", "postgres", "mysql", "kubernetes", "redis"];
const credentials = { user: "fixture", password: "private", database: "fixture" };
const fixture = fixtureSchema.parse({
  version: 1,
  project: "team/fixture",
  deployment: "portable",
  token: "credential-not-for-config",
  control_url: "https://control.fixture.test",
  control_dial_address: "127.0.0.1:10001",
  control_root_pem: "control root",
  relay_root_pem: "relay root",
  service_root_pem: "service root",
  services: Object.fromEntries(services.map((name) => [name, `service-${name}`])),
  endpoints: Object.fromEntries(
    services.map((name) => [
      name,
      { hostname: `${name}.fixture.test`, port: name === "http" ? 443 : 0, public: false },
    ]),
  ),
  relays: [
    { address: "localhost:10002", dial_address: "127.0.0.1:10002", tls_server_name: "localhost" },
    { address: "localhost:10003", dial_address: "127.0.0.1:10003", tls_server_name: "localhost" },
  ],
  spki_pins: Array.from({ length: 3 }, () => "A".repeat(43) + "="),
  api_url: "http://127.0.0.1:10004",
  api_token: "private",
  postgres: credentials,
  mysql: credentials,
  redis_password: "private",
  kubernetes_token: "private",
  source_fingerprint: "a".repeat(64),
});

test("Chrome maps only the fixture control endpoint and pins disposable leaf keys", () => {
  const arguments_ = chromeArguments(fixture);
  expect(arguments_).toContain(
    "--host-resolver-rules=MAP control.fixture.test:443 127.0.0.1:10001, MAP localhost 127.0.0.1",
  );
  expect(arguments_[0]).toBe(
    `--ignore-certificate-errors-spki-list=${fixture.spki_pins.join(",")}`,
  );
  expect(arguments_).not.toContain("--ignore-certificate-errors");
});

test("workerd preserves TLS names while mapping exact loopback addresses", () => {
  const config = workerdConfiguration(fixture, "../tnl-fixture.wasm");
  expect(config).toContain('certificateHost = "control.fixture.test"');
  expect(config).toContain('address = "127.0.0.1:10001"');
  expect(config.match(/certificateHost = "localhost"/g)).toHaveLength(2);
  expect(config).toContain('allow = ["127.0.0.0/8", "::1/128"]');
  expect(config).toContain("trustBrowserCas = false");
  expect(config).toContain('(name = "connector.wasm", wasm = embed "../tnl-fixture.wasm")');
  expect(config).not.toContain(fixture.token);
});
