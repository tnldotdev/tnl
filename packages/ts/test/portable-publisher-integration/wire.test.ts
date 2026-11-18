import { expect, test } from "vitest";
import {
  publisherChromeArguments,
  publisherWorkerdConfiguration,
} from "../../../../scripts/test/portable-publisher-config.ts";
import { fixtureSchema, publisherFailures, PublisherFixtureAssertion } from "./fixture.ts";
import { publisherHandler } from "./handler.ts";

const fixture = fixtureSchema.parse({
  version: 1,
  project: "team/project",
  deployment: "preview",
  token: "private-fixture-token",
  sibling_token: "private-sibling-fixture-token",
  enrollment: "disposable-enrollment-fixture",
  control_url: "https://control.fixture.test",
  control_dial_address: "127.0.0.1:1234",
  control_root_pem: "fixture-control-ca",
  relay_root_pem: "fixture-relay-ca",
  service_root_pem: "fixture-service-ca",
  named_url: "https://web.apps.fixture.test",
  restricted_url: "https://restricted.apps.fixture.test",
  private_host: "private.apps.fixture.test",
  relays: [
    { address: "localhost:1235", dial_address: "127.0.0.1:1235", tls_server_name: "localhost" },
    { address: "localhost:1236", dial_address: "127.0.0.1:1236", tls_server_name: "localhost" },
  ],
  spki_pins: ["a".repeat(43) + "=", "b".repeat(43) + "=", "c".repeat(43) + "="],
  api_url: "https://localhost:1237",
  api_token: "private-fixture-api-token",
  runner_certificate_pem: "fixture-runner-certificate",
  runner_private_key_pem: "fixture-runner-key",
});

test("publisher diagnostics retain safe phases and codes without private error messages", () => {
  const secret = "private request body and signing credential";
  const error = new AggregateError(
    [
      new PublisherFixtureAssertion("public visitor did not verify publisher TLS"),
      Object.assign(new Error(secret), { code: "sdk.cleanup_failed" }),
      new DOMException(secret, "TimeoutError"),
      new Error(secret),
    ],
    secret,
  );
  const failures = publisherFailures(error, "public-exercise");
  expect(failures).toEqual([
    {
      phase: "public-exercise",
      code: "fixture.assertion_failed",
      detail: "public visitor did not verify publisher TLS",
    },
    { phase: "public-exercise", code: "sdk.cleanup_failed" },
    { phase: "public-exercise", code: "TimeoutError" },
    { phase: "public-exercise", code: "fixture.operation_failed" },
  ]);
  expect(JSON.stringify(failures)).not.toContain(secret);
});

test("Chrome trusts exact fixture pins without disabling TLS verification globally", () => {
  const args = publisherChromeArguments(fixture);
  expect(args).not.toContain("--ignore-certificate-errors");
  expect(args).not.toContain("--disable-web-security");
  expect(args).toContain(`--ignore-certificate-errors-spki-list=${fixture.spki_pins.join(",")}`);
});

test("publisher diagnostics name platform error kinds without their messages", () => {
  expect(publisherFailures(new TypeError("private payload"), "upload-response")).toEqual([
    { phase: "upload-response", code: "TypeError" },
  ]);
});

test("workerd uses persisted SQLite, static Go/WASM, and no node compatibility mode", () => {
  const config = publisherWorkerdConfiguration(
    fixture,
    "../tnl-publisher-fixture.wasm",
    "/private/storage",
  );
  expect(config).toContain(
    '(name = "publisher.wasm", wasm = embed "../tnl-publisher-fixture.wasm")',
  );
  expect(config).toContain('durableObjectStorage = (localDisk = "storage")');
  expect(config).toContain('path = "/private/storage", writable = true');
  expect(config).toContain("enableSql = true");
  expect(config).not.toContain("inMemory");
  expect(config).not.toContain("nodejs_compat");
  expect(config).not.toContain("preventEviction");
});

// these prove fixture synchronization only, not Go/WASM publication. the opt-in
// daemon suite is the only proof that these events cross actual publisher I/O.
test("the fixture response exposes a first chunk before another request releases its tail", async () => {
  const fixture = publisherHandler("fixture");
  const response = await fixture.handle(new Request("https://service.fixture.test/stream"));
  const reader = response.body?.getReader();
  expect(reader).toBeDefined();
  expect(new TextDecoder().decode((await reader?.read())?.value)).toBe("first\n");
  await fixture.handle(new Request("https://service.fixture.test/release"));
  expect(new TextDecoder().decode((await reader?.read())?.value)).toBe("last\n");
  expect((await reader?.read())?.done).toBe(true);
  reader?.releaseLock();
});

test("the fixture independently records response cancellation and request abortion", async () => {
  const fixture = publisherHandler("fixture");
  const controller = new AbortController();
  const response = await fixture.handle(
    new Request("https://service.fixture.test/cancel", {
      signal: controller.signal,
    }),
  );
  await response.body?.cancel();
  controller.abort();
  const evidence = await fixture.handle(new Request("https://service.fixture.test/evidence"));
  expect(await evidence.json()).toMatchObject({ canceled: true, requestAborted: true });
});
