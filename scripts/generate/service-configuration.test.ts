import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it } from "vitest";
import { repositoryGraph } from "./api-contracts.ts";

it("requires a full configuration fingerprint or explicit unconditional replacement", async () => {
  const bundle = (await repositoryGraph()).bundle("controlv1");
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  ajv.addSchema({ components: bundle.components }, "https://contracts.test/control");
  const check = ajv.compile({
    $ref: "https://contracts.test/control#/components/schemas/UpdateServiceRequest",
  });
  const metadata = {
    protocol: "http",
    publisher_pool: false,
    expected_trust_revision: "7",
  };
  const replacement = { ...metadata, configuration: { target: "localhost:3000" } };
  const digest = `sha256:${"a".repeat(64)}`;
  expect(check(metadata)).toBe(true);
  expect(check({ ...replacement, expected_configuration_digest: digest })).toBe(true);
  expect(check({ ...replacement, unconditional_configuration: true })).toBe(true);
  for (const invalid of [
    replacement,
    { ...metadata, expected_configuration_digest: digest },
    { ...metadata, unconditional_configuration: true },
    { ...replacement, expected_configuration_digest: digest, unconditional_configuration: true },
    ...[null, false, "true", 1].map((unconditional_configuration) => ({
      ...replacement,
      unconditional_configuration,
    })),
    ...["", digest.toUpperCase(), `"${digest}"`, null].map((expected_configuration_digest) => ({
      ...replacement,
      expected_configuration_digest,
    })),
  ]) {
    expect(check(invalid), JSON.stringify(invalid)).toBe(false);
  }
});

it("allows raw IP aliases for the server's 256 normalized-prefix limit", async () => {
  const bundle = (await repositoryGraph()).bundle("controlv1");
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  ajv.addSchema({ components: bundle.components }, "https://contracts.test/control");
  const check = ajv.compile({
    $ref: "https://contracts.test/control#/components/schemas/ProjectHTTPAccess",
  });
  const ip = Array.from({ length: 256 }, (_, index) => `192.0.2.${index}`);
  expect(check({ ip })).toBe(true);
  expect(check({ ip: [...ip, ip[0], "::ffff:192.0.2.0", "192.0.2.0/32"] })).toBe(true);
  for (const invalid of [null, [], [null], ["a".repeat(65)]]) {
    expect(check({ ip: invalid }), JSON.stringify(invalid)).toBe(false);
  }
});
