import { Ajv2020 } from "ajv/dist/2020.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "vitest";
import { parseJSON } from "../validation.ts";
import { record, repositoryGraph, root } from "./api-contracts.ts";
import { z } from "zod";
import { deploymentTargetSchema } from "../../packages/ts/src/internal/management/zod.gen.ts";

test("generated project schema separates public URLs from service endpoint exposure", async () => {
  const schema = parseJSON(
    await readFile(join(root, "schema/v1.json"), "utf8"),
    z.record(z.string(), z.unknown()),
    "configuration schema",
  );
  const validate = new Ajv2020({ strict: false, validateFormats: false }).compile(schema);
  const document = (binding: object) => ({
    version: 1,
    tnl: {
      services: { web: {} },
      deployments: { production: { targets: { web: binding } } },
    },
  });
  for (const binding of [{}, { address: "http://app.internal:3000" }]) {
    expect(
      validate(document({ ...binding, public_url: {} })),
      JSON.stringify(validate.errors),
    ).toBe(true);
    for (const publicExposure of [false, true]) {
      expect(validate(document({ ...binding, public_url: {}, public: publicExposure }))).toBe(
        false,
      );
    }
  }
  for (const publicExposure of [false, true]) {
    expect(
      validate(document({ address: "http://app.internal:3000", public: publicExposure })),
      JSON.stringify(validate.errors),
    ).toBe(true);
  }
});

test("canonical apply contract rejects either endpoint flag on a public URL", async () => {
  const document = (await repositoryGraph()).browserBundle("controlv1", []);
  const schemas = record(record(document.components).schemas);
  const validate = new Ajv2020({ strict: false, validateFormats: false }).compile({
    components: { schemas },
    $ref: "#/components/schemas/ProjectServiceConfiguration",
  });
  for (const target of ["app", "http://app.internal:3000"]) {
    expect(validate({ target, public_url: {} }), JSON.stringify(validate.errors)).toBe(true);
    for (const publicExposure of [false, true]) {
      expect(validate({ target, public_url: {}, public: publicExposure })).toBe(false);
    }
  }
  for (const publicExposure of [false, true]) {
    expect(
      validate({ target: "http://app.internal:3000", public: publicExposure }),
      JSON.stringify(validate.errors),
    ).toBe(true);
  }
});

test("generated runtime management validators cannot accept publication configuration", () => {
  const target = { address: "http://app.internal:3000" };
  expect(deploymentTargetSchema.safeParse(target).success).toBe(true);
  for (const publicExposure of [false, true]) {
    expect(
      deploymentTargetSchema.safeParse({ ...target, public_url: {}, public: publicExposure })
        .success,
    ).toBe(false);
  }
});
