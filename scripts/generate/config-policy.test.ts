import { Ajv2020 } from "ajv/dist/2020.js";
import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";
import { z } from "zod";

it("keeps generated HTTP policy capabilities and duplicate-owner checks exact", async () => {
  const schema = z
    .record(z.string(), z.unknown())
    .parse(JSON.parse(await readFile(new URL("../../schema/v1.json", import.meta.url), "utf8")));
  const validate = new Ajv2020().compile(schema);
  for (const [binding, valid] of [
    [{ public_url: {}, http: { access: "anonymous", limits: { total: 100 } } }, true],
    [
      { public_url: { limits: { traffic: { connections: 8 } } }, http: { limits: { total: 100 } } },
      true,
    ],
    [{ http: { access: "restricted", limits: { total: 100 } } }, true],
    [{ http: { access: "anonymous" } }, false],
    [{ http: { access: { mode: "anonymous" } } }, false],
    [{ public_url: { access: "restricted" }, http: { access: "anonymous" } }, false],
    [
      { public_url: { limits: { http: { total: 100 } } }, http: { limits: { concurrency: 2 } } },
      false,
    ],
    [{ public_url: {}, public: true }, false],
  ] as const) {
    const document = {
      version: 1,
      tnl: { services: { web: {} }, deployments: { local: { targets: { web: binding } } } },
    };
    expect(validate(document), JSON.stringify({ binding, errors: validate.errors })).toBe(valid);
  }
});
