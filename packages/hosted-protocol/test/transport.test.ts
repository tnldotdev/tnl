import { readFileSync } from "node:fs";

import Ajv2020 from "ajv/dist/2020.js";
import { expect, it } from "vitest";

const readJSON = (path: string): unknown =>
  JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));

const descriptor = readJSON("../../../api/fixtures/transport/v1/tailcat-descriptor.json");
const schema = readJSON("../../../api/transport/v1/tailcat-descriptor.schema.json");
const validate = new Ajv2020().compile(schema);

it("validates the Tailcat descriptor fixture", () => {
  expect(validate(descriptor), JSON.stringify(validate.errors)).toBe(true);
});

it("rejects agent-controlled Tailcat configuration", () => {
  expect(validate({ ...descriptor, relay_url: "https://untrusted.example" })).toBe(false);
});
