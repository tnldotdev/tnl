import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { expect, test } from "vitest";
import { tnl } from "@tnldotdev/tnl";
import { subprocessEnvironment } from "../helpers/environment.js";

const run = promisify(execFile);
const fixture = new URL("../consumer-fixtures/environment-client-proposal-v2/", import.meta.url);

async function typecheck(configuration: string) {
  const result = await run(
    "pnpm",
    ["exec", "tsc", "--project", fileURLToPath(new URL(configuration, fixture))],
    { env: subprocessEnvironment(), timeout: 15_000 },
  );
  expect(result.stdout).toBe("");
}

test("the clean-break public SDK no longer accepts a publisher-group descriptor", async () => {
  await typecheck("retired-public-api.tsconfig.json");
});

test("JavaScript callers cannot invoke the retired descriptor constructor", () => {
  const descriptor = {
    schema: 1,
    server: "https://control.example",
    team_id: `tm_${"a".repeat(22)}`,
    project_key: "customer-services",
    source_fingerprint: "a".repeat(64),
    project_label: "customer-services",
    group_id: `pgrp_${"a".repeat(22)}`,
    group_name: "customer-a",
    services: { api: "http" },
    workloads: {
      backend: { provider: "oidc", services: ["api"], max_duration_seconds: 3600 },
    },
  };
  expect(() =>
    Reflect.apply(tnl.client, tnl, [
      { connection: descriptor, workload: { name: "backend", token: async () => "unused" } },
    ]),
  ).toThrow(expect.objectContaining({ code: "sdk.configuration_invalid" }));
});
