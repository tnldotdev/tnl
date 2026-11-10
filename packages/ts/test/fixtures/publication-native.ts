#!/usr/bin/env node
// this test launcher supplies only endpoint discovery. registration, observation,
// publication and stream drain use the native owner's unmodified HTTP boundary.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const raw: unknown = JSON.parse(await readFile(`${process.argv[1]}.json`, "utf8"));
if (
  typeof raw !== "object" ||
  raw === null ||
  !("version" in raw) ||
  raw.version !== 1 ||
  !("scope" in raw) ||
  raw.scope !== "owner" ||
  !("url" in raw) ||
  typeof raw.url !== "string" ||
  !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(raw.url) ||
  !("capability" in raw) ||
  typeof raw.capability !== "string" ||
  !/^[0-9a-f]{64}$/.test(raw.capability)
)
  throw new Error("invalid private native endpoint fixture");
const args = process.argv.slice(2);
assert.deepEqual(args.slice(0, 3), ["--no-telemetry", "runtime", "endpoint"]);
const invocation = args[args.indexOf("--invocation-id") + 1];
assert.ok(invocation && /^ivk_[A-Za-z0-9]{22}$/.test(invocation));
const response = await fetch(`${raw.url}/v1/capabilities`, {
  method: "POST",
  redirect: "manual",
  headers: { Authorization: `Bearer ${raw.capability}`, "Content-Type": "application/json" },
  body: JSON.stringify({ scope: "invocation", invocation_id: invocation }),
});
assert.equal(response.status, 200);
process.stdout.write(await response.text());
