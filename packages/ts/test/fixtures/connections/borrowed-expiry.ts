import assert from "node:assert/strict";
import { createInterface } from "node:readline";
import { createClient } from "@tnldotdev/tnl";
import { ownerIPC } from "../../../dist/internal/connector/connection_ipc.js";

const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const project = process.argv[2];
assert(project);
const deployment = createClient({ project, services: { api: { protocol: "http" } } }).deployment(
  "remote",
);
const first = await deployment.connect("api");
assert.ok("fetch" in first);
console.log("cold");
// keep the external cache from idling out before the original finite expiry.
await new Promise((resolve) => setTimeout(resolve, 20_000));
const warm = await deployment.connect("api");
assert.ok("fetch" in warm);
assert.equal(warm.url, first.url);
assert.equal((await lines.next()).value, "cross");
const crossing = await deployment.connect("api");
assert.ok("fetch" in crossing);
assert.equal(crossing.url, first.url);
assert.equal(crossing.fetch, first.fetch);
assert.equal((await lines.next()).value, "after");
const after = await deployment.connect("api");
assert.ok("fetch" in after);
assert.equal(after.url, first.url);
assert.equal(after.fetch, first.fetch);
const filename = process.env.TNL_CONNECTION_HANDLE;
assert.ok(filename);
const client = await ownerIPC(filename);
client.close();
const retained = await deployment.connect("api");
assert.ok("fetch" in retained);
assert.equal(retained.url, first.url);
console.log("retained");
assert.equal((await lines.next()).value, "stop");
await lines.return?.();
await deployment.close();
