import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { tnl } from "@tnldotdev/tnl";
import { configureWorkload } from "@tnldotdev/tnl/workload";

const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const token = (await readFile("assertion", "utf8")).trim();
configureWorkload({ name: "test", token: async () => token });
const handle = tnl.connect("api");
const first = await handle;
console.log("cold");
assert.equal((await lines.next()).value, "warm");
for (let i = 0; i < 10; i++) {
  const next = await handle;
  assert.deepEqual(next, first);
}
console.log("warm");
assert.equal((await lines.next()).value, "stop");
await lines.return?.();
