/// <reference types="bun" />
import assert from "node:assert/strict";
import { createInterface } from "node:readline";

const bun = process.argv[3] === "bun";
const sdk = bun ? await import("@tnldotdev/tnl/bun") : await import("@tnldotdev/tnl/node");
const input = createInterface({ input: process.stdin });
const lines = input[Symbol.asyncIterator]();
const key = await lines.next();
assert.ok(!key.done);
const instance = process.argv[4];
const controlUrl = process.argv[2];
assert.ok(instance && controlUrl);
const owner = await sdk.publisher({
  instance,
  ...(key.value === "" ? {} : { controlUrl }),
  enrollment: () => {
    if (!key.value) throw new Error("saved publisher asked for bootstrap");
    return key.value;
  },
});
const handler = () => new Response(`${instance}:${key.value ? "initial" : "reopened"}`);
// the first Bun publication uses the SDK's Fetch adapter; reopening also
// exercises its native Bun.serve listener overload with the same identity.
const server =
  bun && !key.value ? Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: handler }) : undefined;
try {
  const publication =
    server === undefined
      ? await (await import("@tnldotdev/tnl/node")).publish(owner, "web", handler)
      : await (await import("@tnldotdev/tnl/bun")).publish(owner, "web", server);
  console.log(
    JSON.stringify({ identity: owner.publisherIdentityID, url: publication.publisherURL }),
  );
  await lines.next();
} finally {
  input.close();
  try {
    await owner.close();
  } finally {
    await server?.stop(true);
  }
}
