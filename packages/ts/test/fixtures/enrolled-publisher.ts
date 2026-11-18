import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const useBun = process.argv[3] === "bun";
const { publisher, TnlError } = useBun
  ? await import("@tnldotdev/tnl/bun")
  : await import("@tnldotdev/tnl/node");

const controlUrl = process.argv[2];
const enrollment = readFileSync(0, "utf8").trim();
assert.ok(controlUrl && enrollment);
let calls = 0;
const first = await publisher({
  controlUrl,
  enrollment: () => {
    calls++;
    return enrollment;
  },
});
try {
  assert.equal(calls, 1);
  await assert.rejects(
    useBun
      ? (await import("@tnldotdev/tnl/bun")).publish(
          first,
          "unapproved",
          () => new Response("unused"),
        )
      : (await import("@tnldotdev/tnl/node")).publish(
          first,
          "unapproved",
          () => new Response("unused"),
        ),
    (cause: unknown) => cause instanceof TnlError && cause.code === "sdk.request_rejected",
  );
} finally {
  await first.close();
}
const second = await publisher({
  enrollment: () => {
    throw new Error("a saved publisher must not read bootstrap again");
  },
});
try {
  assert.equal(second.publisherIdentityID, first.publisherIdentityID);
  assert.equal(second.deploymentID, first.deploymentID);
  assert.equal(second.controlUrl, controlUrl);
} finally {
  await second.close();
}
