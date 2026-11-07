import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import { cp, mkdtemp, readFile, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as z from "zod";
import { createInterface } from "node:readline";
import { tnl } from "@tnldotdev/tnl";
import { configureWorkload } from "@tnldotdev/tnl/workload";

const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const token = (await readFile("assertion", "utf8")).trim();
let acquisitions = 0;
const nativeProvider = process.argv.includes("provider");
const rotatingFile = process.argv.includes("refresh");
if (rotatingFile) configureWorkload({ name: "test", tokenFile: "assertion" });
else if (!nativeProvider)
  configureWorkload({
    name: "test",
    token: async () => {
      acquisitions++;
      return token;
    },
  });
const handle = tnl.connect("api");
const handles = nativeProvider ? Array.from({ length: 4 }, () => tnl.connect("api")) : [handle];
let copy: string | undefined;
let copiedWorkload: typeof import("@tnldotdev/tnl/workload") | undefined;
const listeners = process.listenerCount("beforeExit");
if (process.argv.includes("copies")) {
  const root = path.resolve(import.meta.dirname, "../../..");
  copy = await mkdtemp(path.join(root, ".sdk-copy-"));
  process.once("exit", () => {
    if (copy !== undefined) rmSync(copy, { recursive: true, force: true });
  });
  await cp(path.join(root, "dist"), path.join(copy, "dist"), { recursive: true });
  await cp(path.join(root, "package.json"), path.join(copy, "package.json"));
  const second: typeof import("@tnldotdev/tnl") = await import(
    pathToFileURL(path.join(copy, "dist/index.js")).href
  );
  const common: typeof import("@tnldotdev/tnl") = createRequire(path.join(copy, "package.json"))(
    "@tnldotdev/tnl",
  );
  const unbundled: typeof import("../../../src/internal/connector/connection.js") = await import(
    pathToFileURL(path.join(copy, "dist/internal/connector/connection.js")).href
  );
  copiedWorkload = await import(pathToFileURL(path.join(copy, "dist/workload.js")).href);
  assert.ok(copiedWorkload);
  assert.throws(
    () => copiedWorkload?.configureWorkload({ name: "test", token: async () => "different" }),
    { code: "sdk.workload_required" },
  );
  handles.push(
    second.tnl.connect("api"),
    common.tnl.connect("api"),
    unbundled.connectionHandle("api", () => {}),
  );
}
const [first] = await Promise.all(handles);
assert.ok(first);
assert.ok("fetch" in first);
assert.equal(acquisitions, nativeProvider || rotatingFile ? 0 : handles.length);
assert.equal(process.listenerCount("beforeExit"), listeners + 1);
console.log("cold");
assert.equal((await lines.next()).value, "warm");
if (nativeProvider) process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "provider-warm";
for (let i = 0; i < 10; i++) {
  for (const handle of nativeProvider ? handles.slice(0, 1) : handles)
    assert.deepEqual(await handle, first);
}
assert.equal(acquisitions, nativeProvider || rotatingFile ? 0 : handles.length * 11);
if (nativeProvider) {
  delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  await assert.rejects(Promise.resolve(handle), { code: "sdk.workload_assertion_unavailable" });
  process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "provider-warm";
  assert.deepEqual(await handle, first);
}
console.log("warm");
if (rotatingFile) {
  const response = await first.fetch("/refresh-stream");
  const reader = response.body?.getReader();
  assert.ok(reader);
  const before = await reader.read();
  assert.equal(new TextDecoder().decode(before.value), "before-proof\n");
  console.log("streaming");
  assert.equal((await lines.next()).value, "refreshed");
  let after = "";
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) break;
    after += new TextDecoder().decode(chunk.value);
  }
  assert.equal(after, "after-proof\n");
  console.log("retained");
}
if (copiedWorkload !== undefined) {
  assert.equal((await lines.next()).value, "isolate");
  const directory = process.cwd();
  const isolated = path.join(directory, "other-project");
  await cp(path.join(directory, ".tnl"), path.join(isolated, ".tnl"), { recursive: true });
  const manifest = z
    .object({ server: z.string() })
    .parse(JSON.parse(await readFile(".tnl/generated/workloads.json", "utf8")));
  const settings = [first];
  let isolatedAcquisitions = 0;
  for (const boundary of ["directory", "TNL_STATE_DIR", "TNL_SERVER"]) {
    const previous = process.env[boundary];
    if (boundary === "directory") process.chdir(isolated);
    else
      process.env[boundary] =
        boundary === "TNL_SERVER" ? manifest.server : path.join(directory, "other-state");
    try {
      copiedWorkload.configureWorkload({
        name: "test",
        token: async () => {
          isolatedAcquisitions++;
          return token;
        },
      });
      const current = await tnl.connect("api");
      assert.ok("fetch" in current);
      assert.equal(
        settings.some((value) => value.fetch === current.fetch),
        false,
      );
      settings.push(current);
    } finally {
      process.chdir(directory);
      if (previous === undefined) delete process.env[boundary];
      else process.env[boundary] = previous;
    }
    for (const handle of handles) assert.deepEqual(await handle, first);
  }
  assert.equal(isolatedAcquisitions, 3);
  assert.equal(acquisitions, handles.length * 14);
  assert.equal(process.listenerCount("beforeExit"), listeners + 4);
  console.log("isolated");
}
assert.equal((await lines.next()).value, "stop");
await lines.return?.();
if (copy !== undefined) await rm(copy, { recursive: true, force: true });
