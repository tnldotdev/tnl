import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import { cp, mkdtemp, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as z from "zod";
import { createInterface } from "node:readline";
import { configureWorkload } from "@tnldotdev/tnl/workload";
import { createClient } from "@tnldotdev/tnl";

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
const manifest = z
  .object({ team: z.string(), project_key: z.string(), server: z.string() })
  .parse(JSON.parse(await readFile(".tnl/generated/workloads.json", "utf8")));
const options = {
  project: `${manifest.team}/${manifest.project_key}`,
  services: { api: { protocol: "http" } },
} as const;
const deployment = createClient(options).deployment("production");
const deployments = [deployment];
const handle = () => deployment.connect("api");
const handles = nativeProvider ? Array.from({ length: 4 }, handle) : [handle()];
let copy: string | undefined;
let copiedWorkload: typeof import("@tnldotdev/tnl/workload") | undefined;
let copiedSDK: typeof import("@tnldotdev/tnl") | undefined;
const listeners = process.listenerCount("beforeExit");
if (process.argv.includes("copies")) {
  const root = path.resolve(import.meta.dirname, "../../..");
  copy = await mkdtemp(path.join(root, ".sdk-copy-"));
  process.once("exit", () => {
    if (copy !== undefined) rmSync(copy, { recursive: true, force: true });
  });
  await cp(path.join(root, "dist"), path.join(copy, "dist"), { recursive: true });
  await cp(path.join(root, "package.json"), path.join(copy, "package.json"));
  const unbundled: typeof import("@tnldotdev/tnl") = await import(
    pathToFileURL(path.join(copy, "dist/index.js")).href
  );
  copiedSDK = unbundled;
  copiedWorkload = await import(pathToFileURL(path.join(copy, "dist/workload.js")).href);
  assert.ok(copiedWorkload);
  assert.throws(
    () => copiedWorkload?.configureWorkload({ name: "test", token: async () => "different" }),
    { code: "sdk.workload_required" },
  );
}
const [first] = await Promise.all(handles);
assert.ok(first);
assert.ok("fetch" in first);
assert.equal(acquisitions, nativeProvider || rotatingFile ? 0 : handles.length);
assert.equal(process.listenerCount("beforeExit"), listeners + deployments.length);
console.log("cold");
assert.equal((await lines.next()).value, "warm");
if (nativeProvider) process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "provider-warm";
for (let i = 0; i < 10; i++) {
  for (const selected of nativeProvider ? deployments.slice(0, 1) : deployments)
    assert.equal((await selected.connect("api")).url, first.url);
}
assert.equal(acquisitions, nativeProvider || rotatingFile ? 0 : deployments.length * 11);
if (nativeProvider) {
  delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  await assert.rejects(handle(), { code: "sdk.workload_assertion_unavailable" });
  process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "provider-warm";
  assert.equal((await handle()).url, first.url);
}
console.log("warm");
if (rotatingFile) {
  let created = 0;
  let closed = 0;
  const getClient = deployment.client("api", {
    create(connection) {
      assert.ok("fetch" in connection);
      created++;
      return connection.fetch;
    },
    close() {
      closed++;
    },
  });
  const client = await getClient();
  for (let i = 0; i < 3; i++) assert.equal(await getClient(), client);
  assert.equal(created, 1);
  assert.equal(closed, 0);
  const response = await client("/refresh-stream");
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
  const refreshed = await handle();
  assert.ok("fetch" in refreshed);
  assert.equal(refreshed.url, first.url);
  assert.equal(refreshed.fetch, first.fetch);
  await getClient.close();
  assert.equal(closed, 1);
  console.log("retained");
}
if (copiedWorkload !== undefined) {
  assert.equal((await lines.next()).value, "isolate");
  const directory = process.cwd();
  const isolated = path.join(directory, "other-project");
  await cp(path.join(directory, ".tnl"), path.join(isolated, ".tnl"), { recursive: true });
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
      assert(copiedSDK);
      const isolatedDeployment = copiedSDK.createClient(options).deployment("production");
      deployments.push(isolatedDeployment);
      const current = await isolatedDeployment.connect("api");
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
    assert.equal((await deployment.connect("api")).url, first.url);
  }
  assert.equal(isolatedAcquisitions, 3);
  assert.equal(acquisitions, handles.length * 14);
  assert.equal(process.listenerCount("beforeExit"), listeners + deployments.length);
  console.log("isolated");
}
assert.equal((await lines.next()).value, "stop");
await lines.return?.();
await Promise.all(deployments.map((selected) => selected.close()));
if (copy !== undefined) await rm(copy, { recursive: true, force: true });
