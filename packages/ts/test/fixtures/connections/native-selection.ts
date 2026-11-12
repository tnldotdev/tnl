import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import { cp, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";
import * as z from "zod";
import { tnl, type IdentitySource, type NativeAcquisition } from "@tnldotdev/tnl";
import { environmentSelectionSchema } from "../../../dist/internal/connector/contract.js";
import { identitySourceSelectionSchema } from "../../../dist/internal/identity/validation.js";

// consume the actual defining native startup facts supplied by the Go fixture.
// these facts grant nothing; native/authority still verify the signed proof.
const request = z.strictObject({ schema: z.literal(1), selection: environmentSelectionSchema, source: identitySourceSelectionSchema }).parse(JSON.parse(await readFile("environment.json", "utf8")));
assert.equal(request.source.kind, "oidc");
assert.deepEqual(request.selection.services, { api: "http" });
const directory = process.cwd();
const services = Object.freeze({ api: Object.freeze({ protocol: "http" as const }) });
const token = (await readFile("assertion", "utf8")).trim();
const proofExpiry = () => {
  const encoded = token.split(".")[1];
  assert.ok(encoded);
  // the declared expiry only bounds SDK acquisition. authority verifies it.
  return new Date(z.object({ exp: z.number().int() }).parse(JSON.parse(Buffer.from(encoded, "base64url").toString())).exp * 1000);
};
const nativeProvider = process.argv.includes("provider");
const rotatingFile = process.argv.includes("refresh");
let acquisitions = 0;
const acquisition: NativeAcquisition | undefined = nativeProvider
  ? { method: "github-actions", audience: request.selection.environment.server }
  : rotatingFile ? { method: "token-file", token_file: path.join(directory, "assertion") } : undefined;
const identity: IdentitySource & { permission_id: string } = {
  kind: "oidc", machine_id: request.source.machine_id, permission_id: request.selection.permission_id,
  ...(acquisition === undefined ? { assertion: async () => { acquisitions++; return { token, expiresAt: proofExpiry() }; } } : { acquisition }),
};
const options = { services, environment: request.selection.environment, identity };
const selected = tnl.client(options);
const clients = [selected];
const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const listeners = process.listenerCount("beforeExit");
let copy: string | undefined;

async function actualHandle(): Promise<string> {
  const root = process.env.TMPDIR;
  assert.ok(root);
  const found: string[] = [];
  for (const entry of await readdir(root)) {
    if (!entry.startsWith("tnl-connections-")) continue;
    const file = path.join(root, entry, "handle.json");
    try { await readFile(file); found.push(file); }
    catch (error) { if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error; }
  }
  assert.equal(found.length, 1);
  assert.ok(found[0]);
  return found[0];
}

try {
  const prepared = await Promise.all(Array.from({ length: nativeProvider ? 4 : 1 }, () => selected.connect("api")));
  const first = prepared[0];
  assert.ok(first);
  for (const value of prepared) assert.deepEqual(value, first);
  const owner = await actualHandle();
  assert.equal(acquisitions, nativeProvider || rotatingFile ? 0 : 1);
  assert.equal(process.listenerCount("beforeExit"), listeners);
  console.log("cold");
  assert.equal((await lines.next()).value, "warm");
  if (nativeProvider) process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "provider-warm";
  for (let i = 0; i < 10; i++) assert.deepEqual(await selected.connect("api"), first);
  assert.equal(await actualHandle(), owner);
  assert.equal(acquisitions, nativeProvider || rotatingFile ? 0 : 11);
  if (nativeProvider) {
    delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    await assert.rejects(selected.connect("api"), { code: "sdk.workload_assertion_unavailable" });
    process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "provider-warm";
    assert.deepEqual(await selected.connect("api"), first);
    assert.equal(await actualHandle(), owner);
  }
  console.log("warm");

  if (rotatingFile) {
    let created = 0, closed = 0;
    const previous = process.env.TNL_CONNECTION_HANDLE;
    process.env.TNL_CONNECTION_HANDLE = owner;
    // retain the ordinary driver-factory proof using a borrowed exact owner.
    const getClient = tnl.client("api", {
      create(connection) { assert.ok("fetch" in connection); created++; return connection.fetch; },
      close() { closed++; },
    });
    try {
      const client = await getClient();
      for (let i = 0; i < 3; i++) assert.equal(await getClient(), client);
      assert.equal(created, 1); assert.equal(closed, 0);
      const response = await client("/refresh-stream");
      const reader = response.body?.getReader();
      assert.ok(reader);
      const before = await reader.read();
      assert.equal(new TextDecoder().decode(before.value), "before-proof\n");
      console.log("streaming");
      assert.equal((await lines.next()).value, "refreshed");
      let after = "";
      for (;;) { const chunk = await reader.read(); if (chunk.done) break; after += new TextDecoder().decode(chunk.value); }
      assert.equal(after, "after-proof\n");
      const refreshed = await selected.connect("api");
      assert.equal(refreshed.url, first.url); assert.equal(refreshed.fetch, first.fetch);
      assert.equal(await actualHandle(), owner);
    } finally {
      await getClient.close();
      if (previous === undefined) delete process.env.TNL_CONNECTION_HANDLE; else process.env.TNL_CONNECTION_HANDLE = previous;
    }
    assert.equal(closed, 1);
    console.log("retained");
  }

  if (process.argv.includes("copies")) {
    assert.equal((await lines.next()).value, "isolate");
    const root = path.resolve(import.meta.dirname, "../../..");
    copy = await mkdtemp(path.join(root, ".sdk-copy-"));
    process.once("exit", () => { if (copy !== undefined) rmSync(copy, { recursive: true, force: true }); });
    await cp(path.join(root, "dist"), path.join(copy, "dist"), { recursive: true });
    await cp(path.join(root, "package.json"), path.join(copy, "package.json"));
    const second: typeof import("@tnldotdev/tnl") = await import(pathToFileURL(path.join(copy, "dist/index.js")).href);
    const common: typeof import("@tnldotdev/tnl") = createRequire(path.join(copy, "package.json"))("@tnldotdev/tnl");
    const unbundled: typeof import("../../../src/internal/connector/environment_client.js") = await import(pathToFileURL(path.join(copy, "dist/internal/connector/environment_client.js")).href);
    const retired = "@tnldotdev/tnl/workload";
    await assert.rejects(import(retired), { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" });
    // each copy consumes the normal explicit constructor, not a global registry.
    const isolatedDirectory = path.join(directory, "other-project");
    const settings = [first];
    let isolatedAcquisitions = 0;
    for (const [index, boundary] of ["directory", "TNL_STATE_DIR", "TNL_SERVER"].entries()) {
      const previous = process.env[boundary];
      if (boundary === "directory") {
        const { mkdir } = await import("node:fs/promises"); await mkdir(isolatedDirectory, { recursive: true }); process.chdir(isolatedDirectory);
      } else process.env[boundary] = boundary === "TNL_SERVER" ? "https://must-not-select.invalid" : path.join(directory, "other-state");
      try {
        const isolated = { ...options, identity: { kind: "oidc" as const, machine_id: identity.machine_id, permission_id: identity.permission_id, assertion: async () => { isolatedAcquisitions++; return { token, expiresAt: proofExpiry() }; } } };
        const client = index === 0 ? second.tnl.client(isolated) : index === 1 ? common.tnl.client(isolated) : unbundled.environmentClient(isolated);
        clients.push(client);
        const current = await client.connect("api");
        assert.equal(settings.some((value) => value.fetch === current.fetch), false);
        settings.push(current);
      } finally {
        process.chdir(directory);
        if (previous === undefined) delete process.env[boundary]; else process.env[boundary] = previous;
      }
      assert.deepEqual(await selected.connect("api"), first);
    }
    assert.equal(isolatedAcquisitions, 3);
    assert.equal(acquisitions, 14);
    assert.equal(process.listenerCount("beforeExit"), listeners);
    console.log("isolated");
  }
  assert.equal((await lines.next()).value, "stop");
} finally {
  const results = await Promise.allSettled(clients.map((client) => client.close()));
  await lines.return?.();
  if (copy !== undefined) await rm(copy, { recursive: true, force: true });
  const failures = results.filter((result): result is PromiseRejectedResult => result.status === "rejected");
  if (failures.length) throw new AggregateError(failures.map((result) => result.reason), "fixture clients failed joined cleanup");
}
