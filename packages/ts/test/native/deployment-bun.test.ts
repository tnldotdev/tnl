import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { expect, onTestFinished, test } from "vitest";
import { startTestBootstrap } from "../helpers/bootstrap.js";
import { installRuntimeFixture } from "../helpers/framework.js";
import { subprocessEnvironment } from "../helpers/environment.js";

test("real Bun deployment publication preserves its listener and restores stop", async () => {
  const bootstrap = await startTestBootstrap();
  const directory = await mkdtemp(
    fileURLToPath(new URL("../fixtures/bun/.tnl-publication-", import.meta.url)),
  );
  onTestFinished(() => rm(directory, { recursive: true, force: true }));
  await installRuntimeFixture(directory, bootstrap);
  const file = join(directory, "publish.ts");
  await writeFile(
    file,
    `
    import assert from "node:assert/strict";
    import { createClient, tnl } from "@tnldotdev/tnl";
    assert.equal("open" in tnl, false);
    const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch() { return new Response("Bun publication"); } });
    const stop = server.stop;
    const local = createClient({ services: { api: { protocol: "http" } } }).deployment("local");
    const publication = await local.publish("api", server);
    assert.equal(publication.url, "https://api.member.example");
    assert.notEqual(server.stop, stop);
    await publication.close();
    assert.equal(server.stop, stop);
    assert.equal(await (await fetch(server.url)).text(), "Bun publication");
    await local.close();
    await server.stop(true);
  `,
  );
  await promisify(execFile)("bun", [file], {
    cwd: directory,
    env: subprocessEnvironment(bootstrap.environment),
    timeout: 15_000,
  });
  expect(bootstrap.requests.map((request) => request.path)).toEqual(
    expect.arrayContaining(["/v1/prepare", "/v1/register", "/v1/status", "/v1/unregister"]),
  );
});
