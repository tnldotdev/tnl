import assert from "node:assert/strict";
import { request } from "node:https";
import { readFile } from "node:fs/promises";
import { createClient } from "@tnldotdev/tnl";

const protocol = process.argv[2];
const name = protocol === "kubernetes" ? "cluster" : "api";
const project = process.argv[3],
  hostname = process.argv[4];
assert(project && hostname);
const deployment = createClient({
  project,
  services: { api: { protocol: "http" }, cluster: { protocol: "kubernetes" } },
}).deployment("remote");
const [first, second] = await Promise.all([deployment.connect(name), deployment.connect(name)]);
assert.deepEqual(Object.keys(first), Object.keys(second));
assert.equal(Reflect.get(first, "then"), undefined);
assert(Object.isFrozen(first));
if ("fetch" in first) {
  for (const connection of [first, second]) {
    assert("fetch" in connection);
    const response = await connection.fetch("/echo", {
      method: "POST",
      headers: { authorization: "Bearer application-only" },
      body: "streamed-body",
    });
    assert.equal(response.status, 201);
    assert.equal(await response.text(), "streamed-body");
  }
} else if ("server" in first && "server" in second) {
  assert.equal(first.server, second.server);
  assert(first.server.startsWith("https://127.0.0.1:"));
  const config = await readFile(first.kubeconfig, "utf8");
  assert(config.includes(first.server));
  assert(config.includes(`tls-server-name: ${hostname}`));
  assert(config.includes(first.context));
  const result = await new Promise<{ status: number | undefined; body: string }>(
    (resolve, reject) => {
      const outgoing = request(
        `${first.server}/echo`,
        {
          method: "POST",
          servername: hostname,
          rejectUnauthorized: true,
          headers: { authorization: "Bearer application-only" },
        },
        (response) => {
          const chunks: Buffer[] = [];
          response.on("data", (data: Buffer) => chunks.push(data));
          response.on("end", () =>
            resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString() }),
          );
          response.on("error", reject);
        },
      );
      outgoing.on("error", reject);
      outgoing.end("streamed-body");
    },
  );
  assert.equal(result.status, 201);
  assert.equal(result.body, "streamed-body");
} else assert.fail("the native fixture returned the wrong protocol settings");
await deployment.close();
