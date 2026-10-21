import assert from "node:assert/strict";
import { request } from "node:https";
import { readFile } from "node:fs/promises";
import { tnl } from "@tnldotdev/tnl";

const protocol = process.argv[2];
const name = protocol === "kubernetes" ? "cluster" : "api";
const handle = tnl.connect(name);
const synchronous = { ...handle };
const [first, second] = await Promise.all([handle, Promise.resolve(handle)]);
assert.deepEqual(Object.keys(first), Object.keys(synchronous));
assert.deepEqual(Object.keys(second), Object.keys(synchronous));
assert.equal(Reflect.get(first, "then"), undefined);
assert(Object.isFrozen(first));
const metadata = tnl.services[name];
assert(metadata && metadata.protocol === protocol);
if ("fetch" in first && "fetch" in synchronous && "url" in metadata) {
  assert.equal(first.url, metadata.url);
  assert.equal(synchronous.url, metadata.url);
  for (const connection of [synchronous, first]) {
    const response = await connection.fetch("/echo", {
      method: "POST",
      headers: { authorization: "Bearer application-only" },
      body: "streamed-body",
    });
    assert.equal(response.status, 201);
    assert.equal(await response.text(), "streamed-body");
  }
} else if ("server" in first && "server" in synchronous && "url" in metadata) {
  assert.equal(first.server, `https://127.0.0.1:${metadata.port}`);
  assert.equal(synchronous.server, first.server);
  assert.notEqual(first.server, metadata.url);
  const config = await readFile(first.kubeconfig, "utf8");
  assert(config.includes(first.server));
  assert(config.includes(`tls-server-name: ${metadata.hostname}`));
  assert(config.includes(first.context));
  const result = await new Promise<{ status: number | undefined; body: string }>(
    (resolve, reject) => {
      const outgoing = request(
        `${first.server}/echo`,
        {
          method: "POST",
          servername: metadata.hostname,
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
