import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createClient, tnl } from "@tnldotdev/tnl";

// installed-package proof: real SDK listeners and private HTTP registration.
// control authorization and native worker behavior have separate integration tests.
const root = await mkdtemp(join(tmpdir(), "tnl-package-publication-"));
const previous = process.env.TNL_APP_ENDPOINT;
const registration = `reg_${"a".repeat(32)}`;
const url = "https://web.example.test";
let target = "";
let unregistered = 0;
const api = createServer(async (request, response) => {
  if (request.headers.authorization !== `Bearer ${"b".repeat(64)}`) {
    response.writeHead(401).end();
    return;
  }
  if (request.url === "/v1/health") {
    response.writeHead(204).end();
    return;
  }
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  const value: unknown =
    chunks.length === 0 ? undefined : JSON.parse(Buffer.concat(chunks).toString());
  response.setHeader("Content-Type", "application/json");
  if (request.url === "/v1/prepare") {
    response.end(
      JSON.stringify({
        version: 1,
        registration_id: registration,
        service: "web",
        hostname: "web.example.test",
        public_url: url,
        project: {
          namespace: "example.test",
          dev: true,
          services: {
            web: {
              protocol: "http",
              namespace: "example.test",
              hostname: "web.example.test",
              port: 443,
              public: true,
              url,
            },
          },
        },
      }),
    );
  } else if (request.url === "/v1/register") {
    assert(
      value !== null &&
        typeof value === "object" &&
        "target" in value &&
        typeof value.target === "string",
    );
    target = value.target;
    response.writeHead(204).end();
  } else if (request.url === "/v1/status") {
    response.end(
      JSON.stringify({
        schema_version: 1,
        project: root,
        cursor: "cursor",
        observed_at: new Date().toISOString(),
        services: [
          {
            service: "web",
            directory: ".",
            registration_id: registration,
            target,
            registered: true,
            routable: true,
            ready: false,
            readiness: { path: "/" },
            public_url: url,
            run_number: 1,
          },
        ],
      }),
    );
  } else if (request.url === "/v1/unregister") {
    unregistered++;
    response.writeHead(204).end();
  } else if (request.url === "/v1/renew") {
    response.writeHead(204).end();
  } else response.writeHead(404).end();
});
async function listen(server: Server) {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address !== null && typeof address !== "string");
  return address.port;
}
async function close(server: Server) {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}
const app = createServer((_request, response) => response.end("application owned"));
try {
  assert.equal("open" in tnl, false);
  const port = await listen(api);
  await listen(app);
  const descriptor = join(root, "endpoint.json");
  await writeFile(
    descriptor,
    JSON.stringify({
      version: 1,
      url: `http://127.0.0.1:${port}`,
      capability: "b".repeat(64),
      owner_id: "a".repeat(32),
      scope: "app",
      service: "web",
    }),
    { mode: 0o600 },
  );
  process.env.TNL_APP_ENDPOINT = descriptor;
  const local = createClient({ services: { web: { protocol: "http" } } }).deployment("local");
  const node = await local.publish("web", app);
  assert.equal(node.url, url);
  await node.close();
  assert.equal(app.listening, true);
  const fetch = await local.publish("web", () => new Response("Fetch publication"));
  assert.equal(fetch.url, url);
  await fetch.close();
  await local.close();
  assert.equal(unregistered, 2);
} finally {
  if (previous === undefined) delete process.env.TNL_APP_ENDPOINT;
  else process.env.TNL_APP_ENDPOINT = previous;
  await Promise.all([close(app), close(api)]);
  await rm(root, { recursive: true, force: true });
}
