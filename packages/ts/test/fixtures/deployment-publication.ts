/// <reference types="bun" />

// real SDK subprocess; control authority and native registration are not mocked.
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { createClient, tnl, TnlError } from "@tnldotdev/tnl";

assert.equal("open" in tnl, false);
const deployment = createClient({ project: "acme/sdk-publication" }).deployment("production");
const variant = process.argv[2];
if (variant === "lost-reply") {
  await assert.rejects(
    deployment.publish(() => new Response("SDK publication"), { access: "anonymous" }),
    (error: unknown) => error instanceof TnlError && error.code === "sdk.dev_unavailable",
  );
  await deployment.close();
  console.log(JSON.stringify({ recovered: true }));
} else {
  let node: Server | undefined;
  let bun: Bun.Server<undefined> | undefined;
  if (variant === "bun") {
    bun = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: () => new Response("SDK publication"),
    });
  } else if (variant !== "fetch") {
    const server = createServer((_request, response) => response.end("SDK publication"));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    node = server;
  }
  const server = bun ?? node ?? (() => new Response("SDK publication"));
  const publication =
    variant === "node" || variant === "node-restart"
      ? await deployment.publish("web", server)
      : await deployment.publish(server, {
          access: "anonymous",
        });
  console.log(JSON.stringify({ url: publication.url }));
  await new Promise((resolve) => process.stdin.once("data", resolve));
  await publication.close();
  await deployment.close();
  if (bun !== undefined) {
    assert.equal(await (await fetch(bun.url)).text(), "SDK publication");
    await bun.stop(true);
  } else if (node !== undefined) {
    const server = node;
    assert.equal(server.listening, true);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}
