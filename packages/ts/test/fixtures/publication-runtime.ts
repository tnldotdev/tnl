import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { createRequire } from "node:module";
import path from "node:path";
import { createInterface } from "node:readline";
import { createTnl, type TnlApplicationResource } from "@tnldotdev/tnl";

const [credentialFile, resource, mode, native] = process.argv.slice(2);
assert.ok(credentialFile && resource && /^url_[A-Za-z0-9]{22}$/.test(resource));
assert.ok(mode === "prepare" || mode === "publish" || mode === "fetch");
assert.ok(native);
const require = createRequire(import.meta.url);
const nativePackage = require.resolve(
  `@tnldotdev/tnl-${process.platform}-${process.arch}/package.json`,
);
assert.equal(realpathSync(path.join(path.dirname(nativePackage), "bin/tnl")), realpathSync(native));
const selected = resource as TnlApplicationResource;
const lines = createInterface({ input: process.stdin });
const commands = lines[Symbol.asyncIterator]();
const command = async (expected: string) => assert.equal((await commands.next()).value, expected);
const app = createTnl({
  credential: await readFile(credentialFile, "utf8"),
  directory: process.cwd(),
  stateDir: path.join(process.cwd(), "state"),
});
const listeners: Server[] = [];
let releaseHeld: (() => void) | undefined;
const listen = async (body: string) => {
  const listener = createServer((request, response) => {
    assert.equal(request.headers["tnl-visitor-token"], undefined);
    if (request.url === "/held") {
      response.write("held prefix");
      releaseHeld = () => response.end(" held suffix");
      return;
    }
    response.end(body);
  });
  listeners.push(listener);
  await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
  return listener;
};
try {
  const prepared = mode === "prepare" ? await app.prepare({ resource: selected }) : undefined;
  if (prepared !== undefined) {
    console.log("prepared", prepared.publicURL);
    await command("bind");
  }
  const first = mode === "fetch" ? undefined : await listen("first SDK listener");
  const fetch = (request: Request) => {
    assert.equal(request.headers.get("Tnl-Visitor-Token"), null);
    if (new URL(request.url).pathname !== "/held") return new Response("first SDK listener");
    const encoder = new TextEncoder();
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode("held prefix"));
          releaseHeld = () => {
            controller.enqueue(encoder.encode(" held suffix"));
            controller.close();
          };
        },
      }),
    );
  };
  console.log("starting");
  const publication = await (async () => {
    if (prepared !== undefined) {
      assert.ok(first);
      return prepared.register(first);
    }
    return app.publish(first ?? fetch, { resource: selected });
  })();
  if (prepared !== undefined) {
    const status = await publication.status();
    assert.equal(status.registered, true);
    assert.equal(status.routable, false);
    console.log("bound");
    await command("ready");
  }
  await publication.wait({ signal: AbortSignal.timeout(15_000) });
  const status = await publication.status();
  const events = publication
    .watch({ after: status.cursor, signal: AbortSignal.timeout(15_000) })
    [Symbol.asyncIterator]();
  try {
    const next = events.next();
    await publication.wait({ signal: AbortSignal.timeout(15_000) });
    const event = await next;
    assert.equal(event.done, false);
    assert.notEqual(event.value?.cursor, status.cursor);
    assert.equal(event.value?.snapshot, undefined);
  } finally {
    await events.return?.();
  }
  console.log("ready", publication.url);
  await command("visit");
  if (prepared !== undefined) {
    const second = await listen("replacement SDK listener");
    const replacement = await prepared.register(second);
    await assert.rejects(publication.status(), { code: "sdk.registration_stale" });
    await publication.close();
    await replacement.wait({ signal: AbortSignal.timeout(15_000) });
    assert.equal(first?.listening, true);
    console.log("replaced");
    await command("visit");
  }
  await command("close");
  let completed = false;
  const closing = app.close().then(() => {
    completed = true;
  });
  console.log("closing");
  await command("release");
  assert.equal(completed, false);
  assert.ok(releaseHeld);
  releaseHeld();
  await closing;
  assert.ok(listeners.every((listener) => listener.listening));
  console.log("closed");
} finally {
  await app.close();
  lines.close();
  await Promise.all(
    listeners.map(
      (listener) =>
        new Promise<void>((resolve, reject) => {
          listener.close((error) => (error ? reject(error) : resolve()));
        }),
    ),
  );
}
