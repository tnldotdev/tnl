import { createServer } from "node:http";
import { expect, onTestFinished, test } from "vitest";
import { runtimeRequest, type RuntimeEndpoint } from "../../src/internal/publisher/local.js";

test("event requests encode cursors, classify expiry, and preserve observation abort reasons", async () => {
  const requestStarted = Promise.withResolvers<void>();
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "", "http://localhost");
    expect(request.headers.authorization).toBe(`Bearer ${"b".repeat(64)}`);
    expect(request.method).toBe("GET");
    expect(url.pathname).toBe("/v1/events");
    const cursor = url.searchParams.get("after");
    response.setHeader("content-type", "application/json");
    if (cursor === "hold") {
      requestStarted.resolve();
      return;
    }
    if (cursor === "expired") {
      response
        .writeHead(410)
        .end(JSON.stringify({ code: "runtime.cursor_expired", message: "read status" }));
      return;
    }
    expect(cursor).toBe("cursor#with?special&characters");
    response.end("[]");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  onTestFinished(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing listener");
  const endpoint: RuntimeEndpoint = {
    version: 1,
    url: `http://127.0.0.1:${address.port}`,
    owner_id: "a".repeat(32),
    capability: "b".repeat(64),
    scope: "app",
    service: "web",
  };
  expect(
    await runtimeRequest(endpoint, "events", { after: "cursor#with?special&characters" }),
  ).toEqual([]);
  await expect(runtimeRequest(endpoint, "events", { after: "expired" })).rejects.toHaveProperty(
    "code",
    "sdk.event_cursor_expired",
  );
  const abort = new AbortController();
  const reason = new Error("stop watching");
  const held = runtimeRequest(endpoint, "events", { after: "hold" }, abort.signal);
  const rejected = expect(held).rejects.toBe(reason);
  await requestStarted.promise;
  abort.abort(reason);
  await rejected;
});
