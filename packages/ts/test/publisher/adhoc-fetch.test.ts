import { request as httpRequest } from "node:http";
import { connect } from "node:net";
import { expect, test } from "vitest";
import { createFetchServer } from "../../src/internal/publisher/fetch.js";
import { closeServer } from "../../src/internal/publisher/register.js";

function portOf(server: Awaited<ReturnType<typeof createFetchServer>>): number {
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing listener address");
  return address.port;
}

test.each(["app.example.test", "app.example.test:25443"])(
  "inline Fetch retains %s and streams request and response bodies",
  async (host) => {
    let requestURL = "";
    const server = await createFetchServer(async (request) => {
      requestURL = request.url;
      const body = await request.text();
      return new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("first:"));
            controller.enqueue(new TextEncoder().encode(body));
            controller.close();
          },
        }),
        { headers: { "Set-Cookie": "visit=one; HttpOnly" } },
      );
    });
    try {
      const result = await new Promise<{
        status: number;
        body: string;
        cookie: string[] | undefined;
      }>((resolve, reject) => {
        const request = httpRequest(
          {
            hostname: "127.0.0.1",
            port: portOf(server),
            path: "/callback?x=1",
            method: "POST",
            headers: { Host: host },
          },
          (response) => {
            const chunks: Buffer[] = [];
            response.on("data", (chunk: Buffer) => chunks.push(chunk));
            response.on("end", () =>
              resolve({
                status: response.statusCode ?? 0,
                body: Buffer.concat(chunks).toString(),
                cookie: response.headers["set-cookie"],
              }),
            );
          },
        );
        request.on("error", reject);
        request.end("streamed body");
      });
      expect(requestURL).toBe(`https://${host}/callback?x=1`);
      expect(result).toEqual({
        status: 200,
        body: "first:streamed body",
        cookie: ["visit=one; HttpOnly"],
      });
    } finally {
      await closeServer(server);
    }
  },
);

test.each([
  "app.example.test:0",
  "app.example.test:65536",
  "app.example.test:025443",
  "app.example.test:abc",
  "user@app.example.test:25443",
  "app.example.test:25443/path",
  "app.example.test:25443?query",
  "app.example.test:25443#fragment",
  "app.example.test:25443,other.example.test",
])("inline Fetch rejects malformed authority %s without calling the handler", async (host) => {
  let called = false;
  const server = await createFetchServer(() => {
    called = true;
    return new Response("not reached");
  });
  try {
    const status = await new Promise<number>((resolve, reject) => {
      const request = httpRequest(
        {
          hostname: "127.0.0.1",
          port: portOf(server),
          headers: { Host: host },
        },
        (response) => {
          response.resume();
          response.on("end", () => resolve(response.statusCode ?? 0));
        },
      );
      request.on("error", reject);
      request.end();
    });
    expect(status).toBe(400);
    expect(called).toBe(false);
  } finally {
    await closeServer(server);
  }
});

test("inline Fetch explicitly rejects a WebSocket upgrade before calling the handler", async () => {
  let calls = 0;
  const server = await createFetchServer(() => {
    calls++;
    return new Response("not upgraded");
  });
  try {
    const socket = connect({ host: "127.0.0.1", port: portOf(server) });
    socket.setTimeout(2_000, () => socket.destroy(new Error("upgrade response timed out")));
    socket.write(
      "GET /ws HTTP/1.1\r\nHost: app.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: ZmFrZS1rZXk=\r\nSec-WebSocket-Version: 13\r\n\r\n",
    );
    const chunks: Buffer[] = [];
    for await (const chunk of socket) chunks.push(Buffer.from(chunk));
    expect(Buffer.concat(chunks).toString()).toMatch(/^HTTP\/1\.1 501 Not Implemented\r\n/);
    expect(calls).toBe(0);
  } finally {
    await closeServer(server);
  }
});
