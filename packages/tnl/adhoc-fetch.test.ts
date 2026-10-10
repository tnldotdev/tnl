import { request as httpRequest } from "node:http";
import { connect } from "node:net";
import { expect, test } from "vitest";
import { createFetchServer } from "./src/internal/fetch.js";
import { closeServer } from "./src/internal/register.js";

function portOf(server: Awaited<ReturnType<typeof createFetchServer>>): number {
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing listener address");
  return address.port;
}

test("inline Fetch handlers receive a public origin and can stream request and response bodies", async () => {
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
          headers: { Host: "app.example.test" },
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
    expect(requestURL).toBe("https://app.example.test/callback?x=1");
    expect(result).toEqual({
      status: 200,
      body: "first:streamed body",
      cookie: ["visit=one; HttpOnly"],
    });
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
