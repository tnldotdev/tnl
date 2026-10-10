import { once } from "node:events";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { TnlError } from "../errors.js";
import type { FetchHandler } from "./fetch_types.js";

// the owned HTTP listener adapts Fetch requests without a framework or child publisher.
export async function createFetchServer(handler: FetchHandler): Promise<Server> {
  if (typeof handler !== "function") throw new TnlError("sdk.configuration_invalid");
  const server = createServer((incoming, outgoing) => {
    void serveFetch(handler, incoming, outgoing);
  });
  // Fetch handlers have no portable socket takeover in Node or Bun.
  server.on("upgrade", (_request, socket) => {
    socket.end("HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
  } catch (cause) {
    try {
      server.close();
    } catch {
      /* the listener never opened. */
    }
    throw new TnlError("sdk.listener_failed", { cause });
  }
  return server;
}

async function serveFetch(
  handler: FetchHandler,
  incoming: IncomingMessage,
  outgoing: ServerResponse,
): Promise<void> {
  const controller = new AbortController();
  outgoing.once("close", () => controller.abort());
  try {
    const host = incoming.headers.host;
    if (
      typeof host !== "string" ||
      !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host) ||
      typeof incoming.url !== "string" ||
      !incoming.url.startsWith("/") ||
      incoming.url.startsWith("//")
    ) {
      outgoing.writeHead(400).end();
      return;
    }
    const headers = new Headers();
    for (const [name, value] of Object.entries(incoming.headers)) {
      if (typeof value === "string") headers.append(name, value);
      else if (Array.isArray(value)) for (const entry of value) headers.append(name, entry);
    }
    // node's stream/web reader has the same runtime shape as a DOM stream.
    const body =
      incoming.method === "GET" || incoming.method === "HEAD"
        ? undefined
        : (Readable.toWeb(incoming) as unknown as ReadableStream<Uint8Array>);
    const request = new Request(`https://${host}${incoming.url}`, {
      method: incoming.method,
      headers,
      body,
      signal: controller.signal,
      ...(body === undefined ? {} : { duplex: "half" }),
    } as RequestInit & { duplex?: "half" });
    const response = await handler(request);
    if (!(response instanceof Response)) throw new TnlError("sdk.response_invalid");
    for (const [name, value] of response.headers) {
      if (name !== "set-cookie") outgoing.setHeader(name, value);
    }
    for (const cookie of response.headers.getSetCookie())
      outgoing.appendHeader("Set-Cookie", cookie);
    outgoing.writeHead(response.status);
    if (response.body === null || incoming.method === "HEAD") {
      outgoing.end();
      return;
    }
    const reader = response.body.getReader();
    try {
      for (;;) {
        const result = await reader.read();
        if (result.done || controller.signal.aborted) break;
        if (!outgoing.write(Buffer.from(result.value)))
          await once(outgoing, "drain", { signal: controller.signal });
      }
      if (!controller.signal.aborted) outgoing.end();
    } finally {
      reader.releaseLock();
    }
  } catch {
    if (!outgoing.headersSent) outgoing.writeHead(500).end("handler failed\n");
    else outgoing.destroy();
  }
}
