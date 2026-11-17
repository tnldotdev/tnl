import { createServer, request as httpRequest, type ServerResponse } from "node:http";
import { expect, test, vi } from "vitest";
import * as z from "zod";
import { publishFetch } from "../../src/internal/publisher/publication.js";
import { closeServer } from "../../src/internal/publisher/register.js";
import { invocationIDSchema } from "../../src/internal/values.js";

test("owned Fetch forces I/O at the original deadline without joining an uncooperative handler", async () => {
  vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<Response>();
  const unregister = Promise.withResolvers<AbortSignal>();
  let target = "",
    service = "",
    shutdownDeadline = "";
  let nativeJoined = false;
  try {
    const publication = await publishFetch(
      () => {
        entered.resolve();
        return release.promise;
      },
      {},
      {
        start: async (_directory, _binary, selection) => {
          service = selection?.invocationID ?? "";
          return {
            version: 1,
            url: "http://127.0.0.1:12345",
            capability: "b".repeat(64),
            owner_id: "a".repeat(32),
            scope: "invocation",
            invocation_id: invocationIDSchema.parse(service),
          };
        },
        request: async (_endpoint, operation, value, signal) => {
          if (operation === "publications/register") {
            const body = z.looseObject({ target: z.string(), owner: z.string() }).parse(value);
            target = body.target;
            return {
              version: 1,
              registration_id: `reg_${"a".repeat(32)}`,
              owner: body.owner,
              target,
            };
          }
          if (operation === "status")
            return {
              schema_version: 1,
              project: "/project",
              cursor: "cursor",
              observed_at: new Date().toISOString(),
              services: [
                {
                  service,
                  directory: ".",
                  registration_id: `reg_${"a".repeat(32)}`,
                  target,
                  registered: true,
                  routable: true,
                  ready: false,
                  readiness: { path: "/" },
                  public_url: "https://web.example.test",
                  run_number: 1,
                },
              ],
            };
          if (operation === "unregister") {
            const body = z.looseObject({ shutdown_deadline: z.iso.datetime() }).parse(value);
            shutdownDeadline = body.shutdown_deadline;
            if (signal === undefined) throw new Error("native cleanup has no budget");
            unregister.resolve(signal);
            try {
              await new Promise<never>((_resolve, reject) => {
                signal.addEventListener("abort", () => reject(signal.reason), { once: true });
              });
            } finally {
              nativeJoined = true;
            }
          }
          return undefined;
        },
        pause: async (_milliseconds, signal) =>
          new Promise<void>((resolve) => {
            signal?.addEventListener("abort", () => resolve(), { once: true });
          }),
      },
    );
    const visitor = new Promise<unknown>((resolve) => {
      const request = httpRequest(target, { headers: { Host: "app.example.test" } });
      request.on("error", resolve);
      request.end();
    });
    await entered.promise;
    const firstStop = Date.now();
    const closing = publication.close();
    const result = closing.catch((cause: unknown) => cause);
    const signal = await unregister.promise;
    expect(Date.parse(shutdownDeadline)).toBe(firstStop + 10_000);
    await vi.advanceTimersByTimeAsync(9_999);
    expect(signal.aborted).toBe(false);
    expect(nativeJoined).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(signal.aborted).toBe(true);
    expect(await result).toMatchObject({ code: "sdk.cleanup_failed" });
    expect(nativeJoined).toBe(true);
    expect(await visitor).toMatchObject({ code: "ECONNRESET" });
    // the application promise is still pending. its late completion cannot
    // reopen a socket or hold a tnl copy loop after forced shutdown returned.
    release.resolve(new Response("too late"));
    const retry = publication.close().catch((cause: unknown) => cause);
    expect(await retry).toMatchObject({ name: "TimeoutError" });
    expect(Date.parse(shutdownDeadline)).toBe(firstStop + 10_000);
  } finally {
    release.resolve(new Response("cleanup"));
    vi.useRealTimers();
  }
});

test("owned HTTP listener drains accepted final bytes and trailers before closing", async () => {
  const firstBytes = Promise.withResolvers<void>();
  const accepted = Promise.withResolvers<ServerResponse>();
  const server = createServer((_request, response) => {
    response.writeHead(200, { Trailer: "X-Final", Connection: "close" });
    response.write("accepted:");
    accepted.resolve(response);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing listener");
  const visitor = new Promise<{ body: string; final: string | string[] | undefined }>(
    (resolve, reject) => {
      const request = httpRequest(`http://127.0.0.1:${address.port}`, (response) => {
        let body = "";
        response.on("data", (chunk: Buffer) => {
          body += chunk.toString();
          firstBytes.resolve();
        });
        response.on("error", reject);
        response.on("end", () => resolve({ body, final: response.trailers["x-final"] }));
      });
      request.on("error", reject);
      request.end();
    },
  );
  try {
    const response = await accepted.promise;
    await firstBytes.promise;
    const closing = closeServer(server, new AbortController().signal);
    expect(server.listening).toBe(false);
    response.addTrailers({ "X-Final": "delivered" });
    response.end("final");
    expect(await visitor).toEqual({ body: "accepted:final", final: "delivered" });
    await closing;
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
