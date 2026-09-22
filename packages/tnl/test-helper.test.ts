import { once } from "node:events";
import * as fs from "node:fs/promises";
import * as http from "node:http";
import * as path from "node:path";
import { describe, expect, onTestFinished, test, vi } from "vitest";
import { WebSocketServer } from "ws";
import { startTestBootstrap, waitForBootstrapRequest } from "./test-helper/bootstrap.js";
import {
  environmentBaseline,
  subprocessEnvironment,
  withProcessEnvironment,
} from "./test-helper/environment.js";
import {
  closeTestWebSocket,
  openTestWebSocket,
  openTestWebSocketWithMessage,
  requestOnce,
  waitForWebSocketMessage,
} from "./test-helper/http-websocket.js";
import { startTestProcess } from "./test-helper/process.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const original = await importOriginal<typeof fs>();
  return { ...original, chmod: vi.fn(original.chmod) };
});

describe("test resource ownership", () => {
  test("closes the bootstrap and removes its directory if chmod fails", async () => {
    vi.mocked(fs.chmod).mockRejectedValueOnce(new Error("chmod failed"));
    await expect(startTestBootstrap()).rejects.toThrow("chmod failed");
    const socket = vi.mocked(fs.chmod).mock.calls[0]?.[0];
    expect(typeof socket).toBe("string");
    await expect(fs.stat(path.dirname(String(socket)))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(socketRequest(String(socket), "{}")).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("surfaces malformed bootstrap requests through the waiter instead of throwing in an event handler", async () => {
    const bootstrap = await startTestBootstrap();
    const socket = bootstrap.environment.TNL_DEV_SOCKET;
    expect(socket).toBeDefined();
    if (socket === undefined) throw new Error("test bootstrap did not provide a socket");
    expect(await socketRequest(socket, "{")).toBe(400);
    await expect(waitForBootstrapRequest(bootstrap)).rejects.toBeInstanceOf(SyntaxError);
    await bootstrap.close();
    await bootstrap.close();
  });

  test("reports spawn errors and can reap a process that never started", async () => {
    const child = startTestProcess("/nonexistent/tnl-test-command", []);
    await expect(child.ready()).rejects.toMatchObject({ code: "ENOENT" });
    await child.close();
    await child.close();
  });

  test("drains both output pipes while running and kills/reaps a child that ignores SIGTERM", async () => {
    const child = startTestProcess(process.execPath, [
      "--input-type=module",
      "-e",
      `
      process.on("SIGTERM", () => {});
      await Promise.all([process.stdout, process.stderr].map(async (stream) => {
        for (let i = 0; i < 32; i++) await new Promise(resolve => stream.write("x".repeat(65536), resolve));
      }));
      process.stdout.write("both pipes drained");
      setInterval(() => {}, 1000);
    `,
    ]);
    await child.ready();
    await expect.poll(child.output).toContain("both pipes drained");
    expect(child.output().length).toBeLessThanOrEqual(16_384);
    const closed = once(child.child, "close");
    await child.close();
    await expect(closed).resolves.toEqual([null, "SIGKILL"]);
  });

  test("settles a response aborted after headers and partial body", async () => {
    const port = await serve((_request, response) => {
      response.writeHead(200, { "Content-Length": "100" });
      response.write("partial");
      setImmediate(() => response.destroy());
    });
    await expect(requestOnce(port, { timeout: 1000 })).rejects.toThrow(/aborted|closed|reset/i);
  });

  test("bounds a response that sends headers but never finishes", async () => {
    const port = await serve((_request, response) => response.writeHead(200).flushHeaders());
    await expect(requestOnce(port, { timeout: 50 })).rejects.toThrow("request timed out");
  });

  test.each([openTestWebSocket, openTestWebSocketWithMessage])(
    "closes rejected WebSocket upgrades (%#)",
    async (open) => {
      const port = await serve((_request, response) => response.writeHead(403).end());
      await expect(open(port, "/")).rejects.toThrow("WebSocket upgrade returned status 403");
    },
  );

  test("cleans handshake/message listeners on success and close-before-message", async () => {
    const { port, server } = await serveWebSocket();
    server.once("connection", (socket) => socket.send("connected"));
    const { socket, message } = await openTestWebSocketWithMessage(port, "/");
    expect(message).toBe("connected");
    for (const event of ["open", "error", "close", "message", "unexpected-response"]) {
      expect(socket.listenerCount(event)).toBe(0);
    }
    const messagePromise = waitForWebSocketMessage(socket);
    for (const peer of server.clients) peer.close();
    await expect(messagePromise).rejects.toThrow("closed before sending a message");
    for (const event of ["error", "close", "message"]) expect(socket.listenerCount(event)).toBe(0);
  });

  test("closes a WebSocket if its first message times out", async () => {
    const { port } = await serveWebSocket();
    const socket = await openTestWebSocket(port, "/");
    await expect(waitForWebSocketMessage(socket, 50)).rejects.toThrow("did not send a message");
    expect(socket.readyState).toBe(socket.CLOSED);
    for (const event of ["open", "error", "close", "message", "unexpected-response"]) {
      expect(socket.listenerCount(event)).toBe(0);
    }
  });
});

test("environment baselines isolate tests/subprocesses and restore inherited values after failure", async () => {
  for (const name of Object.keys(environmentBaseline)) vi.stubEnv(name, `inherited-${name}`);
  vi.stubEnv("NODE_OPTIONS", "--invalid-inherited-option");
  const inherited = { ...process.env };
  await expect(
    withProcessEnvironment({ TNL_DEV_PORT: "4321" }, () => {
      expect(process.env.TNL_DEV_PORT).toBe("4321");
      expect(process.env.TNL_DEV_SOCKET).toBeUndefined();
      expect(process.env.TNL_PROJECT_RUNTIME).toBeUndefined();
      throw new Error("callback failed");
    }),
  ).rejects.toThrow("callback failed");
  expect(process.env).toEqual(inherited);
  const sanitized = subprocessEnvironment({ TNL_DEV_PORT: "4321" });
  expect(sanitized.TNL_DEV_PORT).toBe("4321");
  expect(sanitized.NODE_OPTIONS).toBeUndefined();
  expect(sanitized.NODE_ENV).toBe("development");
  for (const name of Object.keys(environmentBaseline).filter(
    (name) => name !== "TNL_DEV_PORT" && name !== "NODE_ENV",
  )) {
    expect(sanitized[name]).toBeUndefined();
  }
});

async function socketRequest(socketPath: string, body: string): Promise<number | undefined> {
  return await new Promise((resolve, reject) => {
    const request = http.request(
      { socketPath, method: "POST", path: "/v1/configure" },
      (response) => {
        response.on("error", reject);
        response.on("end", () => resolve(response.statusCode));
        response.resume();
      },
    );
    request.on("error", reject);
    request.end(body);
  });
}

async function serve(handler: http.RequestListener): Promise<number> {
  const server = http.createServer(handler);
  onTestFinished(async () => {
    const closed = new Promise<void>((resolve) => server.close(() => resolve()));
    server.closeAllConnections();
    await closed;
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing listener");
  return address.port;
}

async function serveWebSocket() {
  const server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  onTestFinished(async () => {
    await Promise.all([...server.clients].map(closeTestWebSocket));
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing listener");
  return { port: address.port, server };
}
