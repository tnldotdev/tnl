import * as http from "node:http";
import * as net from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { onTestFinished } from "vitest";
import WebSocket, { type ClientOptions, type Data } from "ws";
import { errorMessage } from "./process.js";

interface TestRequestOptions {
  readonly address?: string;
  readonly headers?: http.OutgoingHttpHeaders;
  readonly host?: string;
  readonly path?: string;
  readonly timeout?: number;
}

export interface TestResponse {
  readonly body: string;
  readonly headers: http.IncomingHttpHeaders;
  readonly status: number | undefined;
}

interface TestWebSocketOptions {
  readonly host?: string;
  readonly origin?: string;
  readonly protocol?: string;
}

// The returned port is available only at the instant we close the probe listener.
export async function findAvailableLoopbackPort(host = "127.0.0.1"): Promise<number> {
  const reservation = await holdLoopbackPort(host);
  await reservation.close();
  return reservation.port;
}

export async function holdLoopbackPort(host = "127.0.0.1") {
  const server = net.createServer((socket) => socket.destroy());
  const close = await listen(server, 0, host);
  const address = server.address();
  if (address === null || typeof address === "string") {
    await close();
    throw new Error("test server did not receive a TCP port");
  }
  return { port: address.port, close };
}

export async function occupyPort(port: number, host?: string): Promise<() => Promise<void>> {
  return await listen(
    net.createServer((socket) => socket.destroy()),
    port,
    host,
  );
}

async function listen(server: net.Server, port: number, host?: string) {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ port, host }, () => {
      server.off("error", reject);
      resolve();
    });
  });
  let closing: Promise<void> | undefined;
  const close = () =>
    (closing ??= new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    }));
  onTestFinished(close);
  return close;
}

export async function requestTestServer(
  port: number,
  options: TestRequestOptions = {},
): Promise<TestResponse> {
  const deadline = Date.now() + (options.timeout ?? 30_000);
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      return await requestOnce(port, {
        ...options,
        timeout: Math.min(1000, deadline - Date.now()),
      });
    } catch (error) {
      lastError = error;
      await delay(Math.min(100, Math.max(0, deadline - Date.now())));
    }
  }
  throw new Error(`development server did not start: ${errorMessage(lastError)}`);
}

export async function requestOnce(
  port: number,
  options: TestRequestOptions = {},
): Promise<TestResponse> {
  return await new Promise<TestResponse>((resolve, reject) => {
    // A wall-clock deadline also bounds a server that keeps trickling response bytes.
    let timer: ReturnType<typeof setTimeout> | undefined;
    const fail = (error: Error) => {
      clearTimeout(timer);
      request.destroy();
      reject(error);
    };
    const request = http.get(
      {
        host: options.address ?? "127.0.0.1",
        port,
        path: options.path ?? "/",
        headers: { Host: options.host ?? "api.member.example", ...options.headers },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("error", fail);
        response.on("aborted", () => fail(new Error("response aborted")));
        response.on("close", () => {
          if (!response.complete) fail(new Error("response closed before completion"));
        });
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          clearTimeout(timer);
          resolve({
            body: Buffer.concat(chunks).toString("utf8"),
            headers: response.headers,
            status: response.statusCode,
          });
        });
      },
    );
    request.on("error", fail);
    timer = setTimeout(
      () => request.destroy(new Error("request timed out")),
      options.timeout ?? 1000,
    );
  });
}

export async function openTestWebSocket(
  port: number,
  path: string,
  options: TestWebSocketOptions = {},
): Promise<WebSocket> {
  const socket = createTestWebSocket(port, path, options);
  try {
    await waitForWebSocketOpen(socket);
    return socket;
  } catch (error) {
    await closeTestWebSocket(socket);
    throw error;
  }
}

export async function openTestWebSocketWithMessage(
  port: number,
  path: string,
  options: TestWebSocketOptions = {},
): Promise<{ message: string; socket: WebSocket }> {
  const socket = createTestWebSocket(port, path, options);
  try {
    // Attach both waiters before the handshake; handle either rejection immediately.
    const [, message] = await Promise.all([
      waitForWebSocketOpen(socket),
      waitForWebSocketMessage(socket),
    ]);
    return { message, socket };
  } catch (error) {
    await closeTestWebSocket(socket);
    throw error;
  }
}

async function waitForWebSocketOpen(socket: WebSocket): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      socket.off("open", onOpen);
      socket.off("error", onError);
      socket.off("close", onClose);
      socket.off("unexpected-response", onResponse);
    };
    const onOpen = () => {
      cleanup();
      resolve();
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => onError(new Error("WebSocket closed before opening"));
    const onResponse = (_request: http.ClientRequest, response: http.IncomingMessage) => {
      response.resume();
      onError(new Error(`WebSocket upgrade returned status ${response.statusCode}`));
    };
    const timer = setTimeout(() => onError(new Error("WebSocket did not open")), 5000);
    socket.once("open", onOpen);
    socket.once("error", onError);
    socket.once("close", onClose);
    socket.once("unexpected-response", onResponse);
  });
}

export async function waitForWebSocketMessage(
  socket: WebSocket,
  timeout = 10_000,
): Promise<string> {
  try {
    return await new Promise<string>((resolve, reject) => {
      if (socket.readyState === WebSocket.CLOSED || socket.readyState === WebSocket.CLOSING) {
        reject(new Error("WebSocket closed before sending a message"));
        return;
      }
      const cleanup = () => {
        clearTimeout(timer);
        socket.off("message", onMessage);
        socket.off("error", onError);
        socket.off("close", onClose);
      };
      const onMessage = (data: Data) => {
        cleanup();
        resolve(webSocketDataString(data));
      };
      const onError = (error: Error) => {
        cleanup();
        reject(error);
      };
      const onClose = () => onError(new Error("WebSocket closed before sending a message"));
      const timer = setTimeout(
        () => onError(new Error("WebSocket did not send a message")),
        timeout,
      );
      socket.once("message", onMessage);
      socket.once("error", onError);
      socket.once("close", onClose);
    });
  } catch (error) {
    await closeTestWebSocket(socket);
    throw error;
  }
}

export async function closeTestWebSocket(socket: WebSocket): Promise<void> {
  if (socket.readyState === WebSocket.CLOSED) return;
  await new Promise<void>((resolve, reject) => {
    const ignoreError = () => {};
    const cleanup = () => {
      clearTimeout(terminateTimer);
      clearTimeout(deadline);
      socket.off("error", ignoreError);
      socket.off("close", onClose);
    };
    const onClose = () => {
      cleanup();
      resolve();
    };
    socket.on("error", ignoreError); // terminate() emits an error while CONNECTING.
    socket.once("close", onClose);
    const terminateTimer = setTimeout(() => socket.terminate(), 250);
    const deadline = setTimeout(() => {
      cleanup();
      reject(new Error("WebSocket did not close"));
    }, 1000);
    if (socket.readyState === WebSocket.CONNECTING) socket.terminate();
    else socket.close();
  });
}

function createTestWebSocket(port: number, path: string, options: TestWebSocketOptions): WebSocket {
  const clientOptions: ClientOptions = {
    handshakeTimeout: 5000,
    headers: {
      Host: options.host ?? "api.member.example",
      ...(options.origin === undefined ? {} : { Origin: options.origin }),
    },
  };
  const url = `ws://127.0.0.1:${port}${path}`;
  const socket =
    options.protocol === undefined
      ? new WebSocket(url, clientOptions)
      : new WebSocket(url, options.protocol, clientOptions);
  onTestFinished(() => closeTestWebSocket(socket));
  return socket;
}

function webSocketDataString(data: Data): string {
  if (Array.isArray(data)) return Buffer.concat(data).toString("utf8");
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
  return data.toString("utf8");
}
