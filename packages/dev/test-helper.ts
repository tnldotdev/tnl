import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import * as http from "node:http";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import WebSocket, { type ClientOptions, type Data } from "ws";

export interface BootstrapRequest {
  readonly authorization: string | undefined;
  readonly body: unknown;
  readonly contentType: string | undefined;
  readonly method: string | undefined;
  readonly path: string | undefined;
}

export interface TestBootstrap {
  readonly environment: Record<string, string>;
  readonly requests: BootstrapRequest[];
  close(): Promise<void>;
}

interface BootstrapOptions {
  readonly responseBody?: string;
  readonly status?: number;
}

export interface TestProcess {
  readonly child: ChildProcess;
  close(): Promise<void>;
  output(): string;
}

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

export async function startTestBootstrap(options: BootstrapOptions = {}): Promise<TestBootstrap> {
  const status = options.status ?? 200;
  const directory = await mkdtemp(path.join(os.tmpdir(), "tnl-dev-test-"));
  const socket = path.join(directory, "control.sock");
  const requests: BootstrapRequest[] = [];
  const server = http.createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const parsedBody = body === "" ? null : JSON.parse(body);
      requests.push({
        authorization: request.headers.authorization,
        body: parsedBody,
        contentType: request.headers["content-type"],
        method: request.method,
        path: request.url,
      });
      response.statusCode = status;
      if (status !== 200) {
        response.end(options.responseBody ?? "registration failed");
        return;
      }
      if (request.url === "/v1/target") {
        response.statusCode = 204;
        response.end();
        return;
      }
      response.setHeader("Content-Type", "application/json");
      response.end(
        options.responseBody ??
          JSON.stringify({
            protocol: 1,
            tunnelID: `tunnel_${"b".repeat(32)}`,
            hostname: "demo.tnl.dev",
            publicURL: "https://demo.tnl.dev",
          }),
      );
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socket, resolve);
  });

  const environment = {
    TNL_DEV_PROTOCOL: "1",
    TNL_DEV_SOCKET: socket,
  };
  return {
    environment,
    requests,
    async close() {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
      await rm(directory, { force: true, recursive: true });
    },
  };
}

export async function withProcessEnvironment<T>(
  environment: Readonly<Record<string, string | undefined>>,
  callback: () => T | Promise<T>,
): Promise<T> {
  const previous = new Map<string, string | undefined>();
  for (const [name, value] of Object.entries(environment)) {
    previous.set(name, process.env[name]);
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }
  try {
    return await callback();
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
}

export async function withProcessArguments<T>(
  arguments_: string[],
  callback: () => T | Promise<T>,
): Promise<T> {
  const previous = process.argv;
  process.argv = arguments_;
  try {
    return await callback();
  } finally {
    process.argv = previous;
  }
}

export async function reserveLoopbackPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("test server did not receive a TCP port");
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  return address.port;
}

export async function occupyLoopbackPort(port: number): Promise<() => Promise<void>> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  return async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  };
}

export function startTestProcess(
  command: string,
  arguments_: readonly string[],
  options: SpawnOptions,
): TestProcess {
  const child = spawn(command, arguments_, {
    ...options,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  const collect = (chunk: Buffer | string) => {
    output = `${output}${chunk.toString()}`.slice(-16_384);
  };
  child.stdout?.on("data", collect);
  child.stderr?.on("data", collect);
  return {
    child,
    output: () => output,
    async close() {
      if (child.exitCode !== null || child.signalCode !== null) {
        return;
      }
      const exited = once(child, "exit");
      child.kill("SIGTERM");
      if (await Promise.race([exited.then(() => true), delay(5000, false, { ref: false })])) {
        return;
      }
      child.kill("SIGKILL");
      await exited;
    },
  };
}

export async function waitForProcessExit(
  process_: TestProcess,
  timeout = 30_000,
): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  const child = process_.child;
  if (child.exitCode !== null || child.signalCode !== null) {
    return { code: child.exitCode, signal: child.signalCode };
  }
  return await Promise.race([
    once(child, "exit").then(([code, signal]) => ({
      code: code as number | null,
      signal: signal as NodeJS.Signals | null,
    })),
    delay(timeout, undefined, { ref: false }).then(() => {
      throw new Error("framework process did not exit");
    }),
  ]);
}

export async function waitForBootstrapRequest(
  bootstrap: TestBootstrap,
  index = 0,
  timeout = 30_000,
): Promise<BootstrapRequest> {
  const deadline = Date.now() + timeout;
  while (bootstrap.requests.length <= index) {
    if (Date.now() >= deadline) {
      throw new Error("framework did not register with tnl dev");
    }
    await delay(50);
  }
  const request = bootstrap.requests[index];
  if (request === undefined) {
    throw new Error("framework registration disappeared");
  }
  return request;
}

export async function requestTestServer(
  port: number,
  options: TestRequestOptions = {},
): Promise<TestResponse> {
  const timeout = options.timeout ?? 30_000;
  const deadline = Date.now() + timeout;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      return await requestOnce(port, options);
    } catch (error) {
      lastError = error;
      await delay(100);
    }
  }
  throw new Error(`development server did not start: ${errorMessage(lastError)}`);
}

export async function requestOnce(
  port: number,
  options: TestRequestOptions = {},
): Promise<TestResponse> {
  return await new Promise<TestResponse>((resolve, reject) => {
    const request = http.get(
      {
        host: options.address ?? "127.0.0.1",
        port,
        path: options.path ?? "/",
        headers: { Host: options.host ?? "demo.tnl.dev", ...options.headers },
        timeout: options.timeout ?? 1000,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          resolve({
            body: Buffer.concat(chunks).toString("utf8"),
            headers: response.headers,
            status: response.statusCode,
          });
        });
      },
    );
    request.on("error", reject);
    request.on("timeout", () => request.destroy(new Error("request timed out")));
  });
}

export function nonLoopbackIPv4Addresses(): string[] {
  const addresses: string[] = [];
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal) {
        addresses.push(entry.address);
      }
    }
  }
  return addresses;
}

export async function openTestWebSocket(
  port: number,
  path: string,
  options: TestWebSocketOptions = {},
): Promise<WebSocket> {
  const socket = createTestWebSocket(port, path, options);
  await waitForWebSocketOpen(socket);
  return socket;
}

export async function openTestWebSocketWithMessage(
  port: number,
  path: string,
  options: TestWebSocketOptions = {},
): Promise<{ message: string; socket: WebSocket }> {
  const socket = createTestWebSocket(port, path, options);
  const message = waitForWebSocketMessage(socket);
  try {
    await waitForWebSocketOpen(socket);
    return { message: await message, socket };
  } catch (error) {
    socket.close();
    await message.catch(() => undefined);
    throw error;
  }
}

async function waitForWebSocketOpen(socket: WebSocket): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    socket.once("open", resolve);
    socket.once("unexpected-response", (_request, response) => {
      response.resume();
      reject(new Error(`WebSocket upgrade returned status ${response.statusCode}`));
    });
    socket.once("error", reject);
  });
}

export async function waitForWebSocketMessage(
  socket: WebSocket,
  timeout = 10_000,
): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("WebSocket did not send a message"));
    }, timeout);
    timer.unref();
    const onMessage = (data: Data) => {
      cleanup();
      resolve(webSocketDataString(data));
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      clearTimeout(timer);
      socket.off("message", onMessage);
      socket.off("error", onError);
    };
    socket.on("message", onMessage);
    socket.on("error", onError);
  });
}

function createTestWebSocket(port: number, path: string, options: TestWebSocketOptions): WebSocket {
  const clientOptions: ClientOptions = {
    handshakeTimeout: 5000,
    headers: {
      Host: options.host ?? "demo.tnl.dev",
      ...(options.origin === undefined ? {} : { Origin: options.origin }),
    },
  };
  const url = `ws://127.0.0.1:${port}${path}`;
  return options.protocol === undefined
    ? new WebSocket(url, clientOptions)
    : new WebSocket(url, options.protocol, clientOptions);
}

function webSocketDataString(data: Data): string {
  if (Array.isArray(data)) {
    return Buffer.concat(data).toString("utf8");
  }
  if (data instanceof ArrayBuffer) {
    return Buffer.from(data).toString("utf8");
  }
  return data.toString("utf8");
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
