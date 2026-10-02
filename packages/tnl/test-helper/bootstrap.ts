import { chmod, mkdtemp, rm } from "node:fs/promises";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { onTestFinished } from "vitest";
import { testPublicProject } from "./project.js";

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
  assertHealthy(): void;
  close(): Promise<void>;
}

interface BootstrapOptions {
  readonly responseBody?: string;
  readonly socket?: string;
  readonly status?: number;
}

export async function startTestBootstrap(options: BootstrapOptions = {}): Promise<TestBootstrap> {
  const ownedDirectory =
    options.socket === undefined ? await mkdtemp(path.join(os.tmpdir(), "tnl-dev-test-")) : null;
  const socket = options.socket ?? path.join(ownedDirectory ?? "", "control.sock");
  const requests: BootstrapRequest[] = [];
  let failure: unknown;
  const server = http.createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("error", (error) => {
      failure ??= error;
    });
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      try {
        const body = Buffer.concat(chunks).toString("utf8");
        requests.push({
          authorization: request.headers.authorization,
          body: body === "" ? null : JSON.parse(body),
          contentType: request.headers["content-type"],
          method: request.method,
          path: request.url,
        });
        response.statusCode = options.status ?? 200;
        if (response.statusCode !== 200) {
          response.end(options.responseBody ?? "registration failed");
        } else if (request.url === "/v1/target") {
          response.writeHead(204).end();
        } else {
          response.setHeader("Content-Type", "application/json");
          response.end(
            options.responseBody ??
              JSON.stringify({
                hostname: "api.member.example",
                namespace: "member.example",
                protocol: 1,
                project: testPublicProject(true),
                publicURL: "https://api.member.example",
                service: "api",
                tunnelID: `tun_${"b".repeat(22)}`,
              }),
          );
        }
      } catch (error) {
        failure ??= error;
        response.writeHead(400).end("invalid bootstrap request");
      }
    });
  });
  server.on("error", (error) => {
    failure ??= error;
  });
  // install ownership before listen/chmod: either operation can fail before returning a handle.
  let closing: Promise<void> | undefined;
  const close = () =>
    (closing ??= (async () => {
      try {
        if (server.listening) {
          const closed = new Promise<void>((resolve, reject) => {
            server.close((error) => (error ? reject(error) : resolve()));
          });
          server.closeAllConnections();
          await closed;
        }
      } finally {
        if (ownedDirectory !== null) await rm(ownedDirectory, { force: true, recursive: true });
      }
    })());
  const assertHealthy = () => {
    if (failure !== undefined) {
      const error = failure;
      failure = undefined; // report handler failures once, including from the cleanup hook.
      throw error;
    }
  };
  onTestFinished(async () => {
    await close();
    assertHealthy();
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(socket, () => {
        server.off("error", reject);
        resolve();
      });
    });
    await chmod(socket, 0o600);
  } catch (error) {
    await close();
    failure = undefined; // the startup caller receives this error directly.
    throw error;
  }
  return {
    environment: { TNL_DEV_PROTOCOL: "1", TNL_DEV_SOCKET: socket },
    requests,
    assertHealthy,
    close,
  };
}

export async function waitForBootstrapRequest(
  bootstrap: TestBootstrap,
  index = 0,
  timeout = 30_000,
  assertRunning: () => void = () => {},
): Promise<BootstrapRequest> {
  const deadline = Date.now() + timeout;
  while (true) {
    bootstrap.assertHealthy();
    const request = bootstrap.requests[index];
    if (request !== undefined) return request;
    assertRunning();
    if (Date.now() >= deadline) throw new Error("framework did not register with tnl dev");
    await delay(50);
  }
}
