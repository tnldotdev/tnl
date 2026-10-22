import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { onTestFinished } from "vitest";
import * as z from "zod";
import { testPublicProject } from "./project.js";
import type { RuntimeEndpoint } from "../../src/internal/publisher/local.js";

export interface BootstrapRequest {
  readonly authorization: string | undefined;
  readonly body: unknown;
  readonly contentType: string | undefined;
  readonly method: string | undefined;
  readonly path: string | undefined;
}

export interface TestBootstrap {
  readonly endpoint: RuntimeEndpoint;
  readonly environment: Record<string, string>;
  readonly requests: BootstrapRequest[];
  assertHealthy(): void;
  close(): Promise<void>;
}

interface BootstrapOptions {
  readonly capability?: string;
  readonly ownerID?: string;
  readonly registrationID?: string;
  readonly responseBody?: string;
  readonly status?: number;
}

export async function startTestBootstrap(options: BootstrapOptions = {}): Promise<TestBootstrap> {
  const ownedDirectory = await mkdtemp(path.join(os.tmpdir(), "tnl-app-test-"));
  const capability = options.capability ?? "a".repeat(64);
  const requests: BootstrapRequest[] = [];
  let failure: unknown;
  let appOwner: string | undefined;
  const server = http.createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("error", (error) => {
      failure ??= error;
    });
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      try {
        if (
          request.headers.authorization !== `Bearer ${capability}` ||
          request.headers.origin !== undefined
        ) {
          response.writeHead(401).end();
          return;
        }
        if (request.method === "GET" && request.url === "/v1/health") {
          // readiness probes are not registration messages.
          response.writeHead(204).end();
          return;
        }
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
          response.setHeader("Content-Type", "application/json");
          response.end(options.responseBody ?? "registration failed");
        } else if (["/v1/register", "/v1/renew", "/v1/unregister"].includes(request.url ?? "")) {
          if (request.url === "/v1/unregister") appOwner = undefined;
          response.writeHead(204).end();
        } else if (request.url === "/v1/prepare") {
          const preparation = z.object({ owner: z.string() }).parse(JSON.parse(body));
          if (appOwner !== undefined && appOwner !== preparation.owner) {
            response.setHeader("Content-Type", "application/json");
            response.writeHead(409).end(
              JSON.stringify({
                code: "runtime.owner_conflict",
                message: "another live app owns this service",
              }),
            );
            return;
          }
          appOwner = preparation.owner;
          const assignment =
            options.responseBody === undefined
              ? {
                  hostname: "api.member.example",
                  project: testPublicProject(true),
                  publicURL: "https://api.member.example",
                  service: "api",
                }
              : JSON.parse(options.responseBody);
          response.setHeader("Content-Type", "application/json");
          response.end(
            JSON.stringify({
              version: 1,
              registration_id: options.registrationID ?? `reg_${"b".repeat(32)}`,
              service: assignment.service,
              hostname: assignment.hostname,
              public_url: assignment.publicURL,
              project: assignment.project,
            }),
          );
        } else {
          response.writeHead(404).end();
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
        await rm(ownedDirectory, { force: true, recursive: true });
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
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    await chmod(ownedDirectory, 0o700);
  } catch (error) {
    await close();
    failure = undefined; // the startup caller receives this error directly.
    throw error;
  }
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing listener");
  const service: string =
    options.responseBody === undefined || options.status !== undefined
      ? "api"
      : JSON.parse(options.responseBody).service;
  const endpoint: RuntimeEndpoint = {
    version: 1,
    url: `http://127.0.0.1:${address.port}`,
    capability,
    owner_id: options.ownerID ?? "b".repeat(32),
    scope: "app",
    service,
  };
  const descriptor = path.join(ownedDirectory, "endpoint.json");
  await writeFile(descriptor, JSON.stringify(endpoint), { mode: 0o400 });
  return {
    endpoint,
    environment: { TNL_APP_ENDPOINT: descriptor, APP_TEST_ENDPOINT: JSON.stringify(endpoint) },
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
    if (Date.now() >= deadline) throw new Error("framework did not register with tnl");
    await delay(50);
  }
}
