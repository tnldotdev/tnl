import { createServer } from "node:http";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, onTestFinished, test, vi } from "vitest";
import { createPreparedService, runtimeRequest, startRuntime } from "./dist/internal/app.js";
import { TnlError } from "./dist/errors.js";
import { startTestBootstrap } from "./test-helper/bootstrap.js";
import { testPublicProject } from "./test-helper/project.js";
import { record } from "./dist/internal/runtime.js";

afterEach(() => vi.useRealTimers());

test("starts a local publisher as a child of the app, then waits for its health", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tnl-sdk-runtime-"));
  const binary = join(directory, "fake-tnl.mjs");
  let workerPID: number | undefined;
  try {
    await writeFile(
      binary,
      `#!/usr/bin/env node
import http from "node:http";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
const directory = process.argv[process.argv.indexOf("--directory") + 1];
const path = join(directory, "manager.sock.endpoint.json");
if (process.argv.includes("endpoint")) process.stdout.write(JSON.stringify({ version: 1, path }) + "\\n");
else if (process.argv.includes("serve")) {
  const credential = "a".repeat(43);
  const server = http.createServer((request, response) => {
    response.writeHead(request.url === "/v1/health" ? 204 : 401).end();
  });
  server.listen(0, "127.0.0.1", () => {
    writeFileSync(path, JSON.stringify({ version: 1, url: "http://127.0.0.1:" + server.address().port, credential }));
    writeFileSync(join(directory, "pid"), String(process.pid));
  });
  process.on("SIGTERM", () => server.close(() => process.exit(0)));
}
`,
    );
    await chmod(binary, 0o700);
    const endpointPath = await startRuntime(directory, undefined, binary);
    expect(endpointPath).toBe(join(directory, "manager.sock.endpoint.json"));
    workerPID = Number(await readFile(join(directory, "pid"), "utf8"));
    expect(workerPID).toBeGreaterThan(0);
  } finally {
    if (workerPID !== undefined) process.kill(workerPID, "SIGTERM");
    await rm(directory, { recursive: true, force: true });
  }
});

test("sends authenticated local publisher requests over loopback TCP", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tnl-sdk-tcp-"));
  const credential = "b".repeat(43);
  const received: boolean[] = [];
  const server = createServer((request, response) => {
    received.push(request.headers.authorization === `Bearer ${credential}`);
    request.resume();
    response.writeHead(204).end();
  });
  try {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("missing bound address");
    const endpointPath = join(directory, "manager.sock.endpoint.json");
    await writeFile(
      endpointPath,
      JSON.stringify({ version: 1, url: `http://127.0.0.1:${address.port}`, credential }),
    );
    await expect(
      runtimeRequest(endpointPath, "renew", {
        registration_id: `reg_${"b".repeat(32)}`,
        owner: "b".repeat(32),
      }),
    ).resolves.toBeUndefined();
    expect(received).toEqual([true]);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

test("keeps temporary publication requests on the app-owned Unix socket", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tnl-sdk-adhoc-"));
  const socket = join(directory, "manager.sock");
  const requests: string[] = [];
  const server = createServer((request, response) => {
    requests.push(request.url ?? "");
    request.resume();
    response.writeHead(204).end();
  });
  try {
    await new Promise<void>((resolve) => server.listen(socket, resolve));
    await expect(runtimeRequest(socket, "ad-hoc/renew", { version: 1 })).resolves.toBeUndefined();
    expect(requests).toEqual(["/v1/ad-hoc/renew"]);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

test("accepts the native private protocol golden assignment", async () => {
  const golden: unknown = JSON.parse(
    await readFile(
      new URL("../../internal/privateprotocol/testdata/runtime.json", import.meta.url),
      "utf8",
    ),
  );
  const fixtures = record(golden, "private protocol fixture");
  const handle = await createPreparedService({ service: "web" }, "node", {
    start: async () => "/isolated/manager.sock",
    request: async (_socket, operation) =>
      operation === "prepare" ? fixtures.assignment : undefined,
  });
  expect(handle.publicURL).toBe("https://web.member.example");
  expect(handle.service).toBe("web");
  await handle.close();
});

function assignment(registration = "a") {
  return {
    version: 1,
    registration_id: `reg_${registration.repeat(32)}`,
    service: "api",
    hostname: "api.member.example",
    public_url: "https://api.member.example",
    project: testPublicProject(true),
  };
}

test("preparation exposes only public metadata and registers an actual port-0 Node listener", async () => {
  const bootstrap = await startTestBootstrap();
  const start = vi.fn(async () => bootstrap.endpointPath);
  const handle = await createPreparedService({ service: "api" }, "node", {
    start,
    request: runtimeRequest,
  });
  onTestFinished(() => handle.close());
  expect(bootstrap.requests).toHaveLength(1);
  expect(bootstrap.requests[0]?.path).toBe("/v1/prepare");
  expect(handle.services.api?.url).toBe("https://api.member.example");
  expect(JSON.stringify(handle)).not.toMatch(/owner|registration_id|socket|token|directory/);
  const server = createServer((_req, res) => res.end("app"));
  onTestFinished(() => new Promise<void>((resolve) => server.close(() => resolve())));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  await handle.register(server);
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing bound address");
  expect(bootstrap.requests[1]).toMatchObject({
    path: `/v1/registrations/reg_${"b".repeat(32)}`,
    body: { target: `http://127.0.0.1:${address.port}` },
  });
  await handle.close();
  expect(server.listening).toBe(true);
  expect(bootstrap.requests.at(-1)?.path).toBe(`/v1/registrations/reg_${"b".repeat(32)}`);
});

test("a surviving app reconnects and re-registers after the manager crashes", async () => {
  vi.useFakeTimers();
  let failed = false;
  const request = vi.fn(async (_socket: string, operation: string) => {
    if (operation === "prepare") return assignment(failed ? "b" : "a");
    if (operation === "renew" && !failed) {
      failed = true;
      throw new TnlError("sdk.dev_unavailable");
    }
    return undefined;
  });
  const start = vi.fn(async () => "/isolated/manager.sock");
  const handle = await createPreparedService({}, "node", { start, request });
  const listener = {
    listening: true,
    address: () => ({ address: "127.0.0.1", port: 1234 }),
    once: () => {},
    off: () => {},
    close: () => {},
  };
  await handle.register(listener);
  await vi.advanceTimersByTimeAsync(5_000);
  expect(start).toHaveBeenCalledTimes(2);
  const registrations = request.mock.calls.filter(([, operation]) => operation === "register");
  expect(registrations).toHaveLength(2);
  expect(handle.publicURL).toBe("https://api.member.example");
  await handle.close();
});

test("Bun hot replacements retain ownership and an old listener stop cannot unregister the replacement", async () => {
  const request = vi.fn(async (_socket: string, operation: string) =>
    operation === "prepare" ? assignment() : undefined,
  );
  const handle = await createPreparedService({}, "bun", {
    start: async () => "/isolated/manager.sock",
    request,
  });
  const firstStop = vi.fn();
  const first = {
    port: 1234,
    hostname: "0.0.0.0",
    url: new URL("http://localhost:1234"),
    stop: firstStop,
  };
  const secondStop = vi.fn();
  const second = {
    port: 1235,
    hostname: "0.0.0.0",
    url: new URL("http://localhost:1235"),
    stop: secondStop,
  };
  await handle.register(first);
  await handle.register(second);
  await first.stop();
  expect(firstStop).toHaveBeenCalledOnce();
  expect(request.mock.calls.filter(([, operation]) => operation === "unregister")).toHaveLength(0);
  await second.stop();
  expect(secondStop).toHaveBeenCalledOnce();
  expect(request.mock.calls.filter(([, operation]) => operation === "unregister")).toHaveLength(1);
  await handle.close();
});

test("malformed metadata and duplicate live ownership are classified without provider text", async () => {
  await expect(
    createPreparedService({}, "node", {
      start: async () => "/isolated/manager.sock",
      request: async () => ({ ...assignment(), access_token: "secret" }),
    }),
  ).rejects.toMatchObject({ code: "sdk.response_invalid" });
  const bootstrap = await startTestBootstrap({
    status: 409,
    responseBody: JSON.stringify({
      code: "runtime.owner_conflict",
      message: "secret provider detail",
    }),
  });
  await expect(runtimeRequest(bootstrap.endpointPath, "prepare", {})).rejects.toMatchObject({
    code: "sdk.owner_conflict",
    message: expect.not.stringContaining("secret"),
  });
});
