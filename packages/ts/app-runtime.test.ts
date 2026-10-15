import { createServer } from "node:http";
import { chmod, mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, onTestFinished, test, vi } from "vitest";
import { createPreparedService, runtimeRequest, startRuntime } from "./dist/internal/app.js";
import { TnlError } from "./dist/errors.js";
import { startTestBootstrap } from "./test-helper/bootstrap.js";
import { createProjectFixture, testPublicProject } from "./test-helper/project.js";
import { record } from "./dist/internal/runtime.js";
import { parseEndpoint, type RuntimeEndpoint } from "./dist/internal/local.js";
import { withProcessEnvironment } from "./test-helper/environment.js";

afterEach(() => vi.useRealTimers());

test("discovers a scoped HTTP endpoint through native and authenticates health", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tnl-sdk-runtime-"));
  const binary = join(directory, "fake-tnl.mjs");
  const bootstrap = await startTestBootstrap();
  try {
    await writeFile(
      binary,
      `#!${process.execPath}
if (!process.argv.includes("endpoint") || !process.argv.includes("--state-dir") || !process.argv.includes("--service")) process.exit(1);
process.stdout.write(${JSON.stringify(JSON.stringify(bootstrap.endpoint))});`,
    );
    await chmod(binary, 0o700);
    const endpoint = await startRuntime(directory, binary, { service: "api", stateDir: directory });
    expect(endpoint).toEqual(bootstrap.endpoint);
  } finally {
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
    start: async () => ({ ...testEndpoint, service: "web" }),
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
  const start = vi.fn(async () => bootstrap.endpoint);
  const handle = await createPreparedService({ service: "api" }, "node", {
    start,
    request: runtimeRequest,
  });
  onTestFinished(() => handle.close());
  expect(bootstrap.requests).toHaveLength(1);
  expect(bootstrap.requests[0]?.path).toBe("/v1/prepare");
  expect(handle.services.api?.url).toBe("https://api.member.example");
  expect(JSON.stringify(handle)).not.toMatch(/owner|registration_id|capability|token|directory/);
  const server = createServer((_req, res) => res.end("app"));
  onTestFinished(() => new Promise<void>((resolve) => server.close(() => resolve())));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  await handle.register(server);
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing bound address");
  expect(bootstrap.requests[1]).toMatchObject({
    path: "/v1/register",
    body: { target: `http://127.0.0.1:${address.port}` },
  });
  await handle.close();
  expect(server.listening).toBe(true);
  expect(bootstrap.requests.at(-1)?.path).toBe("/v1/unregister");
  expect(bootstrap.requests.at(-1)?.body).toMatchObject({
    target: `http://127.0.0.1:${address.port}`,
  });
  expect(
    bootstrap.requests.every(
      (request) => request.authorization === `Bearer ${bootstrap.endpoint.capability}`,
    ),
  ).toBe(true);
});

test("one app prepares without a service hint; cwd selects the project only", async () => {
  const calls: { directory: string; service: string | undefined }[] = [];
  const handle = await createPreparedService({}, "node", {
    start: async (directory, _binary, selection) => {
      calls.push({ directory, service: selection?.service });
      return testEndpoint;
    },
    request: async (_endpoint, operation, body) => {
      if (operation === "prepare") {
        const request = record(body, "prepare request");
        expect(request.directory).toBe(process.cwd());
        expect(request).not.toHaveProperty("service");
        return assignment();
      }
      return undefined;
    },
  });
  expect(calls).toEqual([{ directory: process.cwd(), service: undefined }]);
  expect(handle.service).toBe("api");
  await handle.close();
});

test("multiple app services require an explicit service, even from a service subdirectory", async () => {
  const { serviceDirectory: directory } = await createProjectFixture("tnl-multiple-apps-");
  const start = vi.fn(
    async (_directory: string, _binary?: string, selection?: { service?: string }) => {
      if (selection?.service !== "api") throw new TnlError("sdk.configuration_invalid");
      return testEndpoint;
    },
  );
  const request = vi.fn(async (_endpoint: RuntimeEndpoint, operation: string, body?: unknown) => {
    if (operation !== "prepare") return undefined;
    const prepare = record(body, "prepare request");
    expect(prepare.directory).toBe(directory);
    expect(prepare.service).toBe("api");
    return assignment();
  });
  await expect(
    createPreparedService({ directory }, "node", { start, request }),
  ).rejects.toMatchObject({
    code: "sdk.configuration_invalid",
  });
  expect(request).not.toHaveBeenCalled();
  const handle = await createPreparedService({ directory, service: "api" }, "node", {
    start,
    request,
  });
  expect(start).toHaveBeenCalledTimes(2);
  expect(handle.service).toBe("api");
  await handle.close();
});

test("a surviving app reconnects and re-registers after the manager crashes", async () => {
  vi.useFakeTimers();
  let failed = false;
  const request = vi.fn(async (_endpoint: RuntimeEndpoint, operation: string) => {
    if (operation === "prepare") return assignment(failed ? "b" : "a");
    if (operation === "renew" && !failed) {
      failed = true;
      throw new TnlError("sdk.dev_unavailable");
    }
    return undefined;
  });
  const start = vi.fn(async () => testEndpoint);
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
  const request = vi.fn(async (_endpoint: RuntimeEndpoint, operation: string) =>
    operation === "prepare" ? assignment() : undefined,
  );
  const handle = await createPreparedService({}, "bun", {
    start: async () => testEndpoint,
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
      start: async () => testEndpoint,
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
  await expect(runtimeRequest(bootstrap.endpoint, "prepare", {})).rejects.toMatchObject({
    code: "sdk.owner_conflict",
    message: expect.not.stringContaining("secret"),
  });
});

test("native publisher selection errors are authored without copying private details", async () => {
  for (const [nativeCode, sdkCode, hint] of [
    [
      "runtime.publisher_setup_required",
      "sdk.publisher_setup_required",
      "tnl publisher setup --namespace",
    ],
    ["runtime.publisher_file_invalid", "sdk.publisher_file_invalid", "publisher file"],
  ] as const) {
    const bootstrap = await startTestBootstrap({
      status: 400,
      responseBody: JSON.stringify({ code: nativeCode, message: "secret provider detail" }),
    });
    const { service: _service, ...scoped } = bootstrap.endpoint;
    await expect(
      runtimeRequest(
        { ...scoped, scope: "invocation", invocation_id: `ivk_${"A".repeat(22)}` },
        "ad-hoc/register",
        {},
      ),
    ).rejects.toMatchObject({
      code: sdkCode,
      message: expect.stringContaining(hint),
    });
    await bootstrap.close();
  }
});

const testEndpoint: RuntimeEndpoint = {
  version: 1,
  url: "http://127.0.0.1:12345",
  owner_id: "a".repeat(32),
  capability: "b".repeat(64),
  scope: "app",
  service: "api",
};

test("mounted read-only descriptors never spawn native and reject unsafe replacements", async () => {
  const bootstrap = await startTestBootstrap();
  await withProcessEnvironment(bootstrap.environment, async () => {
    expect(await startRuntime(process.cwd(), "/does-not-exist", { service: "api" })).toEqual(
      bootstrap.endpoint,
    );
    const descriptor = bootstrap.environment.TNL_APP_ENDPOINT;
    if (descriptor === undefined) throw new Error("missing mounted descriptor");
    await chmod(descriptor, 0o644);
    await expect(
      startRuntime(process.cwd(), "/does-not-exist", { service: "api" }),
    ).rejects.toMatchObject({ code: "sdk.configuration_invalid" });
  });
  await bootstrap.close();
});

test("a Compose app waits for its scoped descriptor to be written", async () => {
  const bootstrap = await startTestBootstrap();
  const descriptor = bootstrap.environment.TNL_APP_ENDPOINT;
  if (descriptor === undefined) throw new Error("missing mounted descriptor");
  await unlink(descriptor);
  await withProcessEnvironment(bootstrap.environment, async () => {
    const selected = startRuntime(process.cwd(), "/does-not-exist", { service: "api" });
    await new Promise<void>((resolve) => setTimeout(resolve, 50));
    await writeFile(descriptor, JSON.stringify(bootstrap.endpoint), { mode: 0o400 });
    expect(await selected).toEqual(bootstrap.endpoint);
  });
  await bootstrap.close();
});

test("endpoint validation rejects owner scope, DNS, cross-service grants, and extra secrets", () => {
  for (const endpoint of [
    { ...testEndpoint, scope: "owner" },
    { ...testEndpoint, url: "http://localhost:12345" },
    { ...testEndpoint, service: "web" },
    { ...testEndpoint, session: "secret" },
    { ...testEndpoint, url: "http://127.0.0.1:12345/" },
  ])
    expect(() => parseEndpoint(endpoint, { service: "api" })).toThrow(TnlError);
});

test("a Compose app accepts only its configured publisher authority", () => {
  const authority = "http://publisher:8123";
  const endpoint = { ...testEndpoint, url: authority };
  expect(parseEndpoint(endpoint, { service: "api" }, authority)).toEqual(endpoint);
  for (const selected of [
    undefined,
    "http://another-publisher:8123",
    "http://publisher:8124",
    "http://127.0.0.1:8123",
  ]) {
    expect(() => parseEndpoint(endpoint, { service: "api" }, selected)).toThrow(TnlError);
  }
  expect(() => parseEndpoint({ ...endpoint, scope: "invocation" }, {}, authority)).toThrow(
    TnlError,
  );
});

test(
  "live scoped HTTP reconnect replaces both owner capability and registration",
  { timeout: 15_000 },
  async () => {
    const first = await startTestBootstrap();
    const second = await startTestBootstrap({
      capability: "c".repeat(64),
      ownerID: "d".repeat(32),
      registrationID: `reg_${"e".repeat(32)}`,
    });
    let current = first.endpoint;
    const app = createServer((_request, response) => response.end("app"));
    await new Promise<void>((resolve) => app.listen(0, "127.0.0.1", resolve));
    const handle = await createPreparedService({ service: "api" }, "node", {
      start: async () => current,
      request: runtimeRequest,
    });
    try {
      await handle.register(app);
      await expect(
        runtimeRequest({ ...second.endpoint, capability: first.endpoint.capability }, "health"),
      ).rejects.toMatchObject({ code: "sdk.registration_stale" });
      await first.close();
      current = second.endpoint;
      await expect
        .poll(() => second.requests.filter((request) => request.path === "/v1/register").length, {
          timeout: 10_000,
        })
        .toBe(1);
      expect(second.requests.find((request) => request.path === "/v1/register")).toMatchObject({
        authorization: `Bearer ${second.endpoint.capability}`,
        body: { registration_id: `reg_${"e".repeat(32)}` },
      });
      expect(handle.publicURL).toBe("https://api.member.example");
      await handle.close();
      expect(second.requests.at(-1)?.body).toMatchObject({
        registration_id: `reg_${"e".repeat(32)}`,
      });
    } finally {
      await handle.close();
      await new Promise<void>((resolve) => app.close(() => resolve()));
    }
  },
);
