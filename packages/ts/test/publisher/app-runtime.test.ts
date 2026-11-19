import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chmod, mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assert, afterEach, expect, onTestFinished, test, vi } from "vitest";
import * as z from "zod";
import {
  createPreparedService,
  reportFrameworkTarget,
  runtimeRequest,
  startRuntime,
} from "../../dist/internal/publisher/app.js";
import { parseAssignment } from "../../dist/internal/publisher/registration.js";
import { TnlError } from "../../dist/errors.js";
import { startTestBootstrap } from "../helpers/bootstrap.js";
import {
  createProjectFixture,
  testPrivateAssignment,
  testPublicProject,
} from "../helpers/project.js";
import { invocationIDSchema } from "../../dist/internal/values.js";
import { parseEndpoint, type RuntimeEndpoint } from "../../dist/internal/publisher/local.js";
import { withProcessEnvironment } from "../helpers/environment.js";
import { closeFramework } from "../../dist/internal/publisher/framework.js";

afterEach(() => vi.useRealTimers());

test.each([false, true])(
  "framework cleanup distinguishes an observed registration failure from independent cleanup (%s)",
  async (independent) => {
    const listener = createServer();
    await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
    const primary = new TnlError("sdk.listener_failed");
    const cleanup = new Error("independent unregister failure");
    let unregisters = 0;
    const handle = await createPreparedService({}, "vite", {
      start: async () => testEndpoint,
      request: async (_endpoint, name) => {
        if (name === "prepare") return assignment();
        if (name === "register") throw primary;
        if (name === "unregister") {
          unregisters++;
          if (independent) throw cleanup;
        }
        return undefined;
      },
    });
    try {
      await expect(handle.register(listener)).rejects.toBe(primary);
      if (independent) {
        await expect(closeFramework(handle, primary)).rejects.toMatchObject({
          code: "sdk.cleanup_failed",
          errors: [primary, { code: "sdk.cleanup_failed", errors: [primary, cleanup] }],
        });
      } else {
        await expect(closeFramework(handle, primary)).resolves.toBeUndefined();
        await expect(handle.close()).rejects.toBe(primary);
      }
      expect(unregisters).toBe(1);
      expect(listener.listening).toBe(true);
    } finally {
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    }
  },
);

test.each(["node", "bun", "vite", "next"] as const)(
  "%s default and explicit telemetry choices stay independent across owner rediscovery",
  async (framework) => {
    vi.stubEnv("TNL_NO_TELEMETRY", undefined);
    const requests: unknown[] = [];
    let failRegistration = false;
    const dependencies = {
      start: async () => testEndpoint,
      request: async (_endpoint: RuntimeEndpoint, operation: string, body?: unknown) => {
        if (operation === "prepare") {
          requests.push(body);
          return assignment();
        }
        if (operation === "register" && failRegistration) {
          failRegistration = false;
          throw new TnlError("sdk.registration_stale");
        }
        return undefined;
      },
    };
    const disabled = await createPreparedService({ telemetry: false }, framework, dependencies);
    onTestFinished(() => disabled.close());
    const enabled = await createPreparedService({}, framework, dependencies);
    onTestFinished(() => enabled.close());
    const explicitlyEnabled = await createPreparedService(
      { telemetry: true },
      framework,
      dependencies,
    );
    onTestFinished(() => explicitlyEnabled.close());
    expect(requests).toHaveLength(3);
    expect(requests[0]).toMatchObject({ telemetry_disabled: true });
    expect(requests[1]).toMatchObject({ telemetry_disabled: false });
    expect(requests[2]).toMatchObject({ telemetry_disabled: false });
    vi.stubEnv("TNL_NO_TELEMETRY", "true");
    failRegistration = true;
    await reportFrameworkTarget(disabled, "http://127.0.0.1:3200");
    failRegistration = true;
    await reportFrameworkTarget(enabled, "http://127.0.0.1:3201");
    failRegistration = true;
    await reportFrameworkTarget(explicitlyEnabled, "http://127.0.0.1:3202");
    expect(requests).toHaveLength(6);
    expect(requests[3]).toMatchObject({ telemetry_disabled: true });
    expect(requests[4]).toMatchObject({ telemetry_disabled: false });
    expect(requests[5]).toMatchObject({ telemetry_disabled: false });
  },
);

test("close joins pending registration and preserves independent operation and cleanup failures", async () => {
  const listener = createServer();
  await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const entered = Promise.withResolvers<void>();
  const cleanup = new Error("native cleanup unavailable");
  let operation: Error | undefined;
  const handle = await createPreparedService({}, "node", {
    start: async () => testEndpoint,
    request: async (_endpoint, name, _body, signal) => {
      if (name === "prepare") return assignment();
      if (name === "unregister") throw cleanup;
      if (name === "register") {
        if (signal === undefined) throw new Error("registration has no lifetime");
        entered.resolve();
        return new Promise<never>((_resolve, reject) => {
          signal.addEventListener(
            "abort",
            () => {
              operation = new Error("independent registration failure", { cause: signal.reason });
              reject(operation);
            },
            { once: true },
          );
        });
      }
      return undefined;
    },
  });
  try {
    const registering = handle.register(listener);
    const registrationError = registering.catch((cause: unknown) => cause);
    await entered.promise;
    const closing = await handle.close().catch((cause: unknown) => cause);
    expect(closing).toMatchObject({ code: "sdk.cleanup_failed", errors: [operation, cleanup] });
    expect(await registrationError).toBe(operation);
    expect(operation?.message).toBe("independent registration failure");
    expect(listener.listening).toBe(true);
  } finally {
    await new Promise<void>((resolve) => listener.close(() => resolve()));
  }
});

test("an optional preparation that finishes after its deadline releases its reservation", async () => {
  const beforeExitListeners = process.listenerCount("beforeExit");
  const controller = new AbortController();
  const request = vi.fn(async (_endpoint: RuntimeEndpoint, name: string) => {
    if (name === "prepare") {
      controller.abort(new TnlError("sdk.dev_unavailable"));
      return assignment();
    }
    return undefined;
  });
  await expect(
    createPreparedService(
      {},
      "vite",
      {
        start: async () => testEndpoint,
        request,
      },
      () => {},
      controller.signal,
    ),
  ).rejects.toMatchObject({ code: "sdk.dev_unavailable" });
  expect(request.mock.calls.map(([, name]) => name)).toEqual(["prepare", "unregister"]);
  expect(process.listenerCount("beforeExit")).toBe(beforeExitListeners);
});

test.each(["confirmed", "independent failure"] as const)(
  "late preparation compensation carries the original stop deadline with %s",
  async (outcome) => {
    vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
    const timeout = vi.spyOn(AbortSignal, "timeout");
    const controller = new AbortController();
    const entered = Promise.withResolvers<void>();
    const reply = Promise.withResolvers<void>();
    const stopped = new TnlError("sdk.dev_unavailable");
    const cleanup = new Error("independent compensation failure");
    let compensation: unknown;
    let cleanupSignal: AbortSignal | undefined;
    const preparing = createPreparedService(
      {},
      "vite",
      {
        start: async () => testEndpoint,
        request: async (_endpoint, name, value, signal) => {
          if (name === "prepare") {
            entered.resolve();
            await reply.promise;
            return assignment();
          }
          if (name === "unregister") {
            compensation = value;
            cleanupSignal = signal;
            if (outcome === "independent failure") throw cleanup;
          }
          return undefined;
        },
      },
      () => {},
      controller.signal,
    ).catch((cause: unknown) => cause);
    try {
      await entered.promise;
      const firstStop = Date.now();
      controller.abort(stopped);
      await vi.advanceTimersByTimeAsync(1_000);
      reply.resolve();
      const result = await preparing;
      expect(compensation).toMatchObject({
        shutdown_deadline: new Date(firstStop + 10_000).toISOString(),
      });
      expect(cleanupSignal?.aborted).toBe(false);
      expect(timeout).toHaveBeenLastCalledWith(9_000);
      if (outcome === "independent failure")
        expect(result).toMatchObject({ code: "sdk.cleanup_failed", errors: [stopped, cleanup] });
      else expect(result).toBe(stopped);
    } finally {
      reply.resolve();
      await preparing;
      timeout.mockRestore();
      vi.useRealTimers();
    }
  },
);

test("independent SDK copies share preparation and framework callbacks through close and reprepare", async () => {
  const first = await import("../../dist/internal/publisher/app.js");
  vi.resetModules();
  const second = await import("../../dist/internal/publisher/app.js");
  expect(second.prepareService).not.toBe(first.prepareService);
  expect(second.reportFrameworkTarget).not.toBe(first.reportFrameworkTarget);
  const bootstrap = await startTestBootstrap();
  await withProcessEnvironment(bootstrap.environment, async () => {
    const beforeExitListeners = process.listenerCount("beforeExit");
    const prepared = first.prepareService({}, "next");
    expect(second.prepareService({}, "next")).toBe(prepared);
    const handle = await prepared;
    onTestFinished(() => handle.close());
    await second.reportFrameworkTarget(handle, "http://127.0.0.1:3200");
    await first.reportFrameworkTarget(handle, "http://127.0.0.1:3201");
    expect(bootstrap.requests.map(({ path }) => path)).toEqual([
      "/v1/prepare",
      "/v1/register",
      "/v1/register",
    ]);
    expect(bootstrap.requests.at(-1)?.body).toMatchObject({ target: "http://127.0.0.1:3201" });
    await handle.close();
    expect(process.listenerCount("beforeExit")).toBe(beforeExitListeners);
    await expect(
      second.reportFrameworkTarget(handle, "http://127.0.0.1:3202"),
    ).rejects.toMatchObject({ code: "sdk.registration_stale" });
    const replacement = second.prepareService({}, "next");
    expect(replacement).not.toBe(prepared);
    const replaced = await replacement;
    onTestFinished(() => replaced.close());
    expect(replaced).not.toBe(handle);
    await handle.close();
    expect(first.prepareService({}, "next")).toBe(replacement);
    await first.reportFrameworkTarget(replaced, "http://127.0.0.1:3202");
    await replaced.close();
    expect(process.listenerCount("beforeExit")).toBe(beforeExitListeners);
    expect(bootstrap.requests.map(({ path }) => path)).toEqual([
      "/v1/prepare",
      "/v1/register",
      "/v1/register",
      "/v1/unregister",
      "/v1/prepare",
      "/v1/register",
      "/v1/unregister",
    ]);
  });
});

test("independent SDK copies evict a failed preparation before retrying", async () => {
  const first = await import("../../dist/internal/publisher/app.js");
  vi.resetModules();
  const second = await import("../../dist/internal/publisher/app.js");
  expect(second.prepareService).not.toBe(first.prepareService);
  const options: { status: number; responseBody?: string } = {
    status: 503,
    responseBody: JSON.stringify({ code: "runtime.unavailable", message: "unavailable" }),
  };
  const bootstrap = await startTestBootstrap(options);
  await withProcessEnvironment(bootstrap.environment, async () => {
    const beforeExitListeners = process.listenerCount("beforeExit");
    const failed = first.prepareService({}, "next");
    expect(second.prepareService({}, "next")).toBe(failed);
    await expect(failed).rejects.toMatchObject({ code: "sdk.dev_unavailable" });
    expect(process.listenerCount("beforeExit")).toBe(beforeExitListeners);
    options.status = 200;
    delete options.responseBody;
    const retried = second.prepareService({}, "next");
    expect(retried).not.toBe(failed);
    expect(first.prepareService({}, "next")).toBe(retried);
    const handle = await retried;
    onTestFinished(() => handle.close());
    await first.reportFrameworkTarget(handle, "http://127.0.0.1:3200");
    await handle.close();
    expect(process.listenerCount("beforeExit")).toBe(beforeExitListeners);
    expect(bootstrap.requests.map(({ path }) => path)).toEqual([
      "/v1/prepare",
      "/v1/prepare",
      "/v1/register",
      "/v1/unregister",
    ]);
  });
});

test.each(["close", "failure"] as const)(
  "%s cleanup cannot evict a replacement preparation",
  async (cleanup) => {
    const app = await import("../../dist/internal/publisher/app.js");
    const bootstrap = await startTestBootstrap(cleanup === "failure" ? { status: 503 } : {});
    const replacementHandle = await app.createPreparedService({}, "next", {
      start: async () => testEndpoint,
      request: async (_endpoint, operation) => (operation === "prepare" ? assignment() : undefined),
    });
    onTestFinished(() => replacementHandle.close());
    const replacement = Promise.resolve(replacementHandle);
    await withProcessEnvironment(bootstrap.environment, async () => {
      const prepared = app.prepareService({}, "next");
      const handle = cleanup === "close" ? await prepared : undefined;
      if (handle !== undefined) onTestFinished(() => handle.close());
      const registry = globalThis.__tnlAppRegistry;
      const key = [...(registry?.preparations ?? [])].find(([, value]) => value === prepared)?.[0];
      if (registry === undefined || key === undefined)
        throw new Error("preparation was not cached");
      // replace the entry while the older lifetime still owns its cleanup callback.
      registry.preparations.set(key, replacement);
      onTestFinished(() => {
        if (registry.preparations.get(key) === replacement) registry.preparations.delete(key);
      });
      if (handle === undefined)
        await expect(prepared).rejects.toMatchObject({ code: "sdk.response_invalid" });
      else await handle.close();
      expect(app.prepareService({}, "next")).toBe(replacement);
    });
  },
);

test("close cancels a queued listener wait and removes its listeners before unregistering", async () => {
  const request = vi.fn(async (_endpoint: RuntimeEndpoint, operation: string) =>
    operation === "prepare" ? assignment() : undefined,
  );
  const handle = await createPreparedService({}, "node", {
    start: async () => testEndpoint,
    request,
  });
  const server = createServer();
  const listeningListeners = server.listenerCount("listening");
  const registering = handle.register(server).catch((error: unknown) => error);
  await vi.waitFor(() => expect(server.listenerCount("listening")).toBe(listeningListeners + 1));
  const closed = handle.close();
  const outcome = await Promise.race([
    closed.then(() => "closed"),
    new Promise((resolve) => setTimeout(() => resolve("waiting"), 100)),
  ]);
  // release the old implementation's ten-minute timer even on RED.
  server.emit("close");
  await closed;
  expect(outcome).toBe("closed");
  expect(await registering).toMatchObject({ code: "sdk.registration_stale" });
  expect(server.listenerCount("listening")).toBe(listeningListeners);
  expect(server.listenerCount("error")).toBe(0);
  expect(request.mock.calls.filter(([, op]) => op === "register")).toHaveLength(0);
});

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
      new URL(
        "../../../../internal/publisher/localapi/protocol/testdata/runtime.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  const fixtures = z.object({ assignment: z.unknown().nonoptional() }).parse(golden);
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

function deferredAssignment() {
  return {
    ...assignment(),
    hostname: "",
    public_url: "",
    project: { namespace: "", services: {}, dev: true },
  };
}

test("acquisition can acknowledge a registration before its selected endpoint exists", () => {
  expect(parseAssignment(deferredAssignment())).toEqual({
    registrationID: assignment().registration_id,
    service: "api",
    hostname: undefined,
    publicURL: undefined,
    project: { namespace: "", services: {}, dev: true },
  });
});

test.each([
  ["hostname without metadata", { hostname: "api.member.example" }],
  ["public URL without hostname", { public_url: "https://api.member.example" }],
  ["hidden selected endpoint", { project: testPrivateAssignment().project }],
  ["secret acquisition field", { access_token: "private-secret" }],
] as const)("rejects deferred acquisition with %s", (_name, change) => {
  expect(() => parseAssignment({ ...deferredAssignment(), ...change })).toThrow(
    expect.objectContaining({
      code: "sdk.response_invalid",
      message: expect.not.stringContaining("private-secret"),
    }),
  );
});

test("private HTTP preparation has no public address or browser-visible target", async () => {
  const selected = testPrivateAssignment();
  const handle = await createPreparedService({ service: "api" }, "node", {
    start: async () => testEndpoint,
    request: async (_endpoint, operation) =>
      operation === "prepare"
        ? {
            ...assignment(),
            hostname: selected.hostname,
            public_url: "",
            project: selected.project,
          }
        : undefined,
  });
  expect(handle.hostname).toBe(selected.hostname);
  expect(handle.publicURL).toBeUndefined();
  expect(handle.services).toEqual(selected.project.services);
  expect(JSON.stringify(handle)).not.toMatch(
    /target|owner|registration_id|capability|token|directory/,
  );
  await handle.close();
});

test.each([
  ["deferred acquisition shape at preparation", deferredAssignment()],
  ["missing hostname", { hostname: "" }],
  ["mismatched hostname", { hostname: "other.member.example" }],
  ["private public URL", { public_url: "https://api.member.example" }],
  ["secret assignment field", { access_token: "private-secret" }],
  ["missing selected endpoint", { project: { namespace: "", services: {}, dev: true } }],
  [
    "mismatched metadata URL",
    {
      project: {
        ...testPrivateAssignment().project,
        services: {
          api: {
            ...testPrivateAssignment().project.services.api,
            url: "https://other.member.example",
          },
        },
      },
    },
  ],
  [
    "secret endpoint field",
    {
      project: {
        ...testPrivateAssignment().project,
        services: {
          api: {
            ...testPrivateAssignment().project.services.api,
            target: "http://private-secret:3000",
          },
        },
      },
    },
  ],
  [
    "zero HTTP port",
    {
      project: {
        ...testPrivateAssignment().project,
        services: { api: { ...testPrivateAssignment().project.services.api, port: 0 } },
      },
    },
  ],
  ["public endpoint without public URL", { project: testPublicProject(true) }],
] as const)("rejects private preparation with %s", async (_name, change) => {
  const selected = testPrivateAssignment();
  await expect(
    createPreparedService({ service: "api" }, "node", {
      start: async () => testEndpoint,
      request: async () => ({
        ...assignment(),
        hostname: selected.hostname,
        public_url: "",
        project: selected.project,
        ...change,
      }),
    }),
  ).rejects.toMatchObject({
    code: "sdk.response_invalid",
    message: expect.not.stringContaining("private-secret"),
  });
});

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
  assert(handle.services.api?.protocol === "http");
  expect(handle.services.api.url).toBe("https://api.member.example");
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
        expect(body).toMatchObject({ directory: process.cwd() });
        expect(body).not.toHaveProperty("service");
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
    expect(body).toMatchObject({ directory, service: "api" });
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
    [
      "runtime.publisher_credential_file_invalid",
      "sdk.publisher_credential_file_invalid",
      "publisher file",
    ],
  ] as const) {
    const bootstrap = await startTestBootstrap({
      status: 400,
      responseBody: JSON.stringify({ code: nativeCode, message: "secret provider detail" }),
    });
    assert(bootstrap.endpoint.scope === "app");
    const { service: _service, ...scoped } = bootstrap.endpoint;
    await expect(
      runtimeRequest(
        {
          ...scoped,
          scope: "invocation",
          invocation_id: invocationIDSchema.parse(`ivk_${"A".repeat(22)}`),
        },
        "publications/register",
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

test("a mounted FIFO is rejected before open can block a filesystem worker", async () => {
  const root = await mkdtemp(join(tmpdir(), "tnl-endpoint-fifo-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const file = join(root, "endpoint");
  const run = promisify(execFile);
  await run("mkfifo", ["-m", "600", file]);
  await run(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `
    import assert from 'node:assert/strict';
    import {startRuntime} from ${JSON.stringify(new URL("../../dist/internal/publisher/local.js", import.meta.url).href)};
    await assert.rejects(startRuntime(process.cwd(), '/unused/tnl'), {code:'sdk.configuration_invalid'});
  `,
    ],
    { env: { ...process.env, TNL_APP_ENDPOINT: file }, timeout: 3000, killSignal: "SIGKILL" },
  );
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
