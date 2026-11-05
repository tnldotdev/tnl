import { AsyncLocalStorage } from "node:async_hooks";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { inspect } from "node:util";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

const vercel = vi.hoisted(() => ({ header: undefined as string | undefined, token: vi.fn() }));
vi.mock("@vercel/oidc", () => ({
  getContext: () => ({ headers: { "x-vercel-oidc-token": vercel.header } }),
  getVercelOidcToken: vercel.token,
}));

let directory: string;
beforeEach(async () => {
  vercel.header = undefined;
  vercel.token.mockReset();
  vi.resetModules();
  vi.stubGlobal("__tnlConnectorContextV1", undefined);
  for (const name of [
    "TNL_CONNECTION_HANDLE",
    "TNL_WORKLOAD",
    "VERCEL",
    "FLY_APP_NAME",
    "GITHUB_ACTIONS",
    "K_SERVICE",
    "KUBERNETES_SERVICE_HOST",
  ])
    vi.stubEnv(name, undefined);
  directory = await mkdtemp(path.join(tmpdir(), "tnl-provider-"));
});

test.each([
  ["K_SERVICE", "cloud_run_service", "orders"],
  ["KUBERNETES_SERVICE_HOST", "kubernetes_service_host", "10.0.0.1"],
] as const)(
  "%s forwards only native selection hints, not SDK acquisition",
  async (environment, key, hint) => {
    const { usesWorkload, selectWorkload } =
      await import("../../src/internal/connector/workload/provider.js");
    expect(usesWorkload()).toBe(false);
    vi.stubEnv(environment, hint);
    expect(usesWorkload()).toBe(true);
    const preview = vi.fn(async () => ({
      schema: 1,
      name: "app",
      directory,
      manifest: path.join(directory, ".tnl/generated/workloads.json"),
      source: "native",
      policy: "a".repeat(64),
    }));
    const selected = await selectWorkload(preview);
    expect(selected.sdk_workload?.runtime[key]).toBe(hint);
    expect(selected.assertion).toBeUndefined();
    expect(vercel.token).not.toHaveBeenCalled();
  },
);

test("native selection receives hints and current private provider inputs without SDK acquisition", async () => {
  const { selectWorkload, configureWorkload } =
    await import("../../src/internal/connector/workload/provider.js");
  configureWorkload({ name: "worker", tokenFile: "current.jwt" });
  vi.stubEnv("TNL_WORKLOAD", "");
  vi.stubEnv("GITHUB_ACTIONS", "true");
  const preview = vi.fn(async () => ({
    schema: 1,
    name: "worker",
    directory,
    manifest: path.join(directory, ".tnl/generated/workloads.json"),
    source: "native",
    policy: "a".repeat(64),
  }));
  for (const token of ["first-private-bearer", "rotated-private-bearer"]) {
    vi.stubEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", token);
    const selected = await selectWorkload(preview);
    expect(selected.assertion).toBeUndefined();
    expect(selected.sdk_environment?.github_request_token).toBe(token);
    expect(selected.sdk_workload).toMatchObject({
      name: "worker",
      token_file: "current.jwt",
      callback: false,
      runtime: { workload: "", github_actions: "true" },
    });
    expect(JSON.stringify(preview.mock.calls)).not.toContain(token);
  }
});

test("Vercel request context precedes native fallback and never invokes development refresh", async () => {
  const { acquireAssertion } = await import("../../src/internal/connector/workload/provider.js");
  const selection = { name: "worker", source: "vercel" as const };
  const signal = AbortSignal.timeout(1000);
  expect(await acquireAssertion(selection, signal)).toBeUndefined();
  expect(vercel.token).not.toHaveBeenCalled();
  vercel.header = "request.private.token";
  vercel.token.mockResolvedValue(vercel.header);
  expect(await acquireAssertion(selection, signal)).toBe(vercel.header);
  expect(vercel.token).toHaveBeenCalledExactlyOnceWith({
    expirationBufferMs: Number.NEGATIVE_INFINITY,
  });
  vercel.header = "private invalid token";
  await expect(acquireAssertion(selection, signal)).rejects.toMatchObject({
    code: "sdk.workload_assertion_unavailable",
  });
  expect(vercel.token).toHaveBeenCalledTimes(1);
});

test("a selected environment source forwards only the named current value privately", async () => {
  const { selectWorkload } = await import("../../src/internal/connector/workload/provider.js");
  const preview = vi.fn(async () => ({
    schema: 1,
    name: "worker",
    directory,
    manifest: path.join(directory, ".tnl/generated/workloads.json"),
    source: "native",
    policy: "a".repeat(64),
    token_env: "JOB_ID_TOKEN",
  }));
  for (const token of ["first.private.jwt", "second.private.jwt", ""]) {
    vi.stubEnv("JOB_ID_TOKEN", token);
    vi.stubEnv("UNRELATED_SECRET", "unrelated.private.secret");
    const selected = await selectWorkload(preview);
    expect(selected.assertion).toBeUndefined();
    expect(selected.sdk_environment?.token_env).toBe("JOB_ID_TOKEN");
    expect(selected.sdk_environment?.token_value).toBe(token);
    expect(JSON.stringify(preview.mock.calls)).not.toContain("private.jwt");
    expect(JSON.stringify(selected)).not.toContain("unrelated.private.secret");
  }
});
afterEach(async () => {
  vi.unstubAllGlobals();
  await rm(directory, { force: true, recursive: true });
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});
const callbackSelection = { name: "worker", source: "callback" as const };

test.each(["never", "late"])(
  "callback acquisition is bounded even when it resolves %s",
  async (mode) => {
    const { configureWorkload, acquireAssertion } =
      await import("../../src/internal/connector/workload/provider.js");
    let finish: ((token: string) => void) | undefined;
    let entered: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    configureWorkload({
      name: "worker",
      token: () =>
        new Promise((resolve) => {
          finish = resolve;
          entered?.();
        }),
    });
    const controller = new AbortController();
    const reason = new DOMException("acquisition deadline", "TimeoutError");
    const acquiring = acquireAssertion(callbackSelection, controller.signal);
    await started;
    controller.abort(reason);
    if (mode === "late") finish?.("late.private.assertion");
    const outcome = await Promise.race([
      acquiring.then(
        () => "accepted",
        (error: unknown) => error,
      ),
      new Promise((resolve) => setTimeout(() => resolve("still waiting"), 100)),
    ]);
    expect(outcome).toBe(reason);
  },
);

test("the SDK's ten-second acquisition deadline rejects a callback that never settles", async () => {
  const { configureWorkload, acquireAssertion } =
    await import("../../src/internal/connector/workload/provider.js");
  let finish: ((token: string) => void) | undefined;
  configureWorkload({
    name: "worker",
    token: () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  });
  const started = performance.now();
  await expect(
    acquireAssertion(callbackSelection, new AbortController().signal),
  ).rejects.toMatchObject({ name: "TimeoutError" });
  expect(performance.now() - started).toBeGreaterThanOrEqual(9900);
  finish?.("assertion.after.deadline");
}, 12_000);

test("generic callback registration is fixed, request-scoped, and never verifies or routes using untrusted JWT claims", async () => {
  const { configureWorkload, acquireAssertion } =
    await import("../../src/internal/connector/workload/provider.js");
  const storage = new AsyncLocalStorage<string>();
  const callback = vi.fn(async () => storage.getStore() ?? "");
  configureWorkload({ name: "worker", token: callback });
  configureWorkload({ name: "worker", token: callback });
  expect(() =>
    configureWorkload({ name: "worker", token: async () => "changed-global-token" }),
  ).toThrow(expect.objectContaining({ code: "sdk.workload_required" }));
  const signal = AbortSignal.timeout(1000);
  const tokens = await Promise.all(
    ["opaque-one", "opaque-two"].map((token) =>
      storage.run(token, () => acquireAssertion(callbackSelection, signal)),
    ),
  );
  expect(tokens).toEqual(["opaque-one", "opaque-two"]);
  expect(callback).toHaveBeenCalledTimes(2);
  await expect(acquireAssertion(callbackSelection, signal)).rejects.toMatchObject({
    code: "sdk.workload_assertion_unavailable",
  });
});

test("independent copies share request callbacks only within the selected context", async () => {
  const first = await import("../../src/internal/connector/workload/provider.js");
  vi.resetModules();
  const second = await import("../../src/internal/connector/workload/provider.js");
  const storage = new AsyncLocalStorage<string>();
  const callback = async () => storage.getStore() ?? "";
  first.configureWorkload({ name: "worker", token: callback });
  second.configureWorkload({ name: "worker", token: callback });
  expect(() =>
    second.configureWorkload({ name: "worker", token: async () => "replacement" }),
  ).toThrow(expect.objectContaining({ code: "sdk.workload_required" }));
  for (const variable of ["TNL_SERVER", "TNL_STATE_DIR", "TNL_CONNECTION_HANDLE"]) {
    const previous = process.env[variable];
    vi.stubEnv(variable, "/another/context");
    expect(second.usesWorkload()).toBe(false);
    second.configureWorkload({ name: "worker", token: async () => "isolated" });
    expect(await second.acquireAssertion(callbackSelection, AbortSignal.timeout(1000))).toBe(
      "isolated",
    );
    vi.stubEnv(variable, previous);
  }
  const values = await Promise.all(
    ["one", "two"].map((token) =>
      storage.run(token, () =>
        second.acquireAssertion(callbackSelection, AbortSignal.timeout(1000)),
      ),
    ),
  );
  expect(values).toEqual(["one", "two"]);
});

test("callback and parser causes stay private under normal Node error inspection", async () => {
  const { configureWorkload, acquireAssertion } =
    await import("../../src/internal/connector/workload/provider.js");
  const cause = new Error("Bearer private-provider-secret");
  configureWorkload({
    name: "worker",
    token: async () => {
      throw cause;
    },
  });
  const error: unknown = await acquireAssertion(callbackSelection, AbortSignal.timeout(1000)).catch(
    (error: unknown) => error,
  );
  expect(error).toMatchObject({
    code: "sdk.workload_assertion_unavailable",
    retry: "after_change",
  });
  expect(error).not.toHaveProperty("cause");
  expect(inspect(error, { depth: 10 })).not.toContain("private-provider-secret");
  expect(JSON.stringify(error)).not.toContain("private-provider-secret");
});
