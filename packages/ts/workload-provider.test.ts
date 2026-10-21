import { AsyncLocalStorage } from "node:async_hooks";
import { createServer } from "node:http";
import { createServer as httpsServer } from "node:https";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { getCACertificates, setDefaultCACertificates } from "node:tls";
import { inspect } from "node:util";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { key, cert } from "./fixtures/workload_tls.js";
import type { Workload } from "./src/internal/workload_contract.js";

let directory: string;
beforeEach(async () => {
  vi.resetModules();
  directory = await mkdtemp(path.join(tmpdir(), "tnl-provider-"));
});
afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});
const oidc: Workload = {
  provider: "oidc",
  services: ["inventory"],
  max_duration_seconds: 3600,
  acquisition: { method: "callback", audience: "trusted-audience" },
};

test.each(["never", "late"])(
  "callback acquisition is bounded even when it resolves %s",
  async (mode) => {
    const { configureWorkload, acquireAssertion } =
      await import("./src/internal/workload_provider.js");
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
    const acquiring = acquireAssertion("worker", oidc, directory, controller.signal);
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
    await import("./src/internal/workload_provider.js");
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
    acquireAssertion("worker", oidc, directory, new AbortController().signal),
  ).rejects.toMatchObject({ name: "TimeoutError" });
  expect(performance.now() - started).toBeGreaterThanOrEqual(9900);
  finish?.("assertion.after.deadline");
}, 12_000);

test("generic callback registration is fixed, request-scoped, and never verifies or routes using untrusted JWT claims", async () => {
  const { configureWorkload, acquireAssertion } =
    await import("./src/internal/workload_provider.js");
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
      storage.run(token, () => acquireAssertion("worker", oidc, directory, signal)),
    ),
  );
  expect(tokens).toEqual(["opaque-one", "opaque-two"]);
  expect(callback).toHaveBeenCalledTimes(2);
  await expect(acquireAssertion("worker", oidc, directory, signal)).rejects.toMatchObject({
    code: "sdk.workload_assertion_unavailable",
  });
});

test("generic token files are bounded, reread, and never fall back after a selected file fails", async () => {
  const { acquireAssertion } = await import("./src/internal/workload_provider.js");
  const workload: Workload = {
    ...oidc,
    acquisition: { method: "token-file", audience: "trusted-audience", token_file: "token" },
  };
  const acquire = () => acquireAssertion("worker", workload, directory, AbortSignal.timeout(1000));
  await expect(acquire()).rejects.toMatchObject({ code: "sdk.workload_assertion_unavailable" });
  const file = path.join(directory, "token");
  await writeFile(file, "one\n");
  await expect(acquire()).resolves.toBe("one");
  await writeFile(file, "two");
  await expect(acquire()).resolves.toBe("two");
  for (const value of ["", " ", "a".repeat(32769), "private token", "private\0token"]) {
    await writeFile(file, value);
    await expect(acquire()).rejects.toMatchObject({ code: "sdk.workload_assertion_unavailable" });
  }
});

test("callback and parser causes stay private under normal Node error inspection", async () => {
  const { configureWorkload, acquireAssertion } =
    await import("./src/internal/workload_provider.js");
  const cause = new Error("Bearer private-provider-secret");
  configureWorkload({
    name: "worker",
    token: async () => {
      throw cause;
    },
  });
  const error: unknown = await acquireAssertion(
    "worker",
    oidc,
    directory,
    AbortSignal.timeout(1000),
  ).catch((error: unknown) => error);
  expect(error).toMatchObject({
    code: "sdk.workload_assertion_unavailable",
    retry: "after_change",
  });
  expect(error).not.toHaveProperty("cause");
  expect(inspect(error, { depth: 10 })).not.toContain("private-provider-secret");
  expect(JSON.stringify(error)).not.toContain("private-provider-secret");
});

test("Fly posts its trusted audience to the real Unix-socket API wire format and reads a text JWT", async () => {
  const { flyAssertion } = await import("./src/internal/workload_provider.js");
  const socket = path.join(directory, "fly.sock");
  const calls: unknown[] = [];
  const server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      calls.push({
        method: request.method,
        path: request.url,
        host: request.headers.host,
        body: JSON.parse(Buffer.concat(chunks).toString()) as unknown,
      });
      response.writeHead(200, { "content-type": "text/plain" }).end("signed.machine.assertion\n");
    });
  });
  await new Promise<void>((resolve) => server.listen(socket, resolve));
  try {
    await expect(
      flyAssertion("https://fly.io/saved-org", AbortSignal.timeout(1000), socket),
    ).resolves.toBe("signed.machine.assertion");
    expect(calls).toEqual([
      {
        method: "POST",
        path: "/v1/tokens/oidc",
        host: "localhost",
        body: { aud: "https://fly.io/saved-org" },
      },
    ]);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("GitHub requests the canonical control audience and outside Actions requires an explicit current-job source", async () => {
  const { acquireAssertion, configureWorkload } =
    await import("./src/internal/workload_provider.js");
  const workload: Workload = {
    ...oidc,
    provider: "github",
    acquisition: { method: "github-actions", audience: "https://control.example.test" },
  };
  const roots = getCACertificates("default");
  setDefaultCACertificates([...roots, cert]);
  const calls: { audience: string | null; authorization: string | undefined }[] = [];
  const server = httpsServer({ key, cert }, (request, response) => {
    calls.push({
      audience: new URL(request.url ?? "", "https://localhost").searchParams.get("audience"),
      authorization: request.headers.authorization,
    });
    response
      .writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ value: "signed.current.job" }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing listener");
  vi.stubEnv("GITHUB_ACTIONS", "true");
  vi.stubEnv(
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    `https://localhost:${address.port}/token?audience=wrong`,
  );
  vi.stubEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "actions-private-bearer");
  try {
    await expect(
      acquireAssertion("job", workload, directory, AbortSignal.timeout(1000)),
    ).resolves.toBe("signed.current.job");
    expect(calls).toEqual([
      { audience: "https://control.example.test", authorization: "Bearer actions-private-bearer" },
    ]);
    vi.stubEnv("GITHUB_ACTIONS", undefined);
    await expect(
      acquireAssertion("job", workload, directory, AbortSignal.timeout(1000)),
    ).rejects.toMatchObject({ code: "sdk.workload_assertion_unavailable" });
    await writeFile(path.join(directory, "current-job.jwt"), "explicit.current.job");
    configureWorkload({ name: "job", tokenFile: "current-job.jwt" });
    await expect(
      acquireAssertion("job", workload, directory, AbortSignal.timeout(1000)),
    ).resolves.toBe("explicit.current.job");
    expect(calls).toHaveLength(1);
  } finally {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
    setDefaultCACertificates(roots);
  }
});
