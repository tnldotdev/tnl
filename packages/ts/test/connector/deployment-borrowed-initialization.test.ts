import { expect, test, vi } from "vitest";
import { TnlError } from "../../src/errors.js";
import { createClient } from "../../src/internal/connector/client.js";
import { deploymentConnector } from "../../src/internal/connector/connection.js";
import type { OwnerIPC } from "../../src/internal/connector/connection_ipc.js";

const native = vi.hoisted(() => ({
  open: vi.fn(),
  binary: vi.fn(() => {
    throw new Error("borrowed authority cannot start a native process");
  }),
}));
vi.mock("../../src/internal/connector/connection_ipc.js", () => ({ ownerIPC: native.open }));
vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: native.binary,
}));

function connector() {
  return deploymentConnector({
    project: "acme/project",
    name: "production",
    handle: "/captured/job/handle.json",
  });
}

function prepared() {
  return {
    schema: 1,
    project_runtime: {
      dev: false,
      namespace: "db.example.test",
      services: {
        db: {
          protocol: "tcp",
          namespace: "db.example.test",
          hostname: "db.example.test",
          port: 15432,
          public: false,
        },
      },
    },
    connection: {
      schema: 1,
      protocol: "tcp",
      host: "127.0.0.1",
      port: 15432,
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      transport_id: `ctg_${"a".repeat(22)}`,
    },
  };
}

test("close observes in-flight borrowed initialization failure without retaining it as cleanup work", async () => {
  const opening = Promise.withResolvers<OwnerIPC>();
  const original = new Error("descriptor initialization failed");
  native.open.mockReturnValueOnce(opening.promise);
  const deployment = connector();
  const connecting = deployment.acquire("db");
  const observed = expect(connecting).rejects.toBe(original);
  const closing = expect(deployment.close()).rejects.toMatchObject({
    errors: expect.arrayContaining([original]),
  });
  opening.reject(original);
  await Promise.all([observed, closing]);
  await expect(deployment.close()).resolves.toBeUndefined();
  expect(native.open).toHaveBeenCalledExactlyOnceWith("/captured/job/handle.json");
  expect(native.binary).not.toHaveBeenCalled();
});

test("an initialized borrowed client preserves operation and independent cleanup failures", async () => {
  const request = Promise.withResolvers<unknown>();
  const original = new Error("preparation failed");
  const cleanup = new Error("IPC client cleanup failed");
  const close = vi.fn().mockImplementationOnce(() => {
    throw cleanup;
  });
  const ipc: OwnerIPC = {
    expiresAt: Date.now() + 60_000,
    prepare: vi.fn().mockResolvedValueOnce(prepared()).mockReturnValueOnce(request.promise),
    workload: vi.fn(),
    close,
  };
  native.open.mockResolvedValueOnce(ipc);
  const deployment = connector();
  try {
    await deployment.acquire("db");
    const connecting = deployment.acquire("db");
    const observed = expect(connecting).rejects.toBe(original);
    const closing = expect(deployment.close()).rejects.toMatchObject({
      errors: expect.arrayContaining([original, cleanup]),
    });
    request.reject(original);
    await Promise.all([observed, closing]);
    expect(close).toHaveBeenCalledOnce();
    expect(native.open).toHaveBeenCalledExactlyOnceWith("/captured/job/handle.json");
    expect(native.binary).not.toHaveBeenCalled();
  } finally {
    await deployment.close();
  }
});

test.each(["factory-first", "deployment-first"] as const)(
  "%s close preserves an independent acquisition failure with the closure code",
  async (order) => {
    const entered = Promise.withResolvers<void>();
    const request = Promise.withResolvers<unknown>();
    const independent = new TnlError("sdk.client_closed");
    const ipc: OwnerIPC = {
      expiresAt: Date.now() + 60_000,
      prepare: vi.fn(() => {
        entered.resolve();
        return request.promise;
      }),
      workload: vi.fn(),
      close: vi.fn(),
    };
    native.open.mockResolvedValueOnce(ipc);
    vi.stubEnv("TNL_TOKEN", undefined);
    vi.stubEnv("TNL_CONNECTION_HANDLE", "/captured/job/handle.json");
    const deployment = createClient({
      project: "acme/project",
      services: { db: { protocol: "tcp" } },
    }).deployment("production");
    const create = vi.fn();
    const close = vi.fn();
    const factory = deployment.client("db", { create, close });
    const getter = factory().catch((cause: unknown) => cause);
    await entered.promise;
    let stoppingFactory: Promise<unknown> | undefined;
    if (order === "factory-first")
      stoppingFactory = factory.close().catch((cause: unknown) => cause);
    const stopping = deployment.close().catch((cause: unknown) => cause);
    if (order === "deployment-first")
      stoppingFactory = factory.close().catch((cause: unknown) => cause);
    try {
      request.reject(independent);
      const [getterResult, factoryResult, deploymentResult] = await Promise.all([
        getter,
        stoppingFactory,
        stopping,
      ]);
      expect(getterResult).toBe(independent);
      expect(factoryResult).toBe(independent);
      expect(deploymentResult).toMatchObject({
        errors: expect.arrayContaining([independent]),
      });
      expect(create).not.toHaveBeenCalled();
      expect(close).not.toHaveBeenCalled();
    } finally {
      request.reject(independent);
      await Promise.allSettled([getter, stoppingFactory, stopping]);
      await deployment.close().catch(() => {});
    }
  },
);
