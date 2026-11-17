import { createServer } from "node:http";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { expect, test, vi } from "vitest";
import { createClient } from "../../src/internal/connector/client.js";

vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => process.execPath,
}));

test.each(["factory-first", "deployment-first", "deployment-only"] as const)(
  "%s close joins intentional native acquisition interruption",
  async (order) => {
    const directory = await realpath(await mkdtemp(path.join(tmpdir(), "tnl-factory-close-")));
    const file = path.join(directory, "handle.json");
    const entered = Promise.withResolvers<void>();
    const server = createServer((request) => {
      request.resume();
      // the request stays in flight until the owning IPC client destroys it.
      entered.resolve();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("missing listener");
    await writeFile(
      file,
      JSON.stringify({
        schema: 1,
        url: `http://127.0.0.1:${address.port}`,
        key: "a".repeat(64),
        directory,
        config_digest: "c".repeat(64),
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        executable: process.execPath,
      }),
      { mode: 0o600 },
    );
    vi.stubEnv("TNL_TOKEN", undefined);
    vi.stubEnv("TNL_CONNECTION_HANDLE", file);
    const deployment = createClient({
      project: "acme/project",
      services: { db: { protocol: "tcp" } },
    }).deployment("production");
    const create = vi.fn((connection: unknown) => ({ connection }));
    const close = vi.fn();
    const factory = deployment.client("db", { create, close });
    let getter: Promise<unknown> | undefined;
    let stopping: Promise<unknown> | undefined;
    let stoppingFactory: Promise<unknown> | undefined;
    try {
      getter = factory().catch((cause: unknown) => cause);
      await entered.promise;
      if (order === "factory-first")
        stoppingFactory = factory.close().catch((cause: unknown) => cause);
      stopping = deployment.close().catch((cause: unknown) => cause);
      if (order === "deployment-first")
        stoppingFactory = factory.close().catch((cause: unknown) => cause);
      const [getterResult, deploymentResult, factoryResult] = await Promise.all([
        getter,
        stopping,
        stoppingFactory,
      ]);
      expect(getterResult).toMatchObject({ code: "sdk.client_closed" });
      expect(deploymentResult).toBeUndefined();
      expect(factoryResult).toBeUndefined();
      expect(create).not.toHaveBeenCalled();
      expect(close).not.toHaveBeenCalled();
      await factory.close();
      await deployment.close();
    } finally {
      await deployment.close().catch(() => {});
      await Promise.allSettled([getter, stopping, stoppingFactory]);
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await rm(directory, { recursive: true, force: true });
    }
  },
);
