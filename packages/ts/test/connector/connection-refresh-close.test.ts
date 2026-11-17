import { createServer } from "node:http";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { expect, test, vi } from "vitest";
import { createClient } from "../../src/internal/connector/client.js";

const gate = vi.hoisted(() => ({
  file: "",
  entered: undefined as (() => void) | undefined,
  release: undefined as Promise<void> | undefined,
  closed: undefined as (() => void) | undefined,
  ioFailure: false,
}));

vi.mock("node:fs/promises", async (original) => {
  const fs = await original<typeof import("node:fs/promises")>();
  return {
    ...fs,
    async open(...args: Parameters<typeof fs.open>) {
      if (args[0] === gate.file) {
        gate.entered?.();
        await gate.release;
        if (gate.ioFailure) throw new Error("independent read failure");
      }
      return fs.open(...args);
    },
  };
});
vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => process.execPath,
}));
vi.mock("../../src/internal/connector/connection_ipc.js", async (original) => {
  const module = await original<typeof import("../../src/internal/connector/connection_ipc.js")>();
  return {
    ...module,
    async ownerIPC(filename: string) {
      const ipc = await module.ownerIPC(filename);
      return {
        get expiresAt() {
          return ipc.expiresAt;
        },
        prepare: ipc.prepare,
        workload: ipc.workload,
        close(reason?: Parameters<typeof ipc.close>[0]) {
          ipc.close(reason);
          gate.closed?.();
        },
      };
    },
  };
});

test.each(["valid", "malformed", "io", "identity"] as const)(
  "intentional close during borrowed descriptor refresh preserves %s provenance",
  async (change) => {
    const directory = await realpath(await mkdtemp(path.join(tmpdir(), "tnl-refresh-close-")));
    const file = path.join(directory, "handle.json");
    let requests = 0;
    const server = createServer((request, response) => {
      requests++;
      request.resume();
      response.writeHead(200, { "content-type": "application/json" }).end(
        JSON.stringify({
          schema: 1,
          project_runtime: {
            dev: false,
            namespace: "team.example",
            services: {
              db: {
                protocol: "tcp",
                namespace: "team.example",
                hostname: "db.team.example",
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
        }),
      );
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("missing listener");
    const expires = Date.now() + 60_000;
    const descriptor = {
      schema: 1,
      url: `http://127.0.0.1:${address.port}`,
      key: "a".repeat(64),
      directory,
      config_digest: "c".repeat(64),
      expires_at: new Date(expires).toISOString(),
      executable: process.execPath,
    };
    await writeFile(file, JSON.stringify(descriptor), { mode: 0o600 });
    vi.stubEnv("TNL_TOKEN", undefined);
    vi.stubEnv("TNL_CONNECTION_HANDLE", file);
    const deployment = createClient({
      project: "acme/project",
      services: { db: { protocol: "tcp" } },
    }).deployment("production");
    const release = Promise.withResolvers<void>();
    let connecting: Promise<unknown> | undefined;
    let closing: Promise<unknown> | undefined;
    try {
      expect(await deployment.connect("db")).toEqual({ host: "127.0.0.1", port: 15432 });
      // only Date advances; the real expiry timer cannot race the explicit read gate.
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(expires + 1);
      await writeFile(
        file,
        change === "malformed"
          ? "{"
          : JSON.stringify({
              ...descriptor,
              ...(change === "identity" ? { key: "b".repeat(64) } : {}),
              expires_at: new Date(Date.now() + 60_000).toISOString(),
            }),
      );
      const entered = Promise.withResolvers<void>();
      const closed = Promise.withResolvers<void>();
      gate.file = file;
      gate.entered = entered.resolve;
      gate.release = release.promise;
      gate.closed = closed.resolve;
      gate.ioFailure = change === "io";
      connecting = deployment.connect("db").catch((cause: unknown) => cause);
      await entered.promise;
      closing = deployment.close().catch((cause: unknown) => cause);
      await closed.promise;
      release.resolve();
      const [connectionResult, closeResult] = await Promise.all([connecting, closing]);
      expect(connectionResult).toMatchObject({
        code: change === "valid" ? "sdk.client_closed" : "sdk.connection_unavailable",
      });
      if (change === "valid") expect(closeResult).toBeUndefined();
      else expect(closeResult).toBeInstanceOf(AggregateError);
      expect(requests).toBe(1);
    } finally {
      gate.file = "";
      gate.ioFailure = false;
      gate.closed = undefined;
      release.resolve();
      await Promise.allSettled([connecting, closing]);
      await deployment.close().catch(() => {});
      vi.useRealTimers();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await rm(directory, { recursive: true, force: true });
    }
  },
);
