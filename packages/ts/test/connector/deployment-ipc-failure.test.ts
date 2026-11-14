import { setImmediate } from "node:timers/promises";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { createClient } from "../../src/internal/connector/client.js";
import type { OwnerIPC } from "../../src/internal/connector/connection_ipc.js";
import { TnlError } from "../../src/errors.js";

const fixture = vi.hoisted(() => ({
  open: vi.fn<(file: string) => Promise<OwnerIPC>>(),
  calls: [] as { args: string[]; input: unknown }[],
  recover: true,
  scopes: 0,
  preparations: 0,
}));
vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => "/fixture/tnl",
}));
vi.mock("node:fs/promises", async (original) => ({
  ...(await original<typeof import("node:fs/promises")>()),
  mkdtemp: async (prefix: string) => `${prefix}fixture-${++fixture.scopes}`,
}));
vi.mock("../../src/internal/connector/connection_ipc.js", () => ({
  ownerIPC: fixture.open,
}));
vi.mock("node:child_process", () => ({
  execFile(
    _binary: string,
    args: string[],
    _options: unknown,
    callback: (error: Error | null, stdout: string) => void,
  ) {
    return {
      stdin: {
        on() {},
        end(input: string | undefined) {
          fixture.calls.push({ args, input: input === undefined ? undefined : JSON.parse(input) });
          queueMicrotask(() => {
            if (args[2] === "sdk-stop") {
              callback(null, JSON.stringify({ schema: 1, state: "stopped" }));
            } else if (args.includes("--recover-handle") && !fixture.recover) {
              callback(new Error("native recovery unavailable"), "");
            } else {
              fixture.preparations++;
              callback(null, JSON.stringify(prepared(fixture.preparations)));
            }
          });
        },
      },
    };
  },
}));

function prepared(index: number) {
  return {
    schema: 1,
    owner: {
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      connection_handle: `/fixture/owner-${index}/handle.json`,
      executable: "/fixture/tnl",
    },
    prepared: {
      schema: 1,
      project_runtime: {
        dev: false,
        namespace: "team.example",
        services: {
          db: {
            protocol: "postgres",
            hostname: "db.team.example",
            namespace: "team.example",
            port: 15432,
            public: true,
          },
        },
      },
      connection: {
        schema: 1,
        protocol: "postgres",
        host: "127.0.0.1",
        port: 15432 + index,
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        transport_id: "ctg_aaaaaaaaaaaaaaaaaaaaaa",
        ssl: { servername: "db.team.example", rejectUnauthorized: true },
      },
    },
  };
}

let originalListeners = new Set(process.listeners("beforeExit"));
beforeEach(() => {
  fixture.calls = [];
  fixture.recover = true;
  fixture.scopes = 0;
  fixture.preparations = 0;
  originalListeners = new Set(process.listeners("beforeExit"));
});
afterEach(() => {
  for (const listener of process.listeners("beforeExit"))
    if (!originalListeners.has(listener)) process.removeListener("beforeExit", listener);
});

test.each([false, true])(
  "eager IPC rejection is observed without losing recovery or cleanup failures (recovery=%s)",
  async (recover) => {
    const failed = Promise.withResolvers<OwnerIPC>();
    const observation = vi.spyOn(failed.promise, "catch");
    const close = vi.fn();
    const ipc = {
      expiresAt: Date.now() + 60_000,
      prepare: vi.fn(async () => prepared(2)),
      workload: vi.fn(),
      close,
    };
    fixture.open.mockReturnValueOnce(failed.promise).mockResolvedValue(ipc);
    fixture.recover = recover;
    const deployment = createClient({
      project: "acme/shop",
      token: "private-credential",
      services: { db: { protocol: "postgres" } },
    }).deployment("production");
    const failure = new TnlError("sdk.connection_unavailable");
    try {
      await expect(deployment.connect("db")).resolves.toMatchObject({ port: 15433 });
      expect(observation).toHaveBeenCalledOnce();
      failed.reject(failure);
      // cross a turn after rejection, without a test-owned rejection observer.
      await setImmediate();
      if (recover) {
        await expect(deployment.connect("db")).resolves.toMatchObject({ port: 15434 });
        expect(fixture.open.mock.calls.map(([file]) => file)).toEqual([
          "/fixture/owner-1/handle.json",
          "/fixture/owner-2/handle.json",
        ]);
        await deployment.close();
        expect(close).toHaveBeenCalledOnce();
      } else {
        await expect(deployment.connect("db")).rejects.toBe(failure);
        await expect(deployment.close()).rejects.toMatchObject({ errors: [failure] });
        expect(close).not.toHaveBeenCalled();
      }
      const recovery = fixture.calls.find((call) => call.args.includes("--recover-handle"));
      expect(recovery?.args.at(-1)).toBe("/fixture/owner-1/handle.json");
      expect(recovery?.input).toMatchObject({
        deployment: { project: "acme/shop", name: "production", token: "private-credential" },
      });
      expect(fixture.calls.filter((call) => call.args[2] === "sdk-stop")).toHaveLength(1);
    } finally {
      // keep a pre-fix assertion failure from leaking the test's pending IPC.
      void failed.promise.catch(() => {});
      failed.reject(failure);
      await deployment.close().catch(() => {});
    }
  },
);
