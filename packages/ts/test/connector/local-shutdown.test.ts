import { EventEmitter } from "node:events";
import { setImmediate } from "node:timers/promises";
import { expect, test, vi } from "vitest";
import { createClient } from "../../src/internal/connector/client.js";

const native = vi.hoisted(() => ({
  start: (
    _options: { signal?: AbortSignal; killSignal?: string },
    _child: EventEmitter,
    _complete: (error: Error | null) => void,
  ) => {},
}));
vi.mock("node:child_process", async () => {
  const { EventEmitter } = await import("node:events");
  return {
    execFile(
      _binary: string,
      _args: string[],
      options: { signal?: AbortSignal; killSignal?: string },
      callback: (error: Error | null, stdout: string) => void,
    ) {
      const child = new EventEmitter();
      native.start(options, child, (error) =>
        callback(
          error,
          JSON.stringify({
            schema: 1,
            protocol: "postgres",
            host: "127.0.0.1",
            port: 15432,
            binding: "a".repeat(64),
          }),
        ),
      );
      return child;
    },
  };
});
vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => "/fixture/tnl",
}));

test.each(["canceled", "independent"] as const)(
  "local shutdown interrupts and joins its helper without losing %s provenance",
  async (outcome) => {
    const started = Promise.withResolvers<{
      options: { signal?: AbortSignal; killSignal?: string };
      child: EventEmitter;
      complete(error: Error | null): void;
    }>();
    native.start = (options, child, complete) => {
      options.signal?.addEventListener(
        "abort",
        () => {
          complete(
            outcome === "independent"
              ? new Error("independent helper failure", { cause: options.signal?.reason })
              : Object.assign(new Error("aborted", { cause: options.signal?.reason }), {
                  name: "AbortError",
                  code: "ABORT_ERR",
                }),
          );
        },
        { once: true },
      );
      started.resolve({ options, child, complete });
    };
    const local = createClient({ services: { db: { protocol: "postgres" } } }).deployment("local");
    const getter = local.connect("db").catch((cause: unknown) => cause);
    const helper = await started.promise;
    let joined = false;
    const closing = local.close().then(
      () => {
        joined = true;
        return undefined;
      },
      (cause: unknown) => {
        joined = true;
        return cause;
      },
    );
    try {
      expect(helper.options.killSignal).toBe("SIGKILL");
      expect(helper.options.signal?.aborted).toBe(true);
      // callback delivery is not proof that the owned child exited.
      await setImmediate();
      expect(joined).toBe(false);
      helper.child.emit("close");
      const result = await closing;
      if (outcome === "canceled") {
        expect(result).toBeUndefined();
        expect(await getter).toMatchObject({ code: "sdk.client_closed" });
      } else {
        expect(result).toMatchObject({ code: "sdk.local_connection_unavailable" });
        expect(await getter).toBe(result);
      }
    } finally {
      helper.complete(null);
      helper.child.emit("close");
      await Promise.all([getter, closing]);
    }
  },
);
