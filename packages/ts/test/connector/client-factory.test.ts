import { describe, expect, test, vi } from "vitest";
import { TnlError } from "../../src/errors.js";
import { clientFactory } from "../../src/internal/connector/client_factory.js";

function deferred<Value>() {
  let resolve!: (value: Value) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<Value>((accept, fail) => {
    resolve = accept;
    reject = fail;
  });
  return { promise, resolve, reject };
}

describe("ordinary client factories", () => {
  test.each(["acquire", "create", "close"] as const)(
    "an independent %s failure with the closure code remains observable",
    async (phase) => {
      const entered = deferred<void>();
      const failed = deferred<number>();
      const independent = new TnlError("sdk.client_closed");
      const close = vi.fn(() => {
        if (phase === "close") {
          entered.resolve();
          return failed.promise.then(() => {});
        }
        return undefined;
      });
      const factory = clientFactory(
        async () => {
          if (phase === "acquire") {
            entered.resolve();
            await failed.promise;
          }
          return { key: "a", connection: 1 };
        },
        {
          create() {
            if (phase === "create") {
              entered.resolve();
              return failed.promise;
            }
            return 1;
          },
          close,
        },
      );
      const getter = factory().catch((cause: unknown) => cause);
      if (phase === "close") await getter;
      else await entered.promise;
      const stopping = factory.close().catch((cause: unknown) => cause);
      await entered.promise;
      failed.reject(independent);
      expect(await getter).toBe(phase === "close" ? 1 : independent);
      expect(await stopping).toBe(independent);
      expect(close).toHaveBeenCalledTimes(phase === "close" ? 1 : 0);
    },
  );

  test("slow creation does not delay existing cleanup and late clients are closed once", async () => {
    vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
    const entered = deferred<void>();
    const created = deferred<string>();
    const cleaned = deferred<void>();
    let key = "a";
    const close = vi.fn((value: string) => {
      if (value === "b") cleaned.resolve();
    });
    const factory = clientFactory(async () => ({ key, connection: key }), {
      create(value) {
        if (value === "b") {
          entered.resolve();
          return created.promise;
        }
        return value;
      },
      close,
    });
    try {
      await factory();
      key = "b";
      const getter = factory().catch((cause: unknown) => cause);
      await entered.promise;
      const closing = factory.close().catch((cause: unknown) => cause);
      await vi.advanceTimersByTimeAsync(10_000);
      expect(close).toHaveBeenCalledExactlyOnceWith("a");
      expect(await closing).toMatchObject({ name: "TimeoutError" });
      expect(await getter).toMatchObject({ name: "TimeoutError" });
      created.resolve("b");
      await cleaned.promise;
      await vi.advanceTimersByTimeAsync(0);
      await factory.close();
      expect(close.mock.calls).toEqual([["a"], ["b"]]);
    } finally {
      created.resolve("b");
      vi.useRealTimers();
    }
  });

  test.each(["create", "close"] as const)(
    "late %s failures stay observable without duplicating in-flight callbacks",
    async (phase) => {
      vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
      const entered = deferred<void>();
      const late = deferred<number>();
      const failure = new Error(`late ${phase} failure`);
      const close = vi.fn(() => {
        if (phase === "close") {
          entered.resolve();
          return late.promise.then(() => {});
        }
        return undefined;
      });
      const factory = clientFactory(async () => ({ key: "a", connection: 1 }), {
        create() {
          if (phase === "create") {
            entered.resolve();
            return late.promise;
          }
          return 1;
        },
        close,
      });
      try {
        const getter = factory().catch((cause: unknown) => cause);
        if (phase === "close") await getter;
        else await entered.promise;
        const closing = factory.close().catch((cause: unknown) => cause);
        await entered.promise;
        await vi.advanceTimersByTimeAsync(10_000);
        expect(await closing).toMatchObject({ name: "TimeoutError" });
        await expect(factory.close()).rejects.toMatchObject({ name: "TimeoutError" });
        expect(close).toHaveBeenCalledTimes(phase === "close" ? 1 : 0);
        late.reject(failure);
        await getter;
        await vi.advanceTimersByTimeAsync(0);
        await expect(factory.close()).rejects.toBe(failure);
        expect(close).toHaveBeenCalledTimes(phase === "close" ? 1 : 0);
      } finally {
        late.resolve(1);
        vi.useRealTimers();
      }
    },
  );

  test("slow native acquisition cannot delay cleanup of an existing client", async () => {
    const entered = deferred<void>();
    const selected = deferred<{ key: string; connection: number }>();
    const cleaned = deferred<void>();
    let slow = false;
    const create = vi.fn((value: number) => value);
    const close = vi.fn(() => cleaned.resolve());
    const factory = clientFactory(
      async () => {
        if (!slow) return { key: "a", connection: 1 };
        entered.resolve();
        return selected.promise;
      },
      { create, close },
    );
    await factory();
    slow = true;
    const getter = factory().catch((cause: unknown) => cause);
    await entered.promise;
    const closing = factory.close();
    await cleaned.promise;
    expect(close).toHaveBeenCalledExactlyOnceWith(1);
    selected.resolve({ key: "b", connection: 2 });
    expect(await getter).toMatchObject({ code: "sdk.client_closed" });
    await closing;
    expect(create).toHaveBeenCalledTimes(1);
    expect(close).toHaveBeenCalledTimes(1);
  });

  test("a timeout retains an independent failure from another client's cleanup", async () => {
    vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
    const entered = deferred<void>();
    const late = deferred<string>();
    const failure = new Error("existing client close failed");
    let key = "a";
    const close = vi.fn((value: string) => {
      if (value === "a") throw failure;
    });
    const factory = clientFactory(async () => ({ key, connection: key }), {
      create(value) {
        if (value === "b") {
          entered.resolve();
          return late.promise;
        }
        return value;
      },
      close,
    });
    try {
      await factory();
      key = "b";
      const getter = factory().catch((cause: unknown) => cause);
      await entered.promise;
      const closing = factory.close().catch((cause: unknown) => cause);
      await vi.advanceTimersByTimeAsync(10_000);
      expect(await closing).toMatchObject({
        errors: [expect.objectContaining({ name: "TimeoutError" }), failure],
      });
      late.resolve("b");
      await getter;
      await vi.advanceTimersByTimeAsync(0);
      await expect(factory.close()).rejects.toBe(failure);
      expect(close.mock.calls).toEqual([["a"], ["b"]]);
    } finally {
      late.resolve("b");
      vi.useRealTimers();
    }
  });

  test.each(["create", "close"])(
    "one shutdown budget bounds an uncooperative driver %s callback",
    async (phase) => {
      vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
      const entered = deferred<void>();
      const release = deferred<number>();
      const parent = Date.now() + 700;
      const close = vi.fn(() => (phase === "close" ? release.promise.then(() => {}) : undefined));
      const factory = clientFactory(
        async () => ({ key: "a", connection: 1 }),
        {
          create: () => {
            entered.resolve();
            return phase === "create" ? release.promise : 1;
          },
          close,
        },
        () => parent,
      );
      try {
        const getter = factory();
        const observedGetter = getter.catch((cause: unknown) => cause);
        await entered.promise;
        if (phase === "close") await getter;
        const closing = factory.close();
        const observedClose = closing.catch((cause: unknown) => cause);
        await vi.advanceTimersByTimeAsync(699);
        let finished = false;
        void closing.then(
          () => {
            finished = true;
          },
          () => {
            finished = true;
          },
        );
        expect(finished).toBe(false);
        await vi.advanceTimersByTimeAsync(1);
        expect(await observedClose).toMatchObject({ name: "TimeoutError" });
        if (phase === "create")
          expect(await observedGetter).toMatchObject({ name: "TimeoutError" });
        release.resolve(1);
        await expect(factory.close()).rejects.toMatchObject({ name: "TimeoutError" });
      } finally {
        release.resolve(1);
        vi.useRealTimers();
      }
    },
  );
  test("selects every getter but creates one ordinary client per exact binding", async () => {
    const acquired = vi.fn(async () => ({ key: "a", connection: { port: 1234 } }));
    const create = vi.fn((connection: { port: number }) => ({ connection, query: () => 42 }));
    const close = vi.fn();
    const get = clientFactory(acquired, { create, close });
    expect(acquired).not.toHaveBeenCalled();
    const values = await Promise.all(Array.from({ length: 10 }, () => get()));
    expect(acquired).toHaveBeenCalledTimes(10);
    expect(create).toHaveBeenCalledTimes(1);
    for (const value of values) expect(value).toBe(values[0]);
    expect(values[0]?.query()).toBe(42);
    expect(close).not.toHaveBeenCalled();
    await get.close();
    expect(close).toHaveBeenCalledExactlyOnceWith(values[0]);
  });

  test("keeps A and B separate without closing A when another request selects B", async () => {
    let key = "a";
    const denied = new Error("original native denial");
    let fail = false;
    const close = vi.fn();
    const get = clientFactory(
      async () => {
        if (fail) throw denied;
        return { key, connection: { key } };
      },
      { create: (connection) => ({ connection }), close },
    );
    const a = await get();
    key = "b";
    const b = await get();
    expect(b).not.toBe(a);
    expect(close).not.toHaveBeenCalled();
    key = "a";
    expect(await get()).toBe(a);
    fail = true;
    await expect(get()).rejects.toBe(denied);
    fail = false;
    expect(await get()).toBe(a);
    await get.close();
    expect(close.mock.calls.map(([value]) => value)).toEqual([a, b]);
  });

  test("close joins acquisition without starting a late client", async () => {
    const entered = deferred<void>();
    const selected = deferred<{ key: string; connection: number }>();
    const create = vi.fn((value: number) => ({ value }));
    const close = vi.fn();
    const get = clientFactory(
      () => {
        entered.resolve();
        return selected.promise;
      },
      { create, close },
    );
    const pending = get();
    const rejected = expect(pending).rejects.toMatchObject({ code: "sdk.client_closed" });
    await entered.promise;
    let joined = false;
    const cleanup = get.close().then(() => {
      joined = true;
    });
    await Promise.resolve();
    expect(joined).toBe(false);
    selected.resolve({ key: "a", connection: 1 });
    await Promise.all([rejected, cleanup]);
    expect(create).not.toHaveBeenCalled();
    expect(close).not.toHaveBeenCalled();
  });

  test("close joins pending creation and concurrent close uses one cleanup", async () => {
    const entered = deferred<void>();
    const created = deferred<{ query: () => number }>();
    const client = { query: () => 42 };
    const close = vi.fn();
    const get = clientFactory(async () => ({ key: "a", connection: 1 }), {
      create() {
        entered.resolve();
        return created.promise;
      },
      close,
    });
    const pending = get();
    const rejected = expect(pending).rejects.toMatchObject({ code: "sdk.client_closed" });
    await entered.promise;
    const first = get.close();
    expect(get.close()).toBe(first);
    created.resolve(client);
    await Promise.all([first, rejected]);
    expect(close).toHaveBeenCalledExactlyOnceWith(client);
    await expect(get()).rejects.toMatchObject({ code: "sdk.client_closed" });
    await get.close();
    expect(close).toHaveBeenCalledTimes(1);
  });

  test("concurrent failed creation preserves its original error and permits retry", async () => {
    const entered = deferred<void>();
    const created = deferred<{ value: number }>();
    const failure = new Error("driver setup failed");
    let attempts = 0;
    const get = clientFactory(async () => ({ key: "a", connection: 1 }), {
      create() {
        attempts++;
        entered.resolve();
        return attempts === 1 ? created.promise : { value: 42 };
      },
      close: vi.fn(),
    });
    const first = get();
    const second = get();
    const failures = [expect(first).rejects.toBe(failure), expect(second).rejects.toBe(failure)];
    await entered.promise;
    created.reject(failure);
    await Promise.all(failures);
    expect(attempts).toBe(1);
    expect(await get()).toEqual({ value: 42 });
    expect(attempts).toBe(2);
    await get.close();
  });

  test("failed cleanup retains exact clients and retries only failed closes", async () => {
    let key = "a";
    const failure = new Error("driver close failed");
    const closes: string[] = [];
    let fail = true;
    const get = clientFactory(async () => ({ key, connection: key }), {
      create: (value) => ({ value }),
      close(client) {
        closes.push(client.value);
        if (client.value === "b" && fail) throw failure;
      },
    });
    await get();
    key = "b";
    await get();
    const first = get.close();
    expect(get.close()).toBe(first);
    await expect(first).rejects.toBe(failure);
    fail = false;
    await get.close();
    expect(closes).toEqual(["a", "b", "b"]);
    await expect(get()).rejects.toMatchObject({ code: "sdk.client_closed" });
  });

  test("multiple cleanup failures preserve every original cause", async () => {
    let key = "a";
    const a = new Error("a"),
      b = new Error("b");
    const get = clientFactory(async () => ({ key, connection: key }), {
      create: (value) => value,
      close(value) {
        throw value === "a" ? a : b;
      },
    });
    await get();
    key = "b";
    await get();
    await expect(get.close()).rejects.toMatchObject({ errors: [a, b] });
  });

  test("retained bindings are bounded without evicting a client still in use", async () => {
    let key = 0;
    const close = vi.fn();
    const get = clientFactory(async () => ({ key: String(key), connection: key }), {
      create: (value) => ({ value }),
      close,
    });
    const first = await get();
    for (key = 1; key < 64; key++) await get();
    await expect(get()).rejects.toMatchObject({ code: "sdk.client_capacity" });
    key = 0;
    expect(await get()).toBe(first);
    expect(close).not.toHaveBeenCalled();
    await get.close();
    expect(close).toHaveBeenCalledTimes(64);
  });
});
