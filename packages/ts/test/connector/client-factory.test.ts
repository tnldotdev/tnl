import { describe, expect, test, vi } from "vitest";
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
