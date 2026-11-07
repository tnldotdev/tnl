import { afterEach, describe, expect, it, vi } from "vitest";
import { MAX_CHUNK_BYTES } from "./abi.ts";
import type { ApplicationPump, ByteStream, HostPumpReceiver } from "./abi.ts";
import {
  createSocketHost,
  HOST_SETTLEMENT_TIMEOUT_MS,
  HostCleanupError,
  HostNetworkError,
} from "./host.ts";
import { createPumpHost } from "./host-pump.ts";

function fakeSocket(overrides: Partial<ByteStream> = {}): ByteStream {
  return {
    read: vi.fn(async () => null),
    write: vi.fn(async () => {}),
    close: vi.fn(async () => {}),
    ...overrides,
  };
}

function startPump(socket: ByteStream, receive: HostPumpReceiver): ApplicationPump {
  if (!socket.startPump) throw new Error("missing host pump");
  return socket.startPump(receive);
}

function notifications() {
  const events: Array<Parameters<HostPumpReceiver>> = [];
  let changed = Promise.withResolvers<void>();
  const receive: HostPumpReceiver = (kind, value) => {
    events.push([kind, value]);
    changed.resolve();
    changed = Promise.withResolvers<void>();
  };
  return {
    events,
    receive,
    async wait(count: number) {
      while (events.length < count) await changed.promise;
    },
  };
}

describe("persistent host byte pump", () => {
  afterEach(() => vi.useRealTimers());

  it("limits delivered read bytes, replenishes drained credit, and preserves final bytes before EOF", async () => {
    const chunks = [
      new Uint8Array(19).fill(1),
      new Uint8Array(MAX_CHUNK_BYTES - 19).fill(2),
      new Uint8Array([7]),
    ];
    const raw = fakeSocket({ read: vi.fn(async () => chunks.shift() ?? null) });
    const rawHost = createSocketHost(async () => raw);
    const host = createPumpHost(rawHost);
    const socket = await host.dialTCP("fixture.test:443");
    const notices = notifications();
    const pump = startPump(socket, notices.receive);
    await notices.wait(2);
    expect(raw.read).toHaveBeenNthCalledWith(1, MAX_CHUNK_BYTES);
    expect(raw.read).toHaveBeenNthCalledWith(2, MAX_CHUNK_BYTES - 19);
    expect(raw.read).toHaveBeenCalledTimes(2);
    expect(notices.events.map(([kind]) => kind)).toEqual([1, 1]);
    pump.resume();
    await notices.wait(4);
    expect(notices.events.slice(2)).toEqual([
      [1, new Uint8Array([7])],
      [3, null],
    ]);
    expect(raw.read).toHaveBeenNthCalledWith(3, MAX_CHUNK_BYTES);
    expect(raw.read).toHaveBeenNthCalledWith(4, MAX_CHUNK_BYTES - 1);
    await rawHost.close();
    expect(() => pump.write(new Uint8Array([1]))).toThrow("closed");
    expect(raw.close).toHaveBeenCalledTimes(1);
  });

  it("allows synchronous credit return from the receiver without losing a wakeup", async () => {
    let reads = 0;
    const raw = fakeSocket({
      read: vi.fn(async () => (++reads <= 3 ? new Uint8Array(MAX_CHUNK_BYTES) : null)),
    });
    const host = createPumpHost(createSocketHost(async () => raw));
    const socket = await host.dialTCP("fixture.test:443");
    const notices = notifications();
    const pump = startPump(socket, (kind, value) => {
      notices.receive(kind, value);
      if (kind === 1) pump.resume();
    });
    await notices.wait(4);
    expect(notices.events.map(([kind]) => kind)).toEqual([1, 1, 1, 3]);
    await host.close();
  });

  it("bounds queued plus active writes and batches only already-ready bytes", async () => {
    const gate = Promise.withResolvers<void>();
    const raw = fakeSocket({ write: vi.fn(() => gate.promise) });
    const host = createPumpHost(createSocketHost(async () => raw));
    const socket = await host.dialTCP("fixture.test:443");
    const notices = notifications();
    const pump = startPump(socket, notices.receive);
    await notices.wait(1);
    expect(pump.write(new Uint8Array([1, 2]))).toBe(true);
    expect(pump.write(new Uint8Array([3, 4]))).toBe(true);
    await Promise.resolve();
    expect(raw.write).toHaveBeenCalledTimes(1);
    expect(raw.write).toHaveBeenLastCalledWith(new Uint8Array([1, 2, 3, 4]));
    expect(pump.write(new Uint8Array(MAX_CHUNK_BYTES - 4))).toBe(true);
    expect(pump.write(new Uint8Array([5]))).toBe(false);
    expect(notices.events).toEqual([[3, null]]);
    gate.resolve();
    await notices.wait(3);
    expect(notices.events.slice(1)).toEqual([
      [2, 4],
      [2, MAX_CHUNK_BYTES - 4],
    ]);
    expect(pump.write(new Uint8Array([6]))).toBe(true);
    await notices.wait(4);
    expect(notices.events[3]).toEqual([2, 1]);
    await host.close();
  });

  it("keeps network and cleanup failure identity and leaves programming errors terminal", async () => {
    for (const failure of [
      new HostNetworkError(),
      new HostCleanupError(),
      new TypeError("private"),
    ]) {
      for (const operation of ["read", "write"] as const) {
        const raw = fakeSocket({
          [operation]: vi.fn(async () => {
            throw failure;
          }),
        });
        const host = createPumpHost(createSocketHost(async () => raw));
        const socket = await host.dialTCP("fixture.test:443");
        const notices = notifications();
        const pump = startPump(socket, notices.receive);
        if (operation === "write") pump.write(new Uint8Array([1]));
        await notices.wait(operation === "write" ? 2 : 1);
        expect(notices.events.at(-1)).toEqual([4, failure]);
        expect(() => pump.write(new Uint8Array([2]))).toThrow("closed");
        await host.close();
      }
    }
  });

  it("joins blocked raw I/O through host-wide close and retains failed cleanup for retry", async () => {
    const reading = Promise.withResolvers<Uint8Array | null>();
    const writing = Promise.withResolvers<void>();
    const writeStarted = Promise.withResolvers<void>();
    const failure = new HostCleanupError();
    const raw = fakeSocket({
      read: () => reading.promise,
      write: () => {
        writeStarted.resolve();
        return writing.promise;
      },
      close: vi
        .fn()
        .mockRejectedValueOnce(failure)
        .mockImplementation(async () => {
          reading.resolve(new Uint8Array([9]));
          writing.resolve();
        }),
    });
    const rawHost = createSocketHost(async () => raw);
    const host = createPumpHost(rawHost);
    const socket = await host.dialTCP("fixture.test:443");
    const notices = notifications();
    const pump = startPump(socket, notices.receive);
    pump.write(new Uint8Array([1]));
    await writeStarted.promise;
    await expect(rawHost.close()).rejects.toBe(failure);
    expect(notices.events).toEqual([
      [4, expect.objectContaining({ message: "connector host socket closed" })],
    ]);
    const stoppedEvents = [...notices.events];
    expect(() => pump.write(new Uint8Array([2]))).toThrow("closed");
    await rawHost.close();
    await host.close();
    await socket.close();
    expect(notices.events).toEqual(stoppedEvents);
    expect(raw.close).toHaveBeenCalledTimes(2);
  });

  it("keeps saved close references retryable and fences late pump callbacks", async () => {
    vi.useFakeTimers();
    const reading = Promise.withResolvers<Uint8Array | null>();
    const writing = Promise.withResolvers<void>();
    const writeStarted = Promise.withResolvers<void>();
    const raw = fakeSocket({
      read: () => reading.promise,
      write: () => {
        writeStarted.resolve();
        return writing.promise;
      },
    });
    const host = createPumpHost(createSocketHost(async () => raw));
    const socket = await host.dialTCP("fixture.test:443");
    const close = socket.close;
    const notices = notifications();
    const pump = startPump(socket, notices.receive);
    pump.write(new Uint8Array([1]));
    await writeStarted.promise;
    const closing = expect(close()).rejects.toBeInstanceOf(HostCleanupError);
    await vi.advanceTimersByTimeAsync(HOST_SETTLEMENT_TIMEOUT_MS);
    await closing;
    expect(notices.events).toEqual([
      [4, expect.objectContaining({ message: "connector host socket closed" })],
    ]);
    const stoppedEvents = [...notices.events];
    reading.resolve(new Uint8Array([3]));
    writing.resolve();
    await vi.advanceTimersByTimeAsync(0);
    await close();
    await host.close();
    expect(raw.close).toHaveBeenCalledTimes(2);
    expect(notices.events).toEqual(stoppedEvents);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("rejects mixed promise/pump access and closes a worker waiting for read credit", async () => {
    const raw = fakeSocket({ read: vi.fn(async () => new Uint8Array(MAX_CHUNK_BYTES)) });
    const host = createPumpHost(createSocketHost(async () => raw));
    const socket = await host.dialTCP("fixture.test:443");
    const notices = notifications();
    const pump = startPump(socket, notices.receive);
    await notices.wait(1);
    await expect(socket.read(1)).rejects.toThrow("pump owns reads");
    await expect(socket.write(new Uint8Array([1]))).rejects.toThrow("pump owns writes");
    expect(() => startPump(socket, notices.receive)).toThrow("already started");
    for (const n of [0, MAX_CHUNK_BYTES + 1]) {
      expect(() => pump.write(new Uint8Array(n))).toThrow("byte bounds");
    }
    await socket.close();
    pump.resume();
    await host.close();
    expect(raw.read).toHaveBeenCalledTimes(1);
    expect(raw.close).toHaveBeenCalledTimes(1);
  });

  it("leaves idle reads unbounded and notifies blocked I/O when the original host aborts", async () => {
    vi.useFakeTimers();
    const reading = Promise.withResolvers<Uint8Array | null>();
    const raw = fakeSocket({
      read: () => reading.promise,
      close: async () => reading.resolve(null),
    });
    const abort = new AbortController();
    const rawHost = createSocketHost(async () => raw, abort.signal);
    const host = createPumpHost(rawHost);
    const socket = await host.dialTCP("fixture.test:443");
    const notices = notifications();
    startPump(socket, notices.receive);
    await vi.advanceTimersByTimeAsync(HOST_SETTLEMENT_TIMEOUT_MS * 2);
    expect(notices.events).toEqual([]);
    expect(vi.getTimerCount()).toBe(0);
    abort.abort();
    await notices.wait(1);
    expect(notices.events).toEqual([
      [4, expect.objectContaining({ message: "connector host socket closed" })],
    ]);
    await rawHost.close();
    await host.close();
    expect(vi.getTimerCount()).toBe(0);
  });
});
