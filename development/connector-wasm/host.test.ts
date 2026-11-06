import { createServer, Socket as RawSocket } from "node:net";
import type { Server, Socket } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MAX_CHUNK_BYTES } from "./abi.ts";
import type { ByteStream } from "./abi.ts";
import {
  BoundedSocket,
  createSocketHost,
  HOST_SETTLEMENT_TIMEOUT_MS,
  HostCleanupError,
  HostNetworkError,
  parseTCPAddress,
} from "./host.ts";
import { createNodeHost, NodeSocket } from "./host-node.ts";

function fakeSocket(overrides: Partial<ByteStream> = {}): ByteStream {
  return {
    read: vi.fn(async () => null),
    write: vi.fn(async () => {}),
    close: vi.fn(async () => {}),
    ...overrides,
  };
}

describe("bounded raw host transport (not connector integration)", () => {
  afterEach(() => vi.useRealTimers());
  it("parses TCP addresses without reflecting untrusted input in errors", () => {
    expect(parseTCPAddress("localhost:5432")).toEqual({ hostname: "localhost", port: 5432 });
    expect(parseTCPAddress("[::1]:443")).toEqual({ hostname: "::1", port: 443 });
    for (const address of ["secret@invalid", "localhost:0", "localhost:65536", "::1:443"]) {
      expect(() => parseTCPAddress(address)).toThrow("expected a TCP hostname:port or [IPv6]:port");
    }
  });

  it("waits for each bounded write and rejects an unbounded concurrent queue", async () => {
    const gate = Promise.withResolvers<void>();
    const writes: number[] = [];
    const raw = fakeSocket({
      write: vi.fn(async (bytes) => {
        writes.push(bytes.length);
        await gate.promise;
      }),
    });
    const socket = new BoundedSocket(raw);
    const writing = socket.write(new Uint8Array(MAX_CHUNK_BYTES * 2 + 7));
    expect(writes).toEqual([MAX_CHUNK_BYTES]);
    await expect(socket.write(new Uint8Array(1))).rejects.toThrow("concurrent host writes");
    gate.resolve();
    await writing;
    expect(writes).toEqual([MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, 7]);
    await socket.close();
  });

  it("allows a write during a read, rejects concurrent reads, and validates sizes", async () => {
    const gate = Promise.withResolvers<Uint8Array | null>();
    const raw = fakeSocket({ read: () => gate.promise });
    const socket = new BoundedSocket(raw);
    const reading = socket.read(8);
    await socket.write(new Uint8Array([1]));
    await expect(socket.read(8)).rejects.toThrow("concurrent host reads");
    for (const size of [0, -1, 1.5, MAX_CHUNK_BYTES + 1]) {
      await expect(socket.read(size)).rejects.toThrow("read size");
    }
    gate.resolve(new Uint8Array([2]));
    await expect(reading).resolves.toEqual(new Uint8Array([2]));
    await socket.close();
    await socket.close();
    expect(raw.close).toHaveBeenCalledTimes(1);
  });

  it("closes a transport that violates bounded reads", async () => {
    const raw = fakeSocket({ read: async () => new Uint8Array(2) });
    const socket = new BoundedSocket(raw);
    await expect(socket.read(1)).rejects.toThrow("invalid read size");
    expect(raw.close).toHaveBeenCalledTimes(1);
  });

  it("closes a dial that races host cancellation", async () => {
    const gate = Promise.withResolvers<ByteStream>();
    const raw = fakeSocket();
    const host = createSocketHost(() => gate.promise);
    const dialing = host.dialTCP("localhost:1234");
    const rejected = expect(dialing).rejects.toMatchObject({ name: "AbortError" });
    const closing = host.close();
    gate.resolve(raw);
    await rejected;
    await closing;
    expect(raw.close).toHaveBeenCalledTimes(1);
    await expect(host.dialTCP("localhost:1234")).rejects.toMatchObject({ name: "AbortError" });
  });

  it("retains failed socket ownership and original cleanup errors for a second close", async () => {
    const failure = new Error("fixture cleanup failure");
    const raw = fakeSocket({
      close: vi.fn().mockRejectedValueOnce(failure).mockResolvedValue(undefined),
    });
    const host = createSocketHost(async () => raw);
    const socket = await host.dialTCP("localhost:1234");
    await expect(host.close()).rejects.toBe(failure);
    await expect(socket.read(1)).rejects.toThrow("closed");
    await expect(host.dialTCP("localhost:1234")).rejects.toMatchObject({ name: "AbortError" });
    await host.close();
    await host.close();
    expect(raw.close).toHaveBeenCalledTimes(2);
  });

  it("retains ownership when an individual socket close fails", async () => {
    const failure = new Error("fixture individual cleanup failure");
    const raw = fakeSocket({
      close: vi.fn().mockRejectedValueOnce(failure).mockResolvedValue(undefined),
    });
    const host = createSocketHost(async () => raw);
    const socket = await host.dialTCP("localhost:1234");
    await expect(socket.close()).rejects.toBe(failure);
    await host.close();
    expect(raw.close).toHaveBeenCalledTimes(2);
  });

  it("bounds never-settling close/read promises and safely accepts late settlement", async () => {
    vi.useFakeTimers();
    const read = Promise.withResolvers<Uint8Array | null>();
    const close = Promise.withResolvers<void>();
    const raw = fakeSocket({
      read: () => read.promise,
      close: vi.fn().mockReturnValueOnce(close.promise).mockResolvedValue(undefined),
    });
    const socket = new BoundedSocket(raw);
    const reading = expect(socket.read(1)).rejects.toThrow("closed");
    const closing = expect(socket.close()).rejects.toBeInstanceOf(HostCleanupError);
    await vi.advanceTimersByTimeAsync(HOST_SETTLEMENT_TIMEOUT_MS);
    await reading;
    await closing;
    read.resolve(new Uint8Array([1]));
    close.resolve();
    await Promise.resolve();
    await socket.close();
    await expect(socket.write(new Uint8Array([1]))).rejects.toThrow("closed");
    expect(raw.close).toHaveBeenCalledTimes(2);
  });

  it("leaves healthy idle reads unbounded until close starts cleanup", async () => {
    vi.useFakeTimers();
    const gate = Promise.withResolvers<Uint8Array | null>();
    const raw = fakeSocket({ read: () => gate.promise, close: async () => gate.resolve(null) });
    const socket = new BoundedSocket(raw);
    let settled = false;
    const reading = socket.read(1).finally(() => {
      settled = true;
    });
    const rejected = expect(reading).rejects.toThrow("closed");
    await vi.advanceTimersByTimeAsync(HOST_SETTLEMENT_TIMEOUT_MS * 2);
    expect(settled).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
    await socket.close();
    await rejected;
  });

  it("bounds a noncooperative dial but still owns and closes a late socket", async () => {
    vi.useFakeTimers();
    const gate = Promise.withResolvers<ByteStream>();
    const raw = fakeSocket();
    const host = createSocketHost(() => gate.promise);
    const dialing = expect(host.dialTCP("localhost:1234")).rejects.toBeInstanceOf(HostCleanupError);
    const closing = expect(host.close()).rejects.toBeInstanceOf(HostCleanupError);
    await vi.advanceTimersByTimeAsync(HOST_SETTLEMENT_TIMEOUT_MS);
    await dialing;
    await closing;
    gate.resolve(raw);
    await vi.advanceTimersByTimeAsync(0);
    await host.close();
    expect(raw.close).toHaveBeenCalledTimes(1);
  });

  it("does not drop late-acquired sockets whose first cleanup fails", async () => {
    const gate = Promise.withResolvers<ByteStream>();
    const failure = new Error("fixture late cleanup failure");
    const raw = fakeSocket({
      close: vi.fn().mockRejectedValueOnce(failure).mockResolvedValue(undefined),
    });
    const host = createSocketHost(() => gate.promise);
    const dialing = expect(host.dialTCP("localhost:1234")).rejects.toBe(failure);
    const closing = expect(host.close()).rejects.toBe(failure);
    gate.resolve(raw);
    await dialing;
    await closing;
    await host.close();
    expect(raw.close).toHaveBeenCalledTimes(2);
  });

  it("closes owned sockets even while a sibling acquisition ignores abort", async () => {
    vi.useFakeTimers();
    const raw = fakeSocket();
    const pending = Promise.withResolvers<ByteStream>();
    let attempts = 0;
    const host = createSocketHost(() =>
      ++attempts === 1 ? Promise.resolve(raw) : pending.promise,
    );
    await host.dialTCP("localhost:1234");
    const dialing = expect(host.dialTCP("localhost:1235")).rejects.toBeInstanceOf(HostCleanupError);
    const closing = expect(host.close()).rejects.toBeInstanceOf(HostCleanupError);
    await vi.advanceTimersByTimeAsync(HOST_SETTLEMENT_TIMEOUT_MS);
    await closing;
    await dialing;
    expect(raw.close).toHaveBeenCalledTimes(1);
    const late = fakeSocket();
    pending.resolve(late);
    await vi.advanceTimersByTimeAsync(0);
    await host.close();
    expect(late.close).toHaveBeenCalledTimes(1);
  });
});

describe("Node/Bun node:net loopback transport (not connector integration)", () => {
  const cleanup: Array<() => Promise<void>> = [];
  afterEach(async () => {
    await Promise.all(cleanup.splice(0).map((close) => close()));
  });

  async function listen(
    accept: (socket: Socket) => void,
  ): Promise<{ address: string; server: Server }> {
    const peers = new Set<Socket>();
    const server = createServer((socket) => {
      peers.add(socket);
      socket.on("error", () => {});
      socket.on("close", () => peers.delete(socket));
      accept(socket);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    cleanup.push(async () => {
      for (const peer of peers) peer.destroy();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("missing test listener");
    return { address: `127.0.0.1:${address.port}`, server };
  }

  it("preserves bytes through bounded reads, backpressure, and remote EOF", async () => {
    const expected = Buffer.alloc(MAX_CHUNK_BYTES * 3 + 37);
    for (let i = 0; i < expected.length; i += 1) expected[i] = i % 251;
    const { address } = await listen((peer) => {
      peer.end(expected);
    });
    const host = createNodeHost();
    cleanup.push(() => host.close());
    const socket = await host.dialTCP(address);
    const chunks: Uint8Array[] = [];
    for (;;) {
      const chunk = await socket.read(997);
      if (chunk === null) break;
      expect(chunk.length).toBeLessThanOrEqual(997);
      chunks.push(chunk);
    }
    expect(Buffer.concat(chunks)).toEqual(expected);
    await expect(socket.read(1)).resolves.toBeNull();
    await socket.close();
  });

  it("writes binary data and waits for the peer response", async () => {
    const { address } = await listen((peer) => {
      peer.pipe(peer);
    });
    const host = createNodeHost();
    cleanup.push(() => host.close());
    const socket = await host.dialTCP(address);
    const bytes = new Uint8Array([0, 255, 128, 1]);
    await socket.write(bytes);
    expect(Array.from((await socket.read(4)) ?? [])).toEqual(Array.from(bytes));
    await socket.close();
  });

  it("host abort interrupts an idle read and joins socket close", async () => {
    const { address } = await listen(() => {});
    const controller = new AbortController();
    const host = createNodeHost(controller.signal);
    cleanup.push(() => host.close());
    const socket = await host.dialTCP(address);
    const reading = expect(socket.read(1)).rejects.toThrow("closed");
    controller.abort();
    await host.close();
    await reading;
    await expect(socket.write(new Uint8Array([1]))).rejects.toThrow("closed");
    await socket.close();
  });

  it("classifies a refused replacement dial without exposing the platform error", async () => {
    const reservation = createServer();
    await new Promise<void>((resolve) => reservation.listen(0, "127.0.0.1", resolve));
    const address = reservation.address();
    if (!address || typeof address === "string") throw new Error("missing fixture address");
    await new Promise<void>((resolve) => reservation.close(() => resolve()));
    const host = createNodeHost();
    cleanup.push(() => host.close());
    for (let attempt = 0; attempt < 2; attempt++) {
      await expect(host.dialTCP(`127.0.0.1:${address.port}`)).rejects.toMatchObject({
        name: "TnlHostNetworkError",
        message: "connector host TCP operation failed",
      });
    }
  });

  it("keeps Node read/write network errors typed and programming errors terminal", async () => {
    for (const failure of [
      new Error("private platform detail"),
      new TypeError("private coding detail"),
    ]) {
      const raw = new RawSocket();
      const stream = new NodeSocket(raw);
      raw.emit("error", failure);
      for (const operation of [() => stream.read(1), () => stream.write(new Uint8Array([1]))]) {
        const error: unknown = await operation().catch((error: unknown) => error);
        expect(error).toBeInstanceOf(Error);
        expect(error instanceof HostNetworkError).toBe(!(failure instanceof TypeError));
        expect(String(error)).not.toContain("private");
      }
      await stream.close();
    }
  });
});
