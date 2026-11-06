import { describe, expect, it, vi } from "vitest";
import { BoundedSocket, HostNetworkError } from "./host.ts";
import { dialWebTCP, WebSocketStream } from "./host-web.ts";
import type { WebTCPSocket } from "./host-web.ts";

function webSocket(
  readable: ReadableStream<Uint8Array>,
  writable = new WritableStream<Uint8Array>(),
): WebTCPSocket {
  return {
    readable,
    writable,
    opened: Promise.resolve(),
    closed: Promise.resolve(),
    close: vi.fn(async () => {}),
  };
}

describe("Workers web byte transport with fake sockets (not workerd integration)", () => {
  it("uses BYOB for bounded reads and preserves trailing bytes before EOF", async () => {
    const readable = new ReadableStream<Uint8Array>({
      type: "bytes",
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3, 4, 5]));
        controller.close();
      },
    });
    const socket = webSocket(readable);
    const stream = new BoundedSocket(new WebSocketStream(socket));
    expect(Array.from((await stream.read(2)) ?? [])).toEqual([1, 2]);
    expect(Array.from((await stream.read(2)) ?? [])).toEqual([3, 4]);
    expect(Array.from((await stream.read(2)) ?? [])).toEqual([5]);
    await expect(stream.read(2)).resolves.toBeNull();
    await stream.close();
    await stream.close();
    expect(socket.close).toHaveBeenCalledOnce();
    expect(socket.readable.locked).toBe(false);
    expect(socket.writable.locked).toBe(false);
  });

  it("awaits writable backpressure rather than queueing writes", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const write = vi.fn(async () => gate);
    const socket = webSocket(
      new ReadableStream<Uint8Array>({ type: "bytes" }),
      new WritableStream<Uint8Array>({ write }),
    );
    const stream = new BoundedSocket(new WebSocketStream(socket));
    let finished = false;
    const writing = stream.write(new Uint8Array([1])).then(() => {
      finished = true;
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(write).toHaveBeenCalledOnce();
    expect(finished).toBe(false);
    await expect(stream.write(new Uint8Array([2]))).rejects.toThrow("concurrent host writes");
    release();
    await writing;
    await stream.close();
  });

  it("close interrupts a pending BYOB read and releases locks", async () => {
    const canceled = vi.fn();
    const socket = webSocket(new ReadableStream<Uint8Array>({ type: "bytes", cancel: canceled }));
    const stream = new BoundedSocket(new WebSocketStream(socket));
    const reading = expect(stream.read(8)).rejects.toThrow("closed");
    await stream.close();
    await reading;
    expect(canceled).toHaveBeenCalledOnce();
    expect(socket.readable.locked).toBe(false);
  });

  it("sanitizes readable and writable transport errors", async () => {
    const readable = new ReadableStream<Uint8Array>({
      type: "bytes",
      pull() {
        throw new Error("private transport detail");
      },
    });
    const writable = new WritableStream<Uint8Array>({
      write() {
        throw new Error("private transport detail");
      },
    });
    const stream = new BoundedSocket(new WebSocketStream(webSocket(readable, writable)));
    await expect(stream.read(1)).rejects.toMatchObject({
      name: "TnlHostNetworkError",
      message: "connector host TCP operation failed",
    });
    await expect(stream.write(new Uint8Array([1]))).rejects.toMatchObject({
      name: "TnlHostNetworkError",
      message: "connector host TCP operation failed",
    });
    await stream.close();
  });

  it("classifies rejected Workers socket acquisition, but not validation/coding failures", async () => {
    const socket = webSocket(new ReadableStream<Uint8Array>({ type: "bytes" }));
    socket.opened = Promise.reject(new Error("private dial detail"));
    await expect(
      dialWebTCP("localhost:1234", new AbortController().signal, () => socket),
    ).rejects.toMatchObject({
      name: "TnlHostNetworkError",
      message: "connector host TCP operation failed",
    });
    const connect = vi.fn(() => {
      throw new TypeError("private coding detail");
    });
    const failure: unknown = await dialWebTCP(
      "localhost:1234",
      new AbortController().signal,
      connect,
    ).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    expect(failure).not.toBeInstanceOf(HostNetworkError);
    expect(String(failure)).not.toContain("private");
    await expect(
      dialWebTCP("credential@invalid", new AbortController().signal, connect),
    ).rejects.toThrow("expected a TCP");
    expect(connect).toHaveBeenCalledTimes(1);
  });

  it("retains socket and lock ownership until a failed close is successfully retried", async () => {
    const failure = new HostNetworkError();
    const socket = webSocket(new ReadableStream<Uint8Array>({ type: "bytes" }));
    socket.close = vi.fn().mockRejectedValueOnce(failure).mockResolvedValue(undefined);
    const stream = new WebSocketStream(socket);
    await expect(stream.close()).rejects.toBe(failure);
    expect(socket.readable.locked).toBe(true);
    await expect(stream.read(1)).rejects.toThrow("closed");
    await stream.close();
    await stream.close();
    expect(socket.close).toHaveBeenCalledTimes(2);
    expect(socket.readable.locked).toBe(false);
    expect(socket.writable.locked).toBe(false);
  });
});
