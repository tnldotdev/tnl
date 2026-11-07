import type { Duplex } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import type { ConnectorHandle, ConnectorStream } from "./abi.ts";
import { MAX_CHUNK_BYTES } from "./abi.ts";
import { openPostgresStream } from "./pg-stream.ts";

function fakeStream(overrides: Partial<ConnectorStream> = {}): ConnectorStream {
  const read = Promise.withResolvers<Uint8Array | null>();
  return {
    read: vi.fn(() => read.promise),
    write: vi.fn(async () => {}),
    startTls: vi.fn(async () => {}),
    close: vi.fn(async () => {
      read.resolve(null);
    }),
    ...overrides,
  };
}

function handle(stream: ConnectorStream): ConnectorHandle {
  return { open: vi.fn(async () => stream), close: vi.fn(async () => {}) };
}

async function destroy(stream: Duplex): Promise<void> {
  const closed = new Promise<void>((resolve) => stream.once("close", resolve));
  stream.destroy();
  await closed;
}

const tick = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

describe("pg custom Duplex with fake connector bytes (not PostgreSQL integration)", () => {
  it("can retain owned JS byte buffers without copying or including adjacent bytes", async () => {
    const backing = new Uint8Array([9, 1, 2, 8]);
    const reads: Array<Uint8Array | null> = [backing.subarray(1, 3), null];
    const raw = fakeStream({ read: vi.fn(async () => reads.shift() ?? null) });
    const stream = await openPostgresStream(handle(raw), undefined, false);
    const chunks: Buffer[] = [];
    stream.on("data", (bytes: Buffer) => chunks.push(bytes));
    const closed = new Promise<void>((resolve) => stream.once("close", resolve));
    stream.connect();
    await closed;
    expect(chunks[0]).toEqual(Buffer.from([1, 2]));
    expect(chunks[0]?.buffer).toBe(backing.buffer);
    expect(chunks[0]?.byteOffset).toBe(1);
  });
  it("cannot expose a pg stream before mandatory go TLS finishes", async () => {
    const tls = Promise.withResolvers<void>();
    const raw = fakeStream({ startTls: vi.fn(() => tls.promise) });
    let exposed = false;
    const opening = openPostgresStream(handle(raw)).then((stream) => {
      exposed = true;
      return stream;
    });
    await tick();
    expect(raw.startTls).toHaveBeenCalledOnce();
    expect(exposed).toBe(false);
    expect(raw.read).not.toHaveBeenCalled();
    expect(raw.write).not.toHaveBeenCalled();
    tls.resolve();
    const stream = await opening;
    expect(stream.encrypted).toBe(true);
    expect(stream.authorized).toBe(true);
    expect("getPeerCertificate" in stream).toBe(false);
    await destroy(stream);
    expect(raw.close).toHaveBeenCalledOnce();
  });

  it("fails closed on go TLS rejection without exposing bridge error contents", async () => {
    const raw = fakeStream({
      startTls: async () => {
        throw new Error("private fixture secret");
      },
    });
    await expect(openPostgresStream(handle(raw))).rejects.toThrow(
      "connector PostgreSQL TLS negotiation failed",
    );
    expect(raw.write).not.toHaveBeenCalled();
    expect(raw.read).not.toHaveBeenCalled();
    expect(raw.close).toHaveBeenCalledOnce();
  });

  it("cancels a pending TLS handshake and closes exactly once", async () => {
    const tls = Promise.withResolvers<void>();
    const controller = new AbortController();
    const raw = fakeStream({
      startTls: () => tls.promise,
      close: vi.fn(async () => {
        tls.reject(new Error("closed"));
      }),
    });
    const opening = openPostgresStream(handle(raw), controller.signal);
    const rejected = expect(opening).rejects.toMatchObject({ name: "AbortError" });
    await tick();
    controller.abort();
    await rejected;
    expect(raw.close).toHaveBeenCalledOnce();
    expect(raw.write).not.toHaveBeenCalled();
  });

  it("emits connect asynchronously and stops reading at Duplex backpressure", async () => {
    const raw = fakeStream({ read: vi.fn(async (max) => new Uint8Array(max)) });
    const stream = await openPostgresStream(handle(raw));
    const connect = vi.fn();
    stream.connect();
    stream.once("connect", connect);
    expect(connect).not.toHaveBeenCalled();
    await tick();
    expect(connect).toHaveBeenCalledOnce();
    expect(raw.read).toHaveBeenCalledOnce();
    expect(stream.readableLength).toBe(MAX_CHUNK_BYTES);
    await tick();
    expect(raw.read).toHaveBeenCalledOnce();
    stream.read(MAX_CHUNK_BYTES);
    await tick();
    expect(raw.read).toHaveBeenCalledTimes(2);
    await destroy(stream);
  });

  it("awaits go write backpressure, slices large writes, and flushes before close", async () => {
    const gate = Promise.withResolvers<void>();
    const chunks: number[] = [];
    const raw = fakeStream({
      write: vi.fn(async (bytes) => {
        chunks.push(bytes.length);
        await gate.promise;
      }),
    });
    const stream = await openPostgresStream(handle(raw));
    const written = vi.fn();
    expect(stream.write(Buffer.alloc(MAX_CHUNK_BYTES * 2 + 9), written)).toBe(false);
    stream.end();
    expect(chunks).toEqual([MAX_CHUNK_BYTES]);
    expect(written).not.toHaveBeenCalled();
    expect(raw.close).not.toHaveBeenCalled();
    const closed = new Promise<void>((resolve) => stream.once("close", resolve));
    gate.resolve();
    // the readable side is not consumed here; writable finish still closes go's stream.
    await new Promise<void>((resolve) => stream.once("finish", resolve));
    expect(chunks).toEqual([MAX_CHUNK_BYTES, MAX_CHUNK_BYTES, 9]);
    expect(written).toHaveBeenCalledOnce();
    expect(raw.close).toHaveBeenCalledOnce();
    stream.destroy();
    await closed;
    expect(raw.close).toHaveBeenCalledOnce();
  });

  it("delivers bytes before EOF and joins stream close", async () => {
    const reads: Array<Uint8Array | null> = [new Uint8Array([1, 2, 3]), null];
    const raw = fakeStream({ read: vi.fn(async () => reads.shift() ?? null) });
    const stream = await openPostgresStream(handle(raw));
    const chunks: Buffer[] = [];
    stream.on("data", (bytes: Buffer) => chunks.push(bytes));
    const closed = new Promise<void>((resolve) => stream.once("close", resolve));
    stream.connect();
    await closed;
    expect(Buffer.concat(chunks)).toEqual(Buffer.from([1, 2, 3]));
    expect(raw.close).toHaveBeenCalledOnce();
  });

  it("surfaces read failures once, closes, and does not leak opaque bridge errors", async () => {
    const raw = fakeStream({
      read: async () => {
        throw new Error("secret");
      },
    });
    const stream = await openPostgresStream(handle(raw));
    const errors: Error[] = [];
    stream.on("error", (error: Error) => errors.push(error));
    const closed = new Promise<void>((resolve) => stream.once("close", resolve));
    stream.connect();
    await closed;
    expect(errors.map((error) => error.message)).toEqual(["connector stream read failed"]);
    expect(raw.close).toHaveBeenCalledOnce();
  });

  it("surfaces write failures and joins close", async () => {
    const raw = fakeStream({
      write: async () => {
        throw new Error("secret");
      },
    });
    const stream = await openPostgresStream(handle(raw));
    const errors: Error[] = [];
    stream.on("error", (error: Error) => errors.push(error));
    const closed = new Promise<void>((resolve) => stream.once("close", resolve));
    stream.write(Buffer.from([1]));
    await closed;
    expect(errors.map((error) => error.message)).toEqual(["connector stream write failed"]);
    expect(raw.close).toHaveBeenCalledOnce();
  });

  it("abort interrupts a pending read, emits AbortError, and is idempotent", async () => {
    const raw = fakeStream();
    const controller = new AbortController();
    const stream = await openPostgresStream(handle(raw), controller.signal);
    const errors: Error[] = [];
    stream.on("error", (error: Error) => errors.push(error));
    stream.connect();
    await tick();
    const closed = new Promise<void>((resolve) => stream.once("close", resolve));
    controller.abort();
    await closed;
    expect(errors).toMatchObject([{ name: "AbortError" }]);
    stream.destroy();
    expect(raw.close).toHaveBeenCalledOnce();
  });

  it("abort also interrupts a backpressured write and settles its callback", async () => {
    const write = Promise.withResolvers<void>();
    const raw = fakeStream({
      write: () => write.promise,
      close: vi.fn(async () => {
        write.reject(new Error("closed"));
      }),
    });
    const controller = new AbortController();
    const stream = await openPostgresStream(handle(raw), controller.signal);
    const errors: Error[] = [];
    stream.on("error", (error: Error) => errors.push(error));
    const callback = vi.fn();
    const closed = new Promise<void>((resolve) => stream.once("close", resolve));
    expect(stream.write(Buffer.alloc(MAX_CHUNK_BYTES), callback)).toBe(false);
    controller.abort();
    await closed;
    await tick();
    expect(callback).toHaveBeenCalledOnce();
    expect(errors).toMatchObject([{ name: "AbortError" }]);
    expect(raw.close).toHaveBeenCalledOnce();
  });
});
