import type { Duplex } from "node:stream";
import pg from "pg";
import { describe, expect, it, vi } from "vitest";
import type { ConnectorHandle, ConnectorStream, PumpReceiver } from "./abi.ts";
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

function fakePump() {
  let receive: PumpReceiver | undefined;
  let queued = 0;
  const accepted: Buffer[] = [];
  const control = {
    write: vi.fn((bytes: Uint8Array): boolean => {
      if (queued + bytes.byteLength > MAX_CHUNK_BYTES) return false;
      queued += bytes.byteLength;
      accepted.push(Buffer.from(bytes));
      return true;
    }),
    resume: vi.fn(),
  };
  const raw = fakeStream({
    pump: vi.fn((callback) => {
      receive = callback;
      return control;
    }),
  });
  const notify: PumpReceiver = (kind, value) => {
    queueMicrotask(() => receive?.(kind, value));
  };
  return {
    raw,
    control,
    accepted,
    notify,
    complete(bytes: number): void {
      queued -= bytes;
      notify(2, bytes);
    },
  };
}

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

describe("pg streaming pump adapter (not PostgreSQL integration)", () => {
  it("joins go close and completes pg Client.end without a peer EOF or caller abort", async () => {
    const fixture = fakePump();
    const joined = Promise.withResolvers<void>();
    fixture.raw.close = vi.fn(() => joined.promise);
    const stream = await openPostgresStream(handle(fixture.raw), undefined, false, true);
    const client = new pg.Client({
      stream: () => stream,
      host: "connector.invalid",
      user: "fixture",
      database: "fixture",
      ssl: false,
    });
    const errors: Error[] = [];
    client.on("error", (error: Error) => errors.push(error));
    const connecting = client.connect();
    await tick();
    fixture.complete(fixture.accepted[0]?.length ?? 0);
    // authentication-ok and ready-for-query establish pg's real end lifecycle.
    fixture.notify(1, new Uint8Array([82, 0, 0, 0, 8, 0, 0, 0, 0, 90, 0, 0, 0, 5, 73]));
    await connecting;

    const ended = vi.fn();
    const closed = vi.fn();
    stream.once("close", closed);
    const ending = client.end().then(ended);
    expect(fixture.accepted.at(-1)).toEqual(Buffer.from([88, 0, 0, 0, 4]));
    expect(fixture.raw.close).not.toHaveBeenCalled();
    fixture.complete(5);
    await tick();
    expect(fixture.raw.close).toHaveBeenCalledOnce();
    expect(ended).not.toHaveBeenCalled();
    expect(closed).not.toHaveBeenCalled();

    joined.resolve();
    await tick();
    try {
      expect(ended).toHaveBeenCalledOnce();
      expect(closed).toHaveBeenCalledOnce();
      expect(errors).toEqual([]);
    } finally {
      stream.destroy();
      await ending;
    }
  });

  it("is opt-in and claims the pump only after go TLS completes", async () => {
    const off = fakePump();
    await destroy(await openPostgresStream(handle(off.raw)));
    expect(off.raw.pump).not.toHaveBeenCalled();

    const fixture = fakePump();
    const tls = Promise.withResolvers<void>();
    fixture.raw.startTls = vi.fn(() => tls.promise);
    const opening = openPostgresStream(handle(fixture.raw), undefined, false, true);
    await tick();
    expect(fixture.raw.pump).not.toHaveBeenCalled();
    tls.resolve();
    const stream = await opening;
    expect(fixture.raw.pump).toHaveBeenCalledOnce();
    expect(fixture.raw.read).not.toHaveBeenCalled();
    expect(fixture.raw.write).not.toHaveBeenCalled();
    await destroy(stream);
  });

  it("closes an unavailable or rejected pump setup without leaking bridge errors", async () => {
    for (const pump of [
      undefined,
      () => null,
      () => {
        throw new Error("secret");
      },
    ]) {
      const raw = fakeStream(pump ? { pump } : {});
      await expect(openPostgresStream(handle(raw), undefined, false, true)).rejects.toThrow(
        "connector stream pump setup failed",
      );
      expect(raw.close).toHaveBeenCalledOnce();
      expect(raw.read).not.toHaveBeenCalled();
      expect(raw.write).not.toHaveBeenCalled();
    }
  });

  it("retries full queues without dropping chunks and waits for actual byte completions", async () => {
    const fixture = fakePump();
    const stream = await openPostgresStream(handle(fixture.raw), undefined, false, true);
    const input = Buffer.alloc(MAX_CHUNK_BYTES * 2 + 9, 7);
    const written = vi.fn();
    expect(stream.write(input, written)).toBe(false);
    stream.end();
    expect(fixture.accepted.map((bytes) => bytes.length)).toEqual([MAX_CHUNK_BYTES]);
    expect(written).not.toHaveBeenCalled();
    expect(fixture.raw.close).not.toHaveBeenCalled();

    fixture.complete(MAX_CHUNK_BYTES);
    await tick();
    expect(fixture.accepted.map((bytes) => bytes.length)).toEqual([
      MAX_CHUNK_BYTES,
      MAX_CHUNK_BYTES,
    ]);
    fixture.complete(MAX_CHUNK_BYTES);
    await tick();
    expect(Buffer.concat(fixture.accepted)).toEqual(input);
    expect(written).not.toHaveBeenCalled();
    expect(fixture.raw.close).not.toHaveBeenCalled();

    // completion counts may be split or batched; enqueue alone never settles pg.
    fixture.complete(4);
    await tick();
    expect(written).not.toHaveBeenCalled();
    const finished = new Promise<void>((resolve) => stream.once("finish", resolve));
    fixture.complete(5);
    await finished;
    expect(written).toHaveBeenCalledOnce();
    expect(fixture.raw.close).toHaveBeenCalledOnce();
    expect(fixture.raw.write).not.toHaveBeenCalled();
    await destroy(stream);
  });

  it("grants read credits only under Duplex demand and retains owned byte slices", async () => {
    const fixture = fakePump();
    const stream = await openPostgresStream(handle(fixture.raw), undefined, false, true);
    stream.connect();
    await tick();
    expect(fixture.control.resume).toHaveBeenCalledOnce();
    const backing = new Uint8Array(MAX_CHUNK_BYTES + 2).fill(9);
    const first = backing.subarray(1, MAX_CHUNK_BYTES + 1);
    fixture.notify(1, first);
    await tick();
    expect(stream.readableLength).toBe(MAX_CHUNK_BYTES);
    expect(fixture.control.resume).toHaveBeenCalledOnce();
    const read: unknown = stream.read(MAX_CHUNK_BYTES);
    expect(Buffer.isBuffer(read)).toBe(true);
    if (!Buffer.isBuffer(read)) throw new Error("expected buffer");
    expect(read.buffer).toBe(backing.buffer);
    expect(read.byteOffset).toBe(1);
    await tick();
    expect(fixture.control.resume).toHaveBeenCalledTimes(2);
    fixture.notify(1, new Uint8Array(MAX_CHUNK_BYTES).fill(3));
    await tick();
    expect(fixture.control.resume).toHaveBeenCalledTimes(2);
    expect(read[0]).toBe(9);
    stream.read(MAX_CHUNK_BYTES);
    await tick();
    expect(fixture.control.resume).toHaveBeenCalledTimes(3);
    const closed = new Promise<void>((resolve) => stream.once("close", resolve));
    stream.resume();
    fixture.notify(3, null);
    await closed;
    expect(fixture.raw.close).toHaveBeenCalledOnce();
    expect(fixture.raw.read).not.toHaveBeenCalled();
  });

  it("settles an aborted write once and ignores queued callbacks after joined close", async () => {
    const fixture = fakePump();
    const controller = new AbortController();
    const stream = await openPostgresStream(handle(fixture.raw), controller.signal, false, true);
    const errors: Error[] = [];
    stream.on("error", (error: Error) => errors.push(error));
    const written = vi.fn();
    const closed = new Promise<void>((resolve) => stream.once("close", resolve));
    stream.write(Buffer.alloc(MAX_CHUNK_BYTES + 1), written);
    controller.abort();
    fixture.complete(MAX_CHUNK_BYTES);
    fixture.notify(4, null);
    await closed;
    await tick();
    expect(written).toHaveBeenCalledOnce();
    expect(written.mock.calls[0]?.[0]).toMatchObject({ name: "AbortError" });
    expect(errors).toMatchObject([{ name: "AbortError" }]);
    expect(fixture.accepted).toHaveLength(1);
    expect(fixture.raw.close).toHaveBeenCalledOnce();
  });

  it("delivers a final full chunk before EOF without requiring another read credit", async () => {
    const fixture = fakePump();
    const stream = await openPostgresStream(handle(fixture.raw), undefined, false, true);
    stream.connect();
    await tick();
    fixture.notify(1, new Uint8Array(MAX_CHUNK_BYTES).fill(7));
    fixture.notify(3, null);
    await tick();
    expect(fixture.control.resume).toHaveBeenCalledOnce();
    expect(stream.readableLength).toBe(MAX_CHUNK_BYTES);
    const chunks: Buffer[] = [];
    stream.on("data", (bytes: Buffer) => chunks.push(bytes));
    const closed = new Promise<void>((resolve) => stream.once("close", resolve));
    stream.resume();
    await closed;
    expect(Buffer.concat(chunks)).toEqual(Buffer.alloc(MAX_CHUNK_BYTES, 7));
    expect(fixture.raw.close).toHaveBeenCalledOnce();
  });

  it("reports one generic failure and releases a pending node write", async () => {
    const fixture = fakePump();
    const stream = await openPostgresStream(handle(fixture.raw), undefined, false, true);
    const errors: Error[] = [];
    stream.on("error", (error: Error) => errors.push(error));
    const written = vi.fn();
    const closed = new Promise<void>((resolve) => stream.once("close", resolve));
    stream.write(Buffer.from([1]), written);
    fixture.notify(4, null);
    fixture.notify(4, null);
    await closed;
    expect(written).toHaveBeenCalledOnce();
    expect(errors.map((error) => error.message)).toEqual(["connector stream pump failed"]);
    expect(fixture.raw.close).toHaveBeenCalledOnce();
  });

  it("rejects completions beyond accepted bytes instead of completing a node write early", async () => {
    const fixture = fakePump();
    const stream = await openPostgresStream(handle(fixture.raw), undefined, false, true);
    const error = new Promise<Error>((resolve) => stream.once("error", resolve));
    const closed = new Promise<void>((resolve) => stream.once("close", resolve));
    const written = vi.fn();
    stream.write(Buffer.from([1]), written);
    fixture.notify(2, 2);
    await expect(error).resolves.toMatchObject({
      message: "connector stream pump returned invalid completion",
    });
    await closed;
    expect(written).toHaveBeenCalledOnce();
    expect(written.mock.calls[0]?.[0]).toBeInstanceOf(Error);
  });
});
