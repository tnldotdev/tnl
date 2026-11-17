import { inspect } from "node:util";
import { expect, test, vi } from "vitest";
import { wasmStream } from "../../src/internal/connector/wasm_stream.js";
import { WASM_CHUNK_BYTES } from "../../src/internal/connector/wasm_abi.js";

function rawStream() {
  return {
    read: vi.fn(async (_max: number): Promise<unknown> => null),
    write: vi.fn(async (_bytes: Uint8Array) => {}),
    startTls: vi.fn(async () => {}),
    closeWrite: vi.fn(async () => {}),
    close: vi.fn(async () => {}),
  };
}

test("web stream backpressure crosses Go in bounded acknowledged chunks without read-ahead", async () => {
  const raw = rawStream();
  const acknowledged = Promise.withResolvers<void>();
  raw.write.mockImplementationOnce(async () => acknowledged.promise);
  const released = vi.fn();
  const stream = wasmStream(raw, new AbortController().signal, released);
  expect(raw.read).not.toHaveBeenCalled();
  const writer = stream.writable.getWriter();
  const bytes = new Uint8Array(WASM_CHUNK_BYTES * 3 + 11);
  const writing = writer.write(bytes);
  await Promise.resolve();
  expect(raw.write).toHaveBeenCalledTimes(1);
  acknowledged.resolve();
  await writing;
  expect(raw.write.mock.calls.map(([bytes]) => bytes.byteLength)).toEqual([
    WASM_CHUNK_BYTES,
    WASM_CHUNK_BYTES,
    WASM_CHUNK_BYTES,
    11,
  ]);
  await stream.close();
  expect(released).toHaveBeenCalledOnce();
});

test("reads validate bounds and copy Go-owned crossing buffers", async () => {
  const raw = rawStream();
  const bytes = new Uint8Array([1, 2, 3]);
  raw.read.mockResolvedValueOnce(bytes);
  const stream = wasmStream(raw, new AbortController().signal, vi.fn());
  const reader = stream.readable.getReader();
  const received = await reader.read();
  expect(raw.read).toHaveBeenCalledExactlyOnceWith(WASM_CHUNK_BYTES);
  bytes.fill(0);
  expect(received.value).toEqual(new Uint8Array([1, 2, 3]));
  await stream.close();
});

test.each([new Uint8Array(), new Uint8Array(WASM_CHUNK_BYTES + 1), "private credential"])(
  "invalid read results fail safely and close the owned stream",
  async (value) => {
    const raw = rawStream();
    raw.read.mockResolvedValueOnce(value);
    const stream = wasmStream(raw, new AbortController().signal, vi.fn());
    await expect(stream.readable.getReader().read()).rejects.toMatchObject({
      code: "sdk.wasm_invalid",
    });
    await stream.close();
    expect(raw.close).toHaveBeenCalledOnce();
  },
);

test("close interrupts a blocked read and joins its underlying Go operation", async () => {
  const raw = rawStream();
  const read = Promise.withResolvers<unknown>();
  const entered = Promise.withResolvers<void>();
  const close = Promise.withResolvers<void>();
  raw.read.mockImplementation(async () => {
    entered.resolve();
    return read.promise;
  });
  raw.close.mockImplementation(async () => {
    read.resolve(null);
    return close.promise;
  });
  const released = vi.fn();
  const stream = wasmStream(raw, new AbortController().signal, released);
  const pending = stream.readable.getReader().read();
  const failed = expect(pending).rejects.toMatchObject({ code: "sdk.connection_unavailable" });
  await entered.promise;
  const cleanup = stream.close();
  expect(stream.close()).toBe(cleanup);
  await failed;
  expect(released).not.toHaveBeenCalled();
  close.resolve();
  await cleanup;
  expect(released).toHaveBeenCalledOnce();
  expect(raw.close).toHaveBeenCalledOnce();
});

test("failed raw cleanup remains owned and retryable with redacted diagnostics", async () => {
  const raw = rawStream();
  raw.close.mockRejectedValueOnce(new Error("private credential"));
  const released = vi.fn();
  const stream = wasmStream(raw, new AbortController().signal, released);
  const cleanup = stream.close();
  await expect(cleanup).rejects.toMatchObject({ code: "sdk.cleanup_failed" });
  await expect(cleanup).rejects.not.toHaveProperty("cause");
  expect(released).not.toHaveBeenCalled();
  await stream.close();
  expect(raw.close).toHaveBeenCalledTimes(2);
  expect(released).toHaveBeenCalledOnce();
});

test("abort closes both directions and never exposes the caller's abort reason", async () => {
  const raw = rawStream();
  const controller = new AbortController();
  const stream = wasmStream(raw, controller.signal, vi.fn());
  controller.abort(new Error("private credential"));
  const reading = stream.readable.getReader().read();
  await expect(reading).rejects.toMatchObject({ code: "sdk.connection_unavailable" });
  try {
    await reading;
  } catch (error) {
    expect(inspect(error)).not.toContain("private credential");
  }
  await stream.close();
  expect(raw.close).toHaveBeenCalledOnce();
});

test("TLS cannot race an outstanding application read", async () => {
  const raw = rawStream();
  const read = Promise.withResolvers<unknown>();
  const entered = Promise.withResolvers<void>();
  raw.read.mockImplementation(async () => {
    entered.resolve();
    return read.promise;
  });
  raw.close.mockImplementation(async () => read.resolve(null));
  const stream = wasmStream(raw, new AbortController().signal, vi.fn());
  const pending = stream.readable.getReader().read();
  const failed = expect(pending).rejects.toMatchObject({ code: "sdk.connection_unavailable" });
  await entered.promise;
  await expect(stream.startTls()).rejects.toMatchObject({ code: "sdk.configuration_invalid" });
  expect(raw.startTls).not.toHaveBeenCalled();
  await stream.close();
  await failed;
});

test("writable close preserves the response and retires only after both halves finish", async () => {
  const raw = rawStream();
  raw.read.mockResolvedValueOnce(new Uint8Array([42]));
  const released = vi.fn();
  const stream = wasmStream(raw, new AbortController().signal, released);
  const writer = stream.writable.getWriter();
  await writer.write(new Uint8Array([17]));
  await writer.close();
  expect(raw.closeWrite).toHaveBeenCalledOnce();
  expect(raw.close).not.toHaveBeenCalled();
  const reader = stream.readable.getReader();
  expect((await reader.read()).value).toEqual(new Uint8Array([42]));
  expect(await reader.read()).toEqual({ value: undefined, done: true });
  await stream.close();
  expect(raw.close).toHaveBeenCalledOnce();
  expect(released).toHaveBeenCalledOnce();
});
