import { TnlError } from "../../errors.js";
import type { TnlTLSStream } from "../../project.js";
import { WASM_CHUNK_BYTES, type WasmByteStream } from "./wasm_abi.js";

export function isWasmByteStream(value: unknown): value is WasmByteStream {
  return (
    typeof value === "object" &&
    value !== null &&
    "read" in value &&
    typeof value.read === "function" &&
    "write" in value &&
    typeof value.write === "function" &&
    "closeWrite" in value &&
    typeof value.closeWrite === "function" &&
    "startTls" in value &&
    typeof value.startTls === "function" &&
    "close" in value &&
    typeof value.close === "function"
  );
}

// web streams serialize reads and writes. zero read-ahead avoids consuming a
// mysql greeting or tls byte before its driver explicitly requests it.
export function wasmStream(
  raw: WasmByteStream,
  signal: AbortSignal,
  released: () => void,
): TnlTLSStream {
  const pending = new Set<Promise<unknown>>();
  let stopped = false;
  let upgrading = false;
  let readEnded = false;
  let writeEnded = false;
  let closed = false;
  let closing: Promise<void> | undefined;
  let reading: ReadableStreamDefaultController<Uint8Array> | undefined;
  let writing: WritableStreamDefaultController | undefined;
  const failure = () => new TnlError("sdk.connection_unavailable");

  function track<Value>(work: Promise<Value>): Promise<Value> {
    pending.add(work);
    void work.then(
      () => pending.delete(work),
      () => pending.delete(work),
    );
    return work;
  }

  function close(): Promise<void> {
    stopped = true;
    signal.removeEventListener("abort", aborted);
    reading?.error(failure());
    writing?.error(failure());
    if (closed) return Promise.resolve();
    closing ??= (async () => {
      // raw close must interrupt blocked I/O; joining before it would deadlock.
      try {
        await raw.close();
      } catch {
        throw new TnlError("sdk.cleanup_failed");
      } finally {
        await Promise.allSettled(pending);
      }
      closed = true;
      released();
    })().finally(() => {
      closing = undefined;
    });
    return closing;
  }

  function aborted(): void {
    void close().catch(() => {});
  }

  const readable = new ReadableStream<Uint8Array>(
    {
      start(controller) {
        reading = controller;
      },
      async pull(controller) {
        if (stopped) throw failure();
        if (upgrading) throw new TnlError("sdk.configuration_invalid");
        try {
          const bytes = await track(raw.read(WASM_CHUNK_BYTES));
          if (stopped) return;
          if (bytes === null) {
            readEnded = true;
            controller.close();
            reading = undefined;
            if (writeEnded) await close();
          } else if (
            bytes instanceof Uint8Array &&
            bytes.byteLength > 0 &&
            bytes.byteLength <= WASM_CHUNK_BYTES
          ) {
            // go may reuse its crossing buffer after this call returns.
            controller.enqueue(bytes.slice());
          } else {
            throw new TnlError("sdk.wasm_invalid");
          }
        } catch (error) {
          const safe =
            error instanceof TnlError && error.code === "sdk.wasm_invalid" ? error : failure();
          controller.error(safe);
          reading = undefined;
          void close().catch(() => {});
        }
      },
      cancel: close,
    },
    { highWaterMark: 0 },
  );
  const writable = new WritableStream<Uint8Array>(
    {
      start(controller) {
        writing = controller;
      },
      async write(bytes) {
        if (stopped) throw failure();
        if (upgrading) throw new TnlError("sdk.configuration_invalid");
        if (!(bytes instanceof Uint8Array)) throw new TnlError("sdk.configuration_invalid");
        try {
          // no unbounded queue or full-payload copy. each write is acknowledged
          // before the next 64 kib slice is handed to go.
          for (let offset = 0; offset < bytes.byteLength; offset += WASM_CHUNK_BYTES) {
            if (stopped) throw failure();
            await track(raw.write(bytes.subarray(offset, offset + WASM_CHUNK_BYTES)));
          }
          if (stopped) throw failure();
        } catch {
          void close().catch(() => {});
          throw failure();
        }
      },
      async close() {
        if (stopped) throw failure();
        if (upgrading) throw new TnlError("sdk.configuration_invalid");
        try {
          await track(raw.closeWrite());
          writeEnded = true;
          writing = undefined;
          if (readEnded) await close();
        } catch (error) {
          void close().catch(() => {});
          throw error instanceof TnlError && error.code === "sdk.cleanup_failed"
            ? error
            : failure();
        }
      },
      abort: close,
    },
    { highWaterMark: 1 },
  );
  signal.addEventListener("abort", aborted, { once: true });
  if (signal.aborted) aborted();
  return Object.freeze({
    readable,
    writable,
    close,
    async startTls() {
      if (stopped) throw failure();
      if (pending.size !== 0) throw new TnlError("sdk.configuration_invalid");
      upgrading = true;
      try {
        await track(raw.startTls());
        if (stopped) throw failure();
      } catch {
        void close().catch(() => {});
        throw failure();
      } finally {
        upgrading = false;
      }
    },
  });
}
