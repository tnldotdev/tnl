import { Duplex } from "node:stream";
import type { ApplicationPump, ConnectorHandle, ConnectorStream, PumpReceiver } from "./abi.ts";
import { MAX_CHUNK_BYTES } from "./abi.ts";
import { abortError } from "./host.ts";

// pg sees a socket-shaped Duplex, but all bytes already pass through go TLS.
// this adapter owns one visitor stream, not the prepared connector's lifetime.
class PostgresStream extends Duplex {
  connecting = false;
  readonly encrypted = true;
  readonly authorized = true;
  private connected = false;
  private reading = false;
  private readonly stream: ConnectorStream;
  private readonly signal: AbortSignal | undefined;
  private closing: Promise<void> | undefined;
  private readonly copyReads: boolean;
  private readonly pump: ApplicationPump | undefined;
  private readEnded = false;
  private pendingWrite:
    | {
        bytes: Buffer;
        sent: number;
        completed: number;
        callback: (error?: Error | null) => void;
      }
    | undefined;

  constructor(stream: ConnectorStream, signal?: AbortSignal, copyReads = true, streaming = false) {
    super({ highWaterMark: MAX_CHUNK_BYTES, allowHalfOpen: false, autoDestroy: true });
    this.stream = stream;
    this.signal = signal;
    this.copyReads = copyReads;
    if (streaming) {
      const pump = stream.pump?.(this.receive);
      if (!pump || typeof pump.write !== "function" || typeof pump.resume !== "function") {
        throw new Error("connector stream pump setup failed");
      }
      this.pump = pump;
    }
    signal?.addEventListener("abort", this.onAbort, { once: true });
    if (signal?.aborted) this.onAbort();
  }

  private readonly onAbort = (): void => {
    this.destroy(abortError());
  };

  connect(): this {
    if (this.connected || this.connecting) throw new Error("pg stream already connected");
    this.connecting = true;
    queueMicrotask(() => {
      if (this.destroyed) return;
      this.connecting = false;
      this.connected = true;
      this.emit("connect");
      this._read(MAX_CHUNK_BYTES);
    });
    return this;
  }

  setNoDelay(): this {
    return this;
  }

  setKeepAlive(): this {
    return this;
  }

  ref(): this {
    return this;
  }

  unref(): this {
    return this;
  }

  override _read(size: number): void {
    if (!this.connected || this.reading || this.destroyed || this.readEnded) return;
    this.reading = true;
    if (this.pump) {
      try {
        this.pump.resume();
      } catch {
        this.destroy(new Error("connector stream pump read failed"));
      }
      return;
    }
    const max = Math.max(1, Math.min(size, MAX_CHUNK_BYTES));
    void this.stream.read(max).then(
      (bytes) => {
        this.reading = false;
        if (this.destroyed) return;
        if (bytes !== null && (bytes.byteLength === 0 || bytes.byteLength > max)) {
          this.destroy(new Error("connector stream returned an invalid read size"));
          return;
        }
        // push's false result stops reads until node calls _read again.
        this.push(
          bytes === null
            ? null
            : this.copyReads
              ? Buffer.from(bytes)
              : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength),
        );
      },
      () => {
        this.reading = false;
        if (!this.destroyed) this.destroy(new Error("connector stream read failed"));
      },
    );
  }

  override _write(
    bytes: Buffer,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    if (this.pump) {
      if (bytes.byteLength === 0) {
        callback();
        return;
      }
      this.pendingWrite = { bytes, sent: 0, completed: 0, callback };
      this.flushPumpWrite();
      return;
    }
    const write = async (): Promise<void> => {
      for (let offset = 0; offset < bytes.byteLength; offset += MAX_CHUNK_BYTES) {
        if (this.destroyed) throw new Error("pg stream destroyed");
        await this.stream.write(bytes.subarray(offset, offset + MAX_CHUNK_BYTES));
      }
    };
    void write().then(
      () => callback(),
      () => callback(new Error("connector stream write failed")),
    );
  }

  private flushPumpWrite(): void {
    const write = this.pendingWrite;
    if (!write || !this.pump || this.destroyed) return;
    try {
      while (write.sent < write.bytes.byteLength) {
        const chunk = write.bytes.subarray(write.sent, write.sent + MAX_CHUNK_BYTES);
        if (!this.pump.write(chunk)) return;
        write.sent += chunk.byteLength;
      }
    } catch {
      this.destroy(new Error("connector stream pump write failed"));
    }
  }

  // go schedules notifications in microtasks, outside its queue locks. accepted
  // writes stay pending until completed byte counts cover the entire node write.
  private readonly receive: PumpReceiver = (kind, value): void => {
    if (this.destroyed) return;
    switch (kind) {
      case 1: {
        if (
          !this.reading ||
          this.readEnded ||
          !(value instanceof Uint8Array) ||
          value.byteLength === 0 ||
          value.byteLength > MAX_CHUNK_BYTES
        ) {
          this.destroy(new Error("connector stream pump returned invalid data"));
          return;
        }
        this.reading = false;
        const more = this.push(
          this.copyReads
            ? Buffer.from(value)
            : Buffer.from(value.buffer, value.byteOffset, value.byteLength),
        );
        if (more) this._read(MAX_CHUNK_BYTES);
        return;
      }
      case 2: {
        const write = this.pendingWrite;
        if (
          !write ||
          typeof value !== "number" ||
          !Number.isSafeInteger(value) ||
          value <= 0 ||
          value > write.sent - write.completed
        ) {
          this.destroy(new Error("connector stream pump returned invalid completion"));
          return;
        }
        write.completed += value;
        if (write.completed === write.bytes.byteLength) {
          this.pendingWrite = undefined;
          write.callback();
        } else {
          this.flushPumpWrite();
        }
        return;
      }
      case 3:
        // go may return final bytes and eof from the same credited read.
        if (value !== null || this.readEnded) break;
        this.readEnded = true;
        this.reading = false;
        this.push(null);
        return;
      case 4:
        this.destroy(new Error("connector stream pump failed"));
        return;
    }
    this.destroy(new Error("connector stream pump returned an invalid event"));
  };

  private closeStream(): Promise<void> {
    this.closing ??= this.stream.close();
    return this.closing;
  }

  override _final(callback: (error?: Error | null) => void): void {
    void this.closeStream().then(
      () => {
        // explicit pump close joins and suppresses further notifications, including
        // eof. finish both halves so pg's Client.end can observe the close event.
        if (this.pump && !this.readEnded && !this.destroyed) {
          this.readEnded = true;
          this.reading = false;
          this.push(null);
        }
        callback();
      },
      () => callback(new Error("connector stream close failed")),
    );
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    this.signal?.removeEventListener("abort", this.onAbort);
    const pending = this.pendingWrite;
    this.pendingWrite = undefined;
    pending?.callback(error ?? new Error("pg stream destroyed"));
    void this.closeStream().then(
      () => callback(error),
      () => callback(error ?? new Error("connector stream close failed")),
    );
  }
}

export async function openPostgresStream(
  handle: ConnectorHandle,
  signal?: AbortSignal,
  copyReads = true,
  streaming = false,
): Promise<PostgresStream> {
  if (signal?.aborted) throw abortError();
  let stream: ConnectorStream;
  try {
    stream = await handle.open();
  } catch {
    throw new Error("connector stream open failed");
  }
  let closing: Promise<void> | undefined;
  const close = (): Promise<void> => {
    closing ??= stream.close();
    return closing;
  };
  const onAbort = (): void => {
    void close().catch(() => {});
  };
  signal?.addEventListener("abort", onAbort, { once: true });
  let secure = false;
  try {
    if (signal?.aborted) throw abortError();
    await stream.startTls();
    secure = true;
    if (signal?.aborted) throw abortError();
    return new PostgresStream(stream, signal, copyReads, streaming);
  } catch {
    try {
      await close();
    } catch {
      throw new Error("connector PostgreSQL TLS cleanup failed");
    }
    if (signal?.aborted) throw abortError();
    // do not let an opaque bridge error accidentally include configuration secrets.
    throw new Error(
      secure ? "connector stream pump setup failed" : "connector PostgreSQL TLS negotiation failed",
    );
  } finally {
    signal?.removeEventListener("abort", onAbort);
  }
}
