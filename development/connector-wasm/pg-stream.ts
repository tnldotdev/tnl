import { Duplex } from "node:stream";
import type { ConnectorHandle, ConnectorStream } from "./abi.ts";
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

  constructor(stream: ConnectorStream, signal?: AbortSignal) {
    super({ highWaterMark: MAX_CHUNK_BYTES, allowHalfOpen: false, autoDestroy: true });
    this.stream = stream;
    this.signal = signal;
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
    if (!this.connected || this.reading || this.destroyed) return;
    this.reading = true;
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
        this.push(bytes === null ? null : Buffer.from(bytes));
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

  private closeStream(): Promise<void> {
    this.closing ??= this.stream.close();
    return this.closing;
  }

  override _final(callback: (error?: Error | null) => void): void {
    void this.closeStream().then(
      () => callback(),
      () => callback(new Error("connector stream close failed")),
    );
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    this.signal?.removeEventListener("abort", this.onAbort);
    void this.closeStream().then(
      () => callback(error),
      () => callback(error ?? new Error("connector stream close failed")),
    );
  }
}

export async function openPostgresStream(
  handle: ConnectorHandle,
  signal?: AbortSignal,
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
  try {
    if (signal?.aborted) throw abortError();
    await stream.startTls();
    if (signal?.aborted) throw abortError();
    return new PostgresStream(stream, signal);
  } catch {
    try {
      await close();
    } catch {
      throw new Error("connector PostgreSQL TLS cleanup failed");
    }
    if (signal?.aborted) throw abortError();
    // do not let an opaque bridge error accidentally include configuration secrets.
    throw new Error("connector PostgreSQL TLS negotiation failed");
  } finally {
    signal?.removeEventListener("abort", onAbort);
  }
}
