import { Buffer } from "node:buffer";
import { Duplex } from "node:stream";
import { TnlError } from "../../errors.js";
import type { TnlOpenStream, TnlStream } from "../../project.js";

/** adapts one tnl application stream, not a network address. */
export class DriverSocket extends Duplex {
  readonly #open: TnlOpenStream;
  readonly #abort = new AbortController();
  #opening?: Promise<TnlStream>;
  #reader?: ReadableStreamDefaultReader<Uint8Array>;
  #writer?: WritableStreamDefaultWriter<Uint8Array>;
  #reading = false;

  constructor(open: TnlOpenStream) {
    super({ allowHalfOpen: true, highWaterMark: 64 * 1024 });
    this.#open = open;
  }

  // the driver passes an address here; only tnl can select the destination.
  connect(): this {
    this.#opening ??= Promise.resolve().then(() => this.#open({ signal: this.#abort.signal }));
    return this;
  }

  override _construct(callback: (error?: Error | null) => void): void {
    const opening = this.#opening;
    if (opening === undefined) {
      callback(new TnlError("sdk.connection_unavailable"));
      return;
    }
    void opening
      .then((stream) => {
        if (!this.destroyed) {
          this.#reader = stream.readable.getReader();
          this.#writer = stream.writable.getWriter();
          this.emit("connect");
        }
      })
      .then(() => callback(), callback);
  }

  override destroy(error?: Error): this {
    // _destroy is deferred until _construct finishes; interrupt the open now.
    this.#abort.abort();
    return super.destroy(error);
  }

  override _read(): void {
    if (this.#reading || this.#reader === undefined) return;
    this.#reading = true;
    void this.#reader.read().then(
      (result) => {
        this.#reading = false;
        if (!this.destroyed)
          this.push(
            result.done
              ? null
              : Buffer.from(result.value.buffer, result.value.byteOffset, result.value.byteLength),
          );
      },
      (error: Error) => this.destroy(error),
    );
  }

  override _write(
    bytes: Buffer,
    _encoding: BufferEncoding,
    callback: (error?: Error) => void,
  ): void {
    if (this.#writer === undefined) callback(new TnlError("sdk.connection_unavailable"));
    else void this.#writer.write(bytes).then(() => callback(), callback);
  }

  override _final(callback: (error?: Error) => void): void {
    if (this.#writer === undefined) callback(new TnlError("sdk.connection_unavailable"));
    else void this.#writer.close().then(() => callback(), callback);
  }

  override _destroy(error: Error | null, callback: (error: Error | null) => void): void {
    const cleanup = async () => {
      const stream = await this.#opening?.catch(() => undefined);
      try {
        await stream?.close();
      } finally {
        this.#reader?.releaseLock();
        this.#writer?.releaseLock();
      }
    };
    void cleanup().then(
      () => callback(error),
      (failure: Error) =>
        callback(
          error === null
            ? failure
            : new AggregateError([error, failure], "driver stream failed to close"),
        ),
    );
  }

  // these knobs apply to TCP sockets. tnl owns the carrier configuration.
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
}
