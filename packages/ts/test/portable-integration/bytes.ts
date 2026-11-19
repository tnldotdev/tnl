import type { TnlStream } from "@tnldotdev/tnl";

export const text = new TextEncoder();
export const utf8 = new TextDecoder("utf-8", { fatal: true });
export const MAX_PACKET = 1 << 20;

export function concat(...values: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const output = new Uint8Array(values.reduce((size, value) => size + value.byteLength, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.byteLength;
  }
  return output;
}

export function uint32(value: number, littleEndian = false): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, littleEndian);
  return bytes;
}

export function number32(value: Uint8Array, littleEndian = false): number {
  return new DataView(value.buffer, value.byteOffset, value.byteLength).getUint32(0, littleEndian);
}

// small wire clients below exercise SDK byte streams, not relay/admission logic.
// bounded packets and explicit close keep a malformed target from hanging a run.
export class Wire {
  readonly stream: TnlStream;
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private readonly writer: WritableStreamDefaultWriter<Uint8Array>;
  private buffered = new Uint8Array(0);

  constructor(stream: TnlStream) {
    this.stream = stream;
    this.reader = stream.readable.getReader();
    this.writer = stream.writable.getWriter();
  }

  async read(size: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_PACKET)
      throw new Error("fixture packet exceeds its bound");
    while (this.buffered.byteLength < size) {
      const next = await this.reader.read();
      if (next.done) throw new Error("target ended before the fixture packet was complete");
      if (
        next.value.byteLength === 0 ||
        this.buffered.byteLength + next.value.byteLength > MAX_PACKET
      )
        throw new Error("invalid or oversized target packet");
      this.buffered = concat(this.buffered, next.value);
    }
    const result = this.buffered.slice(0, size);
    this.buffered = this.buffered.slice(size);
    return result;
  }

  write(bytes: Uint8Array): Promise<void> {
    return this.writer.write(bytes);
  }

  async close(): Promise<void> {
    try {
      await this.stream.close();
    } finally {
      this.reader.releaseLock();
      this.writer.releaseLock();
    }
  }
}
