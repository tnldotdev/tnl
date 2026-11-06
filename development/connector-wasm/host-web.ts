import type { ByteStream } from "./abi.ts";
import {
  abortError,
  closedError,
  networkError,
  parseTCPAddress,
  settleHostCleanup,
} from "./host.ts";

export interface WebTCPSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened: Promise<unknown>;
  closed: Promise<unknown>;
  close(): Promise<void>;
}

// TCP sockets in workerd expose a byte stream; BYOB bounds each host allocation.
export class WebSocketStream implements ByteStream {
  private readonly socket: WebTCPSocket;
  private readonly reader: ReadableStreamBYOBReader;
  private readonly writer: WritableStreamDefaultWriter<Uint8Array>;
  private closing: Promise<void> | undefined;
  private stopped = false;
  private closeSucceeded = false;

  constructor(socket: WebTCPSocket) {
    this.socket = socket;
    this.reader = socket.readable.getReader({ mode: "byob" });
    this.writer = socket.writable.getWriter();
    // a remote error is also delivered by read/write; never leave these unhandled.
    void socket.closed.catch(() => {});
    void this.writer.closed.catch(() => {});
  }

  async read(max: number): Promise<Uint8Array | null> {
    if (this.stopped) throw closedError();
    try {
      const { value, done } = await this.reader.read(new Uint8Array(max));
      if (this.stopped) throw closedError();
      return done ? null : value;
    } catch (reason) {
      if (this.stopped) throw closedError();
      throw networkError(reason);
    }
  }

  async write(bytes: Uint8Array): Promise<void> {
    if (this.stopped) throw closedError();
    try {
      await this.writer.ready;
      await this.writer.write(bytes);
      if (this.stopped) throw closedError();
    } catch (reason) {
      if (this.stopped) throw closedError();
      throw networkError(reason);
    }
  }

  close(): Promise<void> {
    this.stopped = true;
    if (this.closeSucceeded) return Promise.resolve();
    if (!this.closing) {
      const attempt = settleHostCleanup(
        (async () => {
          const [socket] = await Promise.allSettled([
            Promise.resolve().then(() => this.socket.close()),
            this.reader.cancel(),
            this.writer.abort(),
          ]);
          if (socket?.status === "rejected") throw networkError(socket.reason);
          this.reader.releaseLock();
          this.writer.releaseLock();
        })(),
      );
      this.closing = attempt.then(
        () => {
          this.closeSucceeded = true;
          this.closing = undefined;
        },
        (error: unknown) => {
          this.closing = undefined;
          throw error;
        },
      );
    }
    return this.closing;
  }
}

export async function dialWebTCP(
  address: string,
  signal: AbortSignal,
  connect: (endpoint: { hostname: string; port: number }) => WebTCPSocket,
): Promise<ByteStream> {
  if (signal.aborted) throw abortError();
  const endpoint = parseTCPAddress(address);
  let socket: WebTCPSocket;
  try {
    socket = connect(endpoint);
  } catch (reason) {
    throw networkError(reason);
  }
  let stream: WebSocketStream;
  try {
    stream = new WebSocketStream(socket);
  } catch {
    await settleHostCleanup(socket.close());
    throw new Error("connector host socket contract failed");
  }
  const onAbort = (): void => {
    void stream.close().catch(() => {});
  };
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    await socket.opened;
    if (signal.aborted) throw abortError();
    return stream;
  } catch (reason) {
    await stream.close();
    if (signal.aborted) throw abortError();
    throw networkError(reason);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}
