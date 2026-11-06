import { Socket } from "node:net";
import { MAX_CHUNK_BYTES } from "./abi.ts";
import type { ByteStream } from "./abi.ts";
import {
  abortError,
  closedError,
  createSocketHost,
  networkError,
  parseTCPAddress,
} from "./host.ts";
import type { SocketHost } from "./host.ts";

export class NodeSocket implements ByteStream {
  private readonly socket: Socket;
  private ended = false;
  private closed = false;
  private failure: Error | undefined;
  private wakeRead: (() => void) | undefined;
  private closing: Promise<void> | undefined;
  private stopping = false;

  constructor(socket: Socket) {
    this.socket = socket;
    socket.on("error", (reason: Error) => {
      this.failure = networkError(reason);
      this.wakeRead?.();
    });
    socket.on("end", () => {
      this.ended = true;
      this.wakeRead?.();
    });
    socket.on("close", () => {
      this.closed = true;
      this.wakeRead?.();
    });
    socket.on("readable", () => this.wakeRead?.());
  }

  async read(max: number): Promise<Uint8Array | null> {
    for (;;) {
      if (this.stopping) throw closedError();
      if (this.failure) throw this.failure;
      const size = Math.min(max, this.socket.readableLength);
      if (size > 0) {
        let bytes: unknown;
        try {
          bytes = this.socket.read(size);
        } catch (reason) {
          throw networkError(reason);
        }
        if (!(bytes instanceof Uint8Array)) throw new Error("invalid TCP socket read");
        return bytes;
      }
      if (this.ended) return null;
      if (this.closed) throw networkError(undefined);
      await new Promise<void>((resolve, reject) => {
        this.wakeRead = resolve;
        try {
          this.socket.read(0);
        } catch (reason) {
          this.wakeRead = undefined;
          reject(networkError(reason));
        }
      });
      this.wakeRead = undefined;
    }
  }

  write(bytes: Uint8Array): Promise<void> {
    if (this.stopping) return Promise.reject(closedError());
    if (this.closed) return Promise.reject(this.failure ?? networkError(undefined));
    if (this.failure) return Promise.reject(this.failure);
    return new Promise<void>((resolve, reject) => {
      const onClose = (): void => reject(this.failure ?? networkError(undefined));
      this.socket.once("close", onClose);
      // the callback, not the boolean return value, releases the next bounded write.
      try {
        this.socket.write(bytes, (error?: Error | null) => {
          this.socket.removeListener("close", onClose);
          if (error || this.failure) reject(this.failure ?? networkError(error));
          else resolve();
        });
      } catch (reason) {
        this.socket.removeListener("close", onClose);
        reject(networkError(reason));
      }
    });
  }

  close(): Promise<void> {
    this.stopping = true;
    if (this.closed) return Promise.resolve();
    if (!this.closing) {
      const attempt = new Promise<void>((resolve, reject) => {
        this.socket.once("close", resolve);
        try {
          this.socket.destroy();
        } catch (reason) {
          this.socket.removeListener("close", resolve);
          reject(networkError(reason));
        }
      });
      this.closing = attempt.then(
        () => {
          this.closing = undefined;
        },
        (reason: unknown) => {
          this.closing = undefined;
          throw reason;
        },
      );
    }
    this.wakeRead?.();
    return this.closing;
  }
}

async function dialTCP(address: string, signal: AbortSignal): Promise<ByteStream> {
  const { hostname, port } = parseTCPAddress(address);
  if (signal.aborted) throw abortError();
  // net.Socket forwards highWaterMark to Duplex, but @types/node omits that option.
  const options = { highWaterMark: MAX_CHUNK_BYTES, allowHalfOpen: true };
  const socket = new Socket(options);
  const stream = new NodeSocket(socket);
  const onAbort = (): void => {
    socket.destroy();
  };
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    await new Promise<void>((resolve, reject) => {
      const cleanup = (): void => {
        socket.removeListener("connect", onConnect);
        socket.removeListener("error", onError);
        socket.removeListener("close", onClose);
      };
      const onConnect = (): void => {
        cleanup();
        resolve();
      };
      const onError = (reason: Error): void => {
        cleanup();
        reject(networkError(reason));
      };
      const onClose = (): void => {
        cleanup();
        reject(signal.aborted ? abortError() : networkError(undefined));
      };
      socket.once("connect", onConnect);
      socket.once("error", onError);
      socket.once("close", onClose);
      socket.connect({ host: hostname, port });
    });
    if (signal.aborted) throw abortError();
    return stream;
  } catch (error) {
    await stream.close();
    throw networkError(error);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

export function createNodeHost(signal?: AbortSignal): SocketHost {
  return createSocketHost(dialTCP, signal);
}
