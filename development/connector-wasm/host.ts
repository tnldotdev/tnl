import { MAX_CHUNK_BYTES } from "./abi.ts";
import type { ByteStream, ConnectorHost } from "./abi.ts";

// these stable names are also recognized by go/host_js.go. messages never carry
// the platform error, requested address, or application credentials.
export class HostNetworkError extends Error {
  override readonly name = "TnlHostNetworkError";
  constructor() {
    super("connector host TCP operation failed");
  }
}

export class HostCleanupError extends Error {
  override readonly name = "TnlHostCleanupError";
  constructor() {
    super("connector host cleanup did not settle within five seconds");
  }
}

// local abort/close must settle promptly, independently of network timeouts.
// keep this equal to hostSettlementTimeout in go/host_js.go.
export const HOST_SETTLEMENT_TIMEOUT_MS = 5_000;

export function networkError(reason: unknown): Error {
  if (reason instanceof TypeError || reason instanceof RangeError) {
    return new Error("connector host socket contract failed");
  }
  if (reason instanceof HostCleanupError || reason instanceof HostNetworkError) return reason;
  if (reason instanceof Error && reason.name === "AbortError") return abortError();
  return new HostNetworkError();
}

export async function settleHostCleanup<T>(operation: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new HostCleanupError()), HOST_SETTLEMENT_TIMEOUT_MS);
  });
  try {
    // late original settlement is consumed by native JS promise reactions. it
    // cannot invoke a released Go callback or become an unhandled rejection.
    return await Promise.race([operation, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

export function checkReadSize(max: number): void {
  if (!Number.isSafeInteger(max) || max < 1 || max > MAX_CHUNK_BYTES) {
    throw new RangeError(`read size must be between 1 and ${MAX_CHUNK_BYTES}`);
  }
}

export function closedError(): Error {
  return new Error("connector host socket closed");
}

export function abortError(): Error {
  return new DOMException("connector host canceled", "AbortError");
}

export function parseTCPAddress(address: string): { hostname: string; port: number } {
  const match = /^(?:\[([^\]]+)\]|([^:[\]\s]+)):(\d+)$/.exec(address);
  const hostname = match?.[1] ?? match?.[2];
  const port = Number(match?.[3]);
  if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
    // do not echo unvalidated input; it may contain a misplaced credential.
    throw new Error("expected a TCP hostname:port or [IPv6]:port");
  }
  return { hostname, port };
}

// no operation queue: callers must wait for backpressure rather than enqueue copies.
export class BoundedSocket implements ByteStream {
  private reading = false;
  private writing = false;
  private closing: Promise<void> | undefined;
  private stopped = false;
  private closeSucceeded = false;
  private readonly interrupted = Promise.withResolvers<never>();
  private readonly pending = new Set<Promise<unknown>>();
  private readonly raw: ByteStream;

  constructor(raw: ByteStream) {
    this.raw = raw;
    void this.interrupted.promise.catch(() => {});
  }

  private track<T>(operation: Promise<T>): Promise<T> {
    this.pending.add(operation);
    void operation.then(
      () => this.pending.delete(operation),
      () => this.pending.delete(operation),
    );
    return Promise.race([operation, this.interrupted.promise]);
  }

  async read(max: number): Promise<Uint8Array | null> {
    checkReadSize(max);
    if (this.stopped) throw closedError();
    if (this.reading) throw new Error("concurrent host reads are not supported");
    this.reading = true;
    try {
      const bytes = await this.track(this.raw.read(max));
      if (this.stopped) throw closedError();
      if (bytes !== null && (bytes.byteLength === 0 || bytes.byteLength > max)) {
        await this.close();
        throw new Error("host socket returned an invalid read size");
      }
      return bytes;
    } finally {
      this.reading = false;
    }
  }

  async write(bytes: Uint8Array): Promise<void> {
    if (this.stopped) throw closedError();
    if (this.writing) throw new Error("concurrent host writes are not supported");
    this.writing = true;
    try {
      for (let offset = 0; offset < bytes.byteLength; offset += MAX_CHUNK_BYTES) {
        if (this.stopped) throw closedError();
        await this.track(this.raw.write(bytes.subarray(offset, offset + MAX_CHUNK_BYTES)));
      }
      if (this.stopped) throw closedError();
    } finally {
      this.writing = false;
    }
  }

  close(): Promise<void> {
    this.stopped = true;
    this.interrupted.reject(closedError());
    if (this.closeSucceeded) return Promise.resolve();
    if (!this.closing) {
      const attempt = settleHostCleanup(
        Promise.all([
          Promise.resolve().then(() => this.raw.close()),
          Promise.allSettled(this.pending),
        ]).then(() => {}),
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

export interface SocketHost extends ConnectorHost {
  close(): Promise<void>;
}

export function createSocketHost(
  dial: (address: string, signal: AbortSignal) => Promise<ByteStream>,
  signal?: AbortSignal,
): SocketHost {
  const controller = new AbortController();
  const sockets = new Set<ByteStream>();
  const pending = new Set<Promise<void>>();
  let closing: Promise<void> | undefined;
  let closeSucceeded = false;

  function close(): Promise<void> {
    controller.abort();
    signal?.removeEventListener("abort", onAbort);
    if (closeSucceeded) return Promise.resolve();
    if (!closing) {
      const attempt = settleHostCleanup(
        (async () => {
          // close existing sockets even if an acquisition ignores cancellation.
          // late acquisitions own their own close before their pending work ends.
          const [acquisitions, results] = await Promise.all([
            Promise.allSettled(pending),
            Promise.allSettled([...sockets].map((socket) => socket.close())),
          ]);
          throwCleanupFailures([...acquisitions, ...results]);
        })(),
      );
      closing = attempt.then(
        () => {
          closeSucceeded = true;
          closing = undefined;
        },
        (error: unknown) => {
          closing = undefined;
          throw error;
        },
      );
    }
    return closing;
  }

  function onAbort(): void {
    void close().catch(() => {});
  }

  signal?.addEventListener("abort", onAbort, { once: true });
  if (signal?.aborted) onAbort();

  return {
    async dialTCP(address, signal) {
      const dialSignal = signal ? AbortSignal.any([controller.signal, signal]) : controller.signal;
      if (dialSignal.aborted) throw abortError();
      let cleaningLateSocket = false;
      const acquiring = dial(address, dialSignal).then(async (raw) => {
        const socket = new BoundedSocket(raw);
        const owned: ByteStream = {
          read: (max) => socket.read(max),
          write: (bytes) => socket.write(bytes),
          async close() {
            await socket.close();
            sockets.delete(owned);
          },
        };
        sockets.add(owned);
        if (dialSignal.aborted) {
          cleaningLateSocket = true;
          await owned.close();
          throw abortError();
        }
        return owned;
      });
      const cleanup = acquiring.then(
        () => {},
        (error: unknown) => {
          if (cleaningLateSocket && !(error instanceof Error && error.name === "AbortError"))
            throw error;
        },
      );
      pending.add(cleanup);
      void cleanup.then(
        () => pending.delete(cleanup),
        () => pending.delete(cleanup),
      );
      const interrupted = Promise.withResolvers<never>();
      const interruption = Symbol();
      const onAbort = (): void => interrupted.reject(interruption);
      dialSignal.addEventListener("abort", onAbort, { once: true });
      if (dialSignal.aborted) onAbort();
      try {
        return await Promise.race([acquiring, interrupted.promise]);
      } catch (error) {
        if (error === interruption) {
          await settleHostCleanup(cleanup);
          throw abortError();
        }
        throw error;
      } finally {
        dialSignal.removeEventListener("abort", onAbort);
      }
    },
    close,
  };
}

function throwCleanupFailures(results: PromiseSettledResult<unknown>[]): void {
  const errors = [
    ...new Set(
      results.flatMap((result) => (result.status === "rejected" ? [result.reason as unknown] : [])),
    ),
  ];
  if (errors.length === 1) throw errors[0];
  if (errors.length > 1) throw new AggregateError(errors, "connector host socket cleanup failed");
}
