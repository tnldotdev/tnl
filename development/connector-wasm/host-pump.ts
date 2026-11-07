import { MAX_CHUNK_BYTES } from "./abi.ts";
import type { ApplicationPump, ByteStream, HostPumpReceiver } from "./abi.ts";
import { closedError } from "./host.ts";
import type { SocketHost } from "./host.ts";

// this decorates the existing owner, including the object in createSocketHost's
// socket set. acquisition, abort, failed-close retention, and raw I/O joins stay
// with that owner; the extra close work only fences and joins these two workers.
export function createPumpHost(host: SocketHost): SocketHost {
  return {
    async dialTCP(address, signal) {
      const socket = await host.dialTCP(address, signal);
      const read = socket.read.bind(socket);
      const write = socket.write.bind(socket);
      const close = socket.close.bind(socket);
      let pump: HostSocketPump | undefined;
      let stopped = false;
      socket.startPump = (receive) => {
        if (stopped) throw closedError();
        if (pump) throw new Error("connector host pump already started");
        pump = new HostSocketPump({ read, write, close }, receive);
        return pump.control;
      };
      socket.read = async (max) => {
        if (pump) throw new Error("connector host pump owns reads");
        return read(max);
      };
      socket.write = async (bytes) => {
        if (pump) throw new Error("connector host pump owns writes");
        await write(bytes);
      };
      socket.close = async () => {
        stopped = true;
        pump?.stop();
        await Promise.all([close(), pump?.joined]);
      };
      return socket;
    },
    close: () => host.close(),
  };
}

class HostSocketPump {
  private stopped = false;
  private failed = false;
  private readCredit = MAX_CHUNK_BYTES;
  private writeBytes = 0;
  private queue: Uint8Array[] = [];
  private readWake = Promise.withResolvers<void>();
  private writeWake = Promise.withResolvers<void>();
  private readonly socket: ByteStream;
  private readonly receive: HostPumpReceiver;
  readonly joined: Promise<void>;
  readonly control: ApplicationPump;

  constructor(socket: ByteStream, receive: HostPumpReceiver) {
    this.socket = socket;
    this.receive = receive;
    this.control = {
      // false means no bytes were accepted. credit includes the active write.
      write: (bytes) => {
        if (this.stopped || this.failed) throw closedError();
        if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > MAX_CHUNK_BYTES)
          throw new RangeError("connector host pump write violated byte bounds");
        if (this.writeBytes + bytes.length > MAX_CHUNK_BYTES) return false;
        this.writeBytes += bytes.length;
        this.queue.push(bytes);
        this.writeWake.resolve();
        return true;
      },
      // go returns the entire read window only after consuming all delivered
      // bytes. a pending raw read is still bounded by this same window.
      resume: () => {
        if (this.stopped || this.failed) return;
        this.readCredit = MAX_CHUNK_BYTES;
        this.readWake.resolve();
      },
    };
    this.joined = Promise.all([this.readLoop(), this.writeLoop()]).then(() => {});
  }

  stop(): void {
    if (this.stopped) return;
    this.stopped = true;
    this.queue = [];
    this.readWake.resolve();
    this.writeWake.resolve();
    // host-wide abort can close this socket before go calls Conn.Close. wake
    // its blocked I/O once; a go-initiated close has already fenced its id.
    if (!this.failed) {
      this.failed = true;
      this.receive(4, closedError());
    }
  }

  private fail(reason: unknown): void {
    if (this.stopped || this.failed) return;
    this.failed = true;
    this.queue = [];
    this.readWake.resolve();
    this.writeWake.resolve();
    // existing typed network/cleanup errors cross unchanged. arbitrary host
    // failures stay terminal and never carry their original message into go.
    this.receive(4, reason instanceof Error ? reason : new Error("connector host pump failed"));
  }

  private async readLoop(): Promise<void> {
    try {
      while (!this.stopped && !this.failed) {
        if (this.readCredit === 0) {
          await this.readWake.promise;
          this.readWake = Promise.withResolvers<void>();
          continue;
        }
        const max = this.readCredit;
        const bytes = await this.socket.read(max);
        if (this.stopped || this.failed) return;
        if (bytes === null) {
          this.receive(3, null);
          return;
        }
        if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > max)
          throw new Error("connector host pump read violated byte bounds");
        this.readCredit -= bytes.length;
        this.receive(1, bytes);
      }
    } catch (error) {
      this.fail(error);
    }
  }

  private async writeLoop(): Promise<void> {
    try {
      while (!this.stopped && !this.failed) {
        if (this.queue.length === 0) {
          await this.writeWake.promise;
          this.writeWake = Promise.withResolvers<void>();
          continue;
        }
        // combine only bytes already ready. there is no batching timer or wait
        // for another write, and one underlying write is active at a time.
        const queued = this.queue;
        this.queue = [];
        const size = queued.reduce((sum, bytes) => sum + bytes.length, 0);
        const first = queued[0];
        if (!first) throw new Error("connector host pump lost a queued write");
        const bytes = queued.length === 1 ? first : new Uint8Array(size);
        if (queued.length > 1) {
          let offset = 0;
          for (const chunk of queued) {
            bytes.set(chunk, offset);
            offset += chunk.length;
          }
        }
        await this.socket.write(bytes);
        if (this.stopped || this.failed) return;
        this.writeBytes -= size;
        this.receive(2, size);
      }
    } catch (error) {
      this.fail(error);
    }
  }
}
