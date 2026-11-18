import { connect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { TnlError } from "../../errors.js";
import type { TnlOpenStream, TnlTLSStream } from "../../project.js";
import type { ConnectionSnapshot } from "./snapshot.js";
import { wasmStream } from "./wasm_stream.js";

const postgresSSLRequest = Uint8Array.of(0, 0, 0, 8, 4, 210, 22, 47);

function trackSocket(socket: Socket) {
  let failed = false;
  socket.on("error", () => {
    failed = true;
  });
  return {
    socket,
    failed: () => failed,
    done: new Promise<void>((resolve) => socket.once("close", () => resolve())),
  };
}

type Transport = ReturnType<typeof trackSocket>;
const unavailable = () => new TnlError("sdk.connection_unavailable");

function activity({ socket, failed }: Transport, event: "connect" | "secureConnect" | "readable") {
  if (socket.destroyed || failed()) return Promise.reject(unavailable());
  return new Promise<void>((resolve, reject) => {
    const cleanup = () => {
      socket.off(event, success).off("error", failure).off("close", failure).off("end", end);
    };
    const success = () => {
      cleanup();
      resolve();
    };
    const failure = () => {
      cleanup();
      reject(unavailable());
    };
    const end = event === "readable" ? success : failure;
    socket.once(event, success).once("error", failure).once("close", failure).once("end", end);
  });
}

async function read(transport: Transport, max: number): Promise<Uint8Array | null> {
  const { socket } = transport;
  for (;;) {
    if (transport.failed()) throw unavailable();
    const length = socket.readableLength;
    if (length > 0) {
      const bytes: unknown = socket.read(Math.min(max, length));
      if (bytes instanceof Uint8Array) return bytes;
    } else {
      // release an empty readable event and allow Node to report EOF.
      socket.read(0);
    }
    if (socket.readableEnded) return null;
    await activity(transport, "readable");
  }
}

function write(socket: Socket, bytes: Uint8Array) {
  return new Promise<void>((resolve, reject) =>
    socket.write(bytes, (error) => (error ? reject(unavailable()) : resolve())),
  );
}

async function closeWrite({ socket }: Transport): Promise<void> {
  if (!socket.writable || socket.destroyed) throw unavailable();
  await new Promise<void>((resolve, reject) => {
    const fail = () => reject(unavailable());
    socket.once("close", fail);
    socket.end(() => {
      socket.off("close", fail);
      if (socket.writableFinished) resolve();
      else fail();
    });
  });
}

function mysqlSSLRequest(bytes: Uint8Array) {
  // require one SSLRequest (sequence 1, CLIENT_PROTOCOL_41 and CLIENT_SSL)
  // before sending any login bytes through this socket.
  return (
    bytes.length === 36 &&
    bytes[0] === 32 &&
    bytes[1] === 0 &&
    bytes[2] === 0 &&
    bytes[3] === 1 &&
    ((bytes[5] ?? 0) & 0x0a) === 0x0a &&
    bytes.subarray(13).every((value) => value === 0)
  );
}

async function openSocket(snapshot: ConnectionSnapshot, signal: AbortSignal, release: () => void) {
  if (snapshot.expires <= Date.now()) throw unavailable();
  signal.throwIfAborted();
  const raw = trackSocket(
    connect({ host: snapshot.host, port: snapshot.port, allowHalfOpen: true }),
  );
  let active = raw;
  let secured = false;
  let mysqlRequest = new Uint8Array();
  const stop = () => {
    active.socket.destroy();
    raw.socket.destroy();
  };
  const close = async () => {
    stop();
    await Promise.all([active.done, raw.done]);
  };
  const startTls = async () => {
    if (
      snapshot.protocol === "tcp" ||
      secured ||
      (snapshot.protocol === "mysql" && mysqlRequest.length !== 36)
    )
      throw new TnlError("sdk.configuration_invalid");
    const timer = setTimeout(stop, 10_000);
    try {
      if (snapshot.protocol === "postgres") {
        await write(raw.socket, postgresSSLRequest);
        const reply = await read(raw, 1);
        if (reply?.[0] !== 83) throw unavailable();
      }
      const options = {
        socket: raw.socket,
        ...snapshot.ssl,
        allowHalfOpen: true,
        minVersion: "TLSv1.2" as const,
        ...(snapshot.protocol === "http" || snapshot.protocol === "kubernetes"
          ? { ALPNProtocols: ["http/1.1"] }
          : {}),
      };
      active = trackSocket(tlsConnect(options));
      await activity(active, "secureConnect");
      secured = true;
      mysqlRequest = new Uint8Array();
    } finally {
      clearTimeout(timer);
    }
  };
  signal.addEventListener("abort", stop, { once: true });
  try {
    const timer = setTimeout(stop, 10_000);
    try {
      await activity(raw, "connect");
    } finally {
      clearTimeout(timer);
    }
    const stream = wasmStream(
      {
        read: (max) => read(active, max),
        async write(bytes) {
          if (snapshot.protocol === "mysql" && !secured) {
            const length = mysqlRequest.length + bytes.length;
            if (length > 36) throw new TnlError("sdk.configuration_invalid");
            const request = new Uint8Array(length);
            request.set(mysqlRequest);
            request.set(bytes, mysqlRequest.length);
            if (length === 36 && !mysqlSSLRequest(request))
              throw new TnlError("sdk.configuration_invalid");
            mysqlRequest = request;
            if (length < 36) return;
            await write(active.socket, request);
            return;
          }
          await write(active.socket, bytes);
        },
        async closeWrite() {
          if (snapshot.protocol === "mysql" && !secured)
            throw new TnlError("sdk.configuration_invalid");
          await closeWrite(active);
        },
        close,
        startTls,
      },
      signal,
      release,
    );
    if (snapshot.protocol !== "tcp" && snapshot.protocol !== "mysql") await stream.startTls();
    signal.throwIfAborted();
    return stream;
  } catch (error) {
    await close();
    if (signal.aborted) throw signal.reason;
    throw error;
  } finally {
    signal.removeEventListener("abort", stop);
  }
}

export function nativeStreams() {
  const lifetime = new AbortController();
  const streams = new Set<TnlTLSStream>();
  const opening = new Set<Promise<TnlTLSStream>>();
  return {
    open(
      select: (signal: AbortSignal) => Promise<ConnectionSnapshot>,
    ): TnlOpenStream<TnlTLSStream> {
      return ({ signal } = {}) => {
        if (lifetime.signal.aborted) return Promise.reject(lifetime.signal.reason);
        if (opening.size + streams.size >= 64)
          return Promise.reject(new TnlError("sdk.client_capacity"));
        const selected = signal ? AbortSignal.any([signal, lifetime.signal]) : lifetime.signal;
        const pending = (async () => {
          selected.throwIfAborted();
          const snapshot = await select(selected);
          const stream = await openSocket(snapshot, selected, () => streams.delete(stream));
          streams.add(stream);
          if (selected.aborted) {
            await stream.close();
            throw selected.reason;
          }
          return stream;
        })();
        opening.add(pending);
        void pending.then(
          () => opening.delete(pending),
          () => opening.delete(pending),
        );
        return pending;
      };
    },
    async close(reason: TnlError) {
      lifetime.abort(reason);
      await Promise.allSettled(opening);
      await Promise.all([...streams].map((stream) => stream.close()));
    },
  };
}
