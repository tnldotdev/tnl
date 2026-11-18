// conformance probe, not a connector SDK. it exercises the portable WebSocket
// surface and a bounded subset of yamux against the native transport fixture.
export function relayWebSocketProbe(
  socket: WebSocket,
  hello: Uint8Array,
  signal: AbortSignal,
): Promise<void> {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const payloads = new Map([
    [3, "portable-a"],
    [5, "portable-b"],
  ]);
  const received = new Map<number, Uint8Array>();
  const finished = new Set<number>();
  let pending = new Uint8Array(0);
  let authenticated = false;
  let echoedServerStream = false;
  let serverStream = false;
  const frame = (
    type: number,
    flags: number,
    id: number,
    payload: Uint8Array = new Uint8Array(0),
  ) => {
    const bytes = new Uint8Array(12 + (type === 0 ? payload.length : 0));
    const view = new DataView(bytes.buffer);
    view.setUint8(1, type);
    view.setUint16(2, flags);
    view.setUint32(4, id);
    view.setUint32(8, type === 0 ? payload.length : 0);
    if (type === 0) bytes.set(payload, 12);
    return bytes;
  };
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const settle = (error?: Error) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", abort);
      socket.close();
      if (error) reject(error);
      else resolve();
    };
    const abort = () => settle(new Error("relay probe deadline exceeded"));
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) {
      abort();
      return;
    }
    socket.binaryType = "arraybuffer";
    socket.onopen = () => {
      if (socket.protocol !== "tnl-yamux-v1") {
        settle(new Error("relay subprotocol mismatch"));
        return;
      }
      // split a yamux frame across messages; coalesce two unrelated streams.
      const control = frame(0, 1, 1, hello);
      socket.send(control.slice(0, 7));
      socket.send(control.slice(7));
      // match yamux's writer: enqueue bytes before the separate half-close.
      // a FIN on the data frame can wake the reader before its data is buffered.
      const a = frame(0, 1, 3, encoder.encode("portable-a"));
      const aFin = frame(1, 4, 3);
      const b = frame(0, 1, 5, encoder.encode("portable-b"));
      const bFin = frame(1, 4, 5);
      const both = new Uint8Array(a.length + aFin.length + b.length + bFin.length);
      let offset = 0;
      for (const part of [a, aFin, b, bFin]) {
        both.set(part, offset);
        offset += part.length;
      }
      socket.send(both);
    };
    socket.onerror = () => settle(new Error("relay probe websocket failed"));
    socket.onclose = () => settle(new Error("relay probe ended before completion"));
    socket.onmessage = (event: MessageEvent<unknown>) => {
      if (settled) return;
      if (!(event.data instanceof ArrayBuffer) || event.data.byteLength > 65536) {
        settle(new Error("invalid relay binary message"));
        return;
      }
      const joined = new Uint8Array(pending.length + event.data.byteLength);
      joined.set(pending);
      joined.set(new Uint8Array(event.data), pending.length);
      pending = joined;
      if (pending.length > 1 << 20) {
        settle(new Error("relay probe receive bound exceeded"));
        return;
      }
      while (pending.length >= 12) {
        const view = new DataView(pending.buffer, pending.byteOffset, pending.byteLength);
        const type = view.getUint8(1),
          flags = view.getUint16(2);
        const id = view.getUint32(4),
          size = view.getUint32(8);
        if (type <= 1 && ![1, 2, 3, 5].includes(id)) {
          settle(new Error("unexpected yamux stream"));
          return;
        }
        if (view.getUint8(0) !== 0 || type > 3 || (type === 0 && size > 1 << 20)) {
          settle(new Error("invalid yamux frame"));
          return;
        }
        const length = 12 + (type === 0 ? size : 0);
        if (pending.length < length) break;
        const data = pending.slice(12, length);
        pending = pending.slice(length);
        if (type === 3 || flags & 8) {
          settle(new Error("unexpected yamux retirement"));
          return;
        }
        if (type === 2 && flags & 1) {
          const response = frame(2, 2, id);
          new DataView(response.buffer).setUint32(8, size);
          socket.send(response);
          continue;
        }
        if (flags & 1) socket.send(frame(1, 2, id));
        if (type === 0) {
          const previous = received.get(id) ?? new Uint8Array(0);
          const next = new Uint8Array(previous.length + data.length);
          next.set(previous);
          next.set(data, previous.length);
          if (next.length > 65536) {
            settle(new Error("relay probe stream bound exceeded"));
            return;
          }
          if (id === 2 && !echoedServerStream && decoder.decode(next) === "server-open") {
            // wait for the server's FIN before closing Chrome: it acknowledges
            // that the echo reached the Go reader, not just the browser socket.
            socket.send(frame(0, 0, id, next));
            socket.send(frame(1, 4, id));
            echoedServerStream = true;
          }
          received.set(id, next);
          if (id === 1 && next.length >= 4) {
            const size = new DataView(next.buffer).getUint32(0);
            if (size > 65532) {
              settle(new Error("invalid hello bound"));
              return;
            }
            if (next.length >= size + 4) {
              let reply: unknown;
              try {
                reply = JSON.parse(decoder.decode(next.slice(4, 4 + size)));
              } catch {
                settle(new Error("invalid relay hello"));
                return;
              }
              if (
                typeof reply !== "object" ||
                reply === null ||
                !("type" in reply) ||
                reply.type !== "hello_accepted"
              ) {
                settle(new Error("relay authentication rejected"));
                return;
              }
              authenticated = true;
            }
          }
        }
        if (flags & 4) {
          const value = decoder.decode(received.get(id));
          if (id === 2) {
            if (!echoedServerStream || value !== "server-open") {
              settle(new Error("server stream mismatch"));
              return;
            }
            serverStream = true;
          } else if (payloads.has(id)) {
            if (value !== payloads.get(id)) {
              settle(new Error("stream echo mismatch"));
              return;
            }
            finished.add(id);
          }
        }
        if (authenticated && serverStream && finished.size === 2) {
          settle();
          return;
        }
      }
    };
  });
}
