import { once } from "node:events";
import { createServer, type AddressInfo } from "node:net";
import { test, expect } from "vitest";
import { TnlError } from "../../src/errors.js";
import { nativeStreams } from "../../src/internal/connector/native_stream.js";

test("native open joins sockets and allows a reply after write EOF", async () => {
  const listener = createServer({ allowHalfOpen: true }, (socket) => {
    socket.on("data", () => {});
    socket.on("end", () => socket.end("reply"));
  });
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const owner = nativeStreams();
  const open = owner.open(async () => ({
    protocol: "tcp",
    host: "127.0.0.1",
    port: (listener.address() as AddressInfo).port,
    expires: Date.now() + 10_000,
    transportID: "fixture",
  }));
  const reason = new TnlError("sdk.client_closed");
  try {
    const stream = await open();
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();
    await writer.write(new TextEncoder().encode("request"));
    await writer.close();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe("reply");
    expect((await reader.read()).done).toBe(true);
    const waiting = await open();
    const pending = waiting.readable.getReader().read();
    const failure = expect(pending).rejects.toMatchObject({ code: "sdk.connection_unavailable" });
    await owner.close(reason);
    await failure;
    await expect(open()).rejects.toBe(reason);
  } finally {
    await owner.close(reason);
    listener.close();
    await once(listener, "close");
  }
});
