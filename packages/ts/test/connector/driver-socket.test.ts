import { once } from "node:events";
import { describe, expect, test, vi } from "vitest";
import { DriverSocket } from "../../src/internal/connector/driver_socket.js";

describe("driver stream", () => {
  test("can receive a response after sending EOF", async () => {
    const close = vi.fn(async () => {});
    const chunks: number[][] = [];
    const socket = new DriverSocket(async () => ({
      readable: new ReadableStream({
        start(controller) {
          send = () => {
            controller.enqueue(new Uint8Array([3, 4]));
            controller.close();
          };
        },
      }),
      writable: new WritableStream({
        write(bytes) {
          chunks.push([...bytes]);
        },
        close() {
          send();
        },
      }),
      close,
    }));
    let send!: () => void;
    socket.connect();
    const joined = once(socket, "close");
    socket.end(new Uint8Array([1, 2]));
    const response: number[] = [];
    for await (const bytes of socket) response.push(...(bytes as Uint8Array));
    await joined;
    expect(chunks).toEqual([[1, 2]]);
    expect(response).toEqual([3, 4]);
    expect(close).toHaveBeenCalledTimes(1);
  });

  test("destroy interrupts and joins an unfinished open", async () => {
    let entered!: () => void;
    const opening = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const stopped = vi.fn();
    const socket = new DriverSocket(
      ({ signal } = {}) =>
        new Promise((_, reject) => {
          if (signal === undefined) throw new Error("missing signal");
          signal.addEventListener("abort", () => {
            stopped();
            reject(signal.reason);
          });
          entered();
        }),
    ).connect();
    await opening;
    // observe both error and close; once(close) rejects on an intervening error.
    const ended = new Promise<void>((resolve) => socket.once("close", resolve));
    socket.on("error", () => {});
    socket.destroy();
    await ended;
    expect(stopped).toHaveBeenCalledTimes(1);
  });
});
