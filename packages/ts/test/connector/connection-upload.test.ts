import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { expect, test, vi } from "vitest";
import { managedFetch } from "../../src/internal/connector/connection.js";
import { TnlCleanupError } from "../../src/errors.js";

async function listener(
  respond: (request: IncomingMessage, response: ServerResponse) => void,
  parent?: () => number | undefined,
) {
  const server = createServer(respond);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing listener");
  const origin = `http://127.0.0.1:${address.port}` as const;
  const fetch = managedFetch(
    origin,
    async () => ({
      protocol: "http",
      host: "127.0.0.1",
      port: address.port,
      ssl: false,
      url: origin,
      expires: Number.MAX_SAFE_INTEGER,
      transportID: "a".repeat(64),
    }),
    parent,
  );
  return {
    fetch,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

test("upload read errors retain their identity and release the owned reader", async () => {
  const received = Promise.withResolvers<void>();
  const server = await listener((request) => {
    request.once("data", () => received.resolve());
  });
  const producer = Promise.withResolvers<ReadableStreamDefaultController<Uint8Array>>();
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("first"));
      producer.resolve(controller);
    },
    cancel,
  });
  try {
    const failure = new Error("upload producer failed");
    const pending = server.fetch("/", { method: "POST", body });
    const rejected = expect(pending).rejects.toBe(failure);
    await received.promise;
    (await producer.promise).error(failure);
    await rejected;
    expect(body.locked).toBe(false);
    expect(cancel).not.toHaveBeenCalled();
    await server.fetch.close();
  } finally {
    await server.close();
  }
});

test("caller abort preserves an independent upload cancellation failure", async () => {
  const received = Promise.withResolvers<void>();
  const server = await listener((request) => {
    request.once("data", () => received.resolve());
  });
  const reason = new Error("caller canceled");
  const cleanup = new Error("producer cleanup failed");
  const controller = new AbortController();
  const cancel = vi.fn(() => Promise.reject(cleanup));
  const body = new ReadableStream<Uint8Array>({
    start(stream) {
      stream.enqueue(new TextEncoder().encode("first"));
    },
    cancel,
  });
  try {
    const pending = server.fetch("/", { method: "POST", body, signal: controller.signal });
    const rejected = expect(pending).rejects.toMatchObject({
      code: "sdk.cleanup_failed",
      cause: reason,
      errors: [reason, cleanup],
    });
    await received.promise;
    controller.abort(reason);
    await rejected;
    expect(cancel).toHaveBeenCalledExactlyOnceWith(reason);
    expect(body.locked).toBe(false);
    await server.fetch.close();
  } finally {
    controller.abort(reason);
    await server.close();
  }
});

test("transport close joins an upload that outlives response headers and preserves cleanup failure", async () => {
  const received = Promise.withResolvers<void>();
  const server = await listener((request, response) => {
    request.once("data", () => {
      received.resolve();
      response.writeHead(200).flushHeaders();
    });
  });
  const cancelStarted = Promise.withResolvers<void>();
  const finishCancel = Promise.withResolvers<void>();
  const failure = new Error("producer cleanup failed");
  const cancel = vi.fn(async () => {
    cancelStarted.resolve();
    await finishCancel.promise;
    throw failure;
  });
  const body = new ReadableStream<Uint8Array>({
    start(stream) {
      stream.enqueue(new TextEncoder().encode("first"));
    },
    cancel,
  });
  try {
    const response = await server.fetch("/", { method: "POST", body });
    await received.promise;
    expect(body.locked).toBe(true);
    let closed = false;
    const closing = server.fetch.close().finally(() => {
      closed = true;
    });
    const rejected = expect(closing).rejects.toMatchObject({ errors: [failure] });
    await cancelStarted.promise;
    expect(closed).toBe(false);
    finishCancel.resolve();
    await rejected;
    expect(cancel).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
    await response.body?.cancel().catch(() => {});
  } finally {
    finishCancel.resolve();
    await server.close();
  }
});

test("preparation failure joins upload cancellation without losing either error", async () => {
  const failure = new Error("preparation failed");
  const cleanup = new Error("producer cleanup failed");
  const cancel = vi.fn(() => Promise.reject(cleanup));
  const body = new ReadableStream<Uint8Array>({ cancel });
  const fetch = managedFetch("https://api.tnl.invalid", async () => {
    throw failure;
  });
  const outcome = await fetch("/", { method: "POST", body }).catch((error: unknown) => error);
  expect(outcome).toBeInstanceOf(TnlCleanupError);
  expect(outcome).toMatchObject({ cause: failure, errors: [failure, cleanup] });
  expect(cancel).toHaveBeenCalledExactlyOnceWith(failure);
  expect(body.locked).toBe(false);
  await fetch.close();
});

test.each([0, 1_000])(
  "upload shutdown reports an uncooperative cancellation with %i ms already spent",
  async (spent) => {
    vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
    const received = Promise.withResolvers<void>();
    const disconnected = Promise.withResolvers<void>();
    const cancelStarted = Promise.withResolvers<void>();
    const finishCancel = Promise.withResolvers<void>();
    let shutdownUntil: number | undefined;
    const server = await listener(
      (request, response) => {
        request.socket.once("close", () => disconnected.resolve());
        request.once("data", () => {
          received.resolve();
          response.writeHead(200).flushHeaders();
        });
      },
      () => shutdownUntil,
    );
    const cancel = vi.fn(async () => {
      cancelStarted.resolve();
      await finishCancel.promise;
    });
    const body = new ReadableStream<Uint8Array>({
      start(stream) {
        stream.enqueue(new TextEncoder().encode("first"));
      },
      cancel,
    });
    let closing: Promise<unknown> | undefined;
    try {
      const response = await server.fetch("/", { method: "POST", body });
      await received.promise;
      shutdownUntil = Date.now() + 10_000;
      await vi.advanceTimersByTimeAsync(spent);
      let settled = false;
      closing = server.fetch.close().then(
        () => {
          settled = true;
          return undefined;
        },
        (cause: unknown) => {
          settled = true;
          return cause;
        },
      );
      await cancelStarted.promise;
      await disconnected.promise;
      await vi.advanceTimersByTimeAsync(9_999 - spent);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      expect(settled).toBe(true);
      expect(await closing).toMatchObject({
        errors: [expect.objectContaining({ name: "TimeoutError" })],
      });
      expect(body.locked).toBe(false);
      expect(cancel).toHaveBeenCalledOnce();
      await expect(server.fetch.close()).rejects.toMatchObject({
        errors: [expect.objectContaining({ name: "TimeoutError" })],
      });
      const stopped = await response.body?.cancel().catch((cause: unknown) => cause);
      expect(stopped === undefined || stopped instanceof Error).toBe(true);
    } finally {
      finishCancel.resolve();
      await closing;
      await server.close();
      vi.useRealTimers();
    }
  },
);

test("shutdown bounds preparation upload cleanup without losing its independent operation failure", async () => {
  vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
  const entered = Promise.withResolvers<void>();
  const finishCancel = Promise.withResolvers<void>();
  const operation = new Error("preparation failed");
  const fetch = managedFetch("https://api.tnl.invalid", async () => {
    throw operation;
  });
  const body = new ReadableStream<Uint8Array>({
    cancel: async () => {
      entered.resolve();
      await finishCancel.promise;
    },
  });
  const request = fetch("/", { method: "POST", body }).catch((cause: unknown) => cause);
  let closing: Promise<unknown> | undefined;
  try {
    await entered.promise;
    let settled = false;
    closing = fetch.close().then(
      () => {
        settled = true;
        return undefined;
      },
      (cause: unknown) => {
        settled = true;
        return cause;
      },
    );
    await vi.advanceTimersByTimeAsync(9_999);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(settled).toBe(true);
    expect(await closing).toMatchObject({
      errors: [expect.objectContaining({ name: "TimeoutError" })],
    });
    expect(await request).toMatchObject({
      errors: [operation, expect.objectContaining({ name: "TimeoutError" })],
    });
    expect(body.locked).toBe(false);
  } finally {
    finishCancel.resolve();
    await Promise.all([request, closing]);
    vi.useRealTimers();
  }
});
