import { expect, it, vi } from "vitest";
import { AdmissionCoordinator } from "../src/edge/admission.ts";
import { HOST_TURN_MS, MAX_HOSTS, MAX_STARTING, STARTUP_MS, hostTarget } from "../src/policy.ts";

it("serializes startup reservations, reuses retries, and expires abandoned turns", async () => {
  vi.useFakeTimers();
  try {
    let saved: unknown;
    let pending = Promise.resolve();
    const storage = {
      get: async () => structuredClone(saved),
      put: async (_: string, value: unknown) => {
        saved = structuredClone(value);
      },
    };
    const coordinator = new AdmissionCoordinator({
      storage: {
        ...storage,
        transaction: <T>(work: (tx: typeof storage) => Promise<T>) => {
          const result = pending.then(() => work(storage));
          pending = result.then(() => {});
          return result;
        },
      },
    });
    const call = (requestID: string, state = "reserve") =>
      coordinator.fetch(
        new Request("https://admission.internal", {
          method: "POST",
          body: JSON.stringify({
            requestID,
            state,
            ...(state === "reserve" ? { bootstrap: false } : {}),
          }),
        }),
      );
    const first = crypto.randomUUID();
    expect((await call(first)).status).toBe(204);
    expect((await call(first)).status).toBe(204);
    const attempts = await Promise.all(
      Array.from({ length: MAX_STARTING }, () => call(crypto.randomUUID())),
    );
    expect(attempts.filter((reply) => reply.status === 429)).toHaveLength(1);
    expect((await call(first, "ready")).status).toBe(204);
    expect((await call(crypto.randomUUID())).status).toBe(204);
    vi.advanceTimersByTime(STARTUP_MS);
    expect((await call(crypto.randomUUID())).status).toBe(204);
    expect((await call(first, "ready")).status).toBe(204);
    vi.advanceTimersByTime(HOST_TURN_MS);
    expect((await call(first, "ready")).status).toBe(409);
    expect((await call(first, "stop")).status).toBe(204);
  } finally {
    vi.useRealTimers();
  }
});

it("can recruit a fixed thousand-host pool without fifty thousand visitors", () => {
  expect(hostTarget(0, 1_000)).toBe(1_000);
  expect(hostTarget(1_000_000)).toBe(1_000);
});

it("bounds a thousand-host fleet and replacement overlap below one storage value's byte limit", async () => {
  let saved: unknown;
  const storage = {
    get: async () => structuredClone(saved),
    put: async (_: string, value: unknown) => {
      saved = structuredClone(value);
    },
  };
  const state = {
    storage: {
      ...storage,
      transaction: <T>(work: (tx: typeof storage) => Promise<T>) => work(storage),
    },
  };
  const coordinator = new AdmissionCoordinator(state);
  const call = (requestID: string, ready = false) =>
    coordinator.fetch(
      new Request("https://admission.internal", {
        method: "POST",
        body: JSON.stringify(
          ready ? { requestID, state: "ready" } : { requestID, state: "reserve", bootstrap: false },
        ),
      }),
    );
  for (let i = 0; i < MAX_HOSTS + MAX_STARTING; i++) {
    const requestID = crypto.randomUUID();
    expect((await call(requestID)).status).toBe(204);
    expect((await call(requestID, true)).status).toBe(204);
  }
  expect((await call(crypto.randomUUID())).status).toBe(429);
  expect(new TextEncoder().encode(JSON.stringify(saved)).byteLength).toBeLessThan(128 * 1024);
  const restarted = new AdmissionCoordinator(state);
  expect(
    (
      await restarted.fetch(
        new Request("https://admission.internal", {
          method: "POST",
          body: JSON.stringify({
            requestID: crypto.randomUUID(),
            state: "reserve",
            bootstrap: false,
          }),
        }),
      )
    ).status,
  ).toBe(429);
});
