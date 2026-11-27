import { expect, it, vi } from "vitest";
import { runArrivals, type ArrivalEvent } from "./arrivals.ts";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

it("continues the offered schedule after failures and counts every slot", async () => {
  vi.useFakeTimers();
  try {
    const rows: ArrivalEvent[] = [];
    const task = runArrivals({
      rate: 10,
      durationMs: 1_000,
      concurrency: 2,
      signal: new AbortController().signal,
      issue: async (slot) => {
        if (slot === 0) throw new Error("failed request");
        return { ok: true, reason: "verified" };
      },
      record: (row) => rows.push(row),
      clock: Date.now,
      sleep,
    });
    await vi.runAllTimersAsync();
    expect(await task).toMatchObject({ scheduled: 10, issued: 10, successful: 9, failed: 1 });
    expect(rows).toHaveLength(10);
  } finally {
    vi.useRealTimers();
  }
});

it("counts capacity skips without reducing arrivals or replaying busy slots", async () => {
  vi.useFakeTimers();
  try {
    const task = runArrivals({
      rate: 10,
      durationMs: 1_000,
      concurrency: 1,
      signal: new AbortController().signal,
      issue: () =>
        new Promise((resolve) => setTimeout(() => resolve({ ok: true, reason: "verified" }), 250)),
      record: () => {},
      clock: Date.now,
      sleep,
    });
    await vi.runAllTimersAsync();
    expect(await task).toMatchObject({
      scheduled: 10,
      issued: 4,
      successful: 4,
      skipped: { capacity: 6 },
      successFraction: 0.4,
      peakInFlight: 1,
    });
  } finally {
    vi.useRealTimers();
  }
});

it("accounts for canceled future arrivals and joins in-flight work", async () => {
  vi.useFakeTimers();
  try {
    const abort = new AbortController();
    const task = runArrivals({
      rate: 10,
      durationMs: 1_000,
      concurrency: 2,
      signal: abort.signal,
      issue: () =>
        new Promise((resolve) =>
          setTimeout(() => resolve({ ok: false, reason: "interrupted" }), 500),
        ),
      record: () => {},
      clock: Date.now,
      sleep,
    });
    setTimeout(() => abort.abort(), 150);
    await vi.runAllTimersAsync();
    expect(await task).toMatchObject({
      scheduled: 10,
      issued: 2,
      failed: 2,
      skipped: { canceled: 8 },
    });
  } finally {
    vi.useRealTimers();
  }
});

it("drops late slots rather than issuing a catch-up burst", async () => {
  let now = 0;
  const issued: number[] = [];
  const result = await runArrivals({
    rate: 10,
    durationMs: 500,
    concurrency: 10,
    signal: new AbortController().signal,
    issue: async (slot) => {
      issued.push(slot);
      return { ok: true, reason: "verified" };
    },
    record: () => {},
    clock: () => now,
    sleep: async (ms) => {
      now += ms + 210;
    },
  });
  expect(issued).toEqual([0, 3]);
  expect(result).toMatchObject({ scheduled: 5, issued: 2, skipped: { late: 3 } });
});

it("joins owned work even if the recorder fails", async () => {
  let finished = false;
  await expect(
    runArrivals({
      rate: 1,
      durationMs: 1,
      concurrency: 1,
      signal: new AbortController().signal,
      issue: async () => {
        finished = true;
        return { ok: true, reason: "verified" };
      },
      record: () => {
        throw new Error("disk full");
      },
    }),
  ).rejects.toThrow("arrival recording failed");
  expect(finished).toBe(true);
});
