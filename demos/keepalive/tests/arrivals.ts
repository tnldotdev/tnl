import { setTimeout as delay } from "node:timers/promises";
import { distribution } from "./measure.ts";

export type ArrivalResult = { ok: boolean; reason: string };
export type ArrivalEvent =
  | { slot: number; outcome: "skipped"; reason: "late" | "capacity" | "canceled"; lateMs: number }
  | { slot: number; outcome: "completed"; result: ArrivalResult; ms: number; lateMs: number };

// independent start slots avoid coordinated omission: slow work occupies
// capacity, but cannot move subsequent arrivals or replay missed slots.
export async function runArrivals({
  rate,
  durationMs,
  concurrency,
  signal,
  issue,
  record,
  clock = () => performance.now(),
  sleep = (ms, lifetime) => delay(ms, undefined, { signal: lifetime }),
}: {
  rate: number;
  durationMs: number;
  concurrency: number;
  signal: AbortSignal;
  issue: (slot: number, signal: AbortSignal) => Promise<ArrivalResult>;
  record: (event: ArrivalEvent) => void;
  clock?: () => number;
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
}) {
  if (
    !Number.isFinite(rate) ||
    rate <= 0 ||
    rate > 10_000 ||
    !Number.isSafeInteger(durationMs) ||
    durationMs < 1 ||
    durationMs > 3_600_000 ||
    (rate * durationMs) / 1_000 > 1_000_000 ||
    !Number.isSafeInteger(concurrency) ||
    concurrency < 1 ||
    concurrency > 8_192
  )
    throw new Error("invalid arrival settings");
  const scheduled = Math.ceil((rate * durationMs) / 1_000);
  const began = clock();
  const interval = 1_000 / rate;
  const pending = new Set<Promise<void>>();
  const errors: unknown[] = [];
  const latencies: number[] = [];
  const skipped = { late: 0, capacity: 0, canceled: 0 };
  let issued = 0;
  let successful = 0;
  let failed = 0;
  let peakInFlight = 0;
  let maximumLateMs = 0;
  function emit(event: ArrivalEvent) {
    try {
      record(event);
    } catch (error) {
      errors.push(error);
    }
  }
  try {
    for (let slot = 0; slot < scheduled; slot++) {
      const due = began + slot * interval;
      const wait = due - clock();
      if (wait > 0 && !signal.aborted) {
        try {
          await sleep(wait, signal);
        } catch (error) {
          if (!signal.aborted) throw error;
        }
      }
      const lateMs = Math.max(0, clock() - due);
      maximumLateMs = Math.max(maximumLateMs, lateMs);
      const reason = signal.aborted
        ? "canceled"
        : lateMs >= interval
          ? "late"
          : pending.size >= concurrency
            ? "capacity"
            : undefined;
      if (reason) {
        skipped[reason]++;
        emit({ slot, outcome: "skipped", reason, lateMs });
        continue;
      }
      issued++;
      const started = clock();
      const task = Promise.resolve()
        .then(() => issue(slot, signal))
        .catch((error: unknown): ArrivalResult => ({
          ok: false,
          reason: error instanceof Error ? error.name : "unknown",
        }))
        .then((result) => {
          const ms = clock() - started;
          if (result.ok) {
            successful++;
            latencies.push(ms);
          } else failed++;
          emit({ slot, outcome: "completed", result, ms, lateMs });
        })
        .finally(() => pending.delete(task));
      pending.add(task);
      peakInFlight = Math.max(peakInFlight, pending.size);
    }
  } finally {
    await Promise.allSettled(pending);
  }
  if (errors.length) throw new AggregateError(errors, "arrival recording failed");
  return {
    scheduled,
    issued,
    successful,
    failed,
    skipped,
    peakInFlight,
    maximumLateMs,
    successfulLatencyMs: distribution(latencies),
    successFraction: successful / scheduled,
    elapsedMs: clock() - began,
  };
}
