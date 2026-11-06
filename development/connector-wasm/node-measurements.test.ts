import { describe, expect, it } from "vitest";
import { memorySnapshot, nodeWarmInstrumentation } from "./node-measurements.ts";

describe("caller-process measurements (not native daemon resource comparisons)", () => {
  it("captures a process memory snapshot without implying forced GC", () => {
    const memory = memorySnapshot();
    expect(memory.rss).toBeGreaterThan(0);
    expect(memory.heapUsed).toBeGreaterThan(0);
    expect(memory.heapTotal).toBeGreaterThanOrEqual(memory.heapUsed);
  });

  it("measures only the warm interval and reports undersampled event-loop delay honestly", () => {
    const stop = nodeWarmInstrumentation(false)();
    const measured = stop();
    expect(measured.scope).toBe("caller-process-only; native Go daemon excluded");
    expect(measured.wallMs).toBeGreaterThanOrEqual(0);
    expect(measured.cpuMicros).toMatchObject({
      user: expect.any(Number),
      system: expect.any(Number),
    });
    expect(measured.eventLoopDelayMs).toBe("insufficient-samples");
  });

  it("does not pretend Bun implements the Node event-loop delay histogram", () => {
    const measured = nodeWarmInstrumentation(true)()();
    expect(measured.eventLoopDelayMs).toBe("unsupported-bun");
  });
});
