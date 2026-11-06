import { monitorEventLoopDelay } from "node:perf_hooks";
import type { WarmInstrumentation, WarmRuntimeMetrics } from "./postgres.ts";

export function memorySnapshot(): NodeJS.MemoryUsage {
  return process.memoryUsage();
}

export function nodeWarmInstrumentation(bun = Boolean(process.versions.bun)): WarmInstrumentation {
  return () => {
    const started = performance.now();
    const cpu = process.cpuUsage();
    const delay = bun ? undefined : monitorEventLoopDelay({ resolution: 10 });
    delay?.enable();
    return (): WarmRuntimeMetrics => {
      const wallMs = performance.now() - started;
      const cpuMicros = process.cpuUsage(cpu);
      delay?.disable();
      return {
        scope: "caller-process-only; native Go daemon excluded",
        wallMs,
        cpuMicros,
        eventLoopDelayMs: bun
          ? "unsupported-bun"
          : !delay || delay.count === 0
            ? "insufficient-samples"
            : { mean: delay.mean / 1e6, p99: delay.percentile(99) / 1e6, max: delay.max / 1e6 },
      };
    };
  };
}
