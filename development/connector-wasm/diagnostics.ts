import * as z from "zod";
import type { ConnectorBridge } from "./abi.ts";

const counts = z.record(z.string(), z.number().int().nonnegative());
export const diagnosticSnapshot = z.object({
  counters: counts,
  memory: counts,
  ciphers: z.record(z.string(), z.string()),
});
export type DiagnosticSnapshot = z.infer<typeof diagnosticSnapshot>;

export interface WarmDiagnostics {
  scope: "wasm-instance-only";
  counters: Record<string, number>;
  memory: Record<string, number>;
  ciphers: Record<string, string>;
  cpuProfile?: {
    file: string;
    scope: "query-call-and-profiler-control-not-exact-loop-decomposition";
    sampledMs: number;
    categoriesMs: Record<string, number>;
    top: Array<{ function: string; selfMs: number }>;
  };
}

export function difference(before: DiagnosticSnapshot, after: DiagnosticSnapshot): WarmDiagnostics {
  const subtract = (left: Record<string, number>, right: Record<string, number>) =>
    Object.fromEntries(
      Object.entries(right).map(([name, value]) => [name, value - (left[name] ?? 0)]),
    );
  return {
    scope: "wasm-instance-only",
    counters: subtract(before.counters, after.counters),
    memory: subtract(before.memory, after.memory),
    ciphers: after.ciphers,
  };
}

export async function observeBridge<T extends object>(
  bridge: ConnectorBridge,
  sample: () => Promise<T>,
): Promise<T & { diagnostics: WarmDiagnostics }> {
  if (!bridge.diagnostics) throw new Error("WASM bridge diagnostics unavailable");
  const before = diagnosticSnapshot.parse(bridge.diagnostics());
  const measured = await sample();
  const after = diagnosticSnapshot.parse(bridge.diagnostics());
  return { ...measured, diagnostics: difference(before, after) };
}
