import { describe, expect, it, vi } from "vitest";
import { diagnosticSnapshot, difference } from "./diagnostics.ts";
import { observeQueries, summarizeProfile } from "./node-profile.ts";
import { observeBridge } from "./diagnostics.ts";
import { parseVariant, tuning } from "./variant.ts";

describe("experimental profile metadata", () => {
  it("measures deltas without resetting live counters or hiding heap decreases", () => {
    const before = diagnosticSnapshot.parse({
      counters: { calls: 2 },
      memory: { totalAlloc: 10, heapAlloc: 20 },
      ciphers: {},
    });
    const after = diagnosticSnapshot.parse({
      counters: { calls: 5 },
      memory: { totalAlloc: 30, heapAlloc: 15 },
      ciphers: { visitor: "TLS_CHACHA20_POLY1305_SHA256" },
    });
    expect(difference(before, after)).toEqual({
      scope: "wasm-instance-only",
      counters: { calls: 3 },
      memory: { totalAlloc: 20, heapAlloc: -5 },
      ciphers: after.ciphers,
    });
    expect(before.counters.calls).toBe(2);
    expect(() => diagnosticSnapshot.parse({ counters: { calls: "private input" } })).toThrow();
  });

  it("does not label idle WASM diagnostics as native connector measurements", async () => {
    const diagnostics = vi.fn(() => {
      throw new Error("must not inspect WASM for native");
    });
    const bridge = { prepare: vi.fn(), diagnostics };
    const measured = {
      backendPid: 1,
      queries: 1,
      elapsedMs: 1,
      queriesPerSecond: 1000,
      latencyMs: { min: 1, p50: 1, p95: 1, p99: 1, max: 1 },
    };
    expect(await observeQueries(bridge)("native", async () => measured)).toBe(measured);
    expect(diagnostics).not.toHaveBeenCalled();
    await expect(observeBridge({ prepare: vi.fn() }, async () => measured)).rejects.toThrow(
      "diagnostics unavailable",
    );
  });

  it("keeps buffer and async experiments independent", () => {
    expect(parseVariant(undefined)).toBe("baseline");
    expect(() => parseVariant("unknown")).toThrow();
    expect(tuning("buffers")).toEqual({ reuseBuffers: true, compactPromises: false });
    expect(tuning("promises")).toEqual({ reuseBuffers: false, compactPromises: true });
    expect(tuning("optimized")).toEqual({ reuseBuffers: true, compactPromises: true });
  });

  it("retains sampled self time separately from heuristic stack categories", () => {
    const frame = (functionName: string) => ({
      functionName,
      scriptId: "1",
      url: "",
      lineNumber: 0,
      columnNumber: 0,
    });
    const result = summarizeProfile({
      startTime: 0,
      endTime: 1000,
      nodes: [
        { id: 1, callFrame: frame("(root)"), children: [2, 3, 4] },
        { id: 2, callFrame: frame("crypto/internal/chacha.block") },
        { id: 3, callFrame: frame("runtime.mallocgc") },
        { id: 4, callFrame: frame("(idle)") },
      ],
      samples: [2, 3, 4],
      timeDeltas: [100, 200, 700],
    });
    expect(result.sampledMs).toBe(1);
    expect(result.categoriesMs).toEqual({
      "crypto-primitive-stack": 0.1,
      "go-allocation-gc-stack": 0.2,
      idle: 0.7,
    });
    expect(result.top[0]).toEqual({ function: "(idle)", selfMs: 0.7 });
  });

  it("does not count JS value finalizers beneath TLS as cipher arithmetic", () => {
    const frame = (functionName: string) => ({
      functionName,
      scriptId: "1",
      url: "",
      lineNumber: 0,
      columnNumber: 0,
    });
    const result = summarizeProfile({
      startTime: 0,
      endTime: 100,
      nodes: [
        { id: 1, callFrame: frame("crypto_tls.__Conn_.Write"), children: [2] },
        { id: 2, callFrame: frame("syscall_js.makeValue"), children: [3] },
        { id: 3, callFrame: frame("runtime.SetFinalizer"), children: [4] },
        { id: 4, callFrame: frame("runtime.addspecial") },
      ],
      samples: [4],
      timeDeltas: [100],
    });
    expect(result.categoriesMs).toEqual({ "js-value-bookkeeping": 0.1 });
  });

  it("classifies baseline and compact waiters under the same bridge category", () => {
    const frame = (functionName: string) => ({
      functionName,
      scriptId: "1",
      url: "",
      lineNumber: 0,
      columnNumber: 0,
    });
    const result = summarizeProfile({
      startTime: 0,
      endTime: 100,
      nodes: [
        { id: 1, callFrame: frame("main.watchPromise") },
        { id: 2, callFrame: frame("main.watchCompactPromise") },
      ],
      samples: [1, 2],
      timeDeltas: [50, 50],
    });
    expect(result.categoriesMs).toEqual({ "bridge-runtime-stack": 0.1 });
  });
});
