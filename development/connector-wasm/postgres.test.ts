import { describe, expect, it, vi } from "vitest";
import { measureWarmPostgres, proveCommittedWrite, queryCount, responseBytes } from "./postgres.ts";
import type { QueryClient } from "./postgres.ts";

function result(
  rows: Record<string, unknown>[],
  rowCount = rows.length,
): Awaited<ReturnType<QueryClient["query"]>> {
  return { rows, rowCount };
}

function fakeClient(): { query: ReturnType<typeof vi.fn<QueryClient["query"]>> } {
  return { query: vi.fn<QueryClient["query"]>() };
}

describe("SQL qualification with fake pg query results (not PostgreSQL integration)", () => {
  it("uses one warmup and the same pg SQL for both warm data-path measurements", async () => {
    const client = fakeClient();
    const query = client.query.mockResolvedValue(result([{ value: 1, backend_pid: 123 }]));
    const measured = await measureWarmPostgres(client, 10);
    expect(query).toHaveBeenCalledTimes(11);
    expect(new Set(query.mock.calls.map(([sql]) => sql)).size).toBe(1);
    expect(measured).toMatchObject({ backendPid: 123, queries: 10 });
    expect(measured.latencyMs.min).toBeLessThanOrEqual(measured.latencyMs.p50);
    expect(measured.latencyMs.p50).toBeLessThanOrEqual(measured.latencyMs.p95);
    expect(measured.latencyMs.p95).toBeLessThanOrEqual(measured.latencyMs.max);
    expect(measured.latencyMs.p99).toBeLessThanOrEqual(measured.latencyMs.max);
    expect(measured.queriesPerSecond).toBeCloseTo(10000 / measured.elapsedMs);
    expect(measured.warmupQueries).toBe(1);
  });

  it("retains one backend across the transaction and independently observes one committed write", async () => {
    const client = fakeClient();
    const observer = fakeClient();
    const query = client.query
      .mockResolvedValue(result([{ value: 1, backend_pid: 123 }]))
      .mockResolvedValueOnce(result([]))
      .mockResolvedValueOnce(result([], 1));
    const observed = observer.query
      .mockResolvedValue(result([{ count: 1, value: 1 }]))
      .mockResolvedValueOnce(result([{ count: 0 }]))
      .mockResolvedValueOnce(result([{ count: 0 }]));
    const interrupt = vi.fn(async () => {});
    await expect(proveCommittedWrite(client, observer, 123, interrupt)).resolves.toEqual({
      backendPidRetained: true,
      committedRows: 1,
      uncommittedInvisible: true,
    });
    expect(query.mock.calls.map(([sql]) => sql)).toEqual([
      "begin",
      "insert into public.connector_wasm_writes (id, value) values ($1, $2)",
      "select 1::int as value, pg_backend_pid()::int as backend_pid",
      "commit",
      "select 1::int as value, pg_backend_pid()::int as backend_pid",
    ]);
    expect(interrupt.mock.invocationCallOrder[0]).toBeGreaterThan(
      query.mock.invocationCallOrder[1] ?? 0,
    );
    expect(interrupt.mock.invocationCallOrder[0]).toBeLessThan(
      query.mock.invocationCallOrder[2] ?? 0,
    );
    expect(observed.mock.calls[0]?.[1]).toEqual([query.mock.calls[1]?.[1]?.[0]]);
  });

  it("never retries the insert or commits after an interruption failure", async () => {
    const client = fakeClient();
    const observer = fakeClient();
    const query = client.query.mockResolvedValue(result([], 1));
    const observed = observer.query.mockResolvedValue(result([{ count: 0 }]));
    await expect(
      proveCommittedWrite(client, observer, 123, async () => {
        throw new Error("interrupted");
      }),
    ).rejects.toThrow("interrupted");
    expect(query).toHaveBeenCalledTimes(2);
    expect(observed).toHaveBeenCalledOnce();
  });

  it("rejects a changed backend and duplicate independently observed writes", async () => {
    const client = fakeClient();
    const observer = fakeClient();
    client.query.mockResolvedValue(result([{ value: 1, backend_pid: 124 }], 1));
    const observed = observer.query.mockResolvedValue(result([{ count: 0 }]));
    await expect(proveCommittedWrite(client, observer, 123)).rejects.toThrow("backend changed");
    expect(observed).toHaveBeenCalledOnce();
    observed
      .mockReset()
      .mockResolvedValue(result([{ count: 2, value: 1 }]))
      .mockResolvedValueOnce(result([{ count: 0 }]))
      .mockResolvedValueOnce(result([{ count: 0 }]));
    await expect(proveCommittedWrite(client, observer, 124)).rejects.toThrow(
      "exactly one committed write",
    );
  });

  it("rejects an uncommitted row visible before the interruption", async () => {
    const client = fakeClient();
    const observer = fakeClient();
    client.query.mockResolvedValue(result([], 1));
    observer.query.mockResolvedValue(result([{ count: 1 }]));
    const interrupt = vi.fn(async () => {});
    await expect(proveCommittedWrite(client, observer, 123, interrupt)).rejects.toThrow(
      "saw an uncommitted write",
    );
    expect(interrupt).not.toHaveBeenCalled();
    expect(client.query).toHaveBeenCalledTimes(2);
  });

  it("keeps default samples small and bounds opt-in load samples", () => {
    expect(queryCount(undefined)).toBe(10);
    expect(queryCount("100")).toBe(100);
    expect(queryCount("10000")).toBe(10000);
    for (const value of ["0", "1.5", "10001", "secret"])
      expect(() => queryCount(value)).toThrow("use --queries");
  });

  it("validates every byte of larger responses across warmup and measurement", async () => {
    const client = fakeClient();
    client.query.mockResolvedValue(
      result([{ value: 1, backend_pid: 123, payload: "x".repeat(16384) }]),
    );
    const measured = await measureWarmPostgres(client, 2, undefined, 2, undefined, 16384);
    expect(measured.payloadBytes).toBe(16384);
    expect(new Set(client.query.mock.calls.map(([sql]) => sql)).size).toBe(1);
    expect(client.query).toHaveBeenCalledTimes(4);
    client.query.mockResolvedValue(
      result([{ value: 1, backend_pid: 123, payload: "x".repeat(16383) + "y" }]),
    );
    await expect(measureWarmPostgres(client, 1, undefined, 1, undefined, 16384)).rejects.toThrow(
      "payload changed",
    );
    expect(responseBytes(undefined)).toBe(0);
    for (const value of ["-1", "1.5", "262145", "secret"])
      expect(() => responseBytes(value)).toThrow("payload bytes");
  });
});
