import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectorBridge, ConnectorHandle, ConnectorStream } from "./abi.ts";
import type { SocketHost } from "./host.ts";

const client = vi.hoisted(() => ({
  options: undefined as Record<string, unknown> | undefined,
  connect: vi.fn(async () => {}),
  query: vi.fn<
    (
      sql: string,
      values?: unknown[],
    ) => Promise<{ rows: Record<string, unknown>[]; rowCount: number }>
  >(async () => ({ rows: [{ value: 1, backend_pid: 42 }], rowCount: 1 })),
  end: vi.fn(async () => {}),
}));

vi.mock("pg", () => ({
  default: {
    Client: class {
      constructor(options: Record<string, unknown>) {
        client.options = options;
      }
      on(): void {}
      connect = client.connect;
      query = client.query;
      end = client.end;
    },
  },
}));

import { runFixture, runnerScenario } from "./run.ts";
import type { Fixture } from "./run.ts";
import { parseLocalFixture } from "./fixture.ts";
import { fixtureInput } from "./test-fixture.ts";

function setup(): {
  bridge: ConnectorBridge;
  handle: ConnectorHandle;
  stream: ConnectorStream;
  host: SocketHost;
} {
  const stream: ConnectorStream = {
    startTls: vi.fn(async () => {}),
    read: vi.fn(async () => null),
    write: vi.fn(async () => {}),
    close: vi.fn(async () => {}),
  };
  const handle: ConnectorHandle = { open: vi.fn(async () => stream), close: vi.fn(async () => {}) };
  const bridge: ConnectorBridge = { prepare: vi.fn(async () => handle) };
  const host: SocketHost = {
    dialTCP: vi.fn(async () => stream),
    close: vi.fn(async () => {}),
  };
  return { bridge, handle, stream, host };
}

const fixture: Fixture = {
  options: { assertion: "private" },
  postgres: { user: "fixture", password: "private", database: "fixture" },
  queries: 2,
};

describe("fixture lifecycle with fake pg and bridge (not PostgreSQL integration)", () => {
  beforeEach(() => {
    client.options = undefined;
    client.connect.mockResolvedValue();
    client.query.mockResolvedValue({ rows: [{ value: 1, backend_pid: 42 }], rowCount: 1 });
    client.end.mockResolvedValue();
  });
  afterEach(() => vi.useRealTimers());

  it("requires go TLS before constructing pg, disables channel binding, and joins all owners", async () => {
    const { bridge, handle, stream, host } = setup();
    stream.startTls = vi.fn(async () => {
      expect(client.options).toBeUndefined();
    });
    const report = await runFixture(bridge, host, fixture);
    expect(stream.startTls).toHaveBeenCalledOnce();
    expect(client.options).toMatchObject({ ssl: false, enableChannelBinding: false });
    expect(client.query).toHaveBeenCalledTimes(3);
    expect(report).toMatchObject({
      ok: true,
      value: 1,
      visitorTls: true,
      targetTls: false,
      backendPid: 42,
      queries: 2,
      scenario: { kind: "full-fault", injectFault: true, renewalHoldMs: 3000 },
    });
    expect(client.end).toHaveBeenCalledOnce();
    expect(handle.close).toHaveBeenCalledOnce();
    expect(host.close).toHaveBeenCalledOnce();
    expect(client.end.mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(handle.close).mock.invocationCallOrder[0] ?? 0,
    );
    expect(vi.mocked(handle.close).mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(host.close).mock.invocationCallOrder[0] ?? 0,
    );
  });

  it("never creates pg if go refuses TLS", async () => {
    const { bridge, handle, stream, host } = setup();
    stream.startTls = async () => {
      throw new Error("private");
    };
    await expect(runFixture(bridge, host, fixture)).rejects.toThrow("failed during PostgreSQL TLS");
    expect(client.options).toBeUndefined();
    expect(handle.close).toHaveBeenCalledOnce();
    expect(host.close).toHaveBeenCalledOnce();
  });

  it("closes host sockets if prepare rejects without leaking bridge errors", async () => {
    const { bridge, handle, host } = setup();
    bridge.prepare = async () => {
      throw new Error("private");
    };
    await expect(runFixture(bridge, host, fixture)).rejects.toThrow("failed during prepare");
    expect(client.options).toBeUndefined();
    expect(handle.close).not.toHaveBeenCalled();
    expect(host.close).toHaveBeenCalledOnce();
  });

  it("joins the connector and host after query errors", async () => {
    const { bridge, handle, host } = setup();
    client.query.mockRejectedValue(new Error("private PostgreSQL error"));
    await expect(runFixture(bridge, host, fixture)).rejects.toThrow(
      "failed during PostgreSQL query",
    );
    expect(client.end).toHaveBeenCalledOnce();
    expect(handle.close).toHaveBeenCalledOnce();
    expect(host.close).toHaveBeenCalledOnce();
  });

  it("rejects a result without a real PostgreSQL backend PID", async () => {
    const { bridge, host } = setup();
    client.query.mockResolvedValue({ rows: [{ value: 1, backend_pid: 0 }], rowCount: 1 });
    await expect(runFixture(bridge, host, fixture)).rejects.toThrow(
      "failed during PostgreSQL query",
    );
  });

  it("still joins connector and host after a pg cleanup error", async () => {
    const { bridge, handle, host } = setup();
    client.end.mockRejectedValue(new Error("private cleanup detail"));
    await expect(runFixture(bridge, host, fixture)).rejects.toThrow(
      "fixture failed during cleanup",
    );
    expect(handle.close).toHaveBeenCalledOnce();
    expect(host.close).toHaveBeenCalledOnce();
  });

  it("does not report real qualification without actual selected relay metadata", async () => {
    const { bridge, host } = setup();
    const local = parseLocalFixture(fixtureInput);
    await expect(runFixture(bridge, host, { ...fixture, local })).rejects.toThrow(
      "selected relay metadata",
    );
  });

  it("bounds experimental worker controls without changing the default fault proof", () => {
    expect(runnerScenario(new URLSearchParams())).toEqual({
      injectFault: true,
      renewalHoldMs: 3000,
    });
    expect(runnerScenario(new URLSearchParams("fault=false&hold_ms=4000"))).toEqual({
      injectFault: false,
      renewalHoldMs: 4000,
    });
    expect(runnerScenario(new URLSearchParams("fault=true&hold_ms=10000"))).toEqual({
      injectFault: true,
      renewalHoldMs: 10000,
    });
    for (const hold of ["0", "2999", "10001", "4000.5", "private"]) {
      expect(() => runnerScenario(new URLSearchParams({ hold_ms: hold }))).toThrow(
        "between 3000 and 10000",
      );
    }
    expect(() => runnerScenario(new URLSearchParams("fault=0"))).toThrow("true or false");
  });

  it("skips faults explicitly and uses the later peer after the earlier peer closes", async () => {
    vi.useFakeTimers();
    const first = setup();
    const second = setup();
    const local = parseLocalFixture(fixtureInput);
    const beginTimes: number[] = [];
    client.query.mockImplementation(async (sql) => {
      if (sql === "begin") beginTimes.push(Date.now());
      if (sql.startsWith("select count(*)")) {
        return { rows: [{ count: sql.includes("min(value)") ? 1 : 0, value: 1 }], rowCount: 1 };
      }
      return { rows: [{ value: 1, backend_pid: 42 }], rowCount: 1 };
    });
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    const started = Date.now();
    const firstRun = runFixture(first.bridge, first.host, {
      ...fixture,
      local,
      injectFault: false,
    });
    const secondRun = runFixture(second.bridge, second.host, {
      ...fixture,
      local,
      injectFault: false,
      renewalHoldMs: 4000,
    });
    await vi.advanceTimersByTimeAsync(3000);
    const firstReport = await firstRun;
    expect(first.handle.close).toHaveBeenCalledOnce();
    expect(second.handle.close).not.toHaveBeenCalled();
    expect(beginTimes).toEqual([started + 3000]);
    await vi.advanceTimersByTimeAsync(1000);
    const secondReport = await secondRun;
    expect(beginTimes).toEqual([started + 3000, started + 4000]);
    for (const report of [firstReport, secondReport]) {
      expect(report.scenario.kind).toBe("concurrency-only");
      expect(report.outerCarrierFault).toEqual({ status: "skipped", reason: "concurrency-only" });
      expect(report.writeProof).toEqual({
        backendPidRetained: true,
        committedRows: 1,
        uncommittedInvisible: true,
      });
    }
    expect(secondReport.renewal?.observationMs).toBe(4000);
    expect(second.handle.close).toHaveBeenCalledOnce();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("holds for renewal and restores an actual fault even when COMMIT fails", async () => {
    vi.useFakeTimers();
    const { bridge, handle, host } = setup();
    const local = parseLocalFixture(fixtureInput);
    Object.defineProperty(handle, "selectedRelayAddress", {
      value: local.relays[0]?.relay_address,
    });
    client.query.mockImplementation(async (sql) => {
      if (sql === "commit") throw new Error("private SQL error");
      if (sql.startsWith("select count(*)")) return { rows: [{ count: 0 }], rowCount: 1 };
      return { rows: [{ value: 1, backend_pid: 42 }], rowCount: 1 };
    });
    const fetcher = vi.fn(async (_url: string, init: RequestInit) => {
      const body: unknown = JSON.parse(String(init.body));
      const blocked =
        typeof body === "object" && body !== null && "blocked" in body && body.blocked === true;
      return Response.json({ closed_connections: blocked ? 3 : 0 });
    });
    vi.stubGlobal("fetch", fetcher);
    const running = runFixture(bridge, host, { ...fixture, local });
    const rejected = expect(running).rejects.toThrow("PostgreSQL write commit");
    await vi.advanceTimersByTimeAsync(2999);
    expect(fetcher).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await rejected;
    expect(fetcher.mock.calls.map(([, init]) => JSON.parse(String(init.body)) as unknown)).toEqual([
      { relay_address: local.relays[0]?.relay_address, blocked: true },
      { relay_address: local.relays[0]?.relay_address, blocked: false },
    ]);
    expect(handle.close).toHaveBeenCalledOnce();
    expect(host.close).toHaveBeenCalledOnce();
  });
});
