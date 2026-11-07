import pg from "pg";
import type { ConnectorBridge, ConnectorHandle, PrepareOptions } from "./abi.ts";
import type { SocketHost } from "./host.ts";
import { abortError } from "./host.ts";
import { openPostgresStream } from "./pg-stream.ts";
import type { LocalFixture } from "./fixture.ts";
import { setRelayBlocked } from "./fixture.ts";
import {
  nativePostgresClient,
  measureWarmPostgres,
  observerPostgresClient,
  proveCommittedWrite,
} from "./postgres.ts";
import type {
  ObserveWarm,
  QueryMeasurements,
  WarmInstrumentation,
  WriteProof,
} from "./postgres.ts";

export interface Fixture {
  options: PrepareOptions;
  postgres: {
    user: string;
    password: string;
    database: string;
  };
  queries: number;
  local?: LocalFixture;
  instrumentWarm?: WarmInstrumentation;
  // experimental qualification controls only; Node leaves fault injection enabled.
  injectFault?: boolean;
  renewalHoldMs?: number;
  warmupQueries?: number;
  observeWarm?: ObserveWarm;
  reuseReadView?: boolean;
  applicationPump?: boolean;
  payloadBytes?: number;
}

export interface FixtureReport {
  ok: true;
  value: 1;
  visitorTls: true;
  targetTls: false;
  backendPid: number;
  queries: number;
  elapsedMs: number;
  scenario: {
    kind: "full-fault" | "concurrency-only";
    injectFault: boolean;
    renewalHoldMs: number;
  };
  compatibility: typeof PG_TLS_COMPATIBILITY;
  wasm: QueryMeasurements & { prepareMs: number; streamTlsMs: number; pgConnectMs: number };
  native?: QueryMeasurements & {
    baseline: "already-ready in-process Go stream.Serve";
    pgConnectMs: number;
    fullNativeHelperComparison: "not-measured";
  };
  writeProof?: WriteProof;
  outerCarrierFault?:
    | { status: "injected"; selectedSlot: 0; closedConnections: number; restored: true }
    | { status: "skipped"; reason: "concurrency-only" };
  renewal?: { observationMs: number; verification: "parent-durable-sequence-and-revocation-check" };
}

function checkedRenewalHold(value: number): number {
  if (!Number.isSafeInteger(value) || value < 3000 || value > 10000) {
    throw new Error("renewal hold must be an integer between 3000 and 10000 milliseconds");
  }
  return value;
}

export function runnerScenario(params: URLSearchParams): {
  injectFault: boolean;
  renewalHoldMs: number;
} {
  const fault = params.get("fault");
  if (fault !== null && fault !== "true" && fault !== "false") {
    throw new Error("experimental fault option must be true or false");
  }
  const hold = params.get("hold_ms");
  return {
    injectFault: fault !== "false",
    renewalHoldMs: checkedRenewalHold(hold === null ? 3000 : Number(hold)),
  };
}

export function renewalObservation(signal?: AbortSignal, holdMs = 3000): Promise<void> {
  checkedRenewalHold(holdMs);
  return new Promise<void>((resolve, reject) => {
    const onAbort = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      reject(abortError());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, holdMs);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

// ssl:false means the custom stream is already verified by go, not cleartext.
// pg cannot inspect go's TLS certificate, so SCRAM-SHA-256-PLUS/channel binding
// and pg's getPeerCertificate/TLS socket APIs are not supported by this spike.
export const PG_TLS_COMPATIBILITY = {
  tlsOwner: "go",
  pgSsl: false,
  scramChannelBinding: false,
  peerCertificateApi: false,
} as const;

export class FixtureFailure extends Error {
  constructor(phase: string) {
    super(`connector WASM fixture failed during ${phase}`);
  }
}

export function safeFixtureError(error: unknown): string {
  return error instanceof FixtureFailure
    ? error.message
    : "connector WASM PostgreSQL fixture failed";
}

export async function runFixture(
  bridge: ConnectorBridge,
  host: SocketHost,
  fixture: Fixture,
  signal?: AbortSignal,
): Promise<FixtureReport> {
  const started = performance.now();
  let handle: ConnectorHandle | undefined;
  let closingHandle: Promise<void> | undefined;
  let client: pg.Client | undefined;
  let stream: Awaited<ReturnType<typeof openPostgresStream>> | undefined;
  let streamClosed: Promise<void> | undefined;
  let succeeded = false;
  let report: FixtureReport | undefined;
  let failure: Error | undefined;
  let phase = "prepare";
  let injectFault = true;
  let renewalHoldMs = 3000;
  const additionalClients: pg.Client[] = [];
  let faultRelay: string | undefined;
  const observeWarm = fixture.observeWarm;
  const closeHandle = (): Promise<void> => {
    closingHandle ??= handle?.close() ?? Promise.resolve();
    return closingHandle;
  };
  const onAbort = (): void => {
    void closeHandle().catch(() => {});
    void host.close().catch(() => {});
    for (const client of additionalClients) void client.end().catch(() => {});
  };
  try {
    if (signal?.aborted) throw abortError();
    phase = "scenario controls";
    injectFault = fixture.injectFault ?? true;
    if (typeof injectFault !== "boolean") throw new Error("invalid fault scenario option");
    renewalHoldMs = checkedRenewalHold(fixture.renewalHoldMs ?? 3000);
    phase = "prepare";
    const preparing = performance.now();
    handle = await bridge.prepare(fixture.options, host, signal);
    const prepareMs = performance.now() - preparing;
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) throw abortError();
    phase = "PostgreSQL TLS";
    const opening = performance.now();
    stream = await openPostgresStream(
      handle,
      signal,
      !fixture.reuseReadView,
      fixture.applicationPump,
    );
    const streamTlsMs = performance.now() - opening;
    streamClosed = new Promise<void>((resolve) => stream?.once("close", resolve));
    // also cover the short interval before pg installs its stream error listener.
    stream.on("error", () => {});
    client = new pg.Client({
      ...fixture.postgres,
      // never ask pg to start a second TLS session; go already negotiated and verified it.
      ssl: false,
      enableChannelBinding: false,
      stream: () => stream,
      host: "connector.invalid",
      port: 5432,
      connectionTimeoutMillis: 10_000,
      query_timeout: 10_000,
    });
    // pg emits idle connection errors outside a query promise too.
    client.on("error", () => {});
    phase = "PostgreSQL connect";
    const connecting = performance.now();
    await client.connect();
    const pgConnectMs = performance.now() - connecting;
    phase = "PostgreSQL query";
    const measured = await measureWarmPostgres(
      client,
      fixture.queries,
      fixture.instrumentWarm,
      fixture.warmupQueries,
      observeWarm && ((sample) => observeWarm("wasm", sample)),
      fixture.payloadBytes,
    );
    report = {
      ok: true,
      value: 1,
      visitorTls: true,
      targetTls: false,
      backendPid: measured.backendPid,
      queries: fixture.queries,
      elapsedMs: Math.round(performance.now() - started),
      scenario: {
        kind: injectFault ? "full-fault" : "concurrency-only",
        injectFault,
        renewalHoldMs,
      },
      compatibility: PG_TLS_COMPATIBILITY,
      wasm: { ...measured, prepareMs, streamTlsMs, pgConnectMs },
    };
    if (fixture.local) {
      phase = "selected relay metadata";
      const selectedRelay = handle.selectedRelayAddress ?? "";
      if (
        injectFault &&
        (!selectedRelay ||
          !fixture.local.relays.some((relay) => relay.relay_address === selectedRelay))
      ) {
        throw new Error("real qualification requires the actual selected slot-zero relay");
      }
      phase = "native PostgreSQL baseline";
      const native = nativePostgresClient(fixture.local);
      additionalClients.push(native);
      const nativeConnecting = performance.now();
      await native.connect();
      const nativeConnectMs = performance.now() - nativeConnecting;
      report.native = {
        ...(await measureWarmPostgres(
          native,
          fixture.queries,
          fixture.instrumentWarm,
          fixture.warmupQueries,
          observeWarm && ((sample) => observeWarm("native", sample)),
          fixture.payloadBytes,
        )),
        baseline: "already-ready in-process Go stream.Serve",
        pgConnectMs: nativeConnectMs,
        fullNativeHelperComparison: "not-measured",
      };
      phase = "workload renewal observation";
      await renewalObservation(signal, renewalHoldMs);
      report.renewal = {
        observationMs: renewalHoldMs,
        verification: "parent-durable-sequence-and-revocation-check",
      };
      phase = "independently observed PostgreSQL write";
      const observer = observerPostgresClient(fixture.local);
      additionalClients.push(observer);
      await observer.connect();
      const local = fixture.local;
      if (!injectFault)
        report.outerCarrierFault = { status: "skipped", reason: "concurrency-only" };
      report.writeProof = await proveCommittedWrite(
        client,
        observer,
        measured.backendPid,
        injectFault
          ? async () => {
              // set this before the request: a failed response can still have blocked a relay.
              faultRelay = selectedRelay;
              const closedConnections = await setRelayBlocked(
                local,
                selectedRelay,
                true,
                signal ?? AbortSignal.timeout(10_000),
              );
              if (report)
                report.outerCarrierFault = {
                  status: "injected",
                  selectedSlot: 0,
                  closedConnections,
                  restored: true,
                };
            }
          : undefined,
        (stage) => {
          phase = `PostgreSQL write ${stage}`;
        },
      );
    }
    report.elapsedMs = Math.round(performance.now() - started);
    succeeded = true;
  } catch {
    failure = new FixtureFailure(phase);
  }
  signal?.removeEventListener("abort", onAbort);
  // join pg, visitor stream, connector renewal, then host sockets in that order.
  if (!succeeded) stream?.destroy();
  const cleanup: Array<[string, () => Promise<unknown> | undefined]> = [
    [
      "relay restoration",
      async () => {
        if (faultRelay && fixture.local) {
          // restoration must not inherit an already-aborted caller signal.
          await setRelayBlocked(fixture.local, faultRelay, false, AbortSignal.timeout(5000));
        }
      },
    ],
    ["PostgreSQL client cleanup", () => client?.end()],
    ...additionalClients.map((client): [string, () => Promise<void>] => [
      "observer client cleanup",
      () => client.end(),
    ]),
    [
      "visitor stream cleanup",
      async () => {
        stream?.destroy();
        await streamClosed;
      },
    ],
    ["connector cleanup", closeHandle],
    ["host cleanup", () => host.close()],
  ];
  for (const [stage, close] of cleanup) {
    try {
      await close();
    } catch {
      failure ??= new FixtureFailure(stage);
    }
  }
  if (failure) throw failure;
  if (!report) throw new Error("connector WASM fixture returned no result");
  return report;
}
