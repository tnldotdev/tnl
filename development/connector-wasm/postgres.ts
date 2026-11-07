import pg from "pg";
import type { LocalFixture } from "./fixture.ts";
import { parseTCPAddress } from "./host.ts";
import type { WarmDiagnostics } from "./diagnostics.ts";

export interface QueryMeasurements {
  backendPid: number;
  queries: number;
  latencyMs: { min: number; p50: number; p95: number; p99: number; max: number };
  elapsedMs: number;
  queriesPerSecond: number | null;
  warmupQueries?: number;
  runtime?: WarmRuntimeMetrics;
  diagnostics?: WarmDiagnostics;
}

export type ObserveWarm = (
  label: "wasm" | "native",
  sample: () => Promise<QueryMeasurements>,
) => Promise<QueryMeasurements>;

export type WarmRuntimeMetrics = {
  scope: "caller-process-only; native Go daemon excluded";
  wallMs: number;
  cpuMicros: { user: number; system: number } | "unsupported";
  cpuMicrosPerQuery?: { user: number; system: number; total: number };
  eventLoopDelayMs:
    | { mean: number; p99: number; max: number }
    | "unsupported-bun"
    | "unsupported-worker"
    | "insufficient-samples";
};

export type WarmInstrumentation = () => () => WarmRuntimeMetrics;

export interface WriteProof {
  backendPidRetained: true;
  committedRows: 1;
  uncommittedInvisible: true;
}

export type WriteStage =
  | "begin"
  | "insert"
  | "observer-uncommitted-before-fault"
  | "fault-http"
  | "retained-pid"
  | "observer-uncommitted-after-fault"
  | "commit"
  | "post-commit-pid"
  | "observer-committed";

export interface QueryClient {
  query(
    sql: string,
    values?: unknown[],
  ): Promise<{
    rows: Record<string, unknown>[];
    rowCount: number | null;
  }>;
}

function round(value: number): number {
  return Math.round(value * 1000) / 1000;
}

export async function measurePostgres(
  client: QueryClient,
  queries: number,
  instrument?: WarmInstrumentation,
): Promise<QueryMeasurements> {
  const times: number[] = [];
  let backendPid = 0;
  const stop = instrument?.();
  const intervalStarted = performance.now();
  let elapsedMs: number;
  let runtime: WarmRuntimeMetrics | undefined;
  try {
    for (let index = 0; index < queries; index += 1) {
      const started = performance.now();
      const result = await client.query(
        "select 1::int as value, pg_backend_pid()::int as backend_pid",
      );
      times.push(performance.now() - started);
      const row = result.rows[0];
      if (
        result.rows.length !== 1 ||
        row?.value !== 1 ||
        typeof row.backend_pid !== "number" ||
        !Number.isSafeInteger(row.backend_pid) ||
        row.backend_pid < 1 ||
        (backendPid !== 0 && backendPid !== row.backend_pid)
      ) {
        throw new Error("fixture requires one retained PostgreSQL connection");
      }
      backendPid = row.backend_pid;
    }
  } finally {
    elapsedMs = performance.now() - intervalStarted;
    runtime = stop?.();
  }
  if (runtime && runtime.cpuMicros !== "unsupported") {
    runtime.cpuMicrosPerQuery = {
      user: runtime.cpuMicros.user / queries,
      system: runtime.cpuMicros.system / queries,
      total: (runtime.cpuMicros.user + runtime.cpuMicros.system) / queries,
    };
  }
  times.sort((a, b) => a - b);
  const percentile = (fraction: number): number =>
    round(times[Math.max(0, Math.ceil(times.length * fraction) - 1)] ?? 0);
  return {
    backendPid,
    queries,
    elapsedMs,
    queriesPerSecond: elapsedMs > 0 ? (queries * 1000) / elapsedMs : null,
    latencyMs: {
      min: percentile(0),
      p50: percentile(0.5),
      p95: percentile(0.95),
      p99: percentile(0.99),
      max: percentile(1),
    },
    ...(runtime ? { runtime } : {}),
  };
}

export async function measureWarmPostgres(
  client: QueryClient,
  queries: number,
  instrument?: WarmInstrumentation,
  warmupQueries = 1,
  observe?: (sample: () => Promise<QueryMeasurements>) => Promise<QueryMeasurements>,
): Promise<QueryMeasurements> {
  if (!Number.isSafeInteger(warmupQueries) || warmupQueries < 1 || warmupQueries > 10000)
    throw new Error("warmup queries must be an integer between 1 and 10000");
  const warmup = await measurePostgres(client, warmupQueries);
  const sample = () => measurePostgres(client, queries, instrument);
  const measured = await (observe ? observe(sample) : sample());
  if (warmup.backendPid !== measured.backendPid)
    throw new Error("PostgreSQL backend changed after warmup");
  return { ...measured, warmupQueries };
}

export function queryCount(value: string | undefined | null): number {
  const count = value === undefined || value === null ? 10 : Number(value);
  if (!Number.isSafeInteger(count) || count < 1 || count > 10000) {
    throw new Error("use --queries with an integer between 1 and 10000");
  }
  return count;
}

function fixturePostgresClient(
  address: string,
  fixture: LocalFixture,
  ssl: pg.ClientConfig["ssl"],
): pg.Client {
  const { hostname, port } = parseTCPAddress(address);
  const client = new pg.Client({
    user: fixture.postgres.user,
    password: fixture.postgres.password,
    database: fixture.postgres.database,
    host: hostname,
    port,
    ssl,
    enableChannelBinding: false,
    connectionTimeoutMillis: 10_000,
    query_timeout: 10_000,
  });
  client.on("error", () => {});
  return client;
}

// the native listener forwards PostgreSQL SSLRequest to the publisher unchanged.
// both Node TLS and cloudflare:sockets must verify the saved service hostname.
// workerd's local network must separately trust service_root_pem; ca is not a
// cloudflare:sockets option, and this code never disables its verification.
export function nativePostgresClient(fixture: LocalFixture): pg.Client {
  const trust = {
    ca: fixture.service_root_pem,
    servername: fixture.postgres.tls_server_name,
    expectedServerHostname: fixture.postgres.tls_server_name,
    rejectUnauthorized: true,
  };
  return fixturePostgresClient(fixture.native_connector_address, fixture, trust);
}

// only the independent direct observer uses the fixture's plaintext target leg.
export function observerPostgresClient(fixture: LocalFixture): pg.Client {
  return fixturePostgresClient(observerAddress(fixture), fixture, false);
}

export function observerAddress(fixture: LocalFixture): string {
  const url = new URL(fixture.postgres.direct_url);
  return `${url.hostname}:${url.port || "5432"}`;
}

export async function proveCommittedWrite(
  client: QueryClient,
  observer: QueryClient,
  expectedPid: number,
  interrupt?: () => Promise<void>,
  stage?: (stage: WriteStage) => void,
): Promise<WriteProof> {
  const id = crypto.randomUUID();
  stage?.("begin");
  await client.query("begin");
  stage?.("insert");
  const inserted = await client.query(
    "insert into public.connector_wasm_writes (id, value) values ($1, $2)",
    [id, 1],
  );
  if (inserted.rowCount !== 1) throw new Error("fixture insert did not affect one row");
  const assertInvisible = async (): Promise<void> => {
    const result = await observer.query(
      "select count(*)::int as count from public.connector_wasm_writes where id = $1",
      [id],
    );
    if (result.rows.length !== 1 || result.rows[0]?.count !== 0) {
      throw new Error("independent observer saw an uncommitted write");
    }
  };
  stage?.("observer-uncommitted-before-fault");
  await assertInvisible();
  // no reconnect, retry, or replay of this transaction is permitted.
  stage?.("fault-http");
  await interrupt?.();
  stage?.("retained-pid");
  const retained = await measurePostgres(client, 1);
  if (retained.backendPid !== expectedPid)
    throw new Error("PostgreSQL backend changed during transaction");
  stage?.("observer-uncommitted-after-fault");
  await assertInvisible();
  stage?.("commit");
  await client.query("commit");
  stage?.("post-commit-pid");
  const after = await measurePostgres(client, 1);
  if (after.backendPid !== expectedPid) throw new Error("PostgreSQL backend changed after commit");
  stage?.("observer-committed");
  const result = await observer.query(
    "select count(*)::int as count, min(value)::int as value from public.connector_wasm_writes where id = $1",
    [id],
  );
  if (result.rows.length !== 1 || result.rows[0]?.count !== 1 || result.rows[0].value !== 1) {
    throw new Error("independent observer did not find exactly one committed write");
  }
  return { backendPidRetained: true, committedRows: 1, uncommittedInvisible: true };
}
