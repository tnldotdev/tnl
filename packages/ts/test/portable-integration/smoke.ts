type Runtime = Pick<typeof import("@tnldotdev/tnl/browser"), "deployment" | "connect" | "client">;
import * as z from "zod";
import {
  check,
  committedRows,
  fixtureCall,
  fixtureSchema,
  FixtureAssertionError,
  type PortableFixture,
} from "./fixture.ts";
import { Wire } from "./bytes.ts";
import { MySQLFixtureClient } from "./mysql.ts";
import { PostgresFixtureClient } from "./postgres.ts";
import { PortableSmokeError, type Phase } from "./errors.ts";

const services = {
  http: { protocol: "http" },
  tcp: { protocol: "tcp" },
  postgres: { protocol: "postgres" },
  mysql: { protocol: "mysql" },
  kubernetes: { protocol: "kubernetes" },
} as const;

async function joinCleanup(
  cleanups: Promise<unknown>[],
  failed: PortableSmokeError | AggregateError | undefined,
): Promise<void> {
  const results = await Promise.allSettled(cleanups);
  const errors = results.flatMap((result) => {
    if (result.status !== "rejected") return [];
    const reason: unknown = result.reason;
    return [
      reason instanceof PortableSmokeError ? reason : new PortableSmokeError("cleanup", reason),
    ];
  });
  if (errors.length > 0)
    throw new AggregateError(
      failed === undefined
        ? errors
        : failed instanceof AggregateError
          ? [...failed.errors, ...errors]
          : [failed, ...errors],
      "portable SDK operation/cleanup failed",
    );
}

function deployment(runtime: Runtime, fixture: PortableFixture) {
  // the runtime's normal package export selects browser/workerd. no private
  // bridge, native CLI, yamux implementation, or fabricated admission is used.
  return runtime.deployment(fixture.deployment, {
    project: fixture.project,
    token: fixture.token,
    services,
  });
}

async function closed(operation: Promise<unknown>): Promise<void> {
  try {
    await operation;
  } catch (error) {
    check(
      typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "sdk.client_closed",
      "closed deployment returned an unexpected failure",
    );
    return;
  }
  throw new FixtureAssertionError("closed deployment accepted new work");
}

export interface SmokeReport {
  protocols: readonly ["http", "tcp", "postgres", "mysql", "kubernetes"];
  postgresBackendPID: number;
  postgresTransactionRetained: true;
  committedRows: 1;
  interruptedCarriers: number;
  mysqlConnectionID: number;
  closed: true;
}

export async function runPortableWorkload(runtime: Runtime, fixture: PortableFixture) {
  function options() {
    const execution = String(crypto.getRandomValues(new Uint32Array(1))[0] || 1);
    return {
      project: fixture.project,
      controlUrl: fixture.control_url,
      services: { http: { protocol: "http" } } as const,
      workload: {
        name: "portable-reader",
        sourceFingerprint: fixture.source_fingerprint,
        async assertion(signal: AbortSignal) {
          return z
            .object({ assertion: z.string().min(1) })
            .parse(await fixtureCall(fixture, "/workload/assertion", { execution }, signal))
            .assertion;
        },
      },
    };
  }
  try {
    const owner = runtime.deployment(fixture.deployment, options());
    try {
      const connection = await runtime.connect(owner, "http");
      const response = await connection.fetch("/workload-smoke");
      check(response.ok, "workload request did not reach the target");
      const result = z.object({ path: z.literal("/workload-smoke") }).parse(await response.json());
      check(result.path === "/workload-smoke", "workload request came from the wrong target");
    } finally {
      await owner.close();
    }
    const wrong = runtime.deployment("not-the-policy-deployment", options());
    try {
      let rejected = false;
      try {
        await runtime.connect(wrong, "http");
      } catch (error) {
        rejected =
          error instanceof Error && "code" in error && error.code === "sdk.connection_unavailable";
      }
      check(rejected, "workload could select an unapproved deployment");
    } finally {
      await wrong.close();
    }

    const denied = runtime.deployment(fixture.deployment, {
      ...options(),
      services: { tcp: { protocol: "tcp" } },
    });
    try {
      let rejected = false;
      try {
        await runtime.connect(denied, "tcp");
      } catch (error) {
        rejected =
          error instanceof Error && "code" in error && error.code === "sdk.connection_unavailable";
      }
      check(rejected, "workload requested an unapproved service");
    } finally {
      await denied.close();
    }

    const started = Promise.withResolvers<void>();
    const aborted = Promise.withResolvers<void>();
    const pending = runtime.deployment(fixture.deployment, {
      ...options(),
      workload: {
        ...options().workload,
        assertion(signal) {
          started.resolve();
          return new Promise<string>((_, reject) => {
            signal.addEventListener(
              "abort",
              () => {
                aborted.resolve();
                reject(signal.reason);
              },
              { once: true },
            );
          });
        },
      },
    });
    const connecting = runtime.connect(pending, "http");
    try {
      await Promise.race([started.promise, connecting]);
    } finally {
      await pending.close();
    }
    await Promise.all([closed(connecting), aborted.promise]);
    return { workload: true as const };
  } catch (error) {
    throw new PortableSmokeError("workload", error);
  }
}

export async function runPortableSmoke(runtime: Runtime, input: unknown): Promise<SmokeReport> {
  const fixture = fixtureSchema.parse(input);
  const selected = deployment(runtime, fixture);
  let closeWaiting: (() => Promise<void>) | undefined;
  const postgres = runtime.client(selected, "postgres", {
    create: async (connection) =>
      PostgresFixtureClient.connect(
        await connection.open({ signal: AbortSignal.timeout(60_000) }),
        fixture.postgres,
      ),
    close: (client) => client.close(),
  });
  let blocked: string | undefined;
  let phase: Phase = "http";
  let failed: PortableSmokeError | AggregateError | undefined;
  try {
    const http = await runtime.connect(selected, "http");
    const response = await http.fetch("/portable-smoke?source=sdk");
    check(response.status === 200, "SDK HTTP request failed");
    const observation = z
      .strictObject({
        method: z.literal("GET"),
        path: z.literal("/portable-smoke?source=sdk"),
        fixture: z.literal("portable-sdk"),
      })
      .parse(await response.json());
    check(observation.fixture === "portable-sdk", "SDK HTTP response came from the wrong target");

    phase = "tcp";
    const tcp = await runtime.connect(selected, "tcp");
    const wire = new Wire(await tcp.open({ signal: AbortSignal.timeout(30_000) }));
    let exchanged = false;
    try {
      const bytes = Uint8Array.from({ length: 192 * 1024 + 17 }, (_, index) => index % 251);
      // the shared native echo target flushes newline-delimited records.
      bytes[bytes.byteLength - 1] = 10;
      const [, echoed] = await Promise.all([wire.write(bytes), wire.read(bytes.byteLength)]);
      check(
        echoed.every((value, index) => value === bytes[index]),
        "SDK TCP stream changed a bounded multi-chunk message",
      );
      exchanged = true;
    } finally {
      if (exchanged) phase = "tcp-close";
      await wire.close();
    }

    phase = "mysql";
    const mysql = await runtime.connect(selected, "mysql");
    const mysqlClient = await MySQLFixtureClient.connect(
      await mysql.open({ signal: AbortSignal.timeout(30_000) }),
      fixture.mysql,
    );
    let mysqlConnectionID: number;
    try {
      mysqlConnectionID = (await mysqlClient.query()).connectionID;
    } finally {
      await mysqlClient.close();
    }

    phase = "kubernetes";
    const kubernetes = await runtime.connect(selected, "kubernetes");
    const pods = await kubernetes.fetch("/api/v1/namespaces/portable/pods", {
      headers: { Authorization: `Bearer ${fixture.kubernetes_token}` },
    });
    check(pods.status === 200, "SDK Kubernetes target rejected its independent cluster bearer");
    z.object({
      apiVersion: z.literal("v1"),
      kind: z.literal("PodList"),
      items: z
        .array(z.object({ metadata: z.object({ name: z.literal("portable-fixture") }) }))
        .length(1),
    }).parse(await pods.json());

    // concurrent factory calls share this handle's ordinary application client.
    // independent deployments below must not share that client or its backend.
    phase = "postgres";
    const clients = await Promise.all(Array.from({ length: 4 }, () => postgres()));
    const client = clients[0];
    check(
      client !== undefined && clients.every((value) => value === client),
      "deployment.client did not reuse the exact prepared binding",
    );
    await client.query("BEGIN");
    const id = "portable-" + crypto.randomUUID();
    await client.query(`INSERT INTO public.portable_writes(id,value) VALUES ('${id}',42)`);
    const before = (await client.query("SELECT pg_backend_pid(),txid_current()"))[0];
    check(before?.length === 2, "PostgreSQL identity query failed");
    const pid = Number(before[0]);
    const transaction = before[1];
    check(
      Number.isSafeInteger(pid) && pid > 0 && transaction !== null,
      "invalid PostgreSQL identity",
    );
    check(
      (await committedRows(fixture, id)) === 0,
      "independent observer saw an uncommitted write",
    );
    phase = "carrier-loss";
    const carrier = z
      .strictObject({ address: z.string().min(1) })
      .parse(await fixtureCall(fixture, "/postgres/carrier", {}));
    check(
      fixture.relays.some((relay) => relay.address === carrier.address),
      "PostgreSQL selected a carrier outside the fixture",
    );
    blocked = carrier.address;
    const fault = z
      .strictObject({
        closed_connections: z.number().int().positive(),
        blocked: z.literal(true),
        boundary: z.literal("connector_wss_carrier"),
      })
      .parse(await fixtureCall(fixture, "/fault/relay", { address: blocked, blocked: true }));
    const after = (
      await client.query(
        `SELECT pg_backend_pid(),txid_current(),value FROM public.portable_writes WHERE id='${id}'`,
      )
    )[0];
    check(
      after?.[0] === String(pid) && after[1] === transaction && after[2] === "42",
      "carrier loss replaced the PostgreSQL backend or its open transaction",
    );
    check((await committedRows(fixture, id)) === 0, "carrier loss committed or replayed the write");
    await client.query("COMMIT");
    check(
      (await committedRows(fixture, id)) === 1,
      "retained transaction did not commit exactly one write",
    );
    await fixtureCall(fixture, "/fault/relay", { address: blocked, blocked: false });
    blocked = undefined;

    // close must settle a pending application read, then reject new work. its
    // peer-close behavior is separately exercised by concurrent Worker requests.
    phase = "close-open";
    const waiting = await tcp.open({ signal: AbortSignal.timeout(30_000) });
    const reader = waiting.readable.getReader();
    closeWaiting = async () => {
      reader.releaseLock();
      try {
        await waiting.close();
      } catch (error) {
        throw new PortableSmokeError("close-stream", error);
      }
    };
    const read = reader.read().then(
      (value) => value.done,
      () => true,
    );
    phase = "close-deployment";
    await Promise.all([selected.close(), selected.close()]);
    phase = "close-read";
    check(await read, "blocked TCP read returned unexpected target bytes");
    phase = "close-reject";
    await closed(runtime.connect(selected, "tcp"));
    return {
      protocols: ["http", "tcp", "postgres", "mysql", "kubernetes"],
      postgresBackendPID: pid,
      postgresTransactionRetained: true,
      committedRows: 1,
      interruptedCarriers: fault.closed_connections,
      mysqlConnectionID,
      closed: true,
    };
  } catch (error) {
    failed =
      error instanceof AggregateError &&
      error.errors.every((child: unknown) => child instanceof PortableSmokeError)
        ? error
        : new PortableSmokeError(phase, error);
    throw failed;
  } finally {
    await joinCleanup(
      [
        blocked === undefined
          ? Promise.resolve()
          : fixtureCall(fixture, "/fault/relay", { address: blocked, blocked: false }),
        selected.close(),
        closeWaiting?.() ?? Promise.resolve(),
      ],
      failed,
    );
  }
}

export interface IsolationReport {
  role: "first" | "second";
  backendPID: number;
  survivedPeerClose: boolean;
}

// call these concurrently from two Worker requests in the same workerd isolate.
// the fixture rendezvous makes peer-close-before-query observable, not timed.
export async function runPortableIsolation(
  runtime: Runtime,
  input: unknown,
  role: "first" | "second",
  run: string,
): Promise<IsolationReport> {
  const fixture = fixtureSchema.parse(input);
  const selected = deployment(runtime, fixture);
  const get = runtime.client(selected, "postgres", {
    create: async (connection) =>
      PostgresFixtureClient.connect(
        await connection.open({ signal: AbortSignal.timeout(60_000) }),
        fixture.postgres,
      ),
    close: (client) => client.close(),
  });
  let failed: PortableSmokeError | undefined;
  try {
    const client = await get();
    const before = (await client.query("SELECT pg_backend_pid()"))[0]?.[0];
    const pid = Number(before);
    check(
      Number.isSafeInteger(pid) && pid > 0,
      "isolation request did not authenticate to PostgreSQL",
    );
    await fixtureCall(fixture, "/isolation", {
      run,
      mark: `${role}-ready`,
      wait: role === "first" ? "second-ready" : "first-ready",
    });
    if (role === "first") {
      await selected.close();
      await closed(get());
      await fixtureCall(fixture, "/isolation", { run, mark: "first-closed", wait: "first-closed" });
      return { role, backendPID: pid, survivedPeerClose: false };
    }
    await fixtureCall(fixture, "/isolation", { run, mark: "second-ready", wait: "first-closed" });
    check(
      (await get()) === client,
      "peer close replaced the sibling request's cached application client",
    );
    check(
      (await client.query("SELECT pg_backend_pid()"))[0]?.[0] === before,
      "closing one Worker request replaced or ended its sibling's PostgreSQL session",
    );
    return { role, backendPID: pid, survivedPeerClose: true };
  } catch (error) {
    failed = new PortableSmokeError("isolation", error);
    throw failed;
  } finally {
    await joinCleanup([selected.close()], failed);
  }
}
