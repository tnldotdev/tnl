import { execFile } from "node:child_process";
import { mkdtemp, realpath } from "node:fs/promises";
import { connect as connectTCP } from "node:net";
import { tmpdir } from "node:os";
import * as path from "node:path";
import type { Pool, Dispatcher } from "undici/index.js";
import { TnlCleanupError, TnlError } from "../../errors.js";
import type { TnlConnectionRegistry, TnlFetch } from "../../project.js";
import { ownerIPC, type OwnerIPC } from "./connection_ipc.js";
import type { NativeScope } from "./context.js";
import { cancellable } from "./cancellation.js";
import type { ConnectionSnapshot } from "./snapshot.js";
import * as z from "zod";
import { parseValue } from "../validation.js";
import { sdkPreparationSchema, preparedConnectionSchema } from "./contract.js";
import { selectWorkload, type WorkloadSource } from "./workload/provider.js";
import type { SelectionOptions, WorkloadRequest } from "./workload/contract.js";
import { resolveNativeBinary } from "../native/launcher.js";
import { launchEnvironment, operation, independent } from "../tracing.js";

type Settings = TnlConnectionRegistry[keyof TnlConnectionRegistry];
const maximumBytes = 128 * 1024;
const command = ["runtime", "connections"];

function machineError(cause: unknown, operation?: string): TnlError {
  // native stderr and JSON parser errors can contain private input; retain only
  // an owned classification, never subprocess output or a credential-bearing cause.
  if (typeof cause === "object" && cause !== null && "stderr" in cause) {
    try {
      const stderr = cause.stderr;
      const problem = z
        .object({ reason: z.string() })
        .parse(JSON.parse(typeof stderr === "string" ? stderr : ""));
      if (
        problem.reason === "TNL_CLIENT_AUTHENTICATION_REQUIRED" ||
        problem.reason === "TNL_CLIENT_AUTH_RECOVERY_REQUIRED"
      )
        return new TnlError("sdk.authentication_required");
      if (problem.reason === "TNL_SERVER_RESPONSE_INVALID")
        return new TnlError("sdk.response_invalid");
      switch (problem.reason) {
        case "TNL_CLIENT_WORKLOAD_REQUIRED":
          return new TnlError("sdk.workload_required");
        case "TNL_CLIENT_WORKLOAD_MANIFEST_INVALID":
          return new TnlError("sdk.workload_manifest_invalid");
        case "TNL_CLIENT_WORKLOAD_SERVICE_DENIED":
          return new TnlError("sdk.workload_denied");
        case "TNL_CLIENT_WORKLOAD_ASSERTION_UNAVAILABLE":
          return new TnlError("sdk.workload_assertion_unavailable");
      }
      if (problem.reason === "TNL_CLIENT_CONNECTION_CLEANUP_FAILED" && operation === "sdk-prepare")
        return new TnlCleanupError(
          new TnlError("sdk.response_invalid"),
          new TnlError("sdk.connection_unavailable"),
        );
    } catch {
      // malformed diagnostics have the same safe connection failure.
    }
  }
  return new TnlError("sdk.connection_unavailable");
}

function machine(
  scope: Pick<NativeScope, "binary" | "environment">,
  args: string[],
  signal?: AbortSignal,
  input?: unknown,
): Promise<unknown> {
  return operation("sdk.native.command", () => machineUntraced(scope, args, signal, input));
}

async function machineUntraced(
  scope: Pick<NativeScope, "binary" | "environment">,
  args: string[],
  signal?: AbortSignal,
  input?: unknown,
): Promise<unknown> {
  try {
    const stdout = await new Promise<string>((resolve, reject) => {
      const child = execFile(
        scope.binary,
        [...command, ...args],
        {
          timeout: args[0] === "sdk-prepare" ? 45_000 : 25_000,
          maxBuffer: maximumBytes,
          encoding: "utf8",
          env: { ...launchEnvironment(), ...scope.environment },
          ...(signal === undefined ? {} : { signal }),
        },
        (error, stdout, stderr) =>
          error === null
            ? resolve(stdout)
            : reject(Object.assign(error, stderr === undefined ? {} : { stderr })),
      );
      child.stdin?.on?.("error", () => {
        /* execFile reports the process failure without exposing pipe data. */
      });
      child.stdin?.end(input === undefined ? undefined : JSON.stringify(input));
    });
    const value: unknown = JSON.parse(stdout);
    return value;
  } catch (cause) {
    if (signal?.aborted) throw signal.reason;
    throw machineError(cause, args[0]);
  }
}

async function nativeScope(captured: {
  binary: string;
  directory: string;
  environment: NativeScope["environment"];
}): Promise<NativeScope> {
  const scope: NativeScope = {
    ...captured,
    registry: await mkdtemp(path.join(await realpath(tmpdir()), "tnl-sdk-")),
    open: ownerIPC,
    // keep native error classification with the copy that owns this IPC.
    select: (...args) => requestSelection(scope, ...args),
    workload: (name, request) => requestWorkload(scope, name, request),
  };
  const cleanup = independent("sdk.app.cleanup", async () => {
    await machine(scope, [
      "sdk-stop",
      "--registry",
      scope.registry,
      "--parent-pid",
      String(process.pid),
    ]);
    if (scope.entry !== undefined) (await scope.entry.ipc).close();
  });
  const beforeExit = () => {
    void cleanup().catch(() => {});
  };
  scope.close = async () => {
    await cleanup();
    process.removeListener("beforeExit", beforeExit);
  };
  process.once("beforeExit", beforeExit);
  return scope;
}

async function requestSelection(
  scope: NativeScope,
  args: string[],
  input: unknown,
  name: string,
  assertion: string | undefined,
  selectionOptions: SelectionOptions,
): Promise<unknown> {
  const entry = scope.entry;
  let raw: unknown;
  if (entry === undefined) raw = await machine(scope, args, undefined, input);
  else {
    try {
      raw = await (await entry.ipc).prepare(name, assertion, selectionOptions);
    } catch (cause) {
      // native recovery checks the kernel lock before doing any selection or
      // network work. a timeout or service denial cannot authorize replacement.
      try {
        raw = await machine(scope, [...args, "--recover-handle", entry.file], undefined, input);
      } catch (recovery) {
        if (recovery instanceof TnlError && recovery.code === "sdk.authentication_required")
          throw recovery;
        throw cause instanceof TnlError ? cause : machineError(cause);
      }
      if (scope.entry === entry) {
        delete scope.entry;
        void entry.ipc.then(
          (ipc) => ipc.close(),
          () => {},
        );
      }
    }
  }
  return raw;
}

async function requestWorkload(
  scope: NativeScope,
  name: string,
  request: WorkloadRequest,
): Promise<unknown> {
  let raw: unknown;
  try {
    if (scope.entry === undefined) throw new Error("cold selection");
    raw = await (await scope.entry.ipc).workload(name, request);
  } catch {
    // preview reads a local artifact only; owner recovery remains gated inside
    // sdk-prepare before any provider acquisition or control request.
    raw = await machine(
      scope,
      ["sdk-workload", "--directory", scope.directory, "--service", name],
      undefined,
      { schema: 1, sdk_workload: request },
    );
  }
  if (typeof raw === "object" && raw !== null && "reason" in raw)
    throw machineError({ stderr: JSON.stringify(raw) });
  return raw;
}

function parsePrepared(value: unknown, name: string, file: string) {
  const { project_runtime: project, connection: snapshot } = parseValue(
    preparedConnectionSchema,
    value,
    "sdk.response_invalid",
  );
  const metadata = project.services[name];
  if (
    metadata === undefined ||
    metadata.protocol !== snapshot.protocol ||
    (snapshot.protocol !== "tcp" && metadata.hostname !== snapshot.ssl.servername) ||
    ((snapshot.protocol === "http" || snapshot.protocol === "kubernetes") &&
      (!("url" in metadata) || metadata.url !== snapshot.url))
  )
    throw new TnlError("sdk.response_invalid");
  return Object.freeze({
    project,
    snapshot,
    file,
  });
}

type LocalHTTPTransport = Readonly<{
  protocol: "http";
  host: string;
  port: number;
  url: `http://${string}`;
  ssl: false;
  expires: number;
  transportID: string;
}>;

export function managedFetch(
  url: `${"http" | "https"}://${string}`,
  current: (signal?: AbortSignal) => Promise<ConnectionSnapshot | LocalHTTPTransport>,
): TnlFetch & { close(): Promise<void> } {
  let active = 0;
  let closed = false;
  let pool: Pool | undefined;
  let dispatcher: Dispatcher | undefined;
  let poolKey: string | undefined;
  const retired = new Set<Pool>();
  const run: TnlFetch = async (input, init) => {
    if (closed) throw new TnlError("sdk.client_closed");
    const running = [...retired, ...(pool === undefined ? [] : [pool])].reduce(
      (sum, p) => sum + p.stats.running + p.stats.pending,
      0,
    );
    if (active + running >= 64) throw new TnlError("sdk.connection_unavailable");
    active++;
    let request: Request | undefined;
    let dispatched = false;
    try {
      const requestOptions: RequestInit & { duplex?: "half" } = {
        ...init,
        ...(init?.body instanceof ReadableStream ? { duplex: "half" } : {}),
      };
      request = new Request(
        input instanceof Request ? input : new URL(String(input), `${url}/`),
        requestOptions,
      );
      if (new URL(request.url).origin !== url) throw new TnlError("sdk.configuration_invalid");
      request.headers.set("host", new URL(url).host);
      const lifetime = request.signal;
      lifetime.throwIfAborted();
      const snapshot = await cancellable(lifetime, () => current(lifetime));
      lifetime.throwIfAborted();
      if (closed) throw new TnlError("sdk.client_closed");
      if (
        (snapshot.protocol !== "http" && snapshot.protocol !== "kubernetes") ||
        snapshot.url !== url ||
        snapshot.expires <= Date.now()
      )
        throw new TnlError("sdk.response_invalid");
      const { Pool, buildConnector, fetch: transportFetch } = await import("undici/index.js");
      const nextKey = JSON.stringify([
        snapshot.host,
        snapshot.port,
        snapshot.ssl,
        snapshot.transportID,
      ]);
      if (pool === undefined || poolKey !== nextKey) {
        if (pool !== undefined) {
          if (retired.size >= 4) throw new TnlError("sdk.connection_unavailable");
          const previous = pool;
          retired.add(previous);
          void previous
            .close()
            .catch(() => {})
            .finally(() => retired.delete(previous));
        }
        const options = {
          connections: 8,
          pipelining: 1,
          headersTimeout: 0,
          bodyTimeout: 0,
        };
        if (snapshot.ssl === false) {
          // the origin was validated as a loopback HTTP address by local selection.
          pool = new Pool(url, options);
        } else {
          const connect = buildConnector(snapshot.ssl);
          pool = new Pool(url, {
            ...options,
            connect(options, callback) {
              if (options.protocol !== "https:" || options.hostname !== snapshot.ssl.servername)
                return callback(new TnlError("sdk.configuration_invalid"), null);
              return connect(
                {
                  ...options,
                  hostname: snapshot.host,
                  port: String(snapshot.port),
                  servername: snapshot.ssl.servername,
                },
                callback,
              );
            },
          });
        }
        dispatcher = pool.compose(
          (dispatch) => (options, handler) => dispatch({ ...options, idempotent: false }, handler),
        );
        poolKey = nextKey;
      }
      if (dispatcher === undefined) throw new TnlError("sdk.connection_unavailable");
      const options = {
        dispatcher,
        redirect: "manual" as const,
        signal: lifetime,
      };
      // bun's global fetch ignores undici dispatchers. own the same transport on
      // both runtimes so the managed origin can never fall back to a direct dial.
      const body = request.body;
      async function* upload() {
        if (body === null) return;
        const reader = body.getReader();
        try {
          for (;;) {
            const chunk = await reader.read();
            if (chunk.done) return;
            yield chunk.value;
          }
        } finally {
          await reader.cancel().catch(() => {});
          reader.releaseLock();
        }
      }
      dispatched = true;
      const response = await transportFetch(request.url, {
        ...options,
        method: request.method,
        headers: [...request.headers],
        cache: request.cache,
        credentials: request.credentials,
        integrity: request.integrity,
        keepalive: request.keepalive,
        mode: request.mode,
        referrer: request.referrer,
        referrerPolicy: request.referrerPolicy,
        ...(body === null ? {} : { body: upload(), duplex: "half" }),
      });
      const reader = response.body?.getReader();
      const stream =
        reader === undefined
          ? null
          : new ReadableStream<Uint8Array>({
              async pull(controller) {
                try {
                  const chunk = await reader.read();
                  if (chunk.done) {
                    controller.close();
                    reader.releaseLock();
                  } else controller.enqueue(chunk.value);
                } catch (error) {
                  controller.error(error);
                  reader.releaseLock();
                }
              },
              async cancel(reason: unknown) {
                try {
                  await reader.cancel(reason);
                } finally {
                  reader.releaseLock();
                }
              },
            });
      const result = new Response(stream, {
        status: response.status,
        statusText: response.statusText,
        headers: [...response.headers],
      });
      return responseIdentity(result, response.url, response.type);
    } catch (error) {
      if (!dispatched && request?.body !== null && request?.body !== undefined)
        void request.body.cancel(error).catch(() => {});
      throw error;
    } finally {
      active--;
    }
  };
  return Object.assign(run, {
    async close() {
      closed = true;
      const results = await Promise.allSettled(
        [...retired, ...(pool === undefined ? [] : [pool])].map((value) => value.destroy()),
      );
      const failures = results.flatMap((result) =>
        result.status === "rejected" ? [result.reason as unknown] : [],
      );
      if (failures.length) throw new AggregateError(failures, "HTTP transport cleanup failed");
    },
  });
}

function responseIdentity(response: Response, url: string, type: string): Response {
  const clone = response.clone.bind(response);
  Object.defineProperties(response, {
    url: { value: url },
    type: { value: type },
    clone: { value: () => responseIdentity(clone(), url, type) },
  });
  return response;
}

function settings(snapshot: ConnectionSnapshot, boundFetch?: TnlFetch): Settings {
  switch (snapshot.protocol) {
    case "tcp":
      return Object.freeze({ host: snapshot.host, port: snapshot.port });
    case "http": {
      if (boundFetch === undefined) throw new TnlError("sdk.response_invalid");
      return Object.freeze({
        url: snapshot.url,
        fetch: boundFetch,
      });
    }
    case "kubernetes":
      return Object.freeze({
        server: `https://${snapshot.host}:${snapshot.port}`,
        kubeconfig: snapshot.kubeconfig,
        context: snapshot.context,
      });
    case "mysql":
      // mysql2 verifies config.host, ignoring ssl.servername. its supported stream
      // factory keeps each pool connection on loopback without changing TLS identity.
      // both mysql drivers mutate ssl; never hand a driver the frozen wire snapshot.
      return Object.freeze({
        host: snapshot.ssl.servername,
        port: snapshot.port,
        ssl: { ...snapshot.ssl, verifyIdentity: true as const },
        stream: () => connectTCP({ host: snapshot.host, port: snapshot.port }),
      });
    case "postgres":
      return Object.freeze({
        host: snapshot.host,
        port: snapshot.port,
        ssl: snapshot.ssl,
      });
  }
}

// cancellation releases one caller's wait without abandoning a shared owner.
async function waitForPreparation<T>(operation: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return operation;
  signal.throwIfAborted();
  return new Promise<T>((resolve, reject) => {
    const aborted = () => reject(signal.reason);
    signal.addEventListener("abort", aborted, { once: true });
    void operation
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", aborted));
  });
}

const credentialAccessSchema = z.strictObject({
  schema: z.literal(1),
  server: z.url(),
  team_id: z.string().min(1),
  project_key: z.string().min(1),
  token: z.string().startsWith("pta_"),
  expires_at: z.iso.datetime({ offset: true }).transform(Date.parse),
});

export async function deploymentAccess(project: string, token: string) {
  const result = await machine(
    {
      binary: resolveNativeBinary(),
      environment: {
        TNL_STATE_DIR: undefined,
        TNL_SERVER: undefined,
        TNL_CONNECTION_HANDLE: undefined,
      },
    },
    ["credential"],
    undefined,
    { schema: 1, project, token },
  );
  return parseValue(credentialAccessSchema, result, "sdk.response_invalid");
}

// one registry per explicit deployment handle. existing native selection, IPC,
// transport adapters and stop acknowledgements retain their owning lifetimes.
export function deploymentConnector(
  selection: Omit<NonNullable<SelectionOptions["deployment"]>, "token"> & {
    readonly token?: string;
    readonly handle?: string;
    readonly workload?: WorkloadSource;
  },
) {
  const captured = {
    binary: selection.handle === undefined ? resolveNativeBinary() : "",
    directory: process.cwd(),
    environment: {
      TNL_STATE_DIR: process.env.TNL_STATE_DIR,
      TNL_SERVER: process.env.TNL_SERVER,
      TNL_CONNECTION_HANDLE: undefined,
    },
  };
  let loading: Promise<NativeScope> | undefined;
  let borrowed: Promise<OwnerIPC> | undefined;
  let closed = false;
  let closing: Promise<void> | undefined;
  const closedError = new TnlError("sdk.client_closed");
  const pending = new Set<Promise<unknown>>();
  const http = new Map<string, ReturnType<typeof managedFetch>>();
  const prepareRemoteWork = async (name: string) => {
    if (closed) throw closedError;
    if (selection.token === undefined && selection.handle !== undefined) {
      const file = selection.handle;
      const ipc = await (borrowed ??= ownerIPC(file));
      const prepared = parsePrepared(
        await ipc.prepare(name, undefined, undefined, {
          project: selection.project,
          name: selection.name,
        }),
        name,
        file,
      );
      if (closed) throw closedError;
      return prepared;
    }
    const scope = await (loading ??= nativeScope(captured));
    const requested_at = new Date().toISOString();
    const deployment =
      selection.token === undefined
        ? undefined
        : {
            project: selection.project,
            name: selection.name,
            token: selection.token,
            ...(selection.services === undefined ? {} : { services: selection.services }),
          };
    if (deployment === undefined && selection.workload === undefined)
      throw new TnlError("sdk.configuration_invalid");
    const options: SelectionOptions = {
      ...(deployment === undefined
        ? await selectWorkload(
            (request) => scope.workload(name, request),
            undefined,
            selection.workload,
            {
              project: selection.project,
              name: selection.name,
            },
          )
        : { deployment }),
      requested_at,
    };
    const args = [
      "sdk-prepare",
      "--directory",
      scope.directory,
      "--registry",
      scope.registry,
      "--parent-pid",
      String(process.pid),
      "--requested-at",
      requested_at,
      "--selected-service",
      name,
    ];
    const { requested_at: _requestedAt, ...privateInput } = options;
    const raw = await scope.select(
      args,
      { schema: 1, ...privateInput },
      name,
      options.assertion,
      options,
    );
    const value = parseValue(sdkPreparationSchema, raw, "sdk.response_invalid");
    if ("reason" in value) throw machineError({ stderr: JSON.stringify(value) }, "sdk-prepare");
    if (value.owner.executable !== scope.binary) throw new TnlError("sdk.response_invalid");
    const prepared = parsePrepared(value.prepared, name, value.owner.connection_handle);
    if (scope.entry === undefined)
      scope.entry = { file: prepared.file, ipc: scope.open(prepared.file) };
    if (closed) throw closedError;
    return prepared;
  };
  const prepareRemote = (name: string) => {
    const work = prepareRemoteWork(name);
    pending.add(work);
    void work.then(
      () => pending.delete(work),
      () => pending.delete(work),
    );
    return work;
  };
  return {
    acquire(name: string) {
      if (closed) throw closedError;
      if (pending.size >= 64) throw new TnlError("sdk.connection_unavailable");
      const work = prepareRemote(name).then((prepared) => {
        let fetch: TnlFetch | undefined;
        if (prepared.snapshot.protocol === "http") {
          const url = prepared.snapshot.url;
          let transport = http.get(url);
          if (transport === undefined) {
            transport = managedFetch(
              url,
              async (signal) => (await waitForPreparation(prepareRemote(name), signal)).snapshot,
            );
            http.set(url, transport);
          }
          fetch = transport;
        }
        const { expires: _expires, ...binding } = prepared.snapshot;
        return {
          key: JSON.stringify([prepared.file, binding]),
          connection: settings(prepared.snapshot, fetch),
          protocol: prepared.snapshot.protocol,
        };
      });
      pending.add(work);
      void work.then(
        () => pending.delete(work),
        () => pending.delete(work),
      );
      return work;
    },
    close(): Promise<void> {
      closed = true;
      closing ??= (async () => {
        const operations = await Promise.allSettled(pending);
        const cleanup = async () => {
          if (borrowed !== undefined) (await borrowed).close();
          if (loading !== undefined) {
            const scope = await loading;
            if (scope.close === undefined) throw new TnlError("sdk.response_invalid");
            await scope.close();
          }
        };
        const results = await Promise.allSettled(
          [...http.values()].map((value) => value.close()).concat(cleanup()),
        );
        const failures = [...operations, ...results].flatMap((result) =>
          result.status === "rejected" && result.reason !== closedError
            ? [result.reason as unknown]
            : [],
        );
        if (failures.length)
          throw new AggregateError(failures, "deployment connection cleanup failed");
      })().finally(() => {
        closing = undefined;
      });
      return closing;
    },
  };
}
