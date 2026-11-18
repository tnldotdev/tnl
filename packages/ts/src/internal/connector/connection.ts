import { execFile } from "node:child_process";
import { mkdtemp, realpath } from "node:fs/promises";
import { connect as connectTCP } from "node:net";
import { tmpdir } from "node:os";
import * as path from "node:path";
import type { Pool, Dispatcher } from "undici/index.js";
import { TnlCleanupError, TnlError } from "../../errors.js";
import type {
  TnlConnectionRegistry,
  TnlFetch,
  TnlOpenStream,
  TnlTLSStream,
} from "../../project.js";
import { nativeStreams } from "./native_stream.js";
import { ownerIPC, type OwnerIPC } from "./connection_ipc.js";
import type { NativeScope } from "./context.js";
import { cancellable, shutdownBudget } from "./cancellation.js";
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
  let exited: Promise<void> | undefined;
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
          killSignal: "SIGKILL",
        },
        (error, stdout, stderr) =>
          error === null
            ? resolve(stdout)
            : reject(Object.assign(error, stderr === undefined ? {} : { stderr })),
      );
      exited = new Promise<void>((resolve) => {
        child.once("close", () => resolve());
      });
      child.stdin?.on?.("error", () => {
        /* execFile reports the process failure without exposing pipe data. */
      });
      child.stdin?.end(input === undefined ? undefined : JSON.stringify(input));
    });
    const value: unknown = JSON.parse(stdout);
    return value;
  } catch (cause) {
    if (
      signal?.aborted &&
      (cause === signal.reason ||
        (cause instanceof Error &&
          cause.name === "AbortError" &&
          "code" in cause &&
          cause.code === "ABORT_ERR" &&
          cause.cause === signal.reason))
    )
      throw signal.reason;
    throw machineError(cause, args[0]);
  } finally {
    await exited;
  }
}

async function nativeScope(captured: {
  binary: string;
  directory: string;
  environment: NativeScope["environment"];
}): Promise<NativeScope> {
  const lifetime = new AbortController();
  const scope: NativeScope = {
    ...captured,
    registry: await mkdtemp(path.join(await realpath(tmpdir()), "tnl-sdk-")),
    open: ownerIPC,
    signal: lifetime.signal,
    // keep native error classification with the copy that owns this IPC.
    select: (...args) => requestSelection(scope, ...args),
    workload: (name, request) => requestWorkload(scope, name, request),
  };
  let shutdownUntil: number | undefined;
  let stopReason = new TnlError("sdk.client_closed");
  const cleanup = independent("sdk.app.cleanup", async () => {
    const budget = shutdownBudget(shutdownUntil);
    shutdownUntil = budget.until;
    lifetime.abort(stopReason);
    const failures: unknown[] = [];
    let closedEntry: NativeScope["entry"];
    const closeIPC = async () => {
      if (scope.entry === undefined || scope.entry === closedEntry) return;
      closedEntry = scope.entry;
      try {
        (await closedEntry.ipc).close(stopReason);
      } catch (cause) {
        failures.push(cause);
      }
    };
    try {
      await closeIPC();
      await machine(
        scope,
        [
          "sdk-stop",
          "--registry",
          scope.registry,
          "--parent-pid",
          String(process.pid),
          "--shutdown-deadline",
          new Date(budget.until).toISOString(),
        ],
        budget.signal,
      );
    } catch (cause) {
      failures.push(cause);
    } finally {
      budget.finish();
      await closeIPC();
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1) throw new AggregateError(failures, "native and IPC cleanup failed");
  });
  const beforeExit = () => {
    void cleanup().catch(() => {});
  };
  scope.close = async (until, reason) => {
    if (reason !== undefined) stopReason = reason;
    shutdownUntil = Math.min(shutdownUntil ?? Infinity, until ?? Infinity);
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
  if (entry === undefined) raw = await machine(scope, args, scope.signal, input);
  else {
    try {
      raw = await (await entry.ipc).prepare(name, assertion, selectionOptions);
    } catch (cause) {
      // native recovery checks the kernel lock before doing any selection or
      // network work. a timeout or service denial cannot authorize replacement.
      try {
        raw = await machine(scope, [...args, "--recover-handle", entry.file], scope.signal, input);
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
      scope.signal,
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
      snapshot.url !== `https://${metadata.hostname}`)
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
  parent?: () => number | undefined,
): TnlFetch & { close(): Promise<void> } {
  let active = 0;
  let closed = false;
  let pool: Pool | undefined;
  let dispatcher: Dispatcher | undefined;
  let poolKey: string | undefined;
  const retired = new Set<Pool>();
  const uploads = new Set<(reason?: unknown) => Promise<void>>();
  const copies = new Set<Promise<void>>();
  const uploadLifetime = new AbortController();
  let shutdownUntil: number | undefined;
  const joinCancellation = async (callback: Promise<void>) => {
    // observe late application failures even when the shutdown fence wins.
    const settled = Promise.allSettled([callback]);
    const [result] = await cancellable(uploadLifetime.signal, () => settled);
    if (result.status === "rejected") throw result.reason;
  };
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
    let cancelUpload: ((reason?: unknown) => Promise<void>) | undefined;
    let uploadFailure: { value: unknown } | undefined;
    let uploadStopped = false;
    try {
      const requestOptions: RequestInit & { duplex?: "half" } = {
        ...init,
        ...(init?.body instanceof ReadableStream ? { duplex: "half" } : {}),
      };
      request = new Request(
        input instanceof Request ? input : new URL(String(input), `${url}/`),
        requestOptions,
      );
      const lifetime = request.signal;
      const body = request.body;
      const reader = body?.getReader();
      if (reader !== undefined) {
        let canceling: Promise<void> | undefined;
        const cancel = (reason?: unknown) => {
          if (canceling === undefined) {
            uploadStopped = true;
            // interrupt a pending read directly: returning the generator cannot do it.
            canceling = joinCancellation(reader.cancel(reason)).finally(() => {
              lifetime.removeEventListener("abort", aborted);
              reader.releaseLock();
            });
            // retain a failed cleanup until the request or transport owner observes it.
            void canceling.then(
              () => uploads.delete(cancel),
              () => {},
            );
          }
          return canceling;
        };
        const aborted = () => {
          void cancel(lifetime.reason).catch(() => {});
        };
        cancelUpload = cancel;
        uploads.add(cancel);
        lifetime.addEventListener("abort", aborted, { once: true });
        if (lifetime.aborted) aborted();
      }
      if (new URL(request.url).origin !== url) throw new TnlError("sdk.configuration_invalid");
      request.headers.set("host", new URL(url).host);
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
      lifetime.throwIfAborted();
      if (closed) throw new TnlError("sdk.client_closed");
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
      async function* upload() {
        if (reader === undefined) return;
        const copied = Promise.withResolvers<void>();
        copies.add(copied.promise);
        try {
          for (;;) {
            if (uploadStopped) return;
            const chunk = await reader.read();
            if (chunk.done || uploadStopped) return;
            lifetime.throwIfAborted();
            yield chunk.value;
          }
        } catch (error) {
          uploadFailure = { value: error };
          throw error;
        } finally {
          try {
            await cancelUpload?.();
          } finally {
            copies.delete(copied.promise);
            copied.resolve();
          }
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
      const responseReader = response.body?.getReader();
      const stream =
        responseReader === undefined
          ? null
          : new ReadableStream<Uint8Array>({
              async pull(controller) {
                try {
                  const chunk = await responseReader.read();
                  if (chunk.done) {
                    controller.close();
                    responseReader.releaseLock();
                  } else controller.enqueue(chunk.value);
                } catch (error) {
                  controller.error(error);
                  responseReader.releaseLock();
                }
              },
              async cancel(reason: unknown) {
                try {
                  await responseReader.cancel(reason);
                } finally {
                  responseReader.releaseLock();
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
      const failure = uploadFailure === undefined ? error : uploadFailure.value;
      try {
        if (cancelUpload !== undefined) await cancelUpload(failure);
        else if (!dispatched && request?.body !== null && request?.body !== undefined)
          await joinCancellation(request.body.cancel(failure));
      } catch (cleanup) {
        if (cleanup !== failure) throw new TnlCleanupError(failure, cleanup);
      } finally {
        if (cancelUpload !== undefined) uploads.delete(cancelUpload);
      }
      throw failure;
    } finally {
      active--;
    }
  };
  return Object.assign(run, {
    async close() {
      closed = true;
      const budget = shutdownBudget(shutdownUntil ?? parent?.());
      shutdownUntil = budget.until;
      const stopUploads = () =>
        uploadLifetime.abort(
          new DOMException(
            "upload cancellation timed out; application cleanup did not finish",
            "TimeoutError",
          ),
        );
      budget.signal.addEventListener("abort", stopUploads, { once: true });
      if (budget.signal.aborted) stopUploads();
      try {
        const results = await Promise.allSettled([
          ...[...uploads].map((cancel) => cancel(new TnlError("sdk.client_closed"))),
          ...[...retired, ...(pool === undefined ? [] : [pool])].map((value) => value.destroy()),
        ]);
        await Promise.all(copies);
        const failures = results.flatMap((result) =>
          result.status === "rejected" ? [result.reason as unknown] : [],
        );
        if (failures.length) throw new AggregateError(failures, "HTTP transport cleanup failed");
      } finally {
        budget.signal.removeEventListener("abort", stopUploads);
        budget.finish();
      }
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

function settings(
  snapshot: ConnectionSnapshot,
  open: TnlOpenStream<TnlTLSStream>,
  boundFetch?: TnlFetch,
): Settings {
  switch (snapshot.protocol) {
    case "tcp":
      return Object.freeze({ host: snapshot.host, port: snapshot.port, open });
    case "http": {
      if (boundFetch === undefined) throw new TnlError("sdk.response_invalid");
      return Object.freeze({
        url: snapshot.url,
        fetch: boundFetch,
        open,
      });
    }
    case "kubernetes":
      return Object.freeze({
        server: `https://${snapshot.host}:${snapshot.port}`,
        kubeconfig: snapshot.kubeconfig,
        context: snapshot.context,
        open,
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
        open,
      });
    case "postgres":
      return Object.freeze({
        host: snapshot.host,
        port: snapshot.port,
        ssl: snapshot.ssl,
        open,
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
  let closedError = new TnlError("sdk.client_closed");
  let shutdownUntil: number | undefined;
  const pending = new Set<Promise<unknown>>();
  const http = new Map<string, ReturnType<typeof managedFetch>>();
  const openers = new Map<string, TnlOpenStream<TnlTLSStream>>();
  const streams = nativeStreams();
  const prepareRemoteWork = async (name: string) => {
    if (closed) throw closedError;
    if (selection.token === undefined && selection.handle !== undefined) {
      const file = selection.handle;
      if (borrowed === undefined) {
        const opening = ownerIPC(file);
        borrowed = opening;
        // retry only this captured capability after an initialization failure.
        // the original promise still reports the error to its waiting callers.
        void opening.catch(() => {
          if (borrowed === opening) borrowed = undefined;
        });
      }
      const ipc = await borrowed;
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
    if (scope.entry === undefined) {
      const ipc = scope.open(prepared.file);
      void ipc.catch(() => {});
      scope.entry = { file: prepared.file, ipc };
    }
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
        const protocol = prepared.snapshot.protocol;
        let fetch: TnlFetch | undefined;
        if (prepared.snapshot.protocol === "http") {
          const url = prepared.snapshot.url;
          let transport = http.get(url);
          if (transport === undefined) {
            transport = managedFetch(
              url,
              async (signal) => (await waitForPreparation(prepareRemote(name), signal)).snapshot,
              () => shutdownUntil,
            );
            http.set(url, transport);
          }
          fetch = transport;
        }
        const { expires: _expires, ...binding } = prepared.snapshot;
        const openerKey = JSON.stringify([name, protocol]);
        let open = openers.get(openerKey);
        if (open === undefined) {
          open = streams.open(async (signal) => {
            const selected = await waitForPreparation(prepareRemote(name), signal);
            if (selected.snapshot.protocol !== protocol) throw new TnlError("sdk.response_invalid");
            return selected.snapshot;
          });
          openers.set(openerKey, open);
        }
        return {
          key: JSON.stringify([prepared.file, binding]),
          connection: settings(prepared.snapshot, open, fetch),
          protocol,
        };
      });
      pending.add(work);
      void work.then(
        () => pending.delete(work),
        () => pending.delete(work),
      );
      return work;
    },
    close(until?: number, reason?: TnlError): Promise<void> {
      closed = true;
      shutdownUntil ??= until ?? Date.now() + 10_000;
      if (reason !== undefined) closedError = reason;
      closing ??= (async () => {
        const cleanup = async () => {
          if (borrowed !== undefined) (await borrowed).close(closedError);
          if (loading !== undefined) {
            const scope = await loading;
            if (scope.close === undefined) throw new TnlError("sdk.response_invalid");
            await scope.close(shutdownUntil, closedError);
          }
        };
        // capture in-flight operations before shutdown can settle and remove them.
        const results = await Promise.allSettled([
          ...pending,
          ...[...http.values()].map((value) => value.close()),
          streams.close(closedError),
          cleanup(),
        ]);
        const failures = new Set(
          results.flatMap((result) =>
            result.status === "rejected" && result.reason !== closedError
              ? [result.reason as unknown]
              : [],
          ),
        );
        if (failures.size)
          throw new AggregateError(failures, "deployment connection cleanup failed");
      })().finally(() => {
        closing = undefined;
      });
      return closing;
    },
  };
}
