import { execFile, execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, realpath } from "node:fs/promises";
import { connect as connectTCP } from "node:net";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { Pool, buildConnector, fetch as transportFetch, type Dispatcher } from "undici/index.js";
import { TnlCleanupError, TnlError } from "../../errors.js";
import type {
  TnlClientFactory,
  TnlClientOptions,
  TnlConnectionHandle,
  TnlConnectionRegistry,
  TnlFetch,
  TnlOptions,
} from "../../project.js";
import { clientFactory } from "./client_factory.js";
import { awaitableConnection } from "./awaitable_connection.js";
import { ownerIPC, prepareExternal } from "./connection_ipc.js";
import { context, contextKey, type NativeScope } from "./context.js";
import { cancellable } from "./cancellation.js";
import type { ConnectionSnapshot } from "./snapshot.js";
import * as z from "zod";
import { parseValue } from "../validation.js";
import { sdkPreparationSchema, preparedConnectionSchema } from "./contract.js";
import {
  usesWorkload,
  selectWorkload,
  parseWorkload,
  workloadRuntime,
  type WorkloadConfiguration,
} from "./workload/provider.js";
import type { SelectionOptions, WorkloadRequest } from "./workload/contract.js";
export { configureWorkload, usesWorkload } from "./workload/provider.js";
import { resolveNativeBinary } from "../native/launcher.js";
import { launchEnvironment, operation, operationSync, independent } from "../tracing.js";
import type { ProjectRuntime } from "../project/runtime.js";
import { isServiceName, pathTextSchema, httpsOriginSchema } from "../values.js";

type Settings = TnlConnectionRegistry[keyof TnlConnectionRegistry];
type Prepared = ReturnType<typeof parsePrepared>;
const maximumBytes = 128 * 1024;
const { scopes, selectedScopes, fetches } = context;
const command = ["--no-telemetry", "runtime", "connections"];

// explicit instances have private native registries, not a mutable current identity.
export interface ConnectionScope {
  readonly key: string;
  readonly directory: string;
  readonly environment: NativeScope["environment"];
  readonly workload?: WorkloadConfiguration;
  readonly runtime: WorkloadRequest["runtime"];
  readonly pending: Set<Promise<unknown>>;
  readonly clients: Set<{ close(): Promise<void> }>;
  readonly fetches: Map<string, ManagedFetch>;
  native?: Promise<NativeScope>;
  closed: boolean;
  closing?: Promise<void>;
  cleanup?: () => Promise<void>;
}

export function createConnectionScope(options: TnlOptions): ConnectionScope {
  const selected = parseValue(
    z.strictObject({
      directory: pathTextSchema.optional(),
      stateDir: pathTextSchema.optional(),
      server: httpsOriginSchema.optional(),
      workload: z.unknown().optional(),
      credential: z.unknown().optional(),
    }),
    options,
    "sdk.configuration_invalid",
  );
  const workload = options.workload === undefined ? undefined : parseWorkload(options.workload);
  const runtime = workloadRuntime();
  if (workload !== undefined) delete runtime.workload;
  const stateDir = selected.stateDir ?? process.env.TNL_STATE_DIR;
  return {
    key: randomUUID(),
    directory: path.resolve(selected.directory ?? process.cwd()),
    environment: {
      TNL_STATE_DIR: stateDir === undefined ? undefined : path.resolve(stateDir),
      TNL_SERVER: selected.server ?? process.env.TNL_SERVER,
      TNL_CONNECTION_HANDLE: undefined,
      TNL_CONFIG: process.env.TNL_CONFIG,
    },
    ...(workload === undefined ? {} : { workload }),
    runtime,
    pending: new Set(),
    clients: new Set(),
    fetches: new Map(),
    closed: false,
  };
}

export function closeConnectionScope(scope: ConnectionScope): Promise<void> {
  scope.closed = true;
  if (scope.closing !== undefined) return scope.closing;
  const closing = (async () => {
    await Promise.allSettled(scope.pending);
    const results = await Promise.allSettled([
      ...[...scope.clients].map((client) => client.close()),
      ...[...scope.fetches.values()].map((fetch) => fetch.close()),
    ]);
    const errors = results.flatMap((result) =>
      result.status === "rejected" ? [result.reason as unknown] : [],
    );
    // drivers may still own sockets after failed cleanup; retain their native owner.
    if (errors.length > 0) throw new AggregateError(errors, "runtime cleanup failed");
    if (scope.native !== undefined) await (await scope.native).stop();
    scope.clients.clear();
    scope.fetches.clear();
  })();
  scope.closing = closing;
  void closing.catch(() => {
    if (scope.closing === closing) delete scope.closing;
  });
  return closing;
}

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
  scope: NativeScope,
  args: string[],
  signal?: AbortSignal,
  input?: unknown,
): Promise<unknown> {
  return operation("sdk.native.command", () => machineUntraced(scope, args, signal, input));
}

async function machineUntraced(
  scope: NativeScope,
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

function machineSync(binary: string, args: string[]): unknown {
  return operationSync("sdk.connect.read", () => machineSyncUntraced(binary, args));
}

function machineSyncUntraced(binary: string, args: string[]): unknown {
  try {
    const value: unknown = JSON.parse(
      execFileSync(binary, [...command, ...args], {
        timeout: 10_000,
        maxBuffer: maximumBytes,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        env: launchEnvironment(),
      }),
    );
    return value;
  } catch (cause) {
    throw machineError(cause);
  }
}

function readArgs(file: string, name: string): string[] {
  if (!path.isAbsolute(file) || file.length > 4096 || file.includes("\0"))
    throw new TnlError("sdk.configuration_invalid");
  // read verifies private handle ownership, expiry and the prepared owner's
  // service scope. it cannot evaluate configuration, start an owner or sign in.
  return ["read", "--handle", file, "--service", name];
}

function nativeScope(key: string, selection?: ConnectionScope): Promise<NativeScope> {
  const binary = resolveNativeBinary();
  const directory = selection?.directory ?? process.cwd();
  const nativeKey = JSON.stringify([key, binary]);
  let loading = scopes.get(nativeKey);
  if (loading === undefined) {
    if (scopes.size >= 32) throw new TnlError("sdk.connection_unavailable");
    // pin the cache key's selection before yielding, not provider inputs or traces.
    const environment = selection?.environment ?? {
      TNL_STATE_DIR: process.env.TNL_STATE_DIR,
      TNL_SERVER: process.env.TNL_SERVER,
      TNL_CONNECTION_HANDLE: process.env.TNL_CONNECTION_HANDLE,
      TNL_CONFIG: process.env.TNL_CONFIG,
    };
    loading = (async () => {
      const scope: NativeScope = {
        directory,
        registry: await mkdtemp(path.join(await realpath(tmpdir()), "tnl-sdk-")),
        binary,
        environment,
        requests: new Map(),
        open: ownerIPC,
        // keep native error classification with the copy that owns this IPC.
        select: (...args) => requestSelection(scope, ...args),
        workload: (name, request) => requestWorkload(scope, name, request),
        stop: async () => {
          await machine(scope, [
            "sdk-stop",
            "--registry",
            scope.registry,
            "--parent-pid",
            String(process.pid),
          ]);
          if (scope.entry !== undefined)
            await scope.entry.ipc.then(
              (ipc) => ipc.close(),
              () => {},
            );
          process.off("beforeExit", beforeExit);
          scopes.delete(nativeKey);
          selectedScopes.get(key)?.delete(binary);
          if (selectedScopes.get(key)?.size === 0) selectedScopes.delete(key);
        },
      };
      const cleanup = independent("sdk.app.cleanup", async () => {
        if (selection === undefined) await scope.stop();
        else if (selection.cleanup !== undefined) await selection.cleanup();
        else await closeConnectionScope(selection);
      });
      const beforeExit = () => {
        void cleanup().catch(() => {});
      };
      process.once("beforeExit", beforeExit);
      let selected = selectedScopes.get(key);
      if (selected === undefined) {
        selected = new Map();
        selectedScopes.set(key, selected);
      }
      selected.set(binary, scope);
      return scope;
    })();
    scopes.set(nativeKey, loading);
  }
  if (selection !== undefined) selection.native = loading;
  return loading;
}

function prepare(
  name: string,
  externalFile?: string,
  selection?: ConnectionScope,
): Promise<Prepared> {
  if (selection?.closed) return Promise.reject(new TnlError("sdk.client_closed"));
  const pending = operation("sdk.connect", async () => {
    const prepared = await prepareUntraced(name, externalFile, selection);
    if (selection?.closed) throw new TnlError("sdk.client_closed");
    return prepared;
  });
  selection?.pending.add(pending);
  void pending.then(
    () => selection?.pending.delete(pending),
    () => selection?.pending.delete(pending),
  );
  return pending;
}

async function prepareUntraced(
  name: string,
  externalFile: string | undefined,
  selection?: ConnectionScope,
): Promise<Prepared> {
  const requestedAt = new Date().toISOString();
  const base = selection?.key ?? contextKey();
  if (externalFile !== undefined) {
    readArgs(externalFile, name);
    return parsePrepared(await prepareExternal(externalFile, name), name, externalFile);
  }
  const workload =
    selection?.workload !== undefined ||
    usesWorkload(base, selection?.runtime, selection === undefined);
  const scope = await nativeScope(base, selection);
  const selectionOptions: SelectionOptions = {
    ...(workload
      ? await selectWorkload(
          (request) => scope.workload(name, request),
          base,
          selection?.workload,
          selection?.runtime,
        )
      : {}),
    requested_at: requestedAt,
  };
  const assertion = selectionOptions.assertion;
  const startArgs = ["--directory", scope.directory];
  const args = [
    "sdk-prepare",
    ...startArgs,
    "--registry",
    scope.registry,
    "--parent-pid",
    String(process.pid),
    "--requested-at",
    requestedAt,
    "--selected-service",
    name,
  ];
  const { requested_at: _requestedAt, ...privateInput } = selectionOptions;
  const input = { schema: 1, ...privateInput };
  // native sources must acquire each request's assertion before owner startup
  // can be coalesced. only an already acquired callback assertion shares a wait.
  const key =
    workload && assertion === undefined
      ? randomUUID()
      : createHash("sha256")
          .update(JSON.stringify([startArgs, name, privateInput]))
          .digest("hex");
  let request = scope.requests.get(key);
  if (request === undefined) {
    if (scope.requests.size >= 64) throw new TnlError("sdk.connection_unavailable");
    request = scope.select(args, input, name, assertion, selectionOptions);
    scope.requests.set(key, request);
  }
  let raw: unknown;
  try {
    raw = await request;
  } finally {
    if (scope.requests.get(key) === request) scope.requests.delete(key);
  }
  const value = parseValue(sdkPreparationSchema, raw, "sdk.response_invalid");
  if ("reason" in value) {
    throw machineError({ stderr: JSON.stringify(value) }, "sdk-prepare");
  }
  const owner = value.owner;
  const file = owner.connection_handle;
  readArgs(file, name);
  if (owner.executable !== scope.binary) throw new TnlError("sdk.response_invalid");
  const prepared = parsePrepared(value.prepared, name, file);
  scope.selected = { file, expiresAt: owner.expires_at };
  if (scope.entry === undefined) {
    const ipc = scope.open(file);
    void ipc.catch(() => {});
    scope.entry = { file, ipc };
  }
  return prepared;
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

function readPrepared(name: string, selection?: ConnectionScope): Prepared {
  const owner =
    selection !== undefined || process.env.TNL_CONNECTION_HANDLE === undefined
      ? selectedScopes.get(selection?.key ?? contextKey())?.get(resolveNativeBinary())?.selected
      : undefined;
  if (owner?.expiresAt !== undefined && owner.expiresAt <= Date.now())
    throw new TnlError("sdk.connection_unprepared");
  const file =
    (selection === undefined ? process.env.TNL_CONNECTION_HANDLE : undefined) ?? owner?.file;
  if (file === undefined) throw new TnlError("sdk.connection_unprepared");
  // a separate native process can use owner IPC while this event loop is blocked.
  // never execute an executable selected by descriptor contents or PATH.
  return parsePrepared(machineSync(resolveNativeBinary(), readArgs(file, name)), name, file);
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

type ManagedFetch = TnlFetch & { close(): Promise<void> };

export function managedFetch(
  url: `https://${string}`,
  current: (signal?: AbortSignal) => Promise<ConnectionSnapshot>,
): ManagedFetch {
  let active = 0;
  let pool: Pool | undefined;
  let dispatcher: Dispatcher | undefined;
  let poolKey: string | undefined;
  const retired = new Set<Pool>();
  let closed = false;
  const fetch: TnlFetch = async (input, init) => {
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
        const connect = buildConnector(snapshot.ssl);
        pool = new Pool(url, {
          connections: 8,
          pipelining: 1,
          headersTimeout: 0,
          bodyTimeout: 0,
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
  return Object.assign(fetch, {
    async close() {
      closed = true;
      await Promise.all(
        [...retired, ...(pool === undefined ? [] : [pool])].map((entry) => entry.close()),
      );
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
  name: string,
  snapshot: ConnectionSnapshot,
  externalFile?: string,
  selection?: ConnectionScope,
): Settings {
  switch (snapshot.protocol) {
    case "tcp":
      return Object.freeze({ host: snapshot.host, port: snapshot.port });
    case "http": {
      const key = JSON.stringify([
        selection?.key ?? contextKey(),
        externalFile === undefined ? resolveNativeBinary() : undefined,
        name,
        snapshot.url,
        externalFile,
      ]);
      const cache = selection?.fetches ?? fetches;
      let fetch = cache.get(key);
      if (fetch === undefined) {
        if (cache.size >= 32) throw new TnlError("sdk.connection_unavailable");
        const managed = managedFetch(snapshot.url, async (signal) => {
          signal?.throwIfAborted();
          const current = await waitForPreparation(prepare(name, externalFile, selection), signal);
          signal?.throwIfAborted();
          return current.snapshot;
        });
        if (selection === undefined) fetches.set(key, managed);
        else selection.fetches.set(key, managed);
        fetch = managed;
      }
      return Object.freeze({
        url: snapshot.url,
        fetch,
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

export function connectionHandle(
  name: string,
  updateProject: (project: ProjectRuntime) => void,
  selection?: ConnectionScope,
): TnlConnectionHandle<Settings> {
  if (selection?.closed) throw new TnlError("sdk.client_closed");
  if (!isServiceName(name)) throw new TnlError("sdk.configuration_invalid");
  const externalFile = selection === undefined ? process.env.TNL_CONNECTION_HANDLE : undefined;
  const result = (prepared: Prepared) => {
    updateProject(prepared.project);
    return settings(name, prepared.snapshot, externalFile, selection);
  };
  return awaitableConnection(
    () => {
      if (selection?.closed) throw new TnlError("sdk.client_closed");
      if (externalFile !== undefined) {
        return result(
          parsePrepared(
            machineSync(resolveNativeBinary(), readArgs(externalFile, name)),
            name,
            externalFile,
          ),
        );
      }
      // a module-shared handle must not select the last request's identity.
      // await yields plain settings; sync workload settings need an explicit file.
      if (
        selection?.workload !== undefined ||
        usesWorkload(selection?.key, selection?.runtime, selection === undefined)
      )
        throw new TnlError("sdk.connection_unprepared");
      return result(readPrepared(name, selection));
    },
    async () => result(await prepare(name, externalFile, selection)),
  );
}

export function connectionClient<Client>(
  name: string,
  options: TnlClientOptions<Settings, Client>,
  updateProject: (project: ProjectRuntime) => void,
  selection?: ConnectionScope,
): TnlClientFactory<Client> {
  if (selection?.closed) throw new TnlError("sdk.client_closed");
  if (!isServiceName(name)) throw new TnlError("sdk.configuration_invalid");
  const externalFile = selection === undefined ? process.env.TNL_CONNECTION_HANDLE : undefined;
  const factory = clientFactory(
    async () => {
      const prepared = await prepare(name, externalFile, selection);
      updateProject(prepared.project);
      const { expires: _expires, ...binding } = prepared.snapshot;
      return {
        key: JSON.stringify([prepared.file, binding]),
        connection: settings(name, prepared.snapshot, externalFile, selection),
      };
    },
    options,
    () => selection?.closed !== true,
  );
  selection?.clients.add(factory);
  return factory;
}
