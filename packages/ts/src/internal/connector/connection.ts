import { execFile, execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, realpath } from "node:fs/promises";
import { connect as connectTCP } from "node:net";
import { tmpdir } from "node:os";
import * as path from "node:path";
import type { Pool, Dispatcher } from "undici/index.js";
import { TnlCleanupError, TnlError } from "../../errors.js";
import type {
  TnlClientFactory,
  TnlClientOptions,
  TnlConnectionHandle,
  TnlConnectionRegistry,
  TnlFetch,
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
import { usesWorkload, selectWorkload } from "./workload/provider.js";
import type { SelectionOptions, WorkloadRequest } from "./workload/contract.js";
export { configureWorkload } from "./workload/provider.js";
import { resolveNativeBinary } from "../native/launcher.js";
import { launchEnvironment, operation, operationSync, independent } from "../tracing.js";
import type { ProjectRuntime } from "../project/runtime.js";
import { isServiceName } from "../values.js";

type Settings = TnlConnectionRegistry[keyof TnlConnectionRegistry];
type Prepared = ReturnType<typeof parsePrepared>;
const maximumBytes = 128 * 1024;
const { scopes, selectedScopes, fetches } = context;
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

function nativeScope(
  key: string,
  captured?: { binary: string; directory: string; environment: NativeScope["environment"] },
): Promise<NativeScope> {
  const binary = captured?.binary ?? resolveNativeBinary();
  const directory = captured?.directory ?? process.cwd();
  const nativeKey = JSON.stringify([key, binary]);
  let loading = scopes.get(nativeKey);
  if (loading === undefined) {
    if (scopes.size >= 32) throw new TnlError("sdk.connection_unavailable");
    // pin the cache key's selection before yielding, not provider inputs or traces.
    const environment = captured?.environment ?? {
      TNL_STATE_DIR: process.env.TNL_STATE_DIR,
      TNL_SERVER: process.env.TNL_SERVER,
      TNL_CONNECTION_HANDLE: process.env.TNL_CONNECTION_HANDLE,
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
  return loading;
}

function prepare(name: string, externalFile?: string): Promise<Prepared> {
  return operation("sdk.connect", () => prepareUntraced(name, externalFile));
}

async function prepareUntraced(name: string, externalFile: string | undefined): Promise<Prepared> {
  const requestedAt = new Date().toISOString();
  const base = contextKey();
  if (externalFile !== undefined) {
    readArgs(externalFile, name);
    return parsePrepared(await prepareExternal(externalFile, name), name, externalFile);
  }
  const workload = usesWorkload(base);
  const scope = await nativeScope(base);
  const selectionOptions: SelectionOptions = {
    ...(workload ? await selectWorkload((request) => scope.workload(name, request), base) : {}),
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

function readPrepared(name: string): Prepared {
  const owner =
    process.env.TNL_CONNECTION_HANDLE === undefined
      ? selectedScopes.get(contextKey())?.get(resolveNativeBinary())?.selected
      : undefined;
  if (owner?.expiresAt !== undefined && owner.expiresAt <= Date.now())
    throw new TnlError("sdk.connection_unprepared");
  const file = process.env.TNL_CONNECTION_HANDLE ?? owner?.file;
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

function settings(
  name: string,
  snapshot: ConnectionSnapshot,
  externalFile?: string,
  boundFetch?: TnlFetch,
): Settings {
  switch (snapshot.protocol) {
    case "tcp":
      return Object.freeze({ host: snapshot.host, port: snapshot.port });
    case "http": {
      if (boundFetch !== undefined) return Object.freeze({ url: snapshot.url, fetch: boundFetch });
      const key = JSON.stringify([
        contextKey(),
        externalFile === undefined ? resolveNativeBinary() : undefined,
        name,
        snapshot.url,
        externalFile,
      ]);
      let fetch = fetches.get(key);
      if (fetch === undefined) {
        if (fetches.size >= 32) throw new TnlError("sdk.connection_unavailable");
        fetch = managedFetch(snapshot.url, async (signal) => {
          signal?.throwIfAborted();
          const current = await waitForPreparation(prepare(name, externalFile), signal);
          signal?.throwIfAborted();
          return current.snapshot;
        });
        fetches.set(key, fetch);
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
): TnlConnectionHandle<Settings> {
  if (!isServiceName(name)) throw new TnlError("sdk.configuration_invalid");
  const externalFile = process.env.TNL_CONNECTION_HANDLE;
  const result = (prepared: Prepared) => {
    updateProject(prepared.project);
    return settings(name, prepared.snapshot, externalFile);
  };
  return awaitableConnection(
    () => {
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
      if (usesWorkload()) throw new TnlError("sdk.connection_unprepared");
      return result(readPrepared(name));
    },
    async () => result(await prepare(name, externalFile)),
  );
}

export function connectionClient<Client>(
  name: string,
  options: TnlClientOptions<Settings, Client>,
  updateProject: (project: ProjectRuntime) => void,
): TnlClientFactory<Client> {
  if (!isServiceName(name)) throw new TnlError("sdk.configuration_invalid");
  const externalFile = process.env.TNL_CONNECTION_HANDLE;
  return clientFactory(async () => {
    const prepared = await prepare(name, externalFile);
    updateProject(prepared.project);
    const { expires: _expires, ...binding } = prepared.snapshot;
    return {
      key: JSON.stringify([prepared.file, binding]),
      connection: settings(name, prepared.snapshot, externalFile),
    };
  }, options);
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
export function deploymentConnector(selection: NonNullable<SelectionOptions["deployment"]>) {
  const key = `deployment:${randomUUID()}`;
  const captured = {
    binary: resolveNativeBinary(),
    directory: process.cwd(),
    environment: {
      TNL_STATE_DIR: process.env.TNL_STATE_DIR,
      TNL_SERVER: process.env.TNL_SERVER,
      TNL_CONNECTION_HANDLE: undefined,
    },
  };
  let loading: Promise<NativeScope> | undefined;
  let closed = false;
  let closing: Promise<void> | undefined;
  const closedError = new TnlError("sdk.client_closed");
  const pending = new Set<Promise<unknown>>();
  const http = new Map<string, ReturnType<typeof managedFetch>>();
  const prepareRemoteWork = async (name: string) => {
    if (closed) throw closedError;
    const scope = await (loading ??= nativeScope(key, captured));
    const requested_at = new Date().toISOString();
    const options: SelectionOptions = { requested_at, deployment: selection };
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
    const raw = await scope.select(
      args,
      { schema: 1, deployment: selection },
      name,
      undefined,
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
          connection: settings(name, prepared.snapshot, prepared.file, fetch),
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
          if (loading !== undefined) {
            const scope = await loading;
            if (scope.close === undefined) throw new TnlError("sdk.response_invalid");
            await scope.close();
            scopes.delete(JSON.stringify([key, scope.binary]));
            selectedScopes.delete(key);
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
