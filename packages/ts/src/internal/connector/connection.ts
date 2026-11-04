import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, realpath } from "node:fs/promises";
import { connect as connectTCP } from "node:net";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { Pool, buildConnector, fetch as transportFetch, type Dispatcher } from "undici/index.js";
import { TnlCleanupError, TnlError } from "../../errors.js";
import type { TnlConnectionHandle, TnlConnectionRegistry, TnlFetch } from "../../project.js";
import { awaitableConnection } from "./awaitable_connection.js";
import { ownerIPC, prepareExternal } from "./connection_ipc.js";
import { context, contextKey, type NativeScope } from "./context.js";
import { cancellable } from "./cancellation.js";
import type { ConnectionSnapshot } from "./snapshot.js";
import * as z from "zod";
import { parseValue } from "../validation.js";
import { sdkPreparationSchema, preparedConnectionSchema } from "./contract.js";
import { usesWorkload, selectWorkload, acquireAssertion } from "./workload/provider.js";
export { configureWorkload } from "./workload/provider.js";
import { resolveNativeBinary } from "../native/launcher.js";
import { launchEnvironment, operation, operationSync, independent } from "../tracing.js";
import type { ProjectRuntime } from "../project/runtime.js";
import { isServiceName } from "../values.js";

type Settings = TnlConnectionRegistry[keyof TnlConnectionRegistry];
type Prepared = ReturnType<typeof parsePrepared>;
const maximumBytes = 128 * 1024;
const { scopes, selectedScopes, fetches } = context;
const command = ["--no-telemetry", "runtime", "connections"];

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
  binary: string,
  args: string[],
  signal?: AbortSignal,
  input?: unknown,
): Promise<unknown> {
  return operation("sdk.native.command", () => machineUntraced(binary, args, signal, input));
}

async function machineUntraced(
  binary: string,
  args: string[],
  signal?: AbortSignal,
  input?: unknown,
): Promise<unknown> {
  try {
    const stdout = await new Promise<string>((resolve, reject) => {
      const child = execFile(
        binary,
        [...command, ...args],
        {
          timeout: args[0] === "sdk-prepare" ? 45_000 : 25_000,
          maxBuffer: maximumBytes,
          encoding: "utf8",
          env: launchEnvironment(),
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

function nativeScope(key: string): Promise<NativeScope> {
  const binary = resolveNativeBinary();
  const nativeKey = JSON.stringify([key, binary]);
  let loading = scopes.get(nativeKey);
  if (loading === undefined) {
    if (scopes.size >= 32) throw new TnlError("sdk.connection_unavailable");
    loading = (async () => {
      const scope: NativeScope = {
        registry: await mkdtemp(path.join(await realpath(tmpdir()), "tnl-sdk-")),
        binary,
        requests: new Map(),
        open: ownerIPC,
        // keep native error classification with the copy that owns this IPC.
        select: (...args) => requestSelection(scope, ...args),
      };
      const cleanup = independent("sdk.app.cleanup", async () => {
        await machine(scope.binary, [
          "sdk-stop",
          "--registry",
          scope.registry,
          "--parent-pid",
          String(process.pid),
        ]);
        if (scope.entry !== undefined) (await scope.entry.ipc).close();
      });
      process.once("beforeExit", () => {
        void cleanup().catch(() => {});
      });
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
  const scope = await nativeScope(base);
  let assertion: string | undefined;
  let manifest: unknown;
  let selectionOptions: { workload?: string; manifest?: string; requested_at: string } = {
    requested_at: requestedAt,
  };
  let startArgs = ["--directory", process.cwd()];
  if (usesWorkload()) {
    const selection = await selectWorkload();
    manifest = selection.manifest;
    if (!selection.selected.services.includes(name)) throw new TnlError("sdk.workload_denied");
    assertion = await acquireAssertion(
      selection.name,
      selection.selected,
      selection.directory,
      AbortSignal.timeout(10_000),
    );
    startArgs = [
      "--directory",
      selection.directory,
      "--workload",
      selection.name,
      "--workload-manifest",
      path.join(selection.directory, ".tnl/generated/workloads.json"),
    ];
    selectionOptions = {
      requested_at: requestedAt,
      workload: selection.name,
      manifest: path.join(selection.directory, ".tnl/generated/workloads.json"),
    };
  }
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
  const input = { schema: 1, ...(assertion === undefined ? {} : { assertion }) };
  const key = createHash("sha256")
    .update(JSON.stringify([startArgs, name, manifest, assertion]))
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
  selectionOptions: { workload?: string; manifest?: string; requested_at: string },
): Promise<unknown> {
  const entry = scope.entry;
  let raw: unknown;
  if (entry === undefined) raw = await machine(scope.binary, args, undefined, input);
  else {
    try {
      raw = await (await entry.ipc).prepare(name, assertion, selectionOptions);
    } catch (cause) {
      // native recovery checks the kernel lock before doing any selection or
      // network work. a timeout or service denial cannot authorize replacement.
      try {
        raw = await machine(
          scope.binary,
          [...args, "--recover-handle", entry.file],
          undefined,
          input,
        );
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

export function managedFetch(
  url: `https://${string}`,
  current: (signal?: AbortSignal) => Promise<ConnectionSnapshot>,
): TnlFetch {
  let active = 0;
  let pool: Pool | undefined;
  let dispatcher: Dispatcher | undefined;
  let poolKey: string | undefined;
  const retired = new Set<Pool>();
  return async (input, init) => {
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

function settings(name: string, snapshot: ConnectionSnapshot, externalFile?: string): Settings {
  switch (snapshot.protocol) {
    case "tcp":
      return Object.freeze({ host: snapshot.host, port: snapshot.port });
    case "http": {
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
