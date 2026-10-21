import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { connect as connectTCP } from "node:net";
import * as path from "node:path";
import { Pool, buildConnector, fetch as transportFetch, type Dispatcher } from "undici/index.js";
import { TnlCleanupError, TnlError } from "../errors.js";
import type {
  TnlConnectionHandle,
  TnlConnectionRegistry,
  TnlNativeTLSOptions,
  TnlFetch,
} from "../project.js";
import { awaitableConnection } from "./awaitable_connection.js";
import { ownerIPC, prepareExternal, type OwnerIPC } from "./connection_ipc.js";
import { cancellable } from "./cancellation.js";
import { usesWorkload, selectWorkload, acquireAssertion } from "./workload_provider.js";
export { configureWorkload } from "./workload_provider.js";
import { resolveNativeBinary } from "./launcher.js";
import { launchEnvironment, operation, operationSync, independent } from "./tracing.js";
import {
  exactKeys,
  record,
  parseProjectRuntime,
  requiredHostname,
  validServiceName,
  type ProjectRuntime,
  type ServiceProtocol,
} from "./runtime.js";

interface Snapshot {
  readonly protocol: ServiceProtocol;
  readonly host: "127.0.0.1";
  readonly port: number;
  readonly ssl?: TnlNativeTLSOptions;
  readonly url?: `https://${string}`;
  readonly kubeconfig?: string;
  readonly context?: string;
  readonly expires: number;
  readonly transportID?: string;
}
type Settings = TnlConnectionRegistry[keyof TnlConnectionRegistry];
interface Prepared {
  readonly project: ProjectRuntime;
  readonly snapshot: Snapshot;
  readonly file: string;
  readonly verification?: {
    readonly digest: string;
    readonly binding: string;
    readonly expires: number;
  };
}
interface OwnedConnection {
  readonly file: string;
  readonly binary: string;
  readonly onExit: () => void;
  ready: boolean;
  expiresAt?: number;
  failure?: { readonly error: unknown };
  stopping?: Promise<void>;
  ipc?: Promise<OwnerIPC>;
}
const maximumBytes = 128 * 1024;
const owners = new Map<string, OwnedConnection>();
const pending = new Map<string, Promise<Prepared>>();
const starting = new Map<string, Promise<OwnedConnection>>();
const selectedOwners = new Map<string, OwnedConnection>();
const fetches = new Map<string, TnlFetch>();
const command = ["--no-telemetry", "runtime", "connections"];
const contexts = new Map<string, Promise<unknown>>();
const approvals = new Map<string, { key: string; expires: number }>();
const identities = new Map<
  string,
  Promise<{ context: unknown; binding: string; expires?: number }>
>();
const digest = (value: string) => createHash("sha256").update(value).digest("hex");

async function prepareIPC(
  owner: OwnedConnection,
  name: string,
  assertion?: string,
): Promise<Prepared> {
  try {
    const loading = (owner.ipc ??= ownerIPC(owner.file));
    let ipc: OwnerIPC;
    try {
      ipc = await loading;
    } catch (cause) {
      if (owner.ipc === loading) delete owner.ipc;
      throw cause;
    }
    return parsePrepared(await ipc.prepare(name, assertion), name, owner.file);
  } catch (cause) {
    if (cause instanceof TnlError) throw cause;
    throw machineError(cause);
  }
}

function machineError(cause: unknown): TnlError {
  // native stderr and JSON parser errors can contain private input; retain only
  // an owned classification, never subprocess output or a credential-bearing cause.
  if (typeof cause === "object" && cause !== null && "stderr" in cause) {
    try {
      const stderr = cause.stderr;
      const problem = record(
        JSON.parse(typeof stderr === "string" ? stderr : ""),
        "native diagnostic",
      );
      if (
        problem.reason === "TNL_CLIENT_AUTHENTICATION_REQUIRED" ||
        problem.reason === "TNL_CLIENT_AUTH_RECOVERY_REQUIRED"
      )
        return new TnlError("sdk.authentication_required");
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
          timeout: args[0] === "start" ? 45_000 : args[0] === "stop" ? 25_000 : 10_000,
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
    throw machineError(cause);
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

function cacheKey(): string {
  try {
    return JSON.stringify([
      realpathSync(process.cwd()),
      process.env.TNL_STATE_DIR,
      process.env.TNL_SERVER,
      process.env.TNL_CONNECTION_HANDLE,
      // service preparation is incremental within one identity/policy owner.
    ]);
  } catch {
    throw new TnlError("sdk.configuration_invalid");
  }
}

function readArgs(file: string, name: string): string[] {
  if (!path.isAbsolute(file) || file.length > 4096 || file.includes("\0"))
    throw new TnlError("sdk.configuration_invalid");
  // read verifies private handle ownership, expiry and the prepared owner's
  // service scope. it cannot evaluate configuration, start an owner or sign in.
  return ["read", "--handle", file, "--service", name];
}

async function stopOwner(key: string, owner: OwnedConnection): Promise<void> {
  const stopping =
    owner.stopping ??
    (owner.stopping = (async () => {
      const value = record(
        await machine(owner.binary, ["stop", "--handle", owner.file]),
        "connection cleanup",
      );
      exactKeys(value, ["schema", "state"], "connection cleanup");
      if (value.schema !== 1 || value.state !== "stopped")
        throw new TnlError("sdk.response_invalid");
      if (owners.get(key) === owner) owners.delete(key);
      if (owner.ipc !== undefined)
        void owner.ipc.then(
          (ipc) => ipc.close(),
          () => {},
        );
      process.removeListener("beforeExit", owner.onExit);
    })());
  try {
    await stopping;
  } finally {
    if (owner.stopping === stopping) delete owner.stopping;
  }
}

async function rollbackOwner(key: string, owner: OwnedConnection, error: unknown): Promise<void> {
  owner.failure = { error };
  try {
    // cleanup has its own lifetime: a canceled read must not abandon an owner.
    await stopOwner(key, owner);
  } catch (cleanupError) {
    throw new TnlCleanupError(error, cleanupError);
  }
}

function prepare(name: string, externalFile?: string): Promise<Prepared> {
  return operation("sdk.connect", () => prepareUntraced(name, externalFile));
}

async function prepareUntraced(name: string, externalFile: string | undefined): Promise<Prepared> {
  const base = cacheKey();
  if (externalFile !== undefined) {
    readArgs(externalFile, name);
    return parsePrepared(await prepareExternal(externalFile, name), name, externalFile);
  }
  const binary = resolveNativeBinary();
  let key = base;
  let assertion: string | undefined;
  let context: unknown;
  let approvalKey: string | undefined;
  let policyKey: string | undefined;
  let bindingKey: ((binding: string) => string) | undefined;
  let startArgs = ["--directory", process.cwd()];
  if (usesWorkload()) {
    const selection = await selectWorkload();
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
    policyKey = JSON.stringify([base, selection.name, selection.manifest]);
    bindingKey = (binding) => JSON.stringify([base, selection.name, selection.manifest, binding]);
    approvalKey = JSON.stringify([policyKey, digest(assertion)]);
    const approved = approvals.get(approvalKey);
    if (approved !== undefined && approved.expires > Date.now()) {
      key = approved.key;
      context = await contexts.get(policyKey);
    } else {
      let identifying = identities.get(approvalKey);
      if (identifying === undefined) {
        if (identities.size >= 128) throw new TnlError("sdk.workload_unavailable");
        identifying = (async () => {
          let selectedContext = contexts.get(policyKey);
          if (selectedContext === undefined) {
            if (contexts.size >= 32) throw new TnlError("sdk.workload_unavailable");
            selectedContext = machine(binary, ["context", ...startArgs]);
            contexts.set(policyKey, selectedContext);
          }
          let nativeContext: unknown;
          try {
            nativeContext = await selectedContext;
          } catch (error) {
            contexts.delete(policyKey);
            throw error;
          }
          const identity = record(
            await machine(binary, ["identity", ...startArgs], undefined, {
              schema: 1,
              context: nativeContext,
              assertion,
            }),
            "workload identity",
          );
          exactKeys(
            identity,
            [
              "schema",
              "binding",
              ...(Object.hasOwn(identity, "assertion_expires_at") ? ["assertion_expires_at"] : []),
            ],
            "workload identity",
          );
          if (
            identity.schema !== 1 ||
            typeof identity.binding !== "string" ||
            !/^[0-9a-f]{64}$/.test(identity.binding)
          )
            throw new TnlError("sdk.workload_response_invalid");
          let expires: number | undefined;
          if (Object.hasOwn(identity, "assertion_expires_at")) {
            if (
              typeof identity.assertion_expires_at !== "string" ||
              !Number.isFinite(Date.parse(identity.assertion_expires_at)) ||
              Date.parse(identity.assertion_expires_at) <= Date.now() ||
              Date.parse(identity.assertion_expires_at) > Date.now() + 12 * 3600_000 + 60_000
            )
              throw new TnlError("sdk.workload_response_invalid");
            expires = Date.parse(identity.assertion_expires_at);
          }
          return {
            context: nativeContext,
            binding: identity.binding,
            ...(expires === undefined ? {} : { expires }),
          };
        })();
        identities.set(approvalKey, identifying);
      }
      let identified: Awaited<typeof identifying>;
      try {
        identified = await identifying;
      } finally {
        if (identities.get(approvalKey) === identifying) identities.delete(approvalKey);
      }
      context = identified.context;
      key = bindingKey(identified.binding);
      if (identified.expires !== undefined) {
        if (approvals.size >= 256) {
          const oldest = approvals.keys().next().value;
          if (oldest !== undefined) approvals.delete(oldest);
        }
        approvals.set(approvalKey, { key, expires: identified.expires - 1000 });
      }
    }
  }
  const approve = (prepared: Prepared): Prepared => {
    if (
      approvalKey !== undefined &&
      prepared.verification !== undefined &&
      assertion !== undefined
    ) {
      const v = prepared.verification;
      if (v.digest !== digest(assertion) || bindingKey?.(v.binding) !== key)
        throw new TnlError("sdk.workload_response_invalid");
      for (const [id, entry] of approvals) if (entry.expires <= Date.now()) approvals.delete(id);
      if (approvals.size >= 256 && !approvals.has(approvalKey)) {
        const oldest = approvals.keys().next().value;
        if (oldest !== undefined) approvals.delete(oldest);
      }
      approvals.set(approvalKey, { key, expires: v.expires - 1000 });
    }
    return prepared;
  };
  const pendingKey = JSON.stringify([key, name]);
  let operation = assertion === undefined ? pending.get(pendingKey) : undefined;
  if (operation !== undefined) return operation;
  operation = (async () => {
    let owner = owners.get(key);
    if (owner?.failure !== undefined) {
      // a failed stop retains ownership and blocks replacement until joined.
      await rollbackOwner(key, owner, owner.failure.error);
      owner = undefined;
    }
    if (owner?.expiresAt !== undefined && owner.expiresAt <= Date.now()) {
      // only a validated owner deadline permits replacement. native stop joins
      // even when deadline cleanup already removed the live handle file.
      owner.ready = false;
      await stopOwner(key, owner);
      owner = undefined;
    }
    // a failed read does not prove an established owner stopped; other clients
    // may still be using its listener, so retries keep the same capability.
    if (owner !== undefined) {
      try {
        const prepared = await prepareIPC(owner, name, assertion);
        selectedOwners.set(base, owner);
        return approve(prepared);
      } catch (error) {
        // only a kernel-held lifetime lock can distinguish owner death from a
        // failed/denied read. a live owner's listener is never duplicated.
        try {
          const recovered = record(
            await machine(binary, ["recover", "--handle", owner.file]),
            "owner recovery",
          );
          exactKeys(recovered, ["schema", "state"], "owner recovery");
          if (recovered.schema !== 1 || recovered.state !== "stopped")
            throw new TnlError("sdk.response_invalid");
        } catch {
          throw error;
        }
        if (owners.get(key) === owner) owners.delete(key);
        if (owner.ipc !== undefined)
          void owner.ipc.then(
            (ipc) => ipc.close(),
            () => {},
          );
        process.removeListener("beforeExit", owner.onExit);
      }
    }
    // another waiter may have completed recovery while this waiter proved the
    // old owner dead. adopt that replacement before considering another start.
    const replacement = owners.get(key);
    if (replacement !== undefined && replacement !== owner) {
      if (!replacement.ready || replacement.failure !== undefined)
        throw new TnlError("sdk.connection_unavailable");
      const prepared = await prepareIPC(replacement, name, assertion);
      selectedOwners.set(base, replacement);
      return approve(prepared);
    }
    let startup = starting.get(key);
    if (startup === undefined) {
      if (owners.size + starting.size >= 32) throw new TnlError("sdk.workload_unavailable");
      startup = (async () => {
        const value = record(
          await machine(
            binary,
            ["start", ...startArgs, "--parent-pid", String(process.pid)],
            undefined,
            assertion === undefined ? undefined : { schema: 1, context, assertion },
          ),
          "connection startup",
        );
        const file = value.private_handle;
        if (typeof file !== "string") throw new TnlError("sdk.response_invalid");
        readArgs(file, name);
        const exitCleanup = independent("sdk.app.cleanup", () => stopOwner(key, startedOwner));
        const startedOwner: OwnedConnection = {
          binary,
          file,
          ready: false,
          onExit: () => {
            void exitCleanup().catch(() => {});
          },
        };
        owners.set(key, startedOwner);
        process.once("beforeExit", startedOwner.onExit);
        try {
          exactKeys(
            value,
            [
              "schema",
              "state",
              "pid",
              "expires_at",
              "public_runtime",
              "private_handle",
              "executable",
              ...(Object.hasOwn(value, "kubeconfig") ? ["kubeconfig"] : []),
            ],
            "connection startup",
          );
          if (
            value.schema !== 1 ||
            value.state !== "ready" ||
            typeof value.private_handle !== "string" ||
            typeof value.pid !== "number" ||
            !Number.isSafeInteger(value.pid) ||
            value.pid <= 0 ||
            typeof value.expires_at !== "string" ||
            !Number.isFinite(Date.parse(value.expires_at)) ||
            Date.parse(value.expires_at) <= Date.now() ||
            typeof value.executable !== "string" ||
            !path.isAbsolute(value.executable) ||
            (Object.hasOwn(value, "kubeconfig") &&
              (typeof value.kubeconfig !== "string" || !path.isAbsolute(value.kubeconfig)))
          )
            throw new TnlError("sdk.response_invalid");
          parseProjectRuntime(value.public_runtime, "connection startup project");
          startedOwner.expiresAt = Date.parse(value.expires_at);
          startedOwner.ready = true;
          return startedOwner;
        } catch (error) {
          await rollbackOwner(key, startedOwner, error);
          throw error;
        }
      })();
      starting.set(key, startup);
    }
    let started: OwnedConnection;
    try {
      started = await startup;
    } finally {
      if (starting.get(key) === startup) starting.delete(key);
    }
    try {
      const prepared = await prepareIPC(started, name, assertion);
      selectedOwners.set(base, started);
      return approve(prepared);
    } catch (error) {
      if (error instanceof TnlError && error.code === "sdk.response_invalid")
        await rollbackOwner(key, started, error);
      throw error;
    }
  })();
  if (assertion === undefined) pending.set(pendingKey, operation);
  try {
    return await operation;
  } finally {
    if (assertion === undefined) pending.delete(pendingKey);
  }
}

function readPrepared(name: string): Prepared {
  const owner =
    process.env.TNL_CONNECTION_HANDLE === undefined ? selectedOwners.get(cacheKey()) : undefined;
  if (owner?.expiresAt !== undefined && owner.expiresAt <= Date.now())
    throw new TnlError("sdk.connection_unprepared");
  const file =
    process.env.TNL_CONNECTION_HANDLE ?? (owner?.ready === true ? owner.file : undefined);
  if (file === undefined) throw new TnlError("sdk.connection_unprepared");
  // a separate native process can use owner IPC while this event loop is blocked.
  // never execute an executable selected by descriptor contents or PATH.
  return parsePrepared(machineSync(resolveNativeBinary(), readArgs(file, name)), name, file);
}

function parsePrepared(value: unknown, name: string, file: string): Prepared {
  const object = record(value, "prepared connection");
  exactKeys(
    object,
    [
      "schema",
      "public_runtime",
      "connection",
      ...(Object.hasOwn(object, "verification") ? ["verification"] : []),
    ],
    "prepared connection",
  );
  if (object.schema !== 1) throw new TnlError("sdk.response_invalid");
  const project = parseProjectRuntime(object.public_runtime, "connection project");
  const snapshot = parseConnection(object.connection);
  const metadata = project.services[name];
  if (
    metadata === undefined ||
    metadata.protocol !== snapshot.protocol ||
    (snapshot.ssl !== undefined && metadata.hostname !== snapshot.ssl.servername) ||
    (snapshot.url !== undefined && metadata.url !== snapshot.url)
  )
    throw new TnlError("sdk.response_invalid");
  let verification: Prepared["verification"];
  if (Object.hasOwn(object, "verification")) {
    const v = record(object.verification, "assertion verification");
    exactKeys(v, ["digest", "binding", "expires_at"], "assertion verification");
    if (
      typeof v.digest !== "string" ||
      !/^[0-9a-f]{64}$/.test(v.digest) ||
      typeof v.binding !== "string" ||
      !/^[0-9a-f]{64}$/.test(v.binding) ||
      typeof v.expires_at !== "string" ||
      !Number.isFinite(Date.parse(v.expires_at)) ||
      Date.parse(v.expires_at) <= Date.now() ||
      Date.parse(v.expires_at) > Date.now() + 12 * 3600_000 + 60_000
    )
      throw new TnlError("sdk.response_invalid");
    verification = { digest: v.digest, binding: v.binding, expires: Date.parse(v.expires_at) };
  }
  return Object.freeze({
    project,
    snapshot,
    file,
    ...(verification === undefined ? {} : { verification }),
  });
}

export function parseConnection(value: unknown): Snapshot {
  const object = record(value, "private connection response");
  exactKeys(
    object,
    [
      "schema",
      "protocol",
      "host",
      "port",
      "expires_at",
      ...["ssl", "url", "kubeconfig", "context", "transport_id"].filter((key) =>
        Object.hasOwn(object, key),
      ),
    ],
    "private connection response",
  );
  if (
    object.schema !== 1 ||
    !(
      object.protocol === "http" ||
      object.protocol === "postgres" ||
      object.protocol === "mysql" ||
      object.protocol === "tcp" ||
      object.protocol === "kubernetes"
    ) ||
    object.host !== "127.0.0.1" ||
    typeof object.port !== "number" ||
    !Number.isInteger(object.port) ||
    object.port < 1 ||
    object.port > 65535 ||
    typeof object.expires_at !== "string" ||
    !Number.isFinite(Date.parse(object.expires_at)) ||
    Date.parse(object.expires_at) <= Date.now()
  )
    throw new TnlError("sdk.response_invalid");
  if (
    Object.hasOwn(object, "transport_id") &&
    (typeof object.transport_id !== "string" || !/^ctg_[A-Za-z0-9]{22}$/.test(object.transport_id))
  )
    throw new TnlError("sdk.response_invalid");
  let ssl: TnlNativeTLSOptions | undefined;
  if (object.protocol !== "tcp") {
    const tls = record(object.ssl, "native TLS");
    exactKeys(
      tls,
      ["servername", "rejectUnauthorized", ...(Object.hasOwn(tls, "ca") ? ["ca"] : [])],
      "native TLS",
    );
    const servername = requiredHostname(tls.servername, "managed service hostname");
    if (
      tls.rejectUnauthorized !== true ||
      (Object.hasOwn(tls, "ca") &&
        (typeof tls.ca !== "string" || tls.ca.length === 0 || tls.ca.length > 32 * 1024))
    )
      throw new TnlError("sdk.response_invalid");
    ssl = Object.freeze({
      servername,
      rejectUnauthorized: true,
      ...(typeof tls.ca === "string" ? { ca: tls.ca } : {}),
    });
  } else if (Object.hasOwn(object, "ssl")) throw new TnlError("sdk.response_invalid");
  let url: `https://${string}` | undefined;
  if (object.protocol === "http" || object.protocol === "kubernetes") {
    if (typeof object.url !== "string" || ssl === undefined)
      throw new TnlError("sdk.response_invalid");
    try {
      const endpoint = new URL(object.url);
      if (
        endpoint.protocol !== "https:" ||
        endpoint.hostname !== ssl.servername ||
        object.url !== endpoint.origin
      )
        throw new TnlError("sdk.response_invalid");
      url = object.url as `https://${string}`;
    } catch {
      throw new TnlError("sdk.response_invalid");
    }
  } else if (Object.hasOwn(object, "url")) throw new TnlError("sdk.response_invalid");
  if (object.protocol === "kubernetes") {
    if (
      typeof object.kubeconfig !== "string" ||
      !path.isAbsolute(object.kubeconfig) ||
      object.kubeconfig.length > 4096 ||
      object.kubeconfig.includes("\0") ||
      typeof object.context !== "string" ||
      !object.context.startsWith("tnl:") ||
      object.context.length > 1024
    )
      throw new TnlError("sdk.response_invalid");
  } else if (Object.hasOwn(object, "kubeconfig") || Object.hasOwn(object, "context"))
    throw new TnlError("sdk.response_invalid");
  return Object.freeze({
    protocol: object.protocol,
    host: object.host,
    port: object.port,
    expires: Date.parse(object.expires_at),
    ...(typeof object.transport_id === "string" ? { transportID: object.transport_id } : {}),
    ...(ssl === undefined ? {} : { ssl }),
    ...(url === undefined ? {} : { url }),
    ...(typeof object.kubeconfig === "string" && typeof object.context === "string"
      ? { kubeconfig: object.kubeconfig, context: object.context }
      : {}),
  });
}

export function managedFetch(
  url: `https://${string}`,
  current: (signal?: AbortSignal) => Promise<Snapshot>,
): TnlFetch {
  let active = 0;
  let pool: Pool | undefined;
  let dispatcher: Dispatcher | undefined;
  let poolKey: string | undefined;
  const retired = new Set<Pool>();
  let legacyGeneration = 0;
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
      if (snapshot.url !== url || snapshot.ssl === undefined || snapshot.expires <= Date.now())
        throw new TnlError("sdk.response_invalid");
      // unknown older snapshots never authorize reuse of a prior transport.
      const nextKey = JSON.stringify([
        snapshot.host,
        snapshot.port,
        snapshot.ssl,
        snapshot.transportID ?? ++legacyGeneration,
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
            if (options.protocol !== "https:" || options.hostname !== snapshot.ssl?.servername)
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

function settings(name: string, snapshot: Snapshot, externalFile?: string): Settings {
  if (snapshot.protocol === "tcp")
    return Object.freeze({ host: snapshot.host, port: snapshot.port });
  if (snapshot.protocol === "http" && snapshot.url !== undefined) {
    const key = JSON.stringify([cacheKey(), name, snapshot.url, externalFile]);
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
  if (
    snapshot.protocol === "kubernetes" &&
    snapshot.url !== undefined &&
    snapshot.kubeconfig !== undefined &&
    snapshot.context !== undefined
  )
    return Object.freeze({
      server: `https://${snapshot.host}:${snapshot.port}`,
      kubeconfig: snapshot.kubeconfig,
      context: snapshot.context,
    });
  if (snapshot.protocol === "mysql" && snapshot.ssl !== undefined)
    // mysql2 verifies config.host, ignoring ssl.servername. its supported stream
    // factory keeps each pool connection on loopback without changing TLS identity.
    // both mysql drivers mutate ssl; never hand a driver the frozen wire snapshot.
    return Object.freeze({
      host: snapshot.ssl.servername,
      port: snapshot.port,
      ssl: { ...snapshot.ssl, verifyIdentity: true as const },
      stream: () => connectTCP({ host: snapshot.host, port: snapshot.port }),
    });
  if (snapshot.protocol === "postgres" && snapshot.ssl !== undefined)
    return Object.freeze({
      host: snapshot.host,
      port: snapshot.port,
      ssl: snapshot.ssl,
    });
  throw new TnlError("sdk.response_invalid");
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
  if (!validServiceName(name)) throw new TnlError("sdk.configuration_invalid");
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
