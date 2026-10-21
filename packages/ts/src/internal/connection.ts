import { execFile, execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import * as path from "node:path";
import { promisify } from "node:util";
import { Agent, Pool, buildConnector } from "undici";
import { TnlCleanupError, TnlError } from "../errors.js";
import type {
  TnlConnectionHandle,
  TnlConnectionRegistry,
  TnlNativeTLSOptions,
  TnlFetch,
} from "../project.js";
import { awaitableConnection } from "./awaitable_connection.js";
import { resolveNativeBinary } from "./launcher.js";
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
}
type Settings = TnlConnectionRegistry[keyof TnlConnectionRegistry];
interface Prepared {
  readonly project: ProjectRuntime;
  readonly snapshot: Snapshot;
  readonly file: string;
}
interface OwnedConnection {
  readonly file: string;
  readonly binary: string;
  readonly onExit: () => void;
  ready: boolean;
  failure?: { readonly error: unknown };
  stopping?: Promise<void>;
}
const maximumBytes = 128 * 1024;
const owners = new Map<string, OwnedConnection>();
const pending = new Map<string, Promise<Prepared>>();
const command = ["--no-telemetry", "runtime", "connections"];

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

async function machine(binary: string, args: string[], signal?: AbortSignal): Promise<unknown> {
  try {
    const { stdout } = await promisify(execFile)(binary, [...command, ...args], {
      timeout: args[0] === "start" ? 45_000 : args[0] === "stop" ? 25_000 : 10_000,
      maxBuffer: maximumBytes,
      encoding: "utf8",
      ...(signal === undefined ? {} : { signal }),
    });
    const value: unknown = JSON.parse(stdout);
    return value;
  } catch (cause) {
    if (signal?.aborted) throw signal.reason;
    throw machineError(cause);
  }
}

function machineSync(binary: string, args: string[]): unknown {
  try {
    const value: unknown = JSON.parse(
      execFileSync(binary, [...command, ...args], {
        timeout: 10_000,
        maxBuffer: maximumBytes,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }),
    );
    return value;
  } catch (cause) {
    throw machineError(cause);
  }
}

function cacheKey(name: string): string {
  try {
    return JSON.stringify([
      realpathSync(process.cwd()),
      process.env.TNL_STATE_DIR,
      process.env.TNL_SERVER,
      process.env.TNL_CONNECTION_HANDLE,
      name,
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

async function prepare(name: string): Promise<Prepared> {
  const key = cacheKey(name);
  let operation = pending.get(key);
  if (operation !== undefined) return operation;
  operation = (async () => {
    const binary = resolveNativeBinary();
    const externalFile = process.env.TNL_CONNECTION_HANDLE;
    if (externalFile !== undefined)
      return parsePrepared(await machine(binary, readArgs(externalFile, name)), name, externalFile);
    let owner = owners.get(key);
    if (owner?.failure !== undefined) {
      // a failed stop retains ownership and blocks replacement until joined.
      await rollbackOwner(key, owner, owner.failure.error);
      owner = undefined;
    }
    // a failed read does not prove an established owner stopped; other clients
    // may still be using its listener, so retries keep the same capability.
    if (owner !== undefined)
      return parsePrepared(await machine(binary, readArgs(owner.file, name)), name, owner.file);

    const value = record(
      await machine(binary, [
        "start",
        "--directory",
        process.cwd(),
        "--service",
        name,
        "--parent-pid",
        String(process.pid),
      ]),
      "connection startup",
    );
    const file = value.private_handle;
    if (typeof file !== "string") throw new TnlError("sdk.response_invalid");
    readArgs(file, name);
    const startedOwner: OwnedConnection = {
      binary,
      file,
      ready: false,
      onExit: () => {
        void stopOwner(key, startedOwner).catch(() => {});
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
      const prepared = parsePrepared(await machine(binary, readArgs(file, name)), name, file);
      startedOwner.ready = true;
      return prepared;
    } catch (error) {
      await rollbackOwner(key, startedOwner, error);
      throw error;
    }
  })();
  pending.set(key, operation);
  try {
    return await operation;
  } finally {
    pending.delete(key);
  }
}

function readPrepared(name: string): Prepared {
  const owner =
    process.env.TNL_CONNECTION_HANDLE === undefined ? owners.get(cacheKey(name)) : undefined;
  const file =
    process.env.TNL_CONNECTION_HANDLE ?? (owner?.ready === true ? owner.file : undefined);
  if (file === undefined) throw new TnlError("sdk.connection_unprepared");
  // a separate native process can use owner IPC while this event loop is blocked.
  // never execute an executable selected by descriptor contents or PATH.
  return parsePrepared(machineSync(resolveNativeBinary(), readArgs(file, name)), name, file);
}

function parsePrepared(value: unknown, name: string, file: string): Prepared {
  const object = record(value, "prepared connection");
  exactKeys(object, ["schema", "public_runtime", "connection"], "prepared connection");
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
  return Object.freeze({ project, snapshot, file });
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
      ...["ssl", "url", "kubeconfig", "context"].filter((key) => Object.hasOwn(object, key)),
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
  return async (input, init) => {
    if (active >= 64) throw new TnlError("sdk.connection_unavailable");
    active++;
    let dispatcher: Agent | undefined;
    try {
      const request = new Request(
        input instanceof Request ? input : new URL(String(input), `${url}/`),
        init,
      );
      if (new URL(request.url).origin !== url) throw new TnlError("sdk.configuration_invalid");
      request.headers.set("host", new URL(url).host);
      const lifetime = AbortSignal.any([request.signal, AbortSignal.timeout(30_000)]);
      lifetime.throwIfAborted();
      const snapshot = await current(lifetime);
      if (snapshot.url !== url || snapshot.ssl === undefined || snapshot.expires <= Date.now())
        throw new TnlError("sdk.response_invalid");
      const connect = buildConnector(snapshot.ssl);
      dispatcher = new Agent({
        factory(origin, options) {
          if (String(origin) !== url) throw new TnlError("sdk.configuration_invalid");
          return new Pool(origin, {
            ...options,
            connections: 1,
            pipelining: 1,
            headersTimeout: 30_000,
            bodyTimeout: 30_000,
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
        },
      });
      const options: RequestInit & { dispatcher: Agent } = {
        dispatcher,
        signal: AbortSignal.any([
          lifetime,
          AbortSignal.timeout(Math.max(1, Math.min(30_000, snapshot.expires - Date.now()))),
        ]),
      };
      return await globalThis.fetch(request, options);
    } finally {
      if (dispatcher === undefined) active--;
      else
        void dispatcher
          .close()
          .catch(() => {})
          .finally(() => {
            active--;
          });
    }
  };
}

function settings(name: string, file: string, snapshot: Snapshot): Settings {
  if (snapshot.protocol === "tcp")
    return Object.freeze({ host: snapshot.host, port: snapshot.port });
  if (snapshot.protocol === "http" && snapshot.url !== undefined) {
    return Object.freeze({
      url: snapshot.url,
      fetch: managedFetch(snapshot.url, async (signal) => {
        return parsePrepared(
          await machine(resolveNativeBinary(), readArgs(file, name), signal),
          name,
          file,
        ).snapshot;
      }),
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
  if (
    (snapshot.protocol === "postgres" || snapshot.protocol === "mysql") &&
    snapshot.ssl !== undefined
  )
    return Object.freeze({ host: snapshot.host, port: snapshot.port, ssl: snapshot.ssl });
  throw new TnlError("sdk.response_invalid");
}

export function connectionHandle(
  name: string,
  updateProject: (project: ProjectRuntime) => void,
): TnlConnectionHandle<Settings> {
  if (!validServiceName(name)) throw new TnlError("sdk.configuration_invalid");
  const result = (prepared: Prepared) => {
    updateProject(prepared.project);
    return settings(name, prepared.file, prepared.snapshot);
  };
  return awaitableConnection(
    () => result(readPrepared(name)),
    async () => result(await prepare(name)),
  );
}
