import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import * as http from "node:http";
import * as path from "node:path";
import { promisify } from "node:util";
import { Agent, Pool } from "undici";
import { TnlError } from "../errors.js";
import type { TnlConnectionRegistry, TnlNativeTLSOptions, TnlFetch } from "../project.js";
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

interface Handle {
  schema: 1;
  url: string;
  key: string;
  directory: string;
  config_digest: string;
  expires_at: string;
  executable: string;
  ci?: string;
  team_id?: string;
}
interface Snapshot {
  protocol: ServiceProtocol;
  host: string;
  port: number;
  ssl?: TnlNativeTLSOptions;
  url?: `https://${string}`;
  kubeconfig?: string;
  context?: string;
  expires: number;
}
const maximumBytes = 128 * 1024;
const starts = new Map<string, Promise<string>>();

async function machine(binary: string, args: string[]): Promise<unknown> {
  try {
    const { stdout } = await promisify(execFile)(
      binary,
      ["--no-telemetry", "runtime", "connections", ...args],
      { timeout: 45_000, maxBuffer: maximumBytes, encoding: "utf8" },
    );
    const value: unknown = JSON.parse(stdout);
    return value;
  } catch (cause) {
    if (
      typeof cause === "object" &&
      cause !== null &&
      "stderr" in cause &&
      typeof cause.stderr === "string"
    ) {
      try {
        const problem = record(JSON.parse(cause.stderr), "native connection diagnostic");
        if (
          problem.reason === "TNL_CLIENT_AUTHENTICATION_REQUIRED" ||
          problem.reason === "TNL_CLIENT_AUTH_RECOVERY_REQUIRED"
        )
          throw new TnlError("sdk.authentication_required");
      } catch (error) {
        if (error instanceof TnlError && error.code === "sdk.authentication_required") throw error;
      }
    }
    throw new TnlError("sdk.connection_unavailable");
  }
}

// only the separate private handle environment variable can select a file.
// TNL_PROJECT_RUNTIME remains browser-safe JSON and never directs filesystem IO.
async function readHandle(file: string): Promise<Handle> {
  try {
    if (!path.isAbsolute(file) || file.includes("\0"))
      throw new TnlError("sdk.configuration_invalid");
    for (let directory = path.dirname(file); ;) {
      const info = await lstat(directory);
      if (
        !info.isDirectory() ||
        info.isSymbolicLink() ||
        ((info.mode & 0o022) !== 0 && (info.mode & 0o1000) === 0)
      )
        throw new TnlError("sdk.configuration_invalid");
      if (directory === path.dirname(directory)) break;
      directory = path.dirname(directory);
    }
    const parent = await lstat(path.dirname(file));
    if ((parent.mode & 0o777) !== 0o700 || parent.uid !== process.getuid?.())
      throw new TnlError("sdk.configuration_invalid");
    const descriptor = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    let value: unknown;
    try {
      const info = await descriptor.stat();
      if (
        !info.isFile() ||
        (info.mode & 0o777) !== 0o600 ||
        info.uid !== process.getuid?.() ||
        info.size > maximumBytes
      )
        throw new TnlError("sdk.configuration_invalid");
      const buffer = Buffer.alloc(maximumBytes + 1);
      const { bytesRead } = await descriptor.read(buffer, 0, buffer.length, 0);
      if (bytesRead > maximumBytes) throw new TnlError("sdk.response_invalid");
      value = JSON.parse(buffer.subarray(0, bytesRead).toString("utf8"));
    } finally {
      await descriptor.close();
    }
    const object = record(value, "private connection handle");
    exactKeys(
      object,
      [
        "schema",
        "url",
        "key",
        "directory",
        "config_digest",
        "expires_at",
        "executable",
        ...["ci", "team_id"].filter((key) => Object.hasOwn(object, key)),
      ],
      "private connection handle",
    );
    if (
      object.schema !== 1 ||
      typeof object.url !== "string" ||
      typeof object.key !== "string" ||
      !/^[a-f0-9]{64}$/.test(object.key) ||
      typeof object.directory !== "string" ||
      !path.isAbsolute(object.directory) ||
      typeof object.executable !== "string" ||
      !path.isAbsolute(object.executable) ||
      typeof object.config_digest !== "string" ||
      !/^[a-f0-9]{64}$/.test(object.config_digest) ||
      typeof object.expires_at !== "string" ||
      !Number.isFinite(Date.parse(object.expires_at)) ||
      Date.parse(object.expires_at) <= Date.now()
    )
      throw new TnlError("sdk.connection_unavailable");
    const endpoint = new URL(object.url);
    if (
      (object.ci === undefined) !== (object.team_id === undefined) ||
      (object.ci !== undefined &&
        (!validServiceName(object.ci) ||
          typeof object.team_id !== "string" ||
          !/^tm_[A-Za-z0-9]{22}$/.test(object.team_id)))
    )
      throw new TnlError("sdk.response_invalid");
    if (
      endpoint.protocol !== "http:" ||
      endpoint.hostname !== "127.0.0.1" ||
      !endpoint.port ||
      Number(endpoint.port) < 1 ||
      Number(endpoint.port) > 65535 ||
      object.url !== `http://127.0.0.1:${endpoint.port}`
    )
      throw new TnlError("sdk.response_invalid");
    return {
      schema: 1,
      url: object.url,
      key: object.key,
      directory: object.directory,
      config_digest: object.config_digest,
      expires_at: object.expires_at,
      executable: object.executable,
      ...(typeof object.ci === "string" && typeof object.team_id === "string"
        ? { ci: object.ci, team_id: object.team_id }
        : {}),
    };
  } catch (error) {
    if (error instanceof TnlError) throw error;
    // malformed descriptors may contain the IPC proof; never retain parse text.
    throw new TnlError("sdk.connection_unavailable");
  }
}

export function connectionRequest(
  handle: Handle,
  operation: "status" | "connect" | "stop",
  service?: string,
  signal?: AbortSignal,
): Promise<unknown> {
  const payload = JSON.stringify({
    schema: 1,
    directory: handle.directory,
    config_digest: handle.config_digest,
    ...(service === undefined ? {} : { service }),
  });
  return new Promise((resolve, reject) => {
    const request = http.request(
      `${handle.url}/v1/connections/${operation}`,
      {
        method: "POST",
        agent: false,
        ...(signal === undefined ? {} : { signal }),
        headers: {
          Authorization: `Bearer ${handle.key}`,
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        let length = 0;
        response.on("data", (chunk: Buffer) => {
          length += chunk.length;
          if (length > maximumBytes) response.destroy();
          else chunks.push(chunk);
        });
        response.on("error", () =>
          reject(signal?.aborted ? signal.reason : new TnlError("sdk.connection_unavailable")),
        );
        response.on("end", () => {
          if (signal?.aborted) {
            reject(signal.reason);
            return;
          }
          try {
            if (
              response.statusCode !== 200 ||
              response.headers["content-type"]?.split(";", 1)[0] !== "application/json"
            )
              throw new TnlError("sdk.connection_unavailable");
            const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            resolve(value);
          } catch (error) {
            reject(error instanceof TnlError ? error : new TnlError("sdk.response_invalid"));
          }
        });
        response.on("close", () => {
          if (!response.complete)
            reject(signal?.aborted ? signal.reason : new TnlError("sdk.connection_unavailable"));
        });
      },
    );
    const timeout = setTimeout(() => request.destroy(), 30_000);
    timeout.unref();
    request.once("close", () => clearTimeout(timeout));
    request.on("error", () =>
      reject(signal?.aborted ? signal.reason : new TnlError("sdk.connection_unavailable")),
    );
    request.end(payload);
  });
}

async function endpoint(name: string): Promise<Handle> {
  let file = process.env.TNL_CONNECTION_HANDLE;
  let localKey: string | undefined;
  if (file === undefined) {
    const key = `${await realpath(process.cwd())}\0${process.env.TNL_STATE_DIR ?? ""}`;
    localKey = key;
    let pending = starts.get(key);
    if (pending === undefined) {
      pending = (async () => {
        const value = record(
          await machine(resolveNativeBinary(), [
            "start",
            "--directory",
            process.cwd(),
            "--parent-pid",
            String(process.pid),
          ]),
          "connection startup",
        );
        if (
          value.schema !== 1 ||
          value.state !== "ready" ||
          typeof value.private_handle !== "string"
        )
          throw new TnlError("sdk.response_invalid");
        const file = value.private_handle;
        process.once("beforeExit", () => {
          void readHandle(file)
            .then((handle) => connectionRequest(handle, "stop"))
            .catch(() => {});
        });
        return file;
      })();
      starts.set(key, pending);
      void pending.catch(() => starts.delete(key));
    }
    file = await pending;
  }
  let handle: Handle;
  try {
    handle = await readHandle(file);
  } catch (error) {
    if (localKey !== undefined) starts.delete(localKey);
    throw error;
  }
  const args = ["context", "--directory", process.cwd(), "--service", name];
  if (handle.ci !== undefined && handle.team_id !== undefined)
    args.push("--ci", handle.ci, "--team-id", handle.team_id);
  const scope = record(await machine(handle.executable, args), "connection context");
  if (
    scope.schema !== 1 ||
    scope.directory !== handle.directory ||
    scope.config_digest !== handle.config_digest
  )
    throw new TnlError("sdk.configuration_invalid");
  return handle;
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
    typeof object.host !== "string" ||
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
    requiredHostname(object.host, "managed service hostname");
    const tls = record(object.ssl, "native TLS");
    exactKeys(
      tls,
      [
        "servername",
        "rejectUnauthorized",
        ...["ca", "cert", "key"].filter((key) => Object.hasOwn(tls, key)),
      ],
      "native TLS",
    );
    if (
      tls.servername !== object.host ||
      tls.rejectUnauthorized !== true ||
      [tls.ca, tls.cert, tls.key].some(
        (value) =>
          value !== undefined &&
          (typeof value !== "string" || value.length === 0 || value.length > 32 * 1024),
      ) ||
      (tls.cert === undefined) !== (tls.key === undefined)
    )
      throw new TnlError("sdk.response_invalid");
    ssl = {
      servername: object.host,
      rejectUnauthorized: true,
      ...(typeof tls.ca === "string" ? { ca: tls.ca } : {}),
      ...(typeof tls.cert === "string" && typeof tls.key === "string"
        ? { cert: tls.cert, key: tls.key }
        : {}),
    };
  } else if (object.host !== "127.0.0.1" || object.ssl !== undefined)
    throw new TnlError("sdk.response_invalid");
  const url =
    object.protocol === "http" || object.protocol === "kubernetes"
      ? (`https://${object.host}${object.port === 443 ? "" : `:${object.port}`}` as const)
      : undefined;
  if ((url !== undefined && object.url !== url) || (url === undefined && object.url !== undefined))
    throw new TnlError("sdk.response_invalid");
  if (
    object.protocol === "kubernetes" &&
    (typeof object.kubeconfig !== "string" ||
      !path.isAbsolute(object.kubeconfig) ||
      typeof object.context !== "string" ||
      !object.context.startsWith("tnl:"))
  )
    throw new TnlError("sdk.response_invalid");
  if (
    object.protocol !== "kubernetes" &&
    (object.kubeconfig !== undefined || object.context !== undefined)
  )
    throw new TnlError("sdk.response_invalid");
  return {
    protocol: object.protocol,
    host: object.host,
    port: object.port,
    expires: Date.parse(object.expires_at),
    ...(ssl === undefined ? {} : { ssl }),
    ...(url === undefined ? {} : { url }),
    ...(typeof object.kubeconfig === "string" && typeof object.context === "string"
      ? { kubeconfig: object.kubeconfig, context: object.context }
      : {}),
  };
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
      const lifetime = AbortSignal.any([request.signal, AbortSignal.timeout(30_000)]);
      lifetime.throwIfAborted();
      const snapshot = await current(lifetime);
      if (snapshot.url !== url || snapshot.ssl === undefined)
        throw new TnlError("sdk.response_invalid");
      const ssl = snapshot.ssl;
      dispatcher = new Agent({
        factory(origin, options) {
          if (String(origin) !== url) throw new TnlError("sdk.configuration_invalid");
          return new Pool(origin, {
            ...options,
            connections: 1,
            pipelining: 1,
            headersTimeout: 30_000,
            bodyTimeout: 30_000,
            connect: ssl,
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

export async function connectService(name: string): Promise<{
  project: ProjectRuntime;
  connection: TnlConnectionRegistry[keyof TnlConnectionRegistry];
}> {
  if (!validServiceName(name)) throw new TnlError("sdk.configuration_invalid");
  const handle = await endpoint(name);
  const status = record(await connectionRequest(handle, "status"), "connection status");
  if (status.schema !== 1 || status.state !== "ready") throw new TnlError("sdk.response_invalid");
  const project = parseProjectRuntime(status.public_runtime, "connection project");
  const current = async (signal?: AbortSignal) => {
    const snapshot = parseConnection(await connectionRequest(handle, "connect", name, signal));
    const metadata = project.services[name];
    if (
      metadata === undefined ||
      metadata.protocol !== snapshot.protocol ||
      metadata.port !== snapshot.port ||
      (snapshot.protocol !== "tcp" && metadata.hostname !== snapshot.host)
    )
      throw new TnlError("sdk.response_invalid");
    return snapshot;
  };
  const snapshot = await current();
  if (snapshot.protocol === "tcp")
    return { project, connection: { host: snapshot.host, port: snapshot.port } };
  if (snapshot.protocol === "http" && snapshot.url !== undefined)
    return {
      project,
      connection: { url: snapshot.url, fetch: managedFetch(snapshot.url, current) },
    };
  if (
    snapshot.protocol === "kubernetes" &&
    snapshot.url !== undefined &&
    snapshot.kubeconfig !== undefined &&
    snapshot.context !== undefined
  )
    return {
      project,
      connection: {
        server: snapshot.url,
        kubeconfig: snapshot.kubeconfig,
        context: snapshot.context,
      },
    };
  if (
    (snapshot.protocol === "postgres" || snapshot.protocol === "mysql") &&
    snapshot.ssl !== undefined
  )
    return { project, connection: { host: snapshot.host, port: snapshot.port, ssl: snapshot.ssl } };
  throw new TnlError("sdk.response_invalid");
}
