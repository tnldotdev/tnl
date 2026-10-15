import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import * as http from "node:http";
import { isIP } from "node:net";
import * as path from "node:path";
import { promisify } from "node:util";
import { TnlError } from "../errors.js";
import { resolveNativeBinary } from "./launcher.js";
import { exactKeys, record, validServiceName } from "./runtime.js";

export interface RuntimeEndpoint {
  readonly version: 1;
  readonly url: string;
  readonly capability: string;
  readonly owner_id: string;
  readonly scope: "app" | "invocation";
  readonly service?: string;
  readonly invocation_id?: string;
}

export interface EndpointSelection {
  readonly service?: string | undefined;
  readonly invocationID?: string | undefined;
  readonly stateDir?: string;
}

export function allowedKeys(
  object: Record<string, unknown>,
  keys: readonly string[],
  description: string,
): void {
  exactKeys(
    object,
    keys.filter((key) => Object.hasOwn(object, key)),
    description,
  );
}

function validComposeAuthority(value: string): boolean {
  const hostname = /^http:\/\/([A-Za-z0-9][A-Za-z0-9._-]{0,127}):8123$/.exec(value)?.[1];
  return hostname !== undefined && isIP(hostname) === 0;
}

export function parseEndpoint(
  value: unknown,
  selection: EndpointSelection = {},
  composeAuthority?: string,
): RuntimeEndpoint {
  try {
    const object = record(value, "local publisher endpoint");
    allowedKeys(
      object,
      ["version", "url", "capability", "owner_id", "scope", "service", "invocation_id"],
      "local publisher endpoint",
    );
    if (
      object.version !== 1 ||
      typeof object.url !== "string" ||
      object.url.length > 128 ||
      typeof object.capability !== "string" ||
      !/^[a-f0-9]{64}$/.test(object.capability) ||
      typeof object.owner_id !== "string" ||
      !/^[a-f0-9]{32}$/.test(object.owner_id)
    )
      throw new TnlError("sdk.response_invalid");
    const url = new URL(object.url);
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    const port = object.url.match(/:([1-9][0-9]{0,4})$/)?.[1];
    if (
      url.protocol !== "http:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.search !== "" ||
      url.hash !== "" ||
      port === undefined ||
      Number(port) > 65535 ||
      object.url !== `http://${url.hostname}:${port}` ||
      !(
        (isIP(hostname) === 4 && hostname.startsWith("127.")) ||
        hostname === "::1" ||
        (object.scope === "app" &&
          composeAuthority !== undefined &&
          validComposeAuthority(composeAuthority) &&
          object.url === composeAuthority)
      )
    )
      throw new TnlError("sdk.response_invalid");
    if (object.scope === "app") {
      if (
        !validServiceName(object.service) ||
        object.invocation_id !== undefined ||
        selection.invocationID !== undefined ||
        (selection.service !== undefined && object.service !== selection.service)
      )
        throw new TnlError("sdk.response_invalid");
      return Object.freeze({
        version: 1,
        url: object.url,
        capability: object.capability,
        owner_id: object.owner_id,
        scope: "app",
        service: object.service,
      });
    }
    if (
      object.scope !== "invocation" ||
      object.service !== undefined ||
      typeof object.invocation_id !== "string" ||
      !/^ivk_[A-Za-z0-9]{22}$/.test(object.invocation_id) ||
      selection.service !== undefined ||
      selection.invocationID !== object.invocation_id
    )
      throw new TnlError("sdk.response_invalid");
    return Object.freeze({
      version: 1,
      url: object.url,
      capability: object.capability,
      owner_id: object.owner_id,
      scope: "invocation",
      invocation_id: object.invocation_id,
    });
  } catch {
    // descriptors contain capabilities; never attach their contents to errors.
    throw new TnlError("sdk.response_invalid");
  }
}

async function readEndpoint(file: string, selection: EndpointSelection): Promise<RuntimeEndpoint> {
  if (!path.isAbsolute(file) || file.includes("\0"))
    throw new TnlError("sdk.configuration_invalid");
  const parent = await lstat(path.dirname(file));
  if (!parent.isDirectory() || parent.mode & 0o077 || parent.uid !== process.getuid?.())
    throw new TnlError("sdk.configuration_invalid");
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await handle.stat();
    if (
      !info.isFile() ||
      info.mode & 0o077 ||
      info.uid !== process.getuid?.() ||
      info.size > 64 * 1024
    )
      throw new TnlError("sdk.configuration_invalid");
    const buffer = Buffer.alloc(64 * 1024 + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > 64 * 1024) throw new TnlError("sdk.response_invalid");
    return parseEndpoint(
      JSON.parse(buffer.subarray(0, bytesRead).toString("utf8")),
      selection,
      process.env.TNL_APP_AUTHORITY,
    );
  } finally {
    await handle.close();
  }
}

async function waitMountedEndpoint(
  file: string,
  selection: EndpointSelection,
): Promise<RuntimeEndpoint> {
  const deadline = Date.now() + 30_000;
  for (;;) {
    try {
      const endpoint = await readEndpoint(file, selection);
      await runtimeRequest(endpoint, "health");
      return endpoint;
    } catch (cause) {
      const missing =
        typeof cause === "object" && cause !== null && "code" in cause && cause.code === "ENOENT";
      if (!missing) throw cause;
      if (Date.now() >= deadline) throw new TnlError("sdk.dev_unavailable");
      await new Promise<void>((resolve) => setTimeout(resolve, 200));
    }
  }
}

export async function startRuntime(
  directory: string,
  binary?: string,
  selection: EndpointSelection = {},
): Promise<RuntimeEndpoint> {
  try {
    let endpoint: RuntimeEndpoint;
    const mounted = process.env.TNL_APP_ENDPOINT;
    if (mounted !== undefined) {
      return await waitMountedEndpoint(mounted, selection);
    } else {
      const args = ["--no-telemetry", "runtime", "endpoint", "--directory", directory];
      const stateDir = selection.stateDir ?? process.env.TNL_STATE_DIR;
      if (stateDir !== undefined) args.push("--state-dir", stateDir);
      if (selection.service !== undefined) args.push("--service", selection.service);
      if (selection.invocationID !== undefined)
        args.push("--invocation-id", selection.invocationID);
      const { stdout } = await promisify(execFile)(binary ?? resolveNativeBinary(), args, {
        timeout: 30_000,
        maxBuffer: 64 * 1024,
        encoding: "utf8",
      });
      endpoint = parseEndpoint(JSON.parse(stdout), selection);
    }
    await runtimeRequest(endpoint, "health");
    return endpoint;
  } catch (cause) {
    if (cause instanceof TnlError) throw cause;
    throw new TnlError("sdk.dev_unavailable");
  }
}

export function runtimeRequest(
  endpoint: RuntimeEndpoint,
  operation: string,
  body?: unknown,
): Promise<unknown> {
  parseEndpoint(
    endpoint,
    endpoint.scope === "app"
      ? { service: endpoint.service }
      : { invocationID: endpoint.invocation_id },
    process.env.TNL_APP_ENDPOINT === undefined ? undefined : process.env.TNL_APP_AUTHORITY,
  );
  if (
    !["health", "status", "prepare", "register", "renew", "unregister", "ad-hoc/register"].includes(
      operation,
    )
  )
    throw new TnlError("sdk.configuration_invalid");
  const get = operation === "health" || operation === "status";
  const payload = get ? undefined : JSON.stringify(body);
  if (
    (get && body !== undefined) ||
    (payload !== undefined && Buffer.byteLength(payload) > 64 * 1024)
  )
    throw new TnlError("sdk.configuration_invalid");
  return new Promise((resolve, reject) => {
    const request = http.request(
      endpoint.url + `/v1/${operation}`,
      {
        method: get ? "GET" : "POST",
        agent: false,
        headers: {
          Host: endpoint.url.slice("http://".length),
          Authorization: `Bearer ${endpoint.capability}`,
          ...(payload === undefined
            ? {}
            : { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) }),
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        let length = 0;
        response.on("data", (chunk: Buffer) => {
          length += chunk.length;
          if (length > 64 * 1024) response.destroy(new TnlError("sdk.response_invalid"));
          else chunks.push(chunk);
        });
        response.on("error", (cause: unknown) =>
          reject(cause instanceof TnlError ? cause : new TnlError("sdk.dev_unavailable")),
        );
        response.on("end", () => {
          try {
            if (
              response.statusCode === 401 &&
              response.headers["content-type"]?.split(";", 1)[0] !== "application/json"
            )
              throw new TnlError("sdk.registration_stale");
            if (response.statusCode === 204) {
              if (length !== 0 || ["prepare", "status", "ad-hoc/register"].includes(operation))
                throw new TnlError("sdk.response_invalid");
              resolve(undefined);
              return;
            }
            if (response.headers["content-type"]?.split(";", 1)[0] !== "application/json")
              throw new TnlError("sdk.response_invalid");
            const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            if (response.statusCode !== 200) {
              const problem = record(value, "local publisher error");
              exactKeys(problem, ["code", "message"], "local publisher error");
              if (typeof problem.code !== "string" || typeof problem.message !== "string")
                throw new TnlError("sdk.response_invalid");
              throw new TnlError(
                problem.code === "runtime.owner_conflict"
                  ? "sdk.owner_conflict"
                  : problem.code === "runtime.registration_stale" ||
                      problem.code === "runtime.unauthorized"
                    ? "sdk.registration_stale"
                    : problem.code === "runtime.authentication_required"
                      ? "sdk.authentication_required"
                      : problem.code === "runtime.publisher_setup_required"
                        ? "sdk.publisher_setup_required"
                        : problem.code === "runtime.publisher_file_invalid"
                          ? "sdk.publisher_file_invalid"
                          : response.statusCode !== undefined && response.statusCode >= 500
                            ? "sdk.dev_unavailable"
                            : "sdk.request_rejected",
              );
            }
            if (!["prepare", "status", "ad-hoc/register"].includes(operation))
              throw new TnlError("sdk.response_invalid");
            resolve(value);
          } catch (cause) {
            reject(cause instanceof TnlError ? cause : new TnlError("sdk.response_invalid"));
          }
        });
        response.on("close", () => {
          if (!response.complete) reject(new TnlError("sdk.dev_unavailable"));
        });
      },
    );
    const deadline = setTimeout(
      () => request.destroy(new TnlError("sdk.dev_unavailable")),
      operation === "unregister" ? 75_000 : 30_000,
    );
    deadline.unref();
    request.once("close", () => clearTimeout(deadline));
    request.on("error", () => reject(new TnlError("sdk.dev_unavailable")));
    request.end(payload);
  });
}
