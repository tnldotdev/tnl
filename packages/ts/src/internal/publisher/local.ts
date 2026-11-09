import { execFile } from "node:child_process";
import { randomInt } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import * as http from "node:http";
import { isIP } from "node:net";
import * as path from "node:path";
import { promisify } from "node:util";
import { TnlError } from "../../errors.js";
import { resolveNativeBinary } from "../native/launcher.js";
import { launchEnvironment, traceHeaders, operation as traceOperation } from "../tracing.js";
import * as z from "zod";
import { parseValue } from "../validation.js";
import { digestSchema, invocationIDSchema, serviceNameSchema } from "../values.js";

const endpointFields = {
  version: z.literal(1),
  url: z
    .string()
    .max(128)
    .refine((value) => {
      const url = URL.parse(value);
      if (url === null) return false;
      const hostname = url.hostname.replace(/^\[|\]$/g, "");
      const port = value.match(/:([1-9][0-9]{0,4})$/)?.[1];
      return (
        port !== undefined &&
        Number(port) <= 65535 &&
        value === `http://${url.hostname}:${port}` &&
        ((isIP(hostname) === 4 && hostname.startsWith("127.")) || hostname === "::1")
      );
    }),
  capability: digestSchema,
  owner_id: z.string().regex(/^[a-f0-9]{32}$/),
};
const endpointSchema = z
  .discriminatedUnion("scope", [
    z.strictObject({ ...endpointFields, scope: z.literal("app"), service: serviceNameSchema }),
    z.strictObject({
      ...endpointFields,
      scope: z.literal("invocation"),
      invocation_id: invocationIDSchema,
    }),
  ])
  .readonly();
const problemSchema = z.strictObject({ code: z.string(), message: z.string() });
export type RuntimeEndpoint = z.output<typeof endpointSchema>;

export interface EndpointSelection {
  readonly service?: string | undefined;
  readonly invocationID?: string | undefined;
  readonly stateDir?: string;
}

export function newInvocationID() {
  return invocationIDSchema.parse(
    `ivk_${Array.from(
      { length: 22 },
      () => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[randomInt(62)],
    ).join("")}`,
  );
}

export function parseEndpoint(value: unknown, selection: EndpointSelection = {}): RuntimeEndpoint {
  const endpoint = parseValue(endpointSchema, value, "sdk.response_invalid");
  if (
    endpoint.scope === "app"
      ? selection.invocationID !== undefined ||
        (selection.service !== undefined && selection.service !== endpoint.service)
      : selection.service !== undefined || selection.invocationID !== endpoint.invocation_id
  ) {
    throw new TnlError("sdk.response_invalid");
  }
  return endpoint;
}

async function readEndpoint(file: string, selection: EndpointSelection): Promise<RuntimeEndpoint> {
  if (!path.isAbsolute(file) || file.includes("\0"))
    throw new TnlError("sdk.configuration_invalid");
  const parent = await lstat(path.dirname(file));
  if (!parent.isDirectory() || parent.mode & 0o077 || parent.uid !== process.getuid?.())
    throw new TnlError("sdk.configuration_invalid");
  const handle = await open(file, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
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
    return parseEndpoint(JSON.parse(buffer.subarray(0, bytesRead).toString("utf8")), selection);
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
        env: launchEnvironment(),
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
  signal?: AbortSignal,
): Promise<unknown> {
  return traceOperation("sdk.native.request", () =>
    runtimeRequestUntraced(endpoint, operation, body, signal),
  );
}

function runtimeRequestUntraced(
  endpoint: RuntimeEndpoint,
  operation: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<unknown> {
  parseEndpoint(
    endpoint,
    endpoint.scope === "app"
      ? { service: endpoint.service }
      : { invocationID: endpoint.invocation_id },
  );
  if (
    ![
      "health",
      "status",
      "events",
      "check",
      "prepare",
      "register",
      "renew",
      "unregister",
      "ad-hoc/register",
      "publications/prepare",
      "publications/register",
    ].includes(operation)
  )
    throw new TnlError("sdk.configuration_invalid");
  signal?.throwIfAborted();
  const get = operation === "health" || operation === "status" || operation === "events";
  const endpointURL = new URL(`/v1/${operation}`, endpoint.url);
  if (operation === "events") {
    const query = parseValue(
      z.strictObject({ after: z.string().min(1).max(128) }),
      body,
      "sdk.configuration_invalid",
    );
    endpointURL.searchParams.set("after", query.after);
  }
  const payload = get ? undefined : JSON.stringify(body);
  if (
    (get && operation !== "events" && body !== undefined) ||
    (payload !== undefined && Buffer.byteLength(payload) > 64 * 1024)
  )
    throw new TnlError("sdk.configuration_invalid");
  return new Promise((resolve, reject) => {
    const request = http.request(
      endpointURL,
      {
        method: get ? "GET" : "POST",
        agent: false,
        ...(signal === undefined ? {} : { signal }),
        headers: {
          ...traceHeaders(),
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
              if (
                length !== 0 ||
                [
                  "prepare",
                  "publications/prepare",
                  "status",
                  "check",
                  "events",
                  "ad-hoc/register",
                ].includes(operation)
              )
                throw new TnlError("sdk.response_invalid");
              resolve(undefined);
              return;
            }
            if (response.headers["content-type"]?.split(";", 1)[0] !== "application/json")
              throw new TnlError("sdk.response_invalid");
            const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            if (response.statusCode !== 200) {
              const problem = parseValue(problemSchema, value, "sdk.response_invalid");
              throw new TnlError(
                problem.code === "runtime.credential_invalid"
                  ? "sdk.credential_invalid"
                  : problem.code === "runtime.credential_denied"
                    ? "sdk.credential_denied"
                    : problem.code === "runtime.credential_unavailable"
                      ? "sdk.credential_unavailable"
                      : problem.code === "runtime.cursor_expired"
                        ? "sdk.event_cursor_expired"
                        : problem.code === "runtime.owner_conflict"
                          ? "sdk.owner_conflict"
                          : problem.code === "runtime.registration_stale" ||
                              problem.code === "runtime.unauthorized"
                            ? "sdk.registration_stale"
                            : problem.code === "runtime.authentication_required"
                              ? "sdk.authentication_required"
                              : problem.code === "runtime.publisher_setup_required"
                                ? "sdk.publisher_setup_required"
                                : problem.code === "runtime.publisher_credential_file_invalid"
                                  ? "sdk.publisher_credential_file_invalid"
                                  : response.statusCode !== undefined && response.statusCode >= 500
                                    ? "sdk.dev_unavailable"
                                    : "sdk.request_rejected",
              );
            }
            if (
              ![
                "prepare",
                "publications/prepare",
                "status",
                "check",
                "events",
                "ad-hoc/register",
              ].includes(operation)
            )
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
    request.on("error", () =>
      reject(signal?.aborted ? signal.reason : new TnlError("sdk.dev_unavailable")),
    );
    request.end(payload);
  });
}
