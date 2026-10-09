import { execFile, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import * as http from "node:http";
import * as path from "node:path";
import { promisify } from "node:util";
import { TnlError } from "../errors.js";
import { canonicalLoopbackTarget, type CanonicalTarget } from "./dev.js";
import { resolveNativeBinary } from "./launcher.js";
import { listeningTarget, isBunServer, type LocalHTTPServer } from "./register.js";
import {
  exactKeys,
  parseProjectRuntime,
  record,
  requiredHostname,
  validServiceName,
  type ProjectRuntime,
} from "./runtime.js";

export interface PrepareOptions {
  readonly service?: string;
  readonly directory?: string;
}

type CanonicalLoopbackTarget = `http://${string}`;

export interface PreparedService extends ProjectRuntime {
  readonly service: string;
  readonly hostname: string;
  readonly publicURL: `https://${string}`;
  /** acknowledges a bound listener; use tnl wait for public readiness. */
  register(server: LocalHTTPServer): Promise<void>;
  /** unregisters publication without stopping the application listener. */
  close(): Promise<void>;
}

interface Assignment {
  readonly registrationID: string;
  readonly service: string;
  readonly hostname: string;
  readonly publicURL: `https://${string}`;
  readonly project: ProjectRuntime;
}

interface Dependencies {
  start(directory: string): Promise<string>;
  request(socket: string, operation: string, body: unknown): Promise<unknown>;
}

const defaultDependencies: Dependencies = { start: startRuntime, request: runtimeRequest };

// one handle survives framework config reloads in the same process. listener
// replacements share ownership while their registration/run observations fence
// requests and probes in the native manager.
declare global {
  var __tnlAppPreparations: Map<string, Promise<PreparedService>> | undefined;
}
const preparations = (globalThis.__tnlAppPreparations ??= new Map<
  string,
  Promise<PreparedService>
>());

const frameworkTargets = new WeakMap<
  PreparedService,
  (target: CanonicalLoopbackTarget) => Promise<void>
>();

// Next reports its framework-provided post-bind origin. its registration lives
// with the framework process rather than a public Node server object.
export function reportFrameworkTarget(
  handle: PreparedService,
  target: CanonicalLoopbackTarget,
): Promise<void> {
  const report = frameworkTargets.get(handle);
  if (report === undefined) throw new TnlError("sdk.configuration_invalid");
  return report(target);
}

export function prepareService(
  options: PrepareOptions = {},
  framework = "node",
): Promise<PreparedService> {
  validateOptions(options);
  const directory = path.resolve(options.directory ?? process.cwd());
  const key = `${directory}\0${options.service ?? ""}\0${framework}`;
  const existing = preparations.get(key);
  if (existing !== undefined) return existing;
  const prepared = createPreparedService(options, framework, defaultDependencies, () =>
    preparations.delete(key),
  );
  preparations.set(key, prepared);
  void prepared.catch(() => preparations.delete(key));
  return prepared;
}

export async function createPreparedService(
  options: PrepareOptions,
  framework: string,
  dependencies: Dependencies,
  onClose: () => void = () => {},
): Promise<PreparedService> {
  validateOptions(options);
  const directory = path.resolve(options.directory ?? process.cwd());
  const owner = randomBytes(16).toString("hex");
  let socket = await dependencies.start(directory);
  const prepareRequest = {
    protocol: 1,
    directory,
    ...(options.service === undefined ? {} : { service: options.service }),
    framework,
    owner,
    pid: process.pid,
  };
  let assignment = parseAssignment(await dependencies.request(socket, "prepare", prepareRequest));
  let server: LocalHTTPServer | undefined;
  let reportedTarget: CanonicalTarget | undefined;
  let closed = false;
  let registered = false;
  let needsPrepare = false;
  let releasing: Promise<void> | undefined;
  let renewing = false;
  let revision = 0;
  let registering = Promise.resolve();
  let timer: ReturnType<typeof setTimeout> | undefined;

  const registration = (target?: string) => ({
    protocol: 1,
    registration_id: assignment.registrationID,
    owner,
    ...(target === undefined ? {} : { target }),
  });
  const reconnect = async () => {
    socket = await dependencies.start(directory);
    const replacement = parseAssignment(
      await dependencies.request(socket, "prepare", prepareRequest),
    );
    if (
      replacement.publicURL !== assignment.publicURL ||
      replacement.service !== assignment.service
    ) {
      await dependencies.request(socket, "unregister", {
        protocol: 1,
        registration_id: replacement.registrationID,
        owner,
      });
      throw new TnlError("sdk.response_invalid");
    }
    assignment = replacement;
    if (closed) {
      await dependencies.request(socket, "unregister", registration());
      throw new TnlError("sdk.registration_stale");
    }
  };
  const close = async () => {
    if (closed) return;
    closed = true;
    revision++;
    clearTimeout(timer);
    process.off("beforeExit", beforeExit);
    onClose();
    try {
      await dependencies.request(socket, "unregister", registration());
    } catch (error) {
      if (
        !(error instanceof TnlError) ||
        (error.code !== "sdk.dev_unavailable" && error.code !== "sdk.registration_stale")
      )
        throw error;
    }
  };
  const beforeExit = () => {
    void close().catch(() => {});
  };
  process.once("beforeExit", beforeExit);

  const schedule = () => {
    if (closed || needsPrepare) return;
    clearTimeout(timer);
    timer = setTimeout(() => {
      void renew();
    }, 5_000);
    timer.unref();
  };
  const renew = async () => {
    if (closed || renewing) return;
    renewing = true;
    const observedRevision = revision;
    try {
      if (registered && server !== undefined && !isBunServer(server) && !server.listening) {
        await release();
        return;
      }
      await dependencies.request(socket, "renew", registration());
    } catch (error) {
      if (closed || observedRevision !== revision) return;
      if (
        !(error instanceof TnlError) ||
        (error.code !== "sdk.dev_unavailable" && error.code !== "sdk.registration_stale")
      )
        return;
      try {
        const replacementSocket = await dependencies.start(directory);
        const replacement = parseAssignment(
          await dependencies.request(replacementSocket, "prepare", prepareRequest),
        );
        if (closed || observedRevision !== revision) {
          if (closed || needsPrepare)
            await dependencies.request(replacementSocket, "unregister", {
              protocol: 1,
              registration_id: replacement.registrationID,
              owner,
            });
          return;
        }
        // a manager restart cannot silently change metadata already compiled into
        // an app. normal restarts keep the saved public URL and get a new run.
        if (
          replacement.publicURL !== assignment.publicURL ||
          replacement.service !== assignment.service
        ) {
          await dependencies.request(replacementSocket, "unregister", {
            protocol: 1,
            registration_id: replacement.registrationID,
            owner,
          });
          throw new TnlError("sdk.response_invalid");
        }
        socket = replacementSocket;
        assignment = replacement;
        if (registered) {
          const target = server === undefined ? reportedTarget : await listeningTarget(server);
          if (target === undefined) throw new TnlError("sdk.listener_failed");
          if (!closed && observedRevision === revision)
            await dependencies.request(socket, "register", registration(target));
        }
      } catch {
        /* a later renewal retries a stopped or restarting manager. */
      }
    } finally {
      renewing = false;
      schedule();
    }
  };
  schedule();

  const registerListener = async (listener: LocalHTTPServer) => {
    if (closed) throw new TnlError("sdk.registration_stale");
    await releasing;
    if (needsPrepare) {
      await reconnect();
      needsPrepare = false;
      schedule();
    }
    const target = await listeningTarget(listener);
    if (closed) throw new TnlError("sdk.registration_stale");
    const currentRevision = ++revision;
    server = listener;
    reportedTarget = target;
    registered = false;
    if (isBunServer(listener)) {
      const original = listener.stop.bind(listener);
      listener.stop = async (force) => {
        try {
          return await original(force);
        } finally {
          if (server === listener && revision === currentRevision) await release();
        }
      };
    } else {
      listener.once("close", () => {
        if (server === listener && revision === currentRevision) void release().catch(() => {});
      });
    }
    try {
      await dependencies.request(socket, "register", registration(target));
    } catch (error) {
      if (closed || revision !== currentRevision)
        throw new TnlError("sdk.listener_failed", { cause: error });
      if (
        !(error instanceof TnlError) ||
        (error.code !== "sdk.registration_stale" && error.code !== "sdk.dev_unavailable")
      )
        throw error;
      await reconnect();
      if (closed || revision !== currentRevision) throw new TnlError("sdk.listener_failed");
      await dependencies.request(socket, "register", registration(target));
    }
    if (closed || revision !== currentRevision || (!isBunServer(listener) && !listener.listening))
      throw new TnlError("sdk.listener_failed");
    registered = true;
  };

  const register = (listener: LocalHTTPServer): Promise<void> => {
    const operation = registering.catch(() => {}).then(() => registerListener(listener));
    registering = operation;
    return operation;
  };

  const release = (): Promise<void> => {
    registered = false;
    needsPrepare = true;
    revision++;
    clearTimeout(timer);
    releasing = dependencies.request(socket, "unregister", registration()).then(
      () => {},
      (error: unknown) => {
        if (
          !(error instanceof TnlError) ||
          (error.code !== "sdk.registration_stale" && error.code !== "sdk.dev_unavailable")
        )
          throw error;
      },
    );
    return releasing;
  };

  const handle = Object.freeze({
    ...assignment.project,
    service: assignment.service,
    hostname: assignment.hostname,
    publicURL: assignment.publicURL,
    register,
    close,
  });
  frameworkTargets.set(handle, async (target) => {
    const parsed = new URL(target);
    if (canonicalLoopbackTarget(parsed.hostname, Number(parsed.port)) !== target)
      throw new TnlError("sdk.target_invalid");
    if (closed) throw new TnlError("sdk.registration_stale");
    await releasing;
    if (needsPrepare) {
      await reconnect();
      needsPrepare = false;
      schedule();
    }
    revision++;
    server = undefined;
    reportedTarget = target;
    await dependencies.request(socket, "register", registration(target));
    registered = true;
  });
  return handle;
}

function validateOptions(options: PrepareOptions): void {
  if (
    options === null ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    Object.keys(options).some((key) => key !== "service" && key !== "directory") ||
    (options.service !== undefined && !validServiceName(options.service)) ||
    (options.directory !== undefined &&
      (typeof options.directory !== "string" || options.directory === ""))
  )
    throw new TnlError("sdk.configuration_invalid");
}

function parseAssignment(value: unknown): Assignment {
  try {
    const object = record(value, "app assignment");
    exactKeys(
      object,
      ["protocol", "registration_id", "service", "hostname", "public_url", "project"],
      "app assignment",
    );
    if (
      object.protocol !== 1 ||
      typeof object.registration_id !== "string" ||
      !/^reg_[a-f0-9]{32}$/.test(object.registration_id) ||
      !validServiceName(object.service)
    )
      throw new TnlError("sdk.response_invalid");
    const hostname = requiredHostname(object.hostname, "app hostname");
    const publicURL: `https://${string}` = `https://${hostname}`;
    const project = parseProjectRuntime(object.project, "app project");
    if (
      object.public_url !== publicURL ||
      !project.dev ||
      project.services[object.service]?.hostname !== hostname
    )
      throw new TnlError("sdk.response_invalid");
    return {
      registrationID: object.registration_id,
      service: object.service,
      hostname,
      publicURL,
      project,
    };
  } catch (cause) {
    throw new TnlError("sdk.response_invalid", { cause });
  }
}

export async function startRuntime(
  directory: string,
  binary: string = resolveNativeBinary(),
): Promise<string> {
  try {
    const { stdout } = await promisify(execFile)(
      binary,
      ["--no-telemetry", "runtime", "address", "--directory", directory],
      { timeout: 30_000, maxBuffer: 64 * 1024, encoding: "utf8" },
    );
    const value: unknown = JSON.parse(stdout);
    const object = record(value, "local publisher socket");
    exactKeys(object, ["protocol", "socket"], "local publisher socket");
    if (
      object.protocol !== 1 ||
      typeof object.socket !== "string" ||
      !path.isAbsolute(object.socket) ||
      object.socket.includes("\0")
    )
      throw new TnlError("sdk.response_invalid");
    if (!(await runtimeHealthy(object.socket))) {
      // the app process owns the local publisher's lifetime. a second service
      // can race this spawn: the runtime's hostname lock elects one owner.
      const process_ = spawn(
        binary,
        ["--no-telemetry", "runtime", "serve", "--directory", directory],
        {
          cwd: directory,
          stdio: "ignore",
        },
      );
      process_.once("error", () => {
        // an available sibling runtime may still win the socket election.
      });
      process_.unref();
      const deadline = Date.now() + 15_000;
      while (!(await runtimeHealthy(object.socket))) {
        if (Date.now() >= deadline) throw new TnlError("sdk.dev_unavailable");
        await new Promise<void>((resolve) => setTimeout(resolve, 50));
      }
    }
    return object.socket;
  } catch (cause) {
    if (cause instanceof TnlError) throw cause;
    throw new TnlError("sdk.dev_unavailable", { cause });
  }
}

function runtimeHealthy(socket: string): Promise<boolean> {
  return new Promise((resolve) => {
    const request = http.get(
      { socketPath: socket, path: "/v1/health", timeout: 1_000 },
      (response) => {
        response.resume();
        resolve(response.statusCode === 204);
      },
    );
    request.on("error", () => resolve(false));
    request.on("timeout", () => request.destroy());
  });
}

export function runtimeRequest(socket: string, operation: string, body: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const request = http.request(
      {
        socketPath: socket,
        path: `/v1/${operation}`,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
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
        response.on("error", (cause) => reject(new TnlError("sdk.dev_unavailable", { cause })));
        response.on("end", () => {
          try {
            if (response.statusCode === 204) {
              if (length !== 0) throw new TnlError("sdk.response_invalid");
              resolve(undefined);
              return;
            }
            const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            if (response.statusCode !== 200) {
              const problem = record(value, "local publisher error");
              const code =
                problem.code === "runtime.owner_conflict"
                  ? "sdk.owner_conflict"
                  : problem.code === "runtime.registration_stale"
                    ? "sdk.registration_stale"
                    : problem.code === "runtime.authentication_required"
                      ? "sdk.authentication_required"
                      : response.statusCode !== undefined && response.statusCode >= 500
                        ? "sdk.dev_unavailable"
                        : "sdk.request_rejected";
              throw new TnlError(code);
            }
            if (response.headers["content-type"]?.split(";", 1)[0] !== "application/json")
              throw new TnlError("sdk.response_invalid");
            resolve(value);
          } catch (cause) {
            reject(
              cause instanceof TnlError ? cause : new TnlError("sdk.response_invalid", { cause }),
            );
          }
        });
        response.on("close", () => {
          if (!response.complete) reject(new TnlError("sdk.dev_unavailable"));
        });
      },
    );
    const deadline = setTimeout(() => request.destroy(new TnlError("sdk.dev_unavailable")), 30_000);
    deadline.unref();
    request.once("close", () => clearTimeout(deadline));
    request.on("error", (cause) => reject(new TnlError("sdk.dev_unavailable", { cause })));
    request.end(payload);
  });
}
