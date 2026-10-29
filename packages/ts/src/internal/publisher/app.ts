import { randomBytes } from "node:crypto";
import * as path from "node:path";
import { TnlError } from "../../errors.js";
import { operation, independent, scheduled, bound as observeBound } from "../tracing.js";
import { canonicalLoopbackTarget, type CanonicalTarget } from "./target.js";
import {
  startRuntime,
  runtimeRequest,
  type RuntimeEndpoint,
  type EndpointSelection,
} from "./local.js";
import { listeningTarget, isBunServer, type LocalHTTPServer } from "./register.js";
import { readTelemetryDisabled } from "./telemetry.js";
import {
  exactKeys,
  parseProjectRuntime,
  record,
  requiredHostname,
  validServiceName,
  type ProjectRuntime,
} from "../project/runtime.js";
export { startRuntime, runtimeRequest } from "./local.js";

export interface PrepareOptions {
  readonly service?: string;
  readonly directory?: string;
  readonly stateDir?: string;
}

export interface PreparedService extends ProjectRuntime {
  readonly service: string;
  readonly hostname: string | undefined;
  readonly publicURL: `https://${string}` | undefined;
  /** acknowledges a bound listener; use tnl wait for public readiness. */
  register(server: LocalHTTPServer): Promise<void>;
  /** unregisters publication without stopping the application listener. */
  close(): Promise<void>;
}

interface Assignment {
  readonly registrationID: string;
  readonly service: string;
  readonly hostname: string | undefined;
  readonly publicURL: `https://${string}` | undefined;
  readonly project: ProjectRuntime;
}
interface Dependencies {
  start(
    directory: string,
    binary?: string,
    selection?: EndpointSelection,
  ): Promise<RuntimeEndpoint>;
  request(endpoint: RuntimeEndpoint, operation: string, body?: unknown): Promise<unknown>;
}
const defaultDependencies: Dependencies = { start: startRuntime, request: runtimeRequest };

declare global {
  var __tnlAppPreparations: Map<string, Promise<PreparedService>> | undefined;
}
const preparations = (globalThis.__tnlAppPreparations ??= new Map<
  string,
  Promise<PreparedService>
>());
const frameworkTargets = new WeakMap<
  PreparedService,
  (target: `http://${string}`) => Promise<void>
>();

export function reportFrameworkTarget(
  handle: PreparedService,
  target: `http://${string}`,
): Promise<void> {
  const report = frameworkTargets.get(handle);
  if (report === undefined) throw new TnlError("sdk.configuration_invalid");
  return report(target);
}
type Framework = "node" | "bun" | "vite" | "next";

export function prepareService(
  options: PrepareOptions = {},
  framework: Framework = "node",
  telemetryDisabled: boolean = readTelemetryDisabled(process.env.TNL_NO_TELEMETRY),
): Promise<PreparedService> {
  validateOptions(options);
  const directory = path.resolve(options.directory ?? process.cwd());
  const key = `${directory}\0${options.service ?? ""}\0${options.stateDir ?? process.env.TNL_STATE_DIR ?? ""}\0${process.env.TNL_APP_ENDPOINT ?? ""}\0${framework}\0${telemetryDisabled}`;
  const existing = preparations.get(key);
  if (existing !== undefined) return existing;
  const prepared = createPreparedService(
    options,
    framework,
    defaultDependencies,
    () => preparations.delete(key),
    telemetryDisabled,
  );
  preparations.set(key, prepared);
  void prepared.catch(() => preparations.delete(key));
  return prepared;
}

export function createPreparedService(
  options: PrepareOptions,
  framework: Framework,
  dependencies: Dependencies,
  onClose: () => void = () => {},
  telemetryDisabled: boolean = readTelemetryDisabled(process.env.TNL_NO_TELEMETRY),
): Promise<PreparedService> {
  return operation("sdk.prepare", () =>
    createPreparedServiceUntraced(options, framework, dependencies, onClose, telemetryDisabled),
  );
}

async function createPreparedServiceUntraced(
  options: PrepareOptions,
  framework: Framework,
  dependencies: Dependencies,
  onClose: () => void,
  telemetryDisabled: boolean,
): Promise<PreparedService> {
  validateOptions(options);
  const directory = path.resolve(options.directory ?? process.cwd());
  const selection = {
    ...(options.service === undefined ? {} : { service: options.service }),
    ...(options.stateDir === undefined ? {} : { stateDir: options.stateDir }),
  };
  const owner = randomBytes(16).toString("hex");
  const prepareRequest = {
    version: 1,
    directory,
    ...(options.service === undefined ? {} : { service: options.service }),
    framework,
    owner,
    pid: process.pid,
    telemetry_disabled: telemetryDisabled,
  };
  let endpoint = await dependencies.start(directory, undefined, selection);
  let assignment = parseAssignment(await dependencies.request(endpoint, "prepare", prepareRequest));
  if (assignment.service !== endpoint.service) throw new TnlError("sdk.response_invalid");
  const initial = assignment;
  let target: CanonicalTarget | undefined;
  let server: LocalHTTPServer | undefined;
  let closed = false;
  let released = false;
  let revision = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let pending = Promise.resolve();
  let closing: Promise<void> | undefined;
  const lifetime = new AbortController();
  const enqueue = (operation: () => Promise<void>) => {
    const result = pending.catch(() => {}).then(operation);
    pending = result;
    return result;
  };
  const registration = () => ({
    version: 1,
    registration_id: assignment.registrationID,
    owner,
    ...(target === undefined ? {} : { target }),
  });
  const reconnect = () =>
    operation("sdk.app.recover", async () => {
      const replacementEndpoint = await dependencies.start(directory, undefined, selection);
      const replacement = parseAssignment(
        await dependencies.request(replacementEndpoint, "prepare", prepareRequest),
      );
      if (
        replacement.publicURL !== initial.publicURL ||
        replacement.service !== initial.service ||
        replacement.service !== replacementEndpoint.service
      ) {
        await dependencies.request(replacementEndpoint, "unregister", {
          version: 1,
          registration_id: replacement.registrationID,
          owner,
        });
        throw new TnlError("sdk.response_invalid");
      }
      endpoint = replacementEndpoint;
      assignment = replacement;
      released = false;
    });
  const release = async () => {
    clearTimeout(timer);
    try {
      await dependencies.request(endpoint, "unregister", registration());
    } catch (error) {
      if (!recoverable(error)) throw error;
    }
    released = true;
  };
  const schedule = () => {
    if (closed || released) return;
    clearTimeout(timer);
    const renew = independent("sdk.app.renew", () =>
      enqueue(async () => {
        if (closed || released) return;
        try {
          if (server !== undefined && !isBunServer(server) && !server.listening) {
            await release();
            return;
          }
          await dependencies.request(endpoint, "renew", registration());
        } catch (error) {
          if (recoverable(error)) {
            try {
              await reconnect();
              if (!closed && target !== undefined)
                await dependencies.request(endpoint, "register", registration());
            } catch {
              /* the next renewal retries a restarting owner. */
            }
          }
        } finally {
          schedule();
        }
      }),
    );
    timer = setTimeout(() => {
      void renew().catch(() => {});
    }, 5_000);
    timer.unref();
  };
  const setTarget = async (bound: CanonicalTarget, listener?: LocalHTTPServer) => {
    if (closed) throw new TnlError("sdk.registration_stale");
    if (released) await reconnect();
    if (target !== bound || server !== listener) observeBound();
    target = bound;
    server = listener;
    const current = ++revision;
    if (listener !== undefined) {
      const stopped = independent("sdk.app.cleanup", async () => {
        if (server === listener && revision === current && !closed)
          return enqueue(async () => {
            if (server === listener && revision === current) await release();
          });
        return Promise.resolve();
      });
      if (isBunServer(listener)) {
        const original = listener.stop.bind(listener);
        listener.stop = async (force) => {
          try {
            await original(force);
          } finally {
            await stopped();
          }
        };
      } else
        listener.once("close", () => {
          void stopped().catch(() => {});
        });
    }
    try {
      await dependencies.request(endpoint, "register", registration());
    } catch (error) {
      if (!recoverable(error) || closed) throw error;
      await reconnect();
      if (closed) throw new TnlError("sdk.registration_stale");
      await dependencies.request(endpoint, "register", registration());
    }
    if (closed || (listener !== undefined && !isBunServer(listener) && !listener.listening))
      throw new TnlError("sdk.listener_failed");
    schedule();
  };
  const close = (): Promise<void> => {
    if (closing !== undefined) return closing;
    closed = true;
    lifetime.abort(new TnlError("sdk.registration_stale"));
    clearTimeout(timer);
    process.off("beforeExit", beforeExit);
    onClose();
    closing = operation(
      framework === "next"
        ? "next.cleanup"
        : framework === "vite"
          ? "vite.cleanup"
          : "sdk.app.cleanup",
      () => enqueue(release),
    );
    return closing;
  };
  const exitCleanup = scheduled(close);
  const beforeExit = () => {
    void exitCleanup().catch(() => {});
  };
  process.once("beforeExit", beforeExit);
  schedule();
  const handle: PreparedService = Object.freeze({
    ...assignment.project,
    service: assignment.service,
    hostname: assignment.hostname,
    publicURL: assignment.publicURL,
    register: (listener: LocalHTTPServer) =>
      operation("sdk.app.register", () =>
        enqueue(async () => {
          await setTarget(await listeningTarget(listener, { signal: lifetime.signal }), listener);
        }),
      ),
    close,
  });
  frameworkTargets.set(handle, (bound) =>
    operation(
      framework === "next" && target !== undefined && target !== bound
        ? "next.restart"
        : "sdk.app.register",
      () =>
        enqueue(async () => {
          const parsed = new URL(bound);
          if (canonicalLoopbackTarget(parsed.hostname, Number(parsed.port)) !== bound)
            throw new TnlError("sdk.target_invalid");
          await setTarget(bound);
        }),
    ),
  );
  return handle;
}

function recoverable(error: unknown): boolean {
  return (
    error instanceof TnlError &&
    (error.code === "sdk.dev_unavailable" || error.code === "sdk.registration_stale")
  );
}
function validateOptions(options: PrepareOptions): void {
  if (
    options === null ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    Object.keys(options).some((key) => !["service", "directory", "stateDir"].includes(key)) ||
    (options.service !== undefined && !validServiceName(options.service)) ||
    [options.directory, options.stateDir].some(
      (value) =>
        value !== undefined &&
        (typeof value !== "string" || value === "" || value.length > 4096 || value.includes("\0")),
    )
  )
    throw new TnlError("sdk.configuration_invalid");
}
function parseAssignment(value: unknown): Assignment {
  try {
    const object = record(value, "app assignment");
    exactKeys(
      object,
      ["version", "registration_id", "service", "hostname", "public_url", "project"],
      "app assignment",
    );
    if (
      object.version !== 1 ||
      typeof object.registration_id !== "string" ||
      !/^reg_[a-f0-9]{32}$/.test(object.registration_id) ||
      !validServiceName(object.service)
    )
      throw new TnlError("sdk.response_invalid");
    const project = parseProjectRuntime(object.project, "app project");
    const service = object.hostname === "" && object.public_url === "";
    const hostname = service ? undefined : requiredHostname(object.hostname, "app hostname");
    const publicURL = hostname === undefined ? undefined : (`https://${hostname}` as const);
    if (
      !project.dev ||
      (service
        ? project.services[object.service] !== undefined
        : object.public_url !== publicURL ||
          project.services[object.service]?.hostname !== hostname ||
          project.services[object.service]?.protocol !== "http")
    )
      throw new TnlError("sdk.response_invalid");
    return {
      registrationID: object.registration_id,
      service: object.service,
      hostname,
      publicURL,
      project,
    };
  } catch {
    throw new TnlError("sdk.response_invalid");
  }
}
