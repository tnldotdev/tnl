import { randomBytes } from "node:crypto";
import * as path from "node:path";
import { TnlCleanupError, TnlError } from "../../errors.js";
import * as z from "zod";
import { parseValue } from "../validation.js";
import { pathTextSchema, serviceNameSchema } from "../values.js";
import { operation, independent, scheduled, bound as observeBound } from "../tracing.js";
import { canonicalLoopbackTarget, type CanonicalTarget } from "./target.js";
import { startRuntime, runtimeRequest, canceledRuntimeRequest } from "./local.js";
import {
  listeningTarget,
  isBunServer,
  observeListenerClose,
  type LocalHTTPServer,
} from "./register.js";
import type { ProjectRuntime } from "../project/runtime.js";
import {
  NativeRegistration,
  recoverableRegistration as recoverable,
  type Assignment,
  type RegistrationRuntime,
} from "./registration.js";
export { startRuntime, runtimeRequest } from "./local.js";

export const prepareOptionsSchema = z.strictObject({
  service: serviceNameSchema.exactOptional(),
  directory: pathTextSchema.exactOptional(),
  stateDir: pathTextSchema.exactOptional(),
  telemetry: z.boolean().exactOptional(),
});
export type PrepareOptions = Readonly<z.output<typeof prepareOptionsSchema>>;

export interface PreparedService extends ProjectRuntime {
  readonly service: string;
  readonly hostname: string | undefined;
  readonly publicURL: `https://${string}` | undefined;
  /** acknowledges a bound listener; use tnl wait for public readiness. */
  register(server: LocalHTTPServer, signal?: AbortSignal): Promise<void>;
  /** unregisters publication without stopping the application listener. */
  close(signal?: AbortSignal): Promise<void>;
}

type AppRegistrationState = {
  readonly phase: "prepared" | "released" | "closed";
  readonly native: NativeRegistration;
};
type Dependencies = RegistrationRuntime;
const defaultDependencies: Dependencies = { start: startRuntime, request: runtimeRequest };

function telemetryDisabled(options: PrepareOptions): boolean {
  return options.telemetry === false || /^(1|true)$/i.test(process.env.TNL_NO_TELEMETRY ?? "");
}

interface AppRegistry {
  readonly preparations: Map<string, Promise<PreparedService>>;
  readonly frameworkTargets: WeakMap<
    PreparedService,
    (target: `http://${string}`, signal?: AbortSignal) => Promise<void>
  >;
}

declare global {
  var __tnlAppRegistry: AppRegistry | undefined;
}
// independently loaded SDK copies must recognize the same prepared handles.
const registry = (globalThis.__tnlAppRegistry ??= {
  preparations: new Map<string, Promise<PreparedService>>(),
  frameworkTargets: new WeakMap<PreparedService, (target: `http://${string}`) => Promise<void>>(),
});

export function reportFrameworkTarget(
  handle: PreparedService,
  target: `http://${string}`,
  signal?: AbortSignal,
): Promise<void> {
  const report = registry.frameworkTargets.get(handle);
  if (report === undefined) throw new TnlError("sdk.configuration_invalid");
  return report(target, signal);
}
type Framework = "node" | "bun" | "vite" | "next";

export function prepareService(
  options: PrepareOptions = {},
  framework: Framework = "node",
  signal?: AbortSignal,
): Promise<PreparedService> {
  validateOptions(options);
  const directory = path.resolve(options.directory ?? process.cwd());
  const key = `${directory}\0${options.service ?? ""}\0${options.stateDir ?? process.env.TNL_STATE_DIR ?? ""}\0${process.env.TNL_APP_ENDPOINT ?? ""}\0${framework}\0${telemetryDisabled(options)}\0${signal === undefined ? "required" : "optional"}`;
  const existing = registry.preparations.get(key);
  if (existing !== undefined) return existing;
  const evict = () => {
    if (registry.preparations.get(key) === prepared) registry.preparations.delete(key);
  };
  const prepared = createPreparedService(options, framework, defaultDependencies, evict, signal);
  registry.preparations.set(key, prepared);
  void prepared.catch(evict);
  return prepared;
}

export function createPreparedService(
  options: PrepareOptions,
  framework: Framework,
  dependencies: Dependencies,
  onClose: () => void = () => {},
  signal?: AbortSignal,
): Promise<PreparedService> {
  return operation("sdk.prepare", () =>
    createPreparedServiceUntraced(options, framework, dependencies, onClose, signal),
  );
}

async function createPreparedServiceUntraced(
  options: PrepareOptions,
  framework: Framework,
  dependencies: Dependencies,
  onClose: () => void,
  signal?: AbortSignal,
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
    telemetry_disabled: telemetryDisabled(options),
  };
  const native = new NativeRegistration(dependencies, directory, selection, {
    kind: "configured",
    request: prepareRequest,
  });
  await native.discover(signal);
  signal?.throwIfAborted();
  let shutdownUntil: string | undefined;
  const beginShutdown = () => (shutdownUntil ??= new Date(Date.now() + 10_000).toISOString());
  const captureShutdown = () => {
    beginShutdown();
  };
  signal?.addEventListener("abort", captureShutdown, { once: true });
  let assignment: Assignment;
  try {
    assignment = parsePreparedAssignment(await native.acquire(signal));
  } finally {
    signal?.removeEventListener("abort", captureShutdown);
  }
  if (signal?.aborted) {
    try {
      await native.unregister({
        deadline: beginShutdown(),
        signal: AbortSignal.timeout(Math.max(0, Date.parse(beginShutdown()) - Date.now())),
      });
    } catch (cleanupError) {
      throw new TnlCleanupError(signal.reason, cleanupError);
    }
    signal.throwIfAborted();
  }
  if (native.endpoint.scope !== "app" || assignment.service !== native.endpoint.service)
    throw new TnlError("sdk.response_invalid");
  const initial = assignment;
  let state: AppRegistrationState = {
    phase: "prepared",
    native,
  };
  let target: CanonicalTarget | undefined;
  let server: LocalHTTPServer | undefined;
  let detachListener: (() => void) | undefined;
  let revision = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let pending = Promise.resolve();
  let closing: Promise<void> | undefined;
  const lifetime = new AbortController();
  const isClosed = () => state.phase === "closed";
  const enqueue = (operation: () => Promise<void>) => {
    const result = pending.catch(() => {}).then(operation);
    pending = result;
    return result;
  };
  const reconnect = (signal?: AbortSignal) =>
    operation("sdk.app.recover", async () => {
      const replacementNative = new NativeRegistration(dependencies, directory, selection, {
        kind: "configured",
        request: prepareRequest,
      });
      await replacementNative.discover(signal);
      const replacement = parsePreparedAssignment(await replacementNative.acquire(signal));
      if (
        replacement.publicURL !== initial.publicURL ||
        replacement.service !== initial.service ||
        replacementNative.endpoint.scope !== "app" ||
        replacement.service !== replacementNative.endpoint.service
      ) {
        const failure = new TnlError("sdk.response_invalid");
        const until = beginShutdown();
        try {
          await replacementNative.unregister({
            deadline: until,
            signal: AbortSignal.timeout(Math.max(0, Date.parse(until) - Date.now())),
          });
        } catch (cleanup) {
          throw new TnlCleanupError(failure, cleanup);
        }
        throw failure;
      }
      if (state.phase !== "closed") {
        shutdownUntil = undefined;
        state = {
          phase: "prepared",
          native: replacementNative,
        };
      }
    });
  const release = async (signal?: AbortSignal, until = beginShutdown()) => {
    detachListener?.();
    detachListener = undefined;
    clearTimeout(timer);
    const current = state.native;
    const bounded = AbortSignal.timeout(Math.max(0, Date.parse(until) - Date.now()));
    await current.unregister({
      deadline: until,
      signal: signal === undefined ? bounded : AbortSignal.any([bounded, signal]),
    });
    if (state.phase !== "closed") state = { phase: "released", native: current };
  };
  const schedule = () => {
    if (state.phase !== "prepared") return;
    clearTimeout(timer);
    const renew = independent("sdk.app.renew", () =>
      enqueue(async () => {
        if (state.phase !== "prepared") return;
        try {
          if (server !== undefined && !isBunServer(server) && !server.listening) {
            await release();
            return;
          }
          await state.native.renew(lifetime.signal);
        } catch (error) {
          if (lifetime.signal.aborted && !canceledRuntimeRequest(error, lifetime.signal))
            throw error;
          if (recoverable(error)) {
            try {
              await reconnect(lifetime.signal);
              if (state.phase === "prepared" && target !== undefined)
                await state.native.bind(target, lifetime.signal);
            } catch (cause) {
              if (lifetime.signal.aborted && !canceledRuntimeRequest(cause, lifetime.signal))
                throw cause;
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
  const setTarget = async (
    bound: CanonicalTarget,
    listener?: LocalHTTPServer,
    signal?: AbortSignal,
  ) => {
    signal = signal === undefined ? lifetime.signal : AbortSignal.any([signal, lifetime.signal]);
    signal?.throwIfAborted();
    if (state.phase === "closed") throw new TnlError("sdk.registration_stale");
    if (state.phase === "released") await reconnect(signal);
    if (target !== bound || server !== listener) observeBound();
    target = bound;
    detachListener?.();
    server = listener;
    const current = ++revision;
    if (listener !== undefined) {
      const stopped = independent("sdk.app.cleanup", async () => {
        if (server === listener && revision === current && state.phase !== "closed")
          return enqueue(async () => {
            if (server === listener && revision === current) await release();
          });
        return Promise.resolve();
      });
      detachListener = observeListenerClose(listener, stopped);
    }
    try {
      await state.native.bind(bound, signal);
    } catch (error) {
      if (!recoverable(error) || isClosed() || signal?.aborted) throw error;
      await reconnect(signal);
      if (isClosed()) throw new TnlError("sdk.registration_stale");
      await state.native.bind(bound, signal);
    }
    if (isClosed() || (listener !== undefined && !isBunServer(listener) && !listener.listening))
      throw new TnlError("sdk.listener_failed");
    schedule();
  };
  const close = (signal?: AbortSignal): Promise<void> => {
    if (closing !== undefined) return closing;
    const until = beginShutdown();
    state = { phase: "closed", native: state.native };
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
      async () => {
        let operationFailure: unknown;
        try {
          await pending;
        } catch (cause) {
          if (!canceledRuntimeRequest(cause, lifetime.signal)) operationFailure = cause;
        }
        try {
          await release(signal, until);
        } catch (cleanup) {
          if (operationFailure !== undefined) throw new TnlCleanupError(operationFailure, cleanup);
          throw cleanup;
        }
        if (operationFailure !== undefined) throw operationFailure;
      },
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
    register: (listener: LocalHTTPServer, signal?: AbortSignal) =>
      operation("sdk.app.register", () =>
        enqueue(async () => {
          await setTarget(
            await listeningTarget(listener, {
              signal:
                signal === undefined ? lifetime.signal : AbortSignal.any([lifetime.signal, signal]),
            }),
            listener,
            signal,
          );
        }),
      ),
    close,
  });
  registry.frameworkTargets.set(handle, (bound, signal) =>
    operation(
      framework === "next" && target !== undefined && target !== bound
        ? "next.restart"
        : "sdk.app.register",
      () =>
        enqueue(async () => {
          const parsed = new URL(bound);
          if (canonicalLoopbackTarget(parsed.hostname, Number(parsed.port)) !== bound)
            throw new TnlError("sdk.target_invalid");
          await setTarget(bound, undefined, signal);
        }),
    ),
  );
  return handle;
}

function validateOptions(options: PrepareOptions): void {
  parseValue(prepareOptionsSchema, options, "sdk.configuration_invalid");
}
// acquisition may precede endpoint allocation, but app/framework preparation
// promises its selected canonical endpoint before the listener starts.
function parsePreparedAssignment(assignment: Assignment | undefined): Assignment {
  if (assignment?.hostname === undefined) throw new TnlError("sdk.response_invalid");
  return assignment;
}
