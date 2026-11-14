import { randomBytes } from "node:crypto";
import * as path from "node:path";
import { TnlCleanupError, TnlError } from "../../errors.js";
import * as z from "zod";
import { parseValue } from "../validation.js";
import {
  hostnameSchema,
  httpsOriginSchema,
  publicHTTPOriginSchema,
  pathTextSchema,
  registrationIDSchema,
  serviceNameSchema,
} from "../values.js";
import { operation, independent, scheduled, bound as observeBound } from "../tracing.js";
import { canonicalLoopbackTarget, type CanonicalTarget } from "./target.js";
import {
  startRuntime,
  runtimeRequest,
  type RuntimeEndpoint,
  type EndpointSelection,
} from "./local.js";
import {
  listeningTarget,
  isBunServer,
  observeListenerClose,
  type LocalHTTPServer,
} from "./register.js";
import { projectRuntimeSchema, type ProjectRuntime } from "../project/runtime.js";
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

const assignmentSchema = z
  .strictObject({
    version: z.literal(1),
    registration_id: registrationIDSchema,
    service: serviceNameSchema,
    hostname: z.union([hostnameSchema, z.literal("")]),
    public_url: z.union([httpsOriginSchema, z.literal("")]),
    project: projectRuntimeSchema,
  })
  .refine(({ service, hostname, public_url, project }) => {
    const metadata = project.services[service];
    return (
      project.dev &&
      (hostname === "" && public_url === ""
        ? metadata === undefined
        : metadata?.hostname === hostname &&
          metadata.protocol === "http" &&
          metadata.url === public_url &&
          (!metadata.public || publicHTTPOriginSchema.safeParse(public_url).success))
    );
  })
  .transform(({ registration_id, service, hostname, public_url, project }) => ({
    registrationID: registration_id,
    service,
    hostname: hostname === "" ? undefined : hostname,
    publicURL: public_url === "" ? undefined : public_url,
    project,
  }))
  .readonly();
type Assignment = z.output<typeof assignmentSchema>;
type AppRegistration = { readonly endpoint: RuntimeEndpoint; readonly assignment: Assignment };
type AppRegistrationState =
  | { readonly phase: "prepared"; readonly registration: AppRegistration }
  | { readonly phase: "released"; readonly registration: AppRegistration }
  | { readonly phase: "closed"; readonly registration: AppRegistration };
interface Dependencies {
  start(
    directory: string,
    binary?: string,
    selection?: EndpointSelection,
    signal?: AbortSignal,
  ): Promise<RuntimeEndpoint>;
  request(
    endpoint: RuntimeEndpoint,
    operation: string,
    body?: unknown,
    signal?: AbortSignal,
  ): Promise<unknown>;
}
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
  const endpoint = await dependencies.start(directory, undefined, selection, signal);
  signal?.throwIfAborted();
  const assignment = parseAssignment(
    await dependencies.request(endpoint, "prepare", prepareRequest, signal),
  );
  if (signal?.aborted) {
    try {
      await dependencies.request(
        endpoint,
        "unregister",
        {
          version: 1,
          registration_id: assignment.registrationID,
          owner,
        },
        AbortSignal.timeout(3_000),
      );
    } catch (cleanupError) {
      throw new TnlCleanupError(signal.reason, cleanupError);
    }
    signal.throwIfAborted();
  }
  if (endpoint.scope !== "app" || assignment.service !== endpoint.service)
    throw new TnlError("sdk.response_invalid");
  const initial = assignment;
  let state: AppRegistrationState = {
    phase: "prepared",
    registration: { endpoint, assignment },
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
  const registration = (current: AppRegistration = state.registration) => ({
    version: 1,
    registration_id: current.assignment.registrationID,
    owner,
    ...(target === undefined ? {} : { target }),
  });
  const reconnect = (signal?: AbortSignal) =>
    operation("sdk.app.recover", async () => {
      const replacementEndpoint = await dependencies.start(directory, undefined, selection, signal);
      const replacement = parseAssignment(
        await dependencies.request(replacementEndpoint, "prepare", prepareRequest, signal),
      );
      if (
        replacement.publicURL !== initial.publicURL ||
        replacement.service !== initial.service ||
        replacementEndpoint.scope !== "app" ||
        replacement.service !== replacementEndpoint.service
      ) {
        await dependencies.request(replacementEndpoint, "unregister", {
          version: 1,
          registration_id: replacement.registrationID,
          owner,
        });
        throw new TnlError("sdk.response_invalid");
      }
      if (state.phase !== "closed")
        state = {
          phase: "prepared",
          registration: { endpoint: replacementEndpoint, assignment: replacement },
        };
    });
  const release = async (signal?: AbortSignal) => {
    detachListener?.();
    detachListener = undefined;
    clearTimeout(timer);
    const current = state.registration;
    try {
      await dependencies.request(current.endpoint, "unregister", registration(current), signal);
    } catch (error) {
      if (!recoverable(error)) throw error;
    }
    if (state.phase !== "closed") state = { phase: "released", registration: current };
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
          await dependencies.request(state.registration.endpoint, "renew", registration());
        } catch (error) {
          if (recoverable(error)) {
            try {
              await reconnect();
              if (state.phase === "prepared" && target !== undefined)
                await dependencies.request(state.registration.endpoint, "register", registration());
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
  const setTarget = async (
    bound: CanonicalTarget,
    listener?: LocalHTTPServer,
    signal?: AbortSignal,
  ) => {
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
      await dependencies.request(state.registration.endpoint, "register", registration(), signal);
    } catch (error) {
      if (!recoverable(error) || isClosed() || signal?.aborted) throw error;
      await reconnect(signal);
      if (isClosed()) throw new TnlError("sdk.registration_stale");
      await dependencies.request(state.registration.endpoint, "register", registration(), signal);
    }
    if (isClosed() || (listener !== undefined && !isBunServer(listener) && !listener.listening))
      throw new TnlError("sdk.listener_failed");
    schedule();
  };
  const close = (signal?: AbortSignal): Promise<void> => {
    if (closing !== undefined) return closing;
    state = { phase: "closed", registration: state.registration };
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
      () => enqueue(() => release(signal)),
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

function recoverable(error: unknown): boolean {
  return (
    error instanceof TnlError &&
    (error.code === "sdk.dev_unavailable" || error.code === "sdk.registration_stale")
  );
}
function validateOptions(options: PrepareOptions): void {
  parseValue(prepareOptionsSchema, options, "sdk.configuration_invalid");
}
export function parseAssignment(value: unknown): Assignment {
  return parseValue(assignmentSchema, value, "sdk.response_invalid");
}
