import { randomBytes } from "node:crypto";
import * as path from "node:path";
import { TnlError } from "../../errors.js";
import * as z from "zod";
import { parseValue } from "../validation.js";
import {
  hostnameSchema,
  httpsOriginSchema,
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
import { listeningTarget, isBunServer, type LocalHTTPServer } from "./register.js";
import { projectRuntimeSchema, type ProjectRuntime } from "../project/runtime.js";
import { publicationHandle, type Publication } from "./publication.js";
export { startRuntime, runtimeRequest } from "./local.js";

const prepareOptionsSchema = z
  .strictObject({
    service: serviceNameSchema.exactOptional(),
    directory: pathTextSchema.exactOptional(),
    stateDir: pathTextSchema.exactOptional(),
  })
  .readonly();
export type PrepareOptions = z.output<typeof prepareOptionsSchema>;

export interface PreparedPublication {
  readonly hostname: string | undefined;
  readonly publicURL: `https://${string}` | undefined;
  /** acknowledges a bound listener; use tnl wait for public readiness. */
  register(server: LocalHTTPServer): Promise<Publication>;
  /** unregisters publication without stopping the application listener. */
  close(): Promise<void>;
}

export interface PreparedService extends ProjectRuntime, PreparedPublication {
  readonly service: string;
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
        : public_url === `https://${hostname}` &&
          metadata?.hostname === hostname &&
          metadata.protocol === "http")
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
interface PreparedAssignment<Metadata extends object> {
  readonly registrationID: string;
  readonly service: string;
  readonly hostname: string | undefined;
  readonly publicURL: `https://${string}` | undefined;
  readonly metadata: Metadata;
}
type AppRegistration<Metadata extends object> = {
  readonly endpoint: RuntimeEndpoint;
  readonly assignment: PreparedAssignment<Metadata>;
};
type AppRegistrationState<Metadata extends object> =
  | { readonly phase: "prepared"; readonly registration: AppRegistration<Metadata> }
  | { readonly phase: "released"; readonly registration: AppRegistration<Metadata> }
  | { readonly phase: "closed"; readonly registration: AppRegistration<Metadata> };
interface Dependencies {
  start(
    directory: string,
    binary?: string,
    selection?: EndpointSelection,
  ): Promise<RuntimeEndpoint>;
  request(endpoint: RuntimeEndpoint, operation: string, body?: unknown): Promise<unknown>;
}
const defaultDependencies: Dependencies = { start: startRuntime, request: runtimeRequest };

interface AppRegistry {
  readonly preparations: Map<string, Promise<PreparedService>>;
  readonly frameworkTargets: WeakMap<
    PreparedService,
    (target: `http://${string}`) => Promise<void>
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
): Promise<void> {
  const report = registry.frameworkTargets.get(handle);
  if (report === undefined) throw new TnlError("sdk.configuration_invalid");
  return report(target);
}
type Framework = "node" | "bun" | "vite" | "next";

export function prepareService(
  options: PrepareOptions = {},
  framework: Framework = "node",
  scope = "",
): Promise<PreparedService> {
  validateOptions(options);
  const directory = path.resolve(options.directory ?? process.cwd());
  const key = `${directory}\0${options.service ?? ""}\0${options.stateDir ?? process.env.TNL_STATE_DIR ?? ""}\0${process.env.TNL_APP_ENDPOINT ?? ""}\0${framework}\0${scope}`;
  const existing = registry.preparations.get(key);
  if (existing !== undefined) return existing;
  const evict = () => {
    if (registry.preparations.get(key) === prepared) registry.preparations.delete(key);
  };
  const prepared = createPreparedService(options, framework, defaultDependencies, evict);
  registry.preparations.set(key, prepared);
  void prepared.catch(evict);
  return prepared;
}

export function createPreparedService(
  options: PrepareOptions,
  framework: Framework,
  dependencies: Dependencies,
  onClose: () => void = () => {},
): Promise<PreparedService> {
  return operation("sdk.prepare", () =>
    createPreparedServiceUntraced(options, framework, dependencies, onClose),
  );
}

async function createPreparedServiceUntraced(
  options: PrepareOptions,
  framework: Framework,
  dependencies: Dependencies,
  onClose: () => void,
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
  };
  return createPreparedRegistration(
    {
      directory,
      framework,
      selection,
      owner,
      registerOperation: "register",
      onClose,
      bootstrap: async (endpoint) => {
        const assignment = parseAssignment(
          await dependencies.request(endpoint, "prepare", prepareRequest),
        );
        if (endpoint.scope !== "app" || assignment.service !== endpoint.service)
          throw new TnlError("sdk.response_invalid");
        return { ...assignment, metadata: { ...assignment.project, service: assignment.service } };
      },
      reportTarget: (handle, report) => {
        registry.frameworkTargets.set(handle, report);
      },
    },
    dependencies,
  );
}

// one registration lifecycle serves project metadata and exact application grants.
// callers provide only validated assignment facts and private setup operations.
export async function createPreparedRegistration<Metadata extends object>(
  options: {
    readonly directory: string;
    readonly framework: Framework;
    readonly selection: EndpointSelection;
    readonly owner: string;
    readonly registerOperation: "register" | "publications/register";
    readonly bootstrap: (endpoint: RuntimeEndpoint) => Promise<PreparedAssignment<Metadata>>;
    readonly reportTarget?: (
      handle: PreparedPublication & Metadata,
      report: (target: `http://${string}`) => Promise<void>,
    ) => void;
    readonly onClose?: () => void;
  },
  dependencies: Dependencies,
): Promise<PreparedPublication & Metadata> {
  const { directory, framework, selection, owner } = options;
  const endpoint = await dependencies.start(directory, undefined, selection);
  const assignment = await options.bootstrap(endpoint);
  const initial = assignment;
  let state: AppRegistrationState<Metadata> = {
    phase: "prepared",
    registration: { endpoint, assignment },
  };
  let target: CanonicalTarget | undefined;
  let server: LocalHTTPServer | undefined;
  let revision = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let pending: Promise<unknown> = Promise.resolve();
  let closing: Promise<void> | undefined;
  const lifetime = new AbortController();
  let active:
    | {
        readonly revision: number;
        readonly lifetime: AbortController;
        readonly done: Promise<void>;
        finish(): void;
      }
    | undefined;
  const finishPublication = () => {
    active?.lifetime.abort(new TnlError("sdk.registration_stale"));
    active?.finish();
    active = undefined;
  };
  const isClosed = () => state.phase === "closed";
  const enqueue = <Result>(operation: () => Promise<Result>): Promise<Result> => {
    const result = pending.catch(() => {}).then(operation);
    pending = result;
    return result;
  };
  const registration = (current: AppRegistration<Metadata> = state.registration) => ({
    version: 1,
    registration_id: current.assignment.registrationID,
    owner,
    ...(target === undefined ? {} : { target }),
  });
  const reconnect = () =>
    operation("sdk.app.recover", async () => {
      const replacementEndpoint = await dependencies.start(directory, undefined, selection);
      const replacement = await options.bootstrap(replacementEndpoint);
      if (replacement.publicURL !== initial.publicURL || replacement.service !== initial.service) {
        await dependencies.request(replacementEndpoint, "unregister", {
          version: 1,
          registration_id: replacement.registrationID,
          owner,
        });
        throw new TnlError("sdk.response_invalid");
      }
      // close fences registration immediately, but its queued release must own
      // a replacement that finishes arriving during recovery.
      state = {
        phase: isClosed() ? "closed" : "prepared",
        registration: { endpoint: replacementEndpoint, assignment: replacement },
      };
    });
  const release = async () => {
    clearTimeout(timer);
    const current = state.registration;
    try {
      await dependencies.request(current.endpoint, "unregister", registration(current));
    } catch (error) {
      if (!(error instanceof TnlError) || error.code !== "sdk.registration_stale") throw error;
    }
    if (state.phase !== "closed") state = { phase: "released", registration: current };
    finishPublication();
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
                await dependencies.request(
                  state.registration.endpoint,
                  options.registerOperation,
                  registration(),
                );
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
    if (state.phase === "closed") throw new TnlError("sdk.registration_stale");
    if (state.phase === "released") await reconnect();
    if (target !== bound || server !== listener) observeBound();
    target = bound;
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
      await dependencies.request(
        state.registration.endpoint,
        options.registerOperation,
        registration(),
      );
    } catch (error) {
      if (!recoverable(error) || isClosed()) throw error;
      await reconnect();
      if (isClosed()) throw new TnlError("sdk.registration_stale");
      await dependencies.request(
        state.registration.endpoint,
        options.registerOperation,
        registration(),
      );
    }
    if (isClosed() || (listener !== undefined && !isBunServer(listener) && !listener.listening))
      throw new TnlError("sdk.listener_failed");
    finishPublication();
    schedule();
  };
  const close = (): Promise<void> => {
    if (closing !== undefined) return closing;
    state = { phase: "closed", registration: state.registration };
    lifetime.abort(new TnlError("sdk.registration_stale"));
    active?.lifetime.abort(new TnlError("sdk.registration_stale"));
    clearTimeout(timer);
    process.off("beforeExit", beforeExit);
    options.onClose?.();
    closing = operation(
      framework === "next"
        ? "next.cleanup"
        : framework === "vite"
          ? "vite.cleanup"
          : "sdk.app.cleanup",
      () => enqueue(release),
    ).catch((cause: unknown) => {
      closing = undefined;
      throw cause;
    });
    return closing;
  };
  const exitCleanup = scheduled(close);
  const beforeExit = () => {
    void exitCleanup().catch(() => {});
  };
  process.once("beforeExit", beforeExit);
  schedule();
  const handle: PreparedPublication & Metadata = Object.freeze({
    ...assignment.metadata,
    hostname: assignment.hostname,
    publicURL: assignment.publicURL,
    register: (listener: LocalHTTPServer) =>
      operation("sdk.app.register", () =>
        enqueue(async () => {
          await setTarget(await listeningTarget(listener, { signal: lifetime.signal }), listener);
          const done = Promise.withResolvers<void>();
          const selected = {
            revision,
            lifetime: new AbortController(),
            done: done.promise,
            finish: () => done.resolve(),
          };
          active = selected;
          return publicationHandle({
            current: () => {
              if (
                active !== selected ||
                selected.revision !== revision ||
                state.phase !== "prepared" ||
                target === undefined
              )
                throw new TnlError("sdk.registration_stale");
              return {
                endpoint: state.registration.endpoint,
                registrationID: state.registration.assignment.registrationID,
                service: initial.service,
                target,
              };
            },
            url: () => initial.publicURL,
            lifetime: selected.lifetime.signal,
            close: () => {
              selected.lifetime.abort(new TnlError("sdk.registration_stale"));
              return enqueue(async () => {
                if (active === selected) await release();
              });
            },
            finished: () => selected.done,
            request: dependencies.request,
          });
        }),
      ),
    close,
  });
  options.reportTarget?.(handle, (bound) =>
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
  parseValue(prepareOptionsSchema, options, "sdk.configuration_invalid");
}
function parseAssignment(value: unknown): Assignment {
  return parseValue(assignmentSchema, value, "sdk.response_invalid");
}
