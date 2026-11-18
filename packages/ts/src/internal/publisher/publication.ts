import { randomBytes, randomInt } from "node:crypto";
import * as path from "node:path";
import { isIP } from "node:net";
import { setTimeout as pause } from "node:timers/promises";
import type { FetchHandler } from "./fetch_types.js";
import { TnlCleanupError, TnlError } from "../../errors.js";
import { operation, independent, scheduled, background, bound } from "../tracing.js";
import { startRuntime, runtimeRequest, canceledRuntimeRequest } from "./local.js";
import {
  closeServer,
  listeningTarget,
  isBunServer,
  observeListenerClose,
  type LocalHTTPServer,
} from "./register.js";
import * as z from "zod";
import { parseValue } from "../validation.js";
import { httpsOriginSchema, pathTextSchema } from "../values.js";
import { parseStatus } from "./status.js";
import {
  NativeRegistration,
  publicationCleanupFailed,
  type RegistrationRuntime,
} from "./registration.js";
import type { TnlRatePeriod } from "../../config.gen.js";
import type { PublicationRun } from "../publication_run.js";
export type { PublicationRun } from "../publication_run.js";

type PublisherCredentialFile = {
  readonly publisherCredentialFile: string;
  readonly publisherIdentityID?: never;
};
type PublisherIdentityID = {
  readonly publisherIdentityID: string;
  readonly publisherCredentialFile?: never;
};
type InvocationOptions = InvocationSettings &
  (
    | PublisherCredentialFile
    | PublisherIdentityID
    | { readonly publisherCredentialFile?: never; readonly publisherIdentityID?: never }
  );
interface InvocationSettings {
  readonly telemetry?: boolean;
  readonly server?: string;
  readonly directory?: string;
  readonly stateDir?: string;
  /** hostname the publisher uses to reach this listener. */
  readonly targetHostname?: string;
  /** require hybrid post-quantum key agreement from HTTPS visitors. */
  readonly requirePostQuantum?: boolean;
  /** defaults to true for temporary publications. */
  readonly public?: boolean;
  readonly access?:
    | "restricted"
    | "anonymous"
    | { readonly mode?: "restricted" | "anonymous"; readonly ip?: readonly string[] };
  readonly limits?: {
    readonly requests?: number;
    readonly rate?: { readonly requests: number; readonly per: TnlRatePeriod };
    readonly concurrency?: number;
  };
  readonly signal?: AbortSignal;
}

export type NamedPublicationOptions = Pick<
  InvocationSettings,
  "targetHostname" | "signal" | "telemetry"
>;
export type TemporaryPublicationOptions = NamedPublicationOptions &
  Pick<InvocationSettings, "requirePostQuantum" | "access" | "limits" | "public">;

export function validatePublicationOptions(
  options: TemporaryPublicationOptions,
  named: boolean,
): void {
  validateOptions(options);
  const allowed = new Set(
    named
      ? ["targetHostname", "signal", "telemetry"]
      : [
          "targetHostname",
          "signal",
          "telemetry",
          "requirePostQuantum",
          "access",
          "limits",
          "public",
        ],
  );
  if (Object.keys(options).some((key) => !allowed.has(key)))
    throw new TnlError("sdk.configuration_invalid");
}

export interface Publication {
  readonly url?: `https://${string}`;
  /** exact-run address, present only when run aliases are enabled. */
  readonly runURL?: `https://${string}` | undefined;
  readonly run?: PublicationRun | undefined;
  close(): Promise<void>;
  wait(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export type PublicationSelection = (
  | { readonly kind: "local"; readonly service?: string }
  | {
      readonly kind: "deployment";
      readonly project: string;
      readonly name: string;
      readonly credential: string;
      readonly service?: string;
    }
) & {
  readonly environment?: NodeJS.ProcessEnv;
  readonly retainCleanup?: (cleanup: () => Promise<void>) => void;
  readonly shutdownDeadline?: () => string | undefined;
};

interface Dependencies extends RegistrationRuntime {
  pause(milliseconds: number, signal?: AbortSignal): Promise<void>;
}

const dependencies: Dependencies = {
  start: startRuntime,
  request: runtimeRequest,
  pause: async (milliseconds, signal) => {
    await pause(milliseconds, undefined, {
      ref: false,
      ...(signal === undefined ? {} : { signal }),
    });
  },
};

interface PublicationShutdown {
  readonly signal: AbortSignal;
  readonly deadline: string;
  finish(): void;
}

function publicationShutdown(original?: string): PublicationShutdown {
  const controller = new AbortController();
  const deadline = original ?? new Date(Date.now() + 10_000).toISOString();
  const abort = () =>
    controller.abort(
      new DOMException(
        "publication shutdown timed out; remote cleanup may be unconfirmed",
        "TimeoutError",
      ),
    );
  const remaining = Date.parse(deadline) - Date.now();
  const timer = setTimeout(abort, Math.max(0, remaining));
  if (remaining <= 0) abort();
  return { signal: controller.signal, deadline, finish: () => clearTimeout(timer) };
}

// registration acknowledges a listener; filtered status identifies its exact run.
export function publishServer(
  server: LocalHTTPServer,
  options: InvocationOptions = {},
  runtime: Dependencies = dependencies,
  publication?: PublicationSelection,
  shutdown?: () => PublicationShutdown,
): Promise<Publication> {
  return operation("sdk.publish", () =>
    publishServerUntraced(server, options, runtime, publication, shutdown),
  );
}

async function publishServerUntraced(
  server: LocalHTTPServer,
  options: InvocationOptions,
  runtime: Dependencies,
  publication?: PublicationSelection,
  shutdown?: () => PublicationShutdown,
): Promise<Publication> {
  validateOptions(options);
  const target = await listeningTarget(server, options);
  bound();
  const directory = path.resolve(options.directory ?? process.cwd());
  const environment = publication?.environment ?? process.env;
  const localService = publication?.kind === "local" ? publication.service : undefined;
  const owner = randomBytes(16).toString("hex");
  const invocationID = `ivk_${Array.from(
    { length: 22 },
    () => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[randomInt(62)],
  ).join("")}`;
  // the SDK process may receive this environment variable after the native
  // owner starts. pass the path, never the credential contents, to that owner.
  const publisherCredentialFile =
    localService === undefined &&
    publication?.kind !== "deployment" &&
    options.publisherIdentityID === undefined
      ? (options.publisherCredentialFile ?? environment.TNL_PUBLISHER_CREDENTIAL_FILE)
      : undefined;
  if (
    publisherCredentialFile !== undefined &&
    !validPublisherCredentialFile(publisherCredentialFile)
  )
    throw new TnlError("sdk.configuration_invalid");
  const request = {
    version: 1,
    invocation_id: invocationID,
    owner,
    pid: process.pid,
    target,
    ...(publication?.kind !== "deployment"
      ? {}
      : {
          deployment: {
            project: publication.project,
            name: publication.name,
            credential: publication.credential,
            ...(publication.service === undefined ? {} : { service: publication.service }),
          },
        }),
    telemetry_disabled:
      options.telemetry === false || /^(1|true)$/i.test(environment.TNL_NO_TELEMETRY ?? ""),
    ...(options.server === undefined ? {} : { server_url: options.server }),
    ...(options.publisherIdentityID === undefined
      ? {}
      : { publisher_identity_id: options.publisherIdentityID }),
    ...(publisherCredentialFile === undefined
      ? {}
      : { publisher_credential_file: publisherCredentialFile }),
    ...(options.access === undefined
      ? {}
      : {
          access_mode:
            typeof options.access === "string"
              ? options.access
              : (options.access.mode ?? "restricted"),
          ...(typeof options.access === "string" || options.access.ip === undefined
            ? {}
            : { ip: [...options.access.ip] }),
        }),
    ...(options.limits === undefined
      ? {}
      : {
          limits: {
            ...(options.limits.requests === undefined ? {} : { total: options.limits.requests }),
            ...(options.limits.concurrency === undefined
              ? {}
              : { concurrency: options.limits.concurrency }),
            ...(options.limits.rate === undefined
              ? {}
              : { rate: { count: options.limits.rate.requests, per: options.limits.rate.per } }),
          },
        }),
    ...(options.requirePostQuantum === undefined
      ? {}
      : { require_post_quantum: options.requirePostQuantum }),
    ...(options.public === undefined ? {} : { public: options.public }),
  };
  const selection = {
    ...(localService === undefined ? { invocationID } : { service: localService }),
    environment,
    ...(publication?.kind === "deployment" ? { publications: true } : {}),
    ...(options.stateDir === undefined ? {} : { stateDir: options.stateDir }),
  };
  const native = new NativeRegistration(
    runtime,
    directory,
    selection,
    localService === undefined
      ? { kind: "invocation", request }
      : {
          kind: "configured",
          target,
          request: {
            version: 1,
            directory,
            service: localService,
            framework: isBunServer(server) ? "bun" : "node",
            owner,
            pid: process.pid,
            telemetry_disabled: request.telemetry_disabled,
          },
        },
  );
  await native.discover(options.signal);
  if (options.signal?.aborted) throw aborted();
  let currentURL: `https://${string}` | undefined;
  let currentRun: PublicationRun | undefined;
  let currentRunURL: `https://${string}` | undefined;
  let shutdownBudget: PublicationShutdown | undefined;
  let shutdownUntil: string | undefined;
  const beginShutdown = () => {
    if (shutdown !== undefined) return shutdown();
    const parent = publication?.shutdownDeadline?.();
    if (parent !== undefined && (shutdownUntil === undefined || parent < shutdownUntil))
      shutdownUntil = parent;
    shutdownBudget ??= publicationShutdown(shutdownUntil);
    shutdownUntil = shutdownBudget.deadline;
    return shutdownBudget;
  };
  const finishShutdown = () => {
    shutdownBudget?.finish();
    shutdownBudget = undefined;
  };
  const lifetime = new AbortController();
  const abortLifetime = () => lifetime.abort(options.signal?.reason);
  options.signal?.addEventListener("abort", abortLifetime, { once: true });
  const register = async (signal: AbortSignal = lifetime.signal) => {
    const assignment = await native.acquire(signal);
    if (assignment === undefined) return;
    if (
      native.endpoint.scope !== "app" ||
      assignment.service !== localService ||
      native.endpoint.service !== localService ||
      (assignment.publicURL !== undefined &&
        currentURL !== undefined &&
        currentURL !== assignment.publicURL)
    )
      throw new TnlError("sdk.response_invalid");
    if (assignment.publicURL !== undefined) currentURL = assignment.publicURL;
    await native.bind(target, signal);
  };
  const unregister = async (budget: PublicationShutdown = beginShutdown()) => {
    try {
      await native.unregister(budget, runtime);
    } finally {
      if (shutdown === undefined) finishShutdown();
    }
  };
  try {
    await register();
  } catch (cause) {
    options.signal?.removeEventListener("abort", abortLifetime);
    try {
      await unregister();
    } catch (cleanup) {
      if (!publicationCleanupFailed(cleanup)) publication?.retainCleanup?.(() => unregister());
      throw new TnlCleanupError(cause, cleanup);
    }
    throw cause;
  }
  let closed = false;
  let resolveClosing!: () => void;
  const closingSignal = new Promise<void>((resolve) => {
    resolveClosing = resolve;
  });
  let terminal = false;
  let readyReached = false;
  let closePromise: Promise<void> | undefined;
  let detachListener: (() => void) | undefined;
  let resolveReady!: (handle: Publication) => void;
  let rejectReady!: (cause: unknown) => void;
  const ready = new Promise<Publication>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  const onListenerClose = () => {
    if (!closed) fail(new TnlError("sdk.listener_failed"));
  };
  let resolveDone!: () => void;
  let rejectDone!: (cause: unknown) => void;
  const done = new Promise<void>((resolve, reject) => {
    resolveDone = resolve;
    rejectDone = reject;
  });
  // a handle may finish before its caller starts waiting.
  void done.catch(() => {});
  const close = (): Promise<void> => {
    if (closePromise !== undefined) return closePromise;
    closed = true;
    resolveClosing();
    options.signal?.removeEventListener("abort", onAbort);
    options.signal?.removeEventListener("abort", abortLifetime);
    process.off("beforeExit", beforeExit);
    detachListener?.();
    if (!terminal && !readyReached) rejectReady(aborted());
    closePromise = operation("sdk.publish.cleanup", async () => {
      const budget = beginShutdown();
      lifetime.abort(aborted());
      let monitorFailure: unknown;
      try {
        await monitoring;
      } catch (cause) {
        monitorFailure = cause;
      }
      try {
        await unregister(budget);
      } catch (cleanup) {
        if (monitorFailure !== undefined) throw new TnlCleanupError(monitorFailure, cleanup);
        throw cleanup;
      } finally {
        if (shutdown === undefined) finishShutdown();
      }
      if (monitorFailure !== undefined) throw monitorFailure;
    }).then(
      () => {
        if (!terminal) {
          terminal = true;
          resolveDone();
        }
      },
      (cause: unknown) => {
        if (!terminal) {
          terminal = true;
          rejectDone(cause);
        }
        closePromise = undefined;
        throw cause;
      },
    );
    return closePromise;
  };
  const fail = (cause: unknown) => {
    if (terminal) return;
    terminal = true;
    if (!readyReached) rejectReady(cause);
    rejectDone(cause);
    void close().catch(() => {});
  };
  const onAbort = () => {
    fail(aborted());
  };
  const exitCleanup = scheduled(close);
  const beforeExit = () => {
    void exitCleanup().catch(() => {});
  };
  options.signal?.addEventListener("abort", onAbort, { once: true });
  process.once("beforeExit", beforeExit);
  let lastRenew = Date.now();
  let lastRun = 0;
  const observe = (status: NonNullable<ReturnType<typeof parseStatus>>) => {
    if (status.publicURL !== undefined) {
      if (options.public === false || (currentURL !== undefined && currentURL !== status.publicURL))
        throw new TnlError("sdk.response_invalid");
      currentURL = status.publicURL;
    }
    if (status.publishRunNumber !== undefined) {
      if (status.publishRunNumber < lastRun) throw new TnlError("sdk.response_invalid");
      lastRun = status.publishRunNumber;
    }
    currentRun = status.run;
    currentRunURL = status.runURL;
    if (status.routable) {
      const named = localService !== undefined || publication?.service !== undefined;
      if (
        status.publicURL === undefined &&
        (currentURL !== undefined || (!named && options.public !== false))
      )
        throw new TnlError("sdk.response_invalid");
      if (!readyReached) {
        readyReached = true;
        resolveReady(
          Object.freeze({
            ...(currentURL === undefined ? {} : { url: currentURL }),
            get runURL() {
              return currentRunURL;
            },
            get run() {
              return currentRun;
            },
            close,
            wait: () => done,
            [Symbol.asyncDispose]: close,
          }),
        );
      }
    } else if (status.failure) fail(new TnlError("sdk.publication_failed"));
  };
  // registering acknowledges the listener, not routability.
  const statusRequest = independent("sdk.publish.status", () => native.status(lifetime.signal));
  const renew = independent("sdk.publish.renew", () => native.renew(lifetime.signal));
  const recover = independent("sdk.publish.recover", async () => {
    await native.discover(lifetime.signal);
    await register();
  });
  const monitoring = background(async () => {
    while (!closed && !terminal) {
      try {
        if (!isBunServer(server) && !server.listening) throw new TnlError("sdk.listener_failed");
        const registration = native.registration;
        if (registration === undefined) throw new TnlError("sdk.response_invalid");
        const status = parseStatus(
          await statusRequest(),
          localService ?? invocationID,
          registration.registration_id,
          target,
        );
        if (status !== undefined) observe(status);
        if (closed || terminal) break;
        await Promise.race([runtime.pause(250, lifetime.signal), closingSignal]);
        if (closed || terminal) break;
        if (Date.now() - lastRenew >= 5_000) {
          await renew();
          lastRenew = Date.now();
        }
      } catch (cause) {
        if (closed || terminal) {
          if (!canceledRuntimeRequest(cause, lifetime.signal)) throw cause;
          break;
        }
        if (
          cause instanceof TnlError &&
          (cause.code === "sdk.dev_unavailable" || cause.code === "sdk.registration_stale")
        ) {
          try {
            await recover();
            continue;
          } catch (restartError) {
            if (closed || terminal) {
              if (!canceledRuntimeRequest(restartError, lifetime.signal)) throw restartError;
              break;
            }
            if (
              restartError instanceof TnlError &&
              (restartError.code === "sdk.dev_unavailable" ||
                restartError.code === "sdk.registration_stale")
            ) {
              await Promise.race([runtime.pause(1_000, lifetime.signal), closingSignal]);
              continue;
            }
            fail(restartError);
            break;
          }
        }
        fail(cause);
        break;
      }
    }
  });
  detachListener = observeListenerClose(server, async () => {
    onListenerClose();
    await close();
  });
  if (options.signal?.aborted) onAbort();
  try {
    return await ready;
  } catch (cause) {
    try {
      await close();
    } catch (cleanupError) {
      if (!publicationCleanupFailed(cleanupError)) publication?.retainCleanup?.(close);
      throw new TnlCleanupError(cause, cleanupError);
    }
    throw cause;
  }
}

const credentialFileSchema = pathTextSchema.refine(path.isAbsolute);
const networkSchema = z
  .string()
  .max(64)
  .refine((value) => {
    const parts = value.split("/");
    const ip = isIP(parts[0] ?? "");
    return (
      ip !== 0 &&
      parts.length <= 2 &&
      (parts.length === 1 ||
        (/^(0|[1-9][0-9]*)$/.test(parts[1] ?? "") && Number(parts[1]) <= (ip === 4 ? 32 : 128)))
    );
  });
const accessModeSchema = z.enum(["restricted", "anonymous"]);
const invocationOptionsSchema = z
  .strictObject({
    publisherCredentialFile: credentialFileSchema.optional(),
    publisherIdentityID: z
      .string()
      .regex(/^pub_[A-Za-z0-9]{22}$/)
      .optional(),
    server: httpsOriginSchema.refine((value) => value.length <= 4096).optional(),
    directory: pathTextSchema.optional(),
    stateDir: pathTextSchema.optional(),
    targetHostname: z.string().min(1).optional(),
    requirePostQuantum: z.boolean().optional(),
    public: z.boolean().optional(),
    telemetry: z.boolean().optional(),
    access: z
      .union([
        accessModeSchema,
        z.strictObject({
          mode: accessModeSchema.optional(),
          ip: z.array(networkSchema).min(1).max(32).optional(),
        }),
      ])
      .optional(),
    // control owns limit normalization, including the generated rate-period contract.
    limits: z.unknown().optional(),
    signal: z.instanceof(AbortSignal).optional(),
  })
  .refine(
    (options) =>
      options.publisherCredentialFile === undefined || options.publisherIdentityID === undefined,
  );

function validateOptions(options: InvocationOptions): void {
  parseValue(invocationOptionsSchema, options, "sdk.configuration_invalid");
}
function validPublisherCredentialFile(value: unknown): value is string {
  return credentialFileSchema.safeParse(value).success;
}

function aborted(): DOMException {
  return new DOMException("publication was aborted", "AbortError");
}

async function closeOwnedPublication(
  server: LocalHTTPServer,
  cleanup: () => Promise<void>,
  budget: PublicationShutdown,
): Promise<void> {
  // detach native monitoring before stopping the owned listener. both phases
  // start now and share the same deadline; arbitrary Fetch handlers are not joined.
  const native = cleanup();
  const results = await Promise.allSettled([native, closeServer(server, budget.signal)]);
  const { joinFetchServer } = await import("./fetch.js");
  await joinFetchServer(server);
  const failures = results.flatMap((result) =>
    result.status === "rejected" ? [result.reason as unknown] : [],
  );
  if (failures.length > 1) throw new TnlCleanupError(failures[0], failures[1]);
  if (failures.length === 1) throw failures[0];
}

// inline Fetch handlers own their Node listener; a supplied server is never closed.
export async function publishFetch(
  handler: FetchHandler,
  options: InvocationOptions = {},
  runtime: Dependencies = dependencies,
  publication?: PublicationSelection,
): Promise<Publication> {
  validateOptions(options);
  const { createFetchServer } = await import("./fetch.js");
  const server = await createFetchServer(handler);
  let shutdown: PublicationShutdown | undefined;
  let shutdownUntil: string | undefined;
  const budget = () => {
    const parent = publication?.shutdownDeadline?.();
    if (parent !== undefined && (shutdownUntil === undefined || parent < shutdownUntil))
      shutdownUntil = parent;
    shutdown ??= publicationShutdown(shutdownUntil);
    shutdownUntil = shutdown.deadline;
    return shutdown;
  };
  const finish = () => {
    shutdown?.finish();
    shutdown = undefined;
  };
  let base: Publication;
  try {
    base = await publishServer(
      server,
      options,
      runtime,
      publication === undefined
        ? undefined
        : {
            ...publication,
            retainCleanup: (cleanup) => {
              publication.retainCleanup?.(() =>
                closeOwnedPublication(server, cleanup, budget()).finally(finish),
              );
            },
          },
      budget,
    );
  } catch (cause) {
    try {
      await closeServer(server, budget().signal);
    } catch (cleanupError) {
      throw new TnlCleanupError(cause, cleanupError);
    } finally {
      finish();
    }
    throw cause;
  }
  let closing: Promise<void> | undefined;
  const close = (): Promise<void> => {
    if (closing !== undefined) return closing;
    closing = closeOwnedPublication(server, base.close, budget())
      .finally(finish)
      .catch((cause: unknown) => {
        closing = undefined;
        throw cause;
      });
    return closing;
  };
  return Object.freeze({
    ...(base.url === undefined ? {} : { url: base.url }),
    get runURL() {
      return base.runURL;
    },
    get run() {
      return base.run;
    },
    close,
    async wait(): Promise<void> {
      let failure: unknown;
      try {
        await base.wait();
      } catch (cause) {
        failure = cause;
      }
      try {
        await close();
      } catch (cause) {
        if (failure !== undefined && failure !== cause) throw new TnlCleanupError(failure, cause);
        throw cause;
      }
      if (failure !== undefined) throw failure;
    },
    [Symbol.asyncDispose]: close,
  });
}
