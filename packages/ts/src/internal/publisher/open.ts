import { randomBytes, randomInt } from "node:crypto";
import * as path from "node:path";
import { isIP } from "node:net";
import type { FetchHandler } from "./fetch_types.js";
import { TnlCleanupError, TnlError } from "../../errors.js";
import { operation, independent, scheduled, background, bound } from "../tracing.js";
import {
  startRuntime,
  runtimeRequest,
  type RuntimeEndpoint,
  type EndpointSelection,
} from "./local.js";
import { closeServer, listeningTarget, isBunServer, type LocalHTTPServer } from "./register.js";
import * as z from "zod";
import { parseValue } from "../validation.js";
import { httpsOriginSchema, pathTextSchema, registrationIDSchema } from "../values.js";
import { parseStatus } from "./status.js";
import type { TnlRatePeriod } from "../../config.gen.js";
import { captureIdentity, type IdentitySource, type OIDCAssertion } from "../identity/source.js";
import { hostnameSchema } from "../values.js";

export type OpenOptions = OpenSettings &
  (
    | { readonly resourceID: string; readonly namespace?: never }
    | { readonly namespace: string; readonly resourceID?: never }
  );
interface OpenSettings {
  readonly server: string;
  readonly identity: IdentitySource;
  readonly directory?: string;
  readonly stateDir?: string;
  /** hostname the publisher uses to reach this listener. */
  readonly targetHostname?: string;
  /** require hybrid post-quantum key agreement from HTTPS visitors. */
  readonly requirePostQuantum?: boolean;
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

export interface AdHocTunnel {
  readonly url: `https://${string}`;
  close(): Promise<void>;
  wait(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

interface Dependencies {
  start(
    directory: string,
    binary?: string,
    selection?: EndpointSelection,
  ): Promise<RuntimeEndpoint>;
  request(endpoint: RuntimeEndpoint, operation: string, body?: unknown): Promise<unknown>;
  pause(milliseconds: number): Promise<void>;
}

const dependencies: Dependencies = {
  start: startRuntime,
  request: runtimeRequest,
  pause: (milliseconds) =>
    new Promise((resolve) => {
      const timer = setTimeout(resolve, milliseconds);
      timer.unref();
    }),
};

// registration acknowledges a listener; filtered status identifies its exact run.
export function openServer(
  server: LocalHTTPServer,
  options: OpenOptions,
  runtime: Dependencies = dependencies,
): Promise<AdHocTunnel> {
  return operation("sdk.open", () => openServerUntraced(server, options, runtime));
}

async function openServerUntraced(
  server: LocalHTTPServer,
  options: OpenOptions,
  runtime: Dependencies,
): Promise<AdHocTunnel> {
  validateOptions(options);
  const target = await listeningTarget(server, options);
  bound();
  const directory = path.resolve(options.directory ?? process.cwd());
  const owner = randomBytes(16).toString("hex");
  const invocationID = `ivk_${Array.from(
    { length: 22 },
    () => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[randomInt(62)],
  ).join("")}`;
  const identity = captureIdentity(options.identity);
  const acquire = identity.assertion;
  if (acquire === undefined) throw new TnlError("sdk.configuration_invalid");
  const request = {
    version: 1,
    invocation_id: invocationID,
    owner,
    pid: process.pid,
    target,
    server_url: options.server,
    ...(options.resourceID === undefined ? { allocate: { namespace: options.namespace } } : { resource_id: options.resourceID }),
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
    ...(options.limits === undefined ? {} : { limits: options.limits }),
    ...(options.requirePostQuantum === undefined
      ? {}
      : { require_post_quantum: options.requirePostQuantum }),
  };
  const selection = {
    invocationID,
    ...(options.stateDir === undefined ? {} : { stateDir: options.stateDir }),
  };
  let endpoint = await runtime.start(directory, undefined, selection);
  const lifetime = new AbortController();
  const sourceSignal = options.signal === undefined ? lifetime.signal : AbortSignal.any([lifetime.signal, options.signal]);
  async function source(fence?: number): Promise<OIDCAssertion> {
    const signal = AbortSignal.any([sourceSignal, AbortSignal.timeout(Math.max(1, Math.min(30_000, (fence ?? Infinity) - Date.now())))]);
    signal.throwIfAborted();
    return new Promise<OIDCAssertion>((resolve, reject) => {
      const abort = () => reject(signal.reason);
      signal.addEventListener("abort", abort, { once: true });
      void acquire(signal).then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
    });
  }
  let proof: OIDCAssertion;
  let accepted: z.output<typeof acceptedPublicationSchema>;
  let registration = { version: 1 as const, registration_id: "", owner, target };
  let requested = false;
  const publish = async (fence?: number) => {
    let next = await source(fence);
    requested = true;
    let response: unknown;
    try { response = await runtime.request(endpoint, "publications", { ...request, auth: { ...identity.selector, assertion: next.token } }); }
    catch (error) {
      if (!(error instanceof TnlError) || error.code !== "sdk.dev_unavailable" && error.code !== "sdk.registration_stale" || sourceSignal.aborted) throw error;
      endpoint = await runtime.start(directory, undefined, selection);
      next = await source(next.expiresAt.getTime());
      response = await runtime.request(endpoint, "publications", { ...request, auth: { ...identity.selector, assertion: next.token } });
    }
    const value = acceptedPublicationSchema.parse(response);
    parseRegistration(value.registration, owner, target);
    if (options.resourceID !== undefined && value.public_url_id !== options.resourceID || value.public_url !== `https://${value.hostname}` || options.namespace !== undefined && !value.hostname.endsWith(`.${options.namespace}`)) throw new TnlError("sdk.response_invalid");
    return { accepted: value, proof: next };
  };
  try {
    const initial = await publish();
    accepted = initial.accepted; proof = initial.proof; registration = accepted.registration;
  } catch (cause) {
    try {
      if (requested) await runtime.request(endpoint, "unregister", registration);
      await runtime.request(endpoint, "capability");
    } catch (cleanup) { throw new TnlCleanupError(cause, cleanup); }
    throw cause;
  }
  let currentURL: `https://${string}` | undefined = `https://${accepted.hostname}`;
  let closed = false;
  let resolveClosing!: () => void;
  const closingSignal = new Promise<void>((resolve) => {
    resolveClosing = resolve;
  });
  let terminal = false;
  let readyReached = false;
  let closePromise: Promise<void> | undefined;
  let resolveReady!: (handle: AdHocTunnel) => void;
  let rejectReady!: (cause: unknown) => void;
  const ready = new Promise<AdHocTunnel>((resolve, reject) => {
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
    lifetime.abort(aborted());
    resolveClosing();
    options.signal?.removeEventListener("abort", onAbort);
    process.off("beforeExit", beforeExit);
    if (!isBunServer(server)) server.off("close", onListenerClose);
    if (!terminal && !readyReached) rejectReady(aborted());
    closePromise = operation("sdk.open.cleanup", async () => {
      await monitoring;
      await runtime.request(endpoint, "unregister", registration);
      await runtime.request(endpoint, "capability");
    }).then(
      () => {
        if (!terminal) {
          terminal = true;
          resolveDone();
        }
      },
      (cause: unknown) => {
        const stale =
          cause instanceof TnlError &&
          (cause.code === "sdk.registration_stale" || cause.code === "sdk.dev_unavailable");
        if (!terminal) {
          terminal = true;
          if (stale) resolveDone();
          else rejectDone(cause);
        }
        if (stale) return;
        throw cause;
      },
    );
    return closePromise;
  };
  const handle: AdHocTunnel = Object.freeze({
    get url(): `https://${string}` {
      if (currentURL === undefined) throw new TnlError("sdk.response_invalid");
      return currentURL;
    },
    close,
    wait: () => done,
    [Symbol.asyncDispose]: close,
  });
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
      if (currentURL !== undefined && currentURL !== status.publicURL)
        throw new TnlError("sdk.response_invalid");
      currentURL = status.publicURL;
    }
    if (status.publishRunNumber !== undefined) {
      if (status.publishRunNumber < lastRun) throw new TnlError("sdk.response_invalid");
      lastRun = status.publishRunNumber;
    }
    if (status.routable) {
      if (!readyReached) {
        readyReached = true;
        resolveReady(handle);
      }
    } else if (status.failure) fail(new TnlError("sdk.publication_failed"));
  };
  // registering acknowledges the listener, not routability.
  const statusRequest = independent("sdk.open.status", () => runtime.request(endpoint, "status"));
  const renew = independent("sdk.open.renew", () =>
    runtime.request(endpoint, "renew", registration),
  );
  const recover = independent("sdk.open.recover", async () => {
    endpoint = await runtime.start(directory, undefined, selection);
    const next = await publish(proof.expiresAt.getTime());
    if (next.accepted.public_url_id !== accepted.public_url_id || next.accepted.hostname !== accepted.hostname || next.accepted.public_url !== accepted.public_url) throw new TnlError("sdk.response_invalid");
    accepted = next.accepted; proof = next.proof; registration = accepted.registration;
  });
  const monitoring = background(async () => {
    while (!closed && !terminal) {
      try {
        if (!isBunServer(server) && !server.listening) throw new TnlError("sdk.listener_failed");
        const status = parseStatus(
          await statusRequest(),
          invocationID,
          registration.registration_id,
          target,
        );
        if (status !== undefined) observe(status);
        if (closed || terminal) break;
        if (Date.now() >= proof.expiresAt.getTime() - 5_000) {
          const next = await publish(proof.expiresAt.getTime());
          if (next.accepted.public_url_id !== accepted.public_url_id || next.accepted.hostname !== accepted.hostname || next.accepted.public_url !== accepted.public_url || next.accepted.registration.registration_id !== registration.registration_id) throw new TnlError("sdk.response_invalid");
          proof = next.proof;
        }
        await Promise.race([runtime.pause(250), closingSignal]);
        if (closed || terminal) break;
        if (Date.now() - lastRenew >= 5_000) {
          await renew();
          lastRenew = Date.now();
        }
      } catch (cause) {
        if (closed || terminal) break;
        if (
          cause instanceof TnlError &&
          (cause.code === "sdk.dev_unavailable" || cause.code === "sdk.registration_stale")
        ) {
          try {
            await recover();
            continue;
          } catch (restartError) {
            if (
              restartError instanceof TnlError &&
              (restartError.code === "sdk.dev_unavailable" ||
                restartError.code === "sdk.registration_stale")
            ) {
              await Promise.race([runtime.pause(1_000), closingSignal]);
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
  if (isBunServer(server)) {
    const original = server.stop.bind(server);
    server.stop = async (force) => {
      try {
        await original(force);
      } finally {
        onListenerClose();
        await close();
      }
    };
  } else server.once("close", onListenerClose);
  if (options.signal?.aborted) onAbort();
  try {
    return await ready;
  } catch (cause) {
    try {
      await close();
    } catch (cleanupError) {
      throw new TnlCleanupError(cause, cleanupError);
    }
    throw cause;
  }
}

function parseRegistration(
  value: unknown,
  owner: string,
  target: string,
): z.output<typeof registrationSchema> {
  const registration = parseValue(registrationSchema, value, "sdk.response_invalid");
  if (registration.owner !== owner || registration.target !== target)
    throw new TnlError("sdk.response_invalid");
  return registration;
}

const registrationSchema = z
  .strictObject({
    version: z.literal(1),
    registration_id: registrationIDSchema,
    owner: z.string(),
    target: z.string(),
  })
  .readonly();
const acceptedPublicationSchema = z.strictObject({ registration: registrationSchema, public_url_id: z.string().regex(/^url_[A-Za-z0-9]{22}$/), hostname: hostnameSchema, public_url: z.string() });
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
const openOptionsSchema = z
  .strictObject({
    identity: z.unknown().nonoptional(),
    resourceID: z.string().regex(/^url_[A-Za-z0-9]{22}$/).optional(),
    namespace: hostnameSchema.optional(),
    server: httpsOriginSchema.refine((value) => value.length <= 4096),
    directory: pathTextSchema.optional(),
    stateDir: pathTextSchema.optional(),
    targetHostname: z.string().min(1).optional(),
    requirePostQuantum: z.boolean().optional(),
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
      (options.resourceID === undefined) !== (options.namespace === undefined) && (options.resourceID === undefined || options.access === undefined && options.limits === undefined),
  );

function validateOptions(options: OpenOptions): void {
  parseValue(openOptionsSchema, options, "sdk.configuration_invalid");
}

function aborted(): DOMException {
  return new DOMException("ad-hoc publication was aborted", "AbortError");
}

// inline Fetch handlers own their Node listener; a supplied server is never closed.
export async function openFetch(
  handler: FetchHandler,
  options: OpenOptions,
  runtime: Dependencies = dependencies,
): Promise<AdHocTunnel> {
  validateOptions(options);
  const { createFetchServer } = await import("./fetch.js");
  const server = await createFetchServer(handler);
  let base: AdHocTunnel;
  try {
    base = await openServer(server, options, runtime);
  } catch (cause) {
    try {
      await closeServer(server);
    } catch (cleanupError) {
      throw new TnlCleanupError(cause, cleanupError);
    }
    throw cause;
  }
  let closing: Promise<void> | undefined;
  const close = (): Promise<void> => {
    if (closing !== undefined) return closing;
    closing = (async () => {
      let publicationError: unknown;
      try {
        await base.close();
      } catch (cause) {
        publicationError = cause;
      }
      try {
        await closeServer(server);
      } catch (cause) {
        if (publicationError !== undefined) throw new TnlCleanupError(publicationError, cause);
        throw cause;
      }
      if (publicationError !== undefined) throw publicationError;
    })();
    return closing;
  };
  return Object.freeze({
    get url(): `https://${string}` {
      return base.url;
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
        if (failure !== undefined) throw new TnlCleanupError(failure, cause);
        throw cause;
      }
      if (failure !== undefined) throw failure;
    },
    [Symbol.asyncDispose]: close,
  });
}
