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
import { publicationHandle, type Publication } from "./publication.js";
import type { TnlRatePeriod } from "../../config.gen.js";

export type PublisherCredentialFile = {
  readonly publisherCredentialFile: string;
  readonly publisherIdentityID?: never;
};
export type PublisherIdentityID = {
  readonly publisherIdentityID: string;
  readonly publisherCredentialFile?: never;
};
export type PublishOptions = PublishSettings &
  (
    | PublisherCredentialFile
    | PublisherIdentityID
    | { readonly publisherCredentialFile?: never; readonly publisherIdentityID?: never }
  );
interface PublishSettings {
  readonly server?: string;
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
export function publishServer(
  server: LocalHTTPServer,
  options: PublishOptions = {},
  runtime: Dependencies = dependencies,
): Promise<Publication> {
  return operation("sdk.publish", () => publishServerUntraced(server, options, runtime));
}

async function publishServerUntraced(
  server: LocalHTTPServer,
  options: PublishOptions,
  runtime: Dependencies,
): Promise<Publication> {
  validateOptions(options);
  const target = await listeningTarget(server, options);
  bound();
  const directory = path.resolve(options.directory ?? process.cwd());
  const owner = randomBytes(16).toString("hex");
  const invocationID = `ivk_${Array.from(
    { length: 22 },
    () => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[randomInt(62)],
  ).join("")}`;
  // the SDK process may receive this environment variable after the native
  // owner starts. pass the path, never the credential contents, to that owner.
  const publisherCredentialFile =
    options.publisherIdentityID === undefined
      ? (options.publisherCredentialFile ?? process.env.TNL_PUBLISHER_CREDENTIAL_FILE)
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
  if (options.signal?.aborted) throw aborted();
  let registration = parseRegistration(
    await runtime.request(endpoint, "ad-hoc/register", request),
    owner,
    target,
  );
  let currentURL: `https://${string}` | undefined;
  let closed = false;
  const lifetime = new AbortController();
  let resolveClosing!: () => void;
  const closingSignal = new Promise<void>((resolve) => {
    resolveClosing = resolve;
  });
  let terminal = false;
  let readyReached = false;
  let closePromise: Promise<void> | undefined;
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
    lifetime.abort(new TnlError("sdk.registration_stale"));
    resolveClosing();
    options.signal?.removeEventListener("abort", onAbort);
    process.off("beforeExit", beforeExit);
    if (!isBunServer(server)) server.off("close", onListenerClose);
    if (!terminal && !readyReached) rejectReady(aborted());
    closePromise = operation("sdk.publish.cleanup", async () => {
      await monitoring;
      await runtime.request(endpoint, "unregister", registration);
    }).then(
      () => {
        if (!terminal) {
          terminal = true;
          resolveDone();
        }
      },
      (cause: unknown) => {
        const stale = cause instanceof TnlError && cause.code === "sdk.registration_stale";
        if (!terminal) {
          terminal = true;
          if (stale) resolveDone();
          else rejectDone(cause);
        }
        if (stale) return;
        closePromise = undefined;
        throw cause;
      },
    );
    return closePromise;
  };
  const handle = publicationHandle({
    current: () => ({
      endpoint,
      service: invocationID,
      registrationID: registration.registration_id,
      target,
    }),
    url: () => currentURL,
    lifetime: lifetime.signal,
    close,
    finished: () => done,
    request: runtime.request,
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
  const statusRequest = independent("sdk.publish.status", () =>
    runtime.request(endpoint, "status"),
  );
  const renew = independent("sdk.publish.renew", () =>
    runtime.request(endpoint, "renew", registration),
  );
  const recover = independent("sdk.publish.recover", async () => {
    endpoint = await runtime.start(directory, undefined, selection);
    registration = parseRegistration(
      await runtime.request(endpoint, "ad-hoc/register", request),
      owner,
      target,
    );
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
const openOptionsSchema = z
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

function validateOptions(options: PublishOptions): void {
  parseValue(openOptionsSchema, options, "sdk.configuration_invalid");
}
function validPublisherCredentialFile(value: unknown): value is string {
  return credentialFileSchema.safeParse(value).success;
}

function aborted(): DOMException {
  return new DOMException("ad-hoc publication was aborted", "AbortError");
}

// inline Fetch handlers own their Node listener; a supplied server is never closed.
export async function publishFetch(
  handler: FetchHandler,
  options: PublishOptions = {},
  runtime: Dependencies = dependencies,
): Promise<Publication> {
  validateOptions(options);
  const { createFetchServer } = await import("./fetch.js");
  const server = await createFetchServer(handler);
  let base: Publication;
  try {
    base = await publishServer(server, options, runtime);
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
      // retain the listener while native drain is unconfirmed; close can retry.
      await base.close();
      await closeServer(server);
    })().catch((cause: unknown) => {
      closing = undefined;
      throw cause;
    });
    return closing;
  };
  return Object.freeze({
    get url() {
      return base.url;
    },
    close,
    status: base.status,
    wait: base.wait,
    watch: base.watch,
    async finished(): Promise<void> {
      let failure: unknown;
      try {
        await base.finished();
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
