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
import {
  closeServer,
  listeningTarget,
  isBunServer,
  observeListenerClose,
  type LocalHTTPServer,
} from "./register.js";
import * as z from "zod";
import { parseValue } from "../validation.js";
import { httpsOriginSchema, pathTextSchema, registrationIDSchema } from "../values.js";
import { parseStatus } from "./status.js";
import { parseAssignment } from "./app.js";
import type { TnlRatePeriod } from "../../config.gen.js";

export type PublisherCredentialFile = {
  readonly publisherCredentialFile: string;
  readonly publisherIdentityID?: never;
};
export type PublisherIdentityID = {
  readonly publisherIdentityID: string;
  readonly publisherCredentialFile?: never;
};
export type OpenOptions = OpenSettings &
  (
    | PublisherCredentialFile
    | PublisherIdentityID
    | { readonly publisherCredentialFile?: never; readonly publisherIdentityID?: never }
  );
interface OpenSettings {
  readonly telemetry?: boolean;
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

export type NamedPublicationOptions = Pick<OpenSettings, "targetHostname" | "signal" | "telemetry">;
export type TemporaryPublicationOptions = NamedPublicationOptions &
  Pick<OpenSettings, "requirePostQuantum" | "access" | "limits">;

export function validatePublicationOptions(
  options: TemporaryPublicationOptions,
  named: boolean,
): void {
  validateOptions(options);
  const allowed = new Set(
    named
      ? ["targetHostname", "signal", "telemetry"]
      : ["targetHostname", "signal", "telemetry", "requirePostQuantum", "access", "limits"],
  );
  if (Object.keys(options).some((key) => !allowed.has(key)))
    throw new TnlError("sdk.configuration_invalid");
}

export interface Publication {
  readonly url: `https://${string}`;
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
) & { readonly environment?: NodeJS.ProcessEnv };

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
  options: OpenOptions = {},
  runtime: Dependencies = dependencies,
  publication?: PublicationSelection,
): Promise<Publication> {
  return operation("sdk.publish", () => openServerUntraced(server, options, runtime, publication));
}

async function openServerUntraced(
  server: LocalHTTPServer,
  options: OpenOptions,
  runtime: Dependencies,
  publication?: PublicationSelection,
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
    ...(options.limits === undefined ? {} : { limits: options.limits }),
    ...(options.requirePostQuantum === undefined
      ? {}
      : { require_post_quantum: options.requirePostQuantum }),
  };
  const selection = {
    ...(localService === undefined ? { invocationID } : { service: localService }),
    environment,
    ...(publication?.kind === "deployment" ? { publications: true } : {}),
    ...(options.stateDir === undefined ? {} : { stateDir: options.stateDir }),
  };
  let endpoint = await runtime.start(directory, undefined, selection);
  if (options.signal?.aborted) throw aborted();
  let assignedURL: `https://${string}` | undefined;
  let registration: z.output<typeof registrationSchema> | undefined;
  let uncertain = false;
  const register = async () => {
    uncertain = true;
    try {
      if (localService === undefined) {
        registration = parseRegistration(
          await runtime.request(endpoint, "ad-hoc/register", request),
          owner,
          target,
        );
        uncertain = false;
        return;
      }
      const assignment = parseAssignment(
        await runtime.request(endpoint, "prepare", {
          version: 1,
          directory,
          service: localService,
          framework: isBunServer(server) ? "bun" : "node",
          owner,
          pid: process.pid,
          telemetry_disabled: request.telemetry_disabled,
        }),
      );
      if (
        endpoint.scope !== "app" ||
        assignment.service !== localService ||
        endpoint.service !== localService ||
        assignment.publicURL === undefined ||
        (assignedURL !== undefined && assignedURL !== assignment.publicURL)
      )
        throw new TnlError("sdk.response_invalid");
      assignedURL = assignment.publicURL;
      registration = {
        version: 1 as const,
        registration_id: assignment.registrationID,
        owner,
        target,
      };
      await runtime.request(endpoint, "register", registration);
      uncertain = false;
    } catch (cause) {
      if (
        cause instanceof TnlError &&
        !["sdk.dev_unavailable", "sdk.registration_stale", "sdk.response_invalid"].includes(
          cause.code,
        )
      )
        uncertain = false;
      throw cause;
    }
  };
  const unregister = async () => {
    // a lost reply is not proof that registration failed. recover the original
    // invocation before unregistering, including when startup was canceled.
    for (let attempt = 0; uncertain; attempt++) {
      try {
        await register();
      } catch (cause) {
        if (attempt >= 2 || !(cause instanceof TnlError) || cause.code !== "sdk.dev_unavailable")
          throw cause;
        endpoint = await runtime.start(directory, undefined, selection);
      }
    }
    if (registration !== undefined) await runtime.request(endpoint, "unregister", registration);
  };
  try {
    await register();
  } catch (cause) {
    try {
      await unregister();
    } catch (cleanup) {
      throw new TnlCleanupError(cause, cleanup);
    }
    throw cause;
  }
  let currentURL: `https://${string}` | undefined;
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
    process.off("beforeExit", beforeExit);
    detachListener?.();
    if (!terminal && !readyReached) rejectReady(aborted());
    closePromise = operation("sdk.publish.cleanup", async () => {
      await monitoring;
      await unregister();
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
  const handle: Publication = Object.freeze({
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
      if (
        (currentURL !== undefined && currentURL !== status.publicURL) ||
        (assignedURL !== undefined && assignedURL !== status.publicURL)
      )
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
    await register();
  });
  const monitoring = background(async () => {
    while (!closed && !terminal) {
      try {
        if (!isBunServer(server) && !server.listening) throw new TnlError("sdk.listener_failed");
        if (registration === undefined) throw new TnlError("sdk.response_invalid");
        const status = parseStatus(
          await statusRequest(),
          localService ?? invocationID,
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

function validateOptions(options: OpenOptions): void {
  parseValue(openOptionsSchema, options, "sdk.configuration_invalid");
}
function validPublisherCredentialFile(value: unknown): value is string {
  return credentialFileSchema.safeParse(value).success;
}

function aborted(): DOMException {
  return new DOMException("publication was aborted", "AbortError");
}

// inline Fetch handlers own their Node listener; a supplied server is never closed.
export async function openFetch(
  handler: FetchHandler,
  options: OpenOptions = {},
  runtime: Dependencies = dependencies,
  publication?: PublicationSelection,
): Promise<Publication> {
  validateOptions(options);
  const { createFetchServer } = await import("./fetch.js");
  const server = await createFetchServer(handler);
  let base: Publication;
  try {
    base = await openServer(server, options, runtime, publication);
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
      // native unregister joins visitor work before the adapter listener stops.
      // retain the listener if that boundary fails so close can retry safely.
      await base.close();
      await closeServer(server);
    })().catch((cause: unknown) => {
      closing = undefined;
      throw cause;
    });
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
