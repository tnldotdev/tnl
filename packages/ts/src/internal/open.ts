import { randomBytes, randomInt } from "node:crypto";
import * as path from "node:path";
import { isIP } from "node:net";
import type { FetchHandler } from "./fetch_types.js";
import { TnlCleanupError, TnlError } from "../errors.js";
import {
  startRuntime,
  runtimeRequest,
  type RuntimeEndpoint,
  type EndpointSelection,
} from "./local.js";
import { closeServer, listeningTarget, isBunServer, type LocalHTTPServer } from "./register.js";
import { record, exactKeys } from "./runtime.js";
import { parseStatus } from "./status.js";

export type PublisherFile = { readonly publisherFile: string; readonly publisherID?: never };
export type PublisherID = { readonly publisherID: string; readonly publisherFile?: never };
export type OpenOptions = OpenSettings &
  (PublisherFile | PublisherID | { readonly publisherFile?: never; readonly publisherID?: never });
interface OpenSettings {
  readonly server?: string;
  readonly directory?: string;
  readonly stateDir?: string;
  /** hostname the publisher uses to reach this listener. */
  readonly targetHostname?: string;
  readonly allowIP?: readonly string[];
  readonly allowAllIPs?: boolean;
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
export async function openServer(
  server: LocalHTTPServer,
  options: OpenOptions = {},
  runtime: Dependencies = dependencies,
): Promise<AdHocTunnel> {
  validateOptions(options);
  const target = await listeningTarget(server, options);
  const directory = path.resolve(options.directory ?? process.cwd());
  const owner = randomBytes(16).toString("hex");
  const invocationID = `ivk_${Array.from(
    { length: 22 },
    () => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[randomInt(62)],
  ).join("")}`;
  // the SDK process may receive this environment variable after the native
  // owner starts. pass the path, never the credential contents, to that owner.
  const publisherFile =
    options.publisherID === undefined
      ? (options.publisherFile ?? process.env.TNL_PUBLISHER_FILE)
      : undefined;
  if (publisherFile !== undefined && !validPublisherFile(publisherFile))
    throw new TnlError("sdk.configuration_invalid");
  const request = {
    version: 1,
    invocation_id: invocationID,
    owner,
    pid: process.pid,
    target,
    ...(options.server === undefined ? {} : { server_url: options.server }),
    ...(options.publisherID === undefined ? {} : { publisher_id: options.publisherID }),
    ...(publisherFile === undefined ? {} : { publisher_file: publisherFile }),
    ...(options.allowIP === undefined ? {} : { allow_ip: [...options.allowIP] }),
    ...(options.allowAllIPs === undefined ? {} : { allow_all_ips: options.allowAllIPs }),
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
    resolveClosing();
    options.signal?.removeEventListener("abort", onAbort);
    process.off("beforeExit", beforeExit);
    if (!isBunServer(server)) server.off("close", onListenerClose);
    if (!terminal && !readyReached) rejectReady(aborted());
    closePromise = (async () => {
      await monitoring;
      await runtime.request(endpoint, "unregister", registration);
    })().then(
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
  const beforeExit = () => {
    void close().catch(() => {});
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
  const monitoring = (async () => {
    while (!closed && !terminal) {
      try {
        if (!isBunServer(server) && !server.listening) throw new TnlError("sdk.listener_failed");
        const status = parseStatus(
          await runtime.request(endpoint, "status"),
          invocationID,
          registration.registration_id,
          target,
        );
        if (status !== undefined) observe(status);
        if (closed || terminal) break;
        await Promise.race([runtime.pause(250), closingSignal]);
        if (closed || terminal) break;
        if (Date.now() - lastRenew >= 5_000) {
          await runtime.request(endpoint, "renew", registration);
          lastRenew = Date.now();
        }
      } catch (cause) {
        if (closed || terminal) break;
        if (
          cause instanceof TnlError &&
          (cause.code === "sdk.dev_unavailable" || cause.code === "sdk.registration_stale")
        ) {
          try {
            endpoint = await runtime.start(directory, undefined, selection);
            registration = parseRegistration(
              await runtime.request(endpoint, "ad-hoc/register", request),
              owner,
              target,
            );
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
  })();
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
): { version: 1; registration_id: string; owner: string; target: string } {
  try {
    const object = record(value, "invocation registration");
    exactKeys(object, ["version", "registration_id", "owner", "target"], "invocation registration");
    if (
      object.version !== 1 ||
      typeof object.registration_id !== "string" ||
      !/^reg_[a-f0-9]{32}$/.test(object.registration_id) ||
      object.owner !== owner ||
      object.target !== target
    )
      throw new TnlError("sdk.response_invalid");
    return { version: 1, registration_id: object.registration_id, owner, target };
  } catch {
    throw new TnlError("sdk.response_invalid");
  }
}

function validateOptions(options: OpenOptions): void {
  if (
    options === null ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    Object.keys(options).some(
      (key) =>
        ![
          "publisherFile",
          "publisherID",
          "server",
          "directory",
          "stateDir",
          "targetHostname",
          "allowIP",
          "allowAllIPs",
          "signal",
        ].includes(key),
    ) ||
    (options.publisherFile !== undefined && !validPublisherFile(options.publisherFile)) ||
    (options.publisherFile !== undefined && options.publisherID !== undefined) ||
    (options.publisherID !== undefined &&
      (typeof options.publisherID !== "string" ||
        !/^pub_[A-Za-z0-9]{22}$/.test(options.publisherID))) ||
    (options.server !== undefined &&
      (typeof options.server !== "string" || !validServer(options.server))) ||
    (options.directory !== undefined &&
      (typeof options.directory !== "string" ||
        options.directory === "" ||
        options.directory.length > 4096 ||
        options.directory.includes("\0"))) ||
    (options.stateDir !== undefined &&
      (typeof options.stateDir !== "string" ||
        options.stateDir === "" ||
        options.stateDir.length > 4096 ||
        options.stateDir.includes("\0"))) ||
    (options.targetHostname !== undefined &&
      (typeof options.targetHostname !== "string" || options.targetHostname === "")) ||
    (options.allowAllIPs !== undefined && typeof options.allowAllIPs !== "boolean") ||
    (options.allowIP !== undefined &&
      (!Array.isArray(options.allowIP) ||
        options.allowIP.length > 64 ||
        options.allowIP.some((value) => !validNetwork(value)))) ||
    (options.allowAllIPs === true && options.allowIP !== undefined) ||
    (options.signal !== undefined && !(options.signal instanceof AbortSignal))
  )
    throw new TnlError("sdk.configuration_invalid");
}

function validPublisherFile(value: unknown): value is string {
  return (
    typeof value === "string" &&
    path.isAbsolute(value) &&
    value.length <= 4096 &&
    !value.includes("\0")
  );
}

function validServer(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      value.length <= 4096 &&
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      value === url.origin
    );
  } catch {
    return false;
  }
}
function validNetwork(value: unknown): boolean {
  if (typeof value !== "string" || value.length > 64) return false;
  const parts = value.split("/");
  const ip = isIP(parts[0] ?? "");
  return (
    ip !== 0 &&
    parts.length <= 2 &&
    (parts.length === 1 ||
      (/^(0|[1-9][0-9]*)$/.test(parts[1] ?? "") && Number(parts[1]) <= (ip === 4 ? 32 : 128)))
  );
}

function aborted(): DOMException {
  return new DOMException("ad-hoc publication was aborted", "AbortError");
}

// inline Fetch handlers own their Node listener; a supplied server is never closed.
export async function openFetch(
  handler: FetchHandler,
  options: OpenOptions = {},
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
