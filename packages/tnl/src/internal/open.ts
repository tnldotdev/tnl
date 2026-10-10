import { randomBytes, randomInt } from "node:crypto";
import * as path from "node:path";
import type { TnlRatePeriod } from "../config.gen.js";
import { TnlCleanupError, TnlError } from "../errors.js";
import { startRuntime, runtimeRequest } from "./app.js";
import { listeningTarget, type LocalHTTPServer } from "./register.js";
import { record, requiredHostname } from "./runtime.js";

export interface OpenOptions {
  readonly credential?: string;
  readonly server?: string;
  readonly directory?: string;
  readonly allowIP?: readonly string[];
  readonly allowAllIPs?: boolean;
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
  start(directory: string): Promise<string>;
  request(socket: string, operation: string, body: unknown): Promise<unknown>;
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

type Status = {
  state: "starting" | "publishing" | "routable" | "draining" | "stopped" | "failed";
  registrationID: string;
  publicURL?: `https://${string}`;
  publicURLID?: string;
  publishRunNumber?: number;
  failureCode?: string;
};

// all local bindings share the same native socket and the same wire contract.
export async function openServer(
  server: LocalHTTPServer,
  options: OpenOptions = {},
  runtime: Dependencies = dependencies,
): Promise<AdHocTunnel> {
  validateOptions(options);
  const credential = options.credential ?? process.env.TNL_CREDENTIAL;
  if (credential === undefined || credential === "") throw new TnlError("sdk.credential_required");
  if (!/^tnl_eph_[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/.test(credential))
    throw new TnlError("sdk.credential_rejected");
  const target = await listeningTarget(server);
  const hostname = new URL(target).hostname;
  if (hostname !== "127.0.0.1" && hostname !== "[::1]") throw new TnlError("sdk.target_invalid");
  const directory = path.resolve(options.directory ?? process.cwd());
  const owner = randomBytes(16).toString("hex");
  const registrationID = `ivk_${Array.from(
    { length: 22 },
    () => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[randomInt(62)],
  ).join("")}`;
  const registration = { version: 1, registration_id: registrationID, owner };
  const request = {
    ...registration,
    pid: process.pid,
    target,
    ...(options.server === undefined ? {} : { server_url: options.server }),
    credential,
    ...(options.allowIP === undefined ? {} : { allow_ip: [...options.allowIP] }),
    ...(options.allowAllIPs === undefined ? {} : { allow_all_ips: options.allowAllIPs }),
    ...(options.limits === undefined ? {} : { limits: options.limits }),
  };
  let socket = await runtime.start(directory);
  if (options.signal?.aborted) throw aborted();
  let initial: Status;
  try {
    initial = parseAdHocStatus(
      await runtime.request(socket, "ad-hoc/register", request),
      registrationID,
    );
  } catch (cause) {
    try {
      await runtime.request(socket, "ad-hoc/unregister", registration);
    } catch {
      // owner loss and the native lease invalidate an uncertain registration.
    }
    throw cause;
  }
  let currentURL: `https://${string}` | undefined;
  let currentURLID: string | undefined;
  let closed = false;
  let terminal = false;
  let readyReached = false;
  let closePromise: Promise<void> | undefined;
  let resolveReady!: (handle: AdHocTunnel) => void;
  let rejectReady!: (cause: unknown) => void;
  const ready = new Promise<AdHocTunnel>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
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
    options.signal?.removeEventListener("abort", onAbort);
    process.off("beforeExit", beforeExit);
    if (!terminal && !readyReached) rejectReady(aborted());
    closePromise = runtime.request(socket, "ad-hoc/unregister", registration).then(
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
        if (
          cause instanceof TnlError &&
          (cause.code === "sdk.registration_stale" || cause.code === "sdk.dev_unavailable")
        )
          return;
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
  if (options.signal?.aborted) onAbort();
  const strictBudget = options.limits?.requests !== undefined || options.limits?.rate !== undefined;
  let lastRenew = Date.now();

  const observe = (status: Status) => {
    if (status.publicURLID !== undefined) {
      if (currentURLID !== undefined && currentURLID !== status.publicURLID)
        throw new TnlError("sdk.response_invalid");
      currentURLID = status.publicURLID;
    }
    if (status.publicURL !== undefined) {
      if (currentURL !== undefined && currentURL !== status.publicURL)
        throw new TnlError("sdk.response_invalid");
      currentURL = status.publicURL;
    }
    if (status.state === "routable") {
      if (
        status.publicURL === undefined ||
        status.publicURLID === undefined ||
        status.publishRunNumber === undefined
      )
        throw new TnlError("sdk.response_invalid");
      if (!readyReached) {
        readyReached = true;
        resolveReady(handle);
      }
    } else if (status.state === "failed") {
      fail(
        new TnlError(
          status.failureCode === "runtime.credential_rejected"
            ? "sdk.credential_rejected"
            : "sdk.publication_failed",
        ),
      );
    } else if (status.state === "stopped") {
      if (!terminal) {
        terminal = true;
        if (!readyReached) rejectReady(new TnlError("sdk.publication_failed"));
        resolveDone();
      }
      void close().catch(() => {});
    }
  };
  // registering acknowledges the listener, not routability.
  void (async () => {
    let status = initial;
    while (!closed && !terminal) {
      try {
        observe(status);
        if (closed || terminal) break;
        await runtime.pause(250);
        if (closed || terminal) break;
        if (Date.now() - lastRenew >= 5_000) {
          await runtime.request(socket, "ad-hoc/renew", registration);
          lastRenew = Date.now();
        }
        status = parseAdHocStatus(
          await runtime.request(socket, "ad-hoc/status", registration),
          registrationID,
        );
      } catch (cause) {
        if (closed || terminal) break;
        if (
          !strictBudget &&
          cause instanceof TnlError &&
          (cause.code === "sdk.dev_unavailable" || cause.code === "sdk.registration_stale")
        ) {
          try {
            socket = await runtime.start(directory);
            status = parseAdHocStatus(
              await runtime.request(socket, "ad-hoc/register", request),
              registrationID,
            );
            continue;
          } catch (restartError) {
            fail(restartError);
            break;
          }
        }
        fail(
          strictBudget && cause instanceof TnlError && cause.code === "sdk.dev_unavailable"
            ? new TnlError("sdk.registration_stale")
            : cause,
        );
        break;
      }
    }
  })();
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

export function parseAdHocStatus(value: unknown, id: string): Status {
  try {
    const object = record(value, "ad-hoc status");
    const allowed = [
      "version",
      "registration_id",
      "state",
      "public_url_id",
      "public_url",
      "publish_run_number",
      "failure_code",
    ];
    if (
      Object.keys(object).some((key) => !allowed.includes(key)) ||
      object.version !== 1 ||
      object.registration_id !== id ||
      !["starting", "publishing", "routable", "draining", "stopped", "failed"].includes(
        String(object.state),
      )
    )
      throw new TnlError("sdk.response_invalid");
    const state = object.state as Status["state"];
    const publicURLID = object.public_url_id;
    if (
      publicURLID !== undefined &&
      (typeof publicURLID !== "string" || !/^url_[A-Za-z0-9_-]{1,128}$/.test(publicURLID))
    )
      throw new TnlError("sdk.response_invalid");
    const number = object.publish_run_number;
    if (
      number !== undefined &&
      (typeof number !== "number" || !Number.isSafeInteger(number) || number < 1)
    )
      throw new TnlError("sdk.response_invalid");
    const failureCode = object.failure_code;
    if (
      failureCode !== undefined &&
      (typeof failureCode !== "string" || !/^[A-Za-z0-9_.-]{1,128}$/.test(failureCode))
    )
      throw new TnlError("sdk.response_invalid");
    let publicURL: `https://${string}` | undefined;
    if (object.public_url !== undefined) {
      const origin = object.public_url;
      if (typeof origin !== "string") throw new TnlError("sdk.response_invalid");
      const url = new URL(origin);
      const hostname = requiredHostname(url.hostname, "ad-hoc public URL");
      if (origin !== `https://${hostname}`) throw new TnlError("sdk.response_invalid");
      publicURL = origin as `https://${string}`;
    }
    return {
      state,
      registrationID: id,
      ...(publicURLID === undefined ? {} : { publicURLID }),
      ...(publicURL === undefined ? {} : { publicURL }),
      ...(number === undefined ? {} : { publishRunNumber: number }),
      ...(failureCode === undefined ? {} : { failureCode }),
    } as Status;
  } catch (cause) {
    throw new TnlError("sdk.response_invalid", { cause });
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
          "credential",
          "server",
          "directory",
          "allowIP",
          "allowAllIPs",
          "limits",
          "signal",
        ].includes(key),
    ) ||
    (options.credential !== undefined && typeof options.credential !== "string") ||
    (options.server !== undefined &&
      (typeof options.server !== "string" || !/^https:\/\/[^/]+$/.test(options.server))) ||
    (options.directory !== undefined &&
      (typeof options.directory !== "string" || options.directory === "")) ||
    (options.allowAllIPs !== undefined && typeof options.allowAllIPs !== "boolean") ||
    (options.allowIP !== undefined &&
      (!Array.isArray(options.allowIP) ||
        options.allowIP.some((value) => typeof value !== "string"))) ||
    (options.allowAllIPs === true && options.allowIP !== undefined) ||
    (options.signal !== undefined && !(options.signal instanceof AbortSignal))
  )
    throw new TnlError("sdk.configuration_invalid");
  const limits = options.limits;
  if (
    limits !== undefined &&
    (limits === null ||
      typeof limits !== "object" ||
      Array.isArray(limits) ||
      Object.keys(limits).some((key) => !["requests", "rate", "concurrency"].includes(key)) ||
      (limits.requests !== undefined &&
        (!Number.isSafeInteger(limits.requests) || limits.requests < 1)) ||
      (limits.concurrency !== undefined &&
        (!Number.isSafeInteger(limits.concurrency) || limits.concurrency < 1)) ||
      (limits.rate !== undefined &&
        (limits.rate === null ||
          !Number.isSafeInteger(limits.rate.requests) ||
          limits.rate.requests < 1 ||
          typeof limits.rate.per !== "string" ||
          !/^([0-9]+(\.[0-9]+)?|\.[0-9]+)(ns|us|µs|ms|s|m|h)([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))*$/.test(
            limits.rate.per,
          ))))
  )
    throw new TnlError("sdk.configuration_invalid");
}

function aborted(): DOMException {
  return new DOMException("ad-hoc publication was aborted", "AbortError");
}
