import * as z from "zod";
import { TnlError, type TnlErrorCode } from "../../errors.js";
import type { TnlRatePeriod } from "../../config.gen.js";
import type { WasmBridge, WasmPublication } from "../connector/wasm_abi.js";
import type { FetchHandler } from "../publisher/fetch_types.js";
import type {
  Publication,
  PublicationRun,
  NamedPublicationOptions,
  TemporaryPublicationOptions,
} from "../publisher/publication.js";
import type { PublisherStorageHost } from "./storage-host.js";
import { preserveRequestHeaders } from "./request.js";
import { publicationRunSchema, publisherURLSchema } from "../publication_run.js";

const optionsSchema = z.strictObject({
  targetHostname: z.string().min(1).exactOptional(),
  telemetry: z.boolean().exactOptional(),
  signal: z.instanceof(AbortSignal).exactOptional(),
  requirePostQuantum: z.boolean().exactOptional(),
  access: z
    .union([
      z.enum(["restricted", "anonymous"]),
      z.strictObject({
        mode: z.enum(["restricted", "anonymous"]).exactOptional(),
        ip: z.array(z.string().min(1).max(64)).max(32).exactOptional(),
      }),
    ])
    .exactOptional(),
  limits: z
    .strictObject({
      requests: z.number().int().positive().exactOptional(),
      concurrency: z.number().int().positive().exactOptional(),
      rate: z
        .strictObject({
          requests: z.number().int().positive(),
          per: z.custom<TnlRatePeriod>(
            (value) =>
              typeof value === "string" &&
              /^(?:[0-9]+(?:\.[0-9]+)?(?:ns|us|µs|ms|s|m|h)){1,4}$/.test(value),
          ),
        })
        .exactOptional(),
    })
    .exactOptional(),
});

export function portablePublicationOptions(
  options: NamedPublicationOptions | TemporaryPublicationOptions,
  named: boolean,
) {
  const parsed = optionsSchema.safeParse(options);
  if (
    !parsed.success ||
    (named &&
      Object.keys(options).some((key) => !["targetHostname", "telemetry", "signal"].includes(key)))
  )
    throw new TnlError("sdk.configuration_invalid");
  // there is no listener hostname or native telemetry process in this host.
  if (parsed.data.targetHostname !== undefined || parsed.data.telemetry === true)
    throw new TnlError("sdk.capability_unsupported");
  const { access, limits, requirePostQuantum, signal } = parsed.data;
  return {
    signal,
    temporary: {
      ...(requirePostQuantum === undefined ? {} : { require_post_quantum: requirePostQuantum }),
      ...(access === undefined
        ? {}
        : {
            access_mode: typeof access === "string" ? access : (access.mode ?? "restricted"),
            ...(typeof access === "string" || access.ip === undefined ? {} : { ip: access.ip }),
          }),
      ...(limits === undefined
        ? {}
        : {
            limits: {
              ...(limits.requests === undefined ? {} : { total: limits.requests }),
              ...(limits.concurrency === undefined ? {} : { concurrency: limits.concurrency }),
              ...(limits.rate === undefined
                ? {}
                : { rate: { count: limits.rate.requests, per: limits.rate.per } }),
            },
          }),
    },
  };
}

function isPromise(value: unknown): value is PromiseLike<unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    "then" in value &&
    typeof value.then === "function"
  );
}
function isPublication(value: unknown): value is WasmPublication {
  return (
    typeof value === "object" &&
    value !== null &&
    "url" in value &&
    "ready" in value &&
    isPromise(value.ready) &&
    "closed" in value &&
    isPromise(value.closed) &&
    "close" in value &&
    typeof value.close === "function"
  );
}
export function publicationError(
  cause: unknown,
  fallback: TnlErrorCode = "sdk.publication_failed",
): Error {
  if (cause instanceof Error && cause.name === "AbortError")
    return new DOMException("publication canceled", "AbortError");
  if (typeof cause === "object" && cause !== null && "code" in cause) {
    switch (cause.code) {
      case "sdk.authentication_required":
      case "sdk.configuration_invalid":
      case "sdk.client_capacity":
      case "sdk.wasm_invalid":
      case "sdk.wasm_unavailable":
      case "sdk.publication_failed":
      case "sdk.publication_cleanup_failed":
        return new TnlError(cause.code);
      case "sdk.cleanup_failed":
        return new TnlError("sdk.publication_cleanup_failed");
    }
  }
  return new TnlError(fallback);
}

function failures(results: readonly PromiseSettledResult<unknown>[]): unknown[] {
  return [
    ...new Set(
      results.flatMap((result) => (result.status === "rejected" ? [result.reason as unknown] : [])),
    ),
  ];
}
function throwFailures(errors: readonly unknown[]): void {
  if (errors.length === 1) throw errors[0];
  if (errors.length > 1)
    throw new AggregateError(errors, "publication operation and cleanup failed");
}

export interface PortablePublication extends Publication {
  /** closed has settled: go joined the run, requests, storage and cleanup. */
  readonly joined: boolean;
}

export async function publishPortable(options: {
  readonly bridge: WasmBridge;
  readonly selection: {
    readonly project: string;
    readonly deployment: string;
    readonly credential: string;
    readonly service?: string;
    readonly temporary?: ReturnType<typeof portablePublicationOptions>["temporary"];
  };
  readonly handler: FetchHandler;
  readonly storage: PublisherStorageHost;
  readonly signal: AbortSignal;
  readonly retain: (publication: PortablePublication) => void;
  readonly release: (publication: PortablePublication) => void;
}): Promise<PortablePublication> {
  const lifetime = new AbortController();
  const signal = AbortSignal.any([options.signal, lifetime.signal]);
  if (signal.aborted) throw new DOMException("publication canceled", "AbortError");
  if (typeof options.bridge.publish !== "function") throw new TnlError("sdk.wasm_invalid");
  let raw: unknown;
  try {
    raw = await options.bridge.publish(JSON.stringify(options.selection), {
      storage: options.storage,
      controlFetch: globalThis.fetch.bind(globalThis),
      signal,
      async fetch(request) {
        if (signal.aborted) throw new DOMException("publication canceled", "AbortError");
        try {
          if (!(request instanceof Request)) throw new TnlError("sdk.wasm_invalid");
          const result = await options.handler(preserveRequestHeaders(request));
          if (!(result instanceof Response)) throw new TnlError("sdk.publication_failed");
          // keep the actual Response, including headers attached by response().
          return result;
        } catch {
          throw new TnlError("sdk.publication_failed");
        }
      },
    });
  } catch (error) {
    throw publicationError(error);
  }
  if (!isPublication(raw)) {
    // even malformed handles may have acquired a run. never silently drop a
    // usable cleanup capability because another field failed validation.
    const invalid = new TnlError("sdk.wasm_invalid");
    if (
      typeof raw === "object" &&
      raw !== null &&
      "close" in raw &&
      typeof raw.close === "function"
    ) {
      try {
        await raw.close();
      } catch {
        throw new AggregateError(
          [invalid, new TnlError("sdk.publication_cleanup_failed")],
          "publication setup and cleanup failed",
        );
      }
    }
    throw invalid;
  }
  let joined = false;
  let stopped = false;
  let closing: Promise<void> | undefined;
  const completion = Promise.resolve(raw.closed).then(
    () => {
      joined = true;
      signal.removeEventListener("abort", aborted);
      lifetime.abort();
    },
    (error: unknown) => {
      joined = true;
      signal.removeEventListener("abort", aborted);
      lifetime.abort();
      throw publicationError(error);
    },
  );
  void completion.catch(() => {});
  const base = raw;
  let run: PublicationRun | undefined;
  let publisherURL: `https://${string}` | undefined;
  function close(): Promise<void> {
    signal.removeEventListener("abort", aborted);
    // fence the application callback before asking go to stop. a saved host
    // function cannot start another handler after this publication is closed.
    lifetime.abort();
    if (closing !== undefined) return closing;
    closing = (async () => {
      const results = await Promise.allSettled([
        Promise.resolve()
          .then(() => base.close())
          .catch((error: unknown) => {
            throw publicationError(error, "sdk.publication_cleanup_failed");
          }),
        completion,
      ]);
      stopped = joined;
      const errors = failures(results);
      if (errors.length === 0) options.release(publication);
      throwFailures(errors);
    })().finally(() => {
      if (!stopped) closing = undefined;
    });
    return closing;
  }
  function aborted(): void {
    void close().catch(() => {});
  }
  const parsedURL = z
    .templateLiteral(["https://", z.string()])
    .refine((value) => {
      const url = URL.parse(value);
      return url !== null && url.origin === value && url.username === "" && url.password === "";
    })
    .safeParse(raw.url);
  const publication: PortablePublication = Object.freeze({
    get url(): `https://${string}` {
      if (!parsedURL.success) throw new TnlError("sdk.wasm_invalid");
      return parsedURL.data;
    },
    get joined() {
      return joined;
    },
    get run() {
      return run;
    },
    get publisherURL() {
      return publisherURL;
    },
    close,
    wait: () => completion,
    [Symbol.asyncDispose]: close,
  });
  options.retain(publication);
  signal.addEventListener("abort", aborted, { once: true });
  if (signal.aborted) aborted();
  try {
    if (!parsedURL.success) throw new TnlError("sdk.wasm_invalid");
    await raw.ready;
    if (signal.aborted) throw new DOMException("publication canceled", "AbortError");
    const reference = publicationRunSchema.safeParse(raw.run);
    if (!reference.success) throw new TnlError("sdk.wasm_invalid");
    run = Object.freeze(reference.data);
    if (raw.publisherURL !== undefined) {
      const parsed = publisherURLSchema.safeParse(raw.publisherURL);
      if (!parsed.success || run === undefined || parsed.data === publication.url)
        throw new TnlError("sdk.wasm_invalid");
      publisherURL = parsed.data;
    }
    return publication;
  } catch (error) {
    const canceled = signal.aborted;
    const cleanup = await Promise.allSettled([close()]);
    const cleanupErrors = failures(cleanup);
    // go's ready promise may report "stopped before readiness" after a clean
    // stop. successful close plus closed is the joined lifecycle result; only
    // that result can distinguish cancellation from an independent failure.
    const original =
      canceled &&
      cleanupErrors.length === 0 &&
      !(error instanceof TnlError && error.code === "sdk.wasm_invalid")
        ? new DOMException("publication canceled", "AbortError")
        : publicationError(error);
    throwFailures([original, ...cleanupErrors]);
    throw original;
  }
}
