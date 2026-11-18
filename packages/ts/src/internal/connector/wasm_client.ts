import * as z from "zod";
import { TnlError } from "../../errors.js";
import type {
  TnlClientFactory,
  TnlClientOptions,
  TnlFetch,
  TnlStreamConnectionRegistry,
  TnlTLSStream,
  ServiceFacts,
} from "../../project.js";
import { hostnameSchema, protocolSchema, serviceNameSchema } from "../values.js";
import { clientFactory } from "./client_factory.js";
import type { WasmRuntime } from "./wasm_loader.js";
import type { DeploymentOptions, HTTPNames, ServiceNames as Names } from "./deployment_types.js";
import type { WasmConnection, WasmDeployment } from "./wasm_abi.js";
import { isWasmByteStream, wasmStream } from "./wasm_stream.js";
import type { FetchHandler } from "../publisher/fetch_types.js";
import type {
  Publication,
  NamedPublicationOptions,
  TemporaryPublicationOptions,
} from "../publisher/publication.js";
import {
  portablePublicationOptions,
  publishPortable,
  type PortablePublication,
} from "../portable/publication.js";
import { createPublisherStorageHost, type PublisherStorageHost } from "../portable/storage-host.js";
import { createBrowserPublisherStorage } from "../portable/storage-browser.js";
import type { PublisherStorage } from "../portable/storage.js";

interface Closable {
  close(): Promise<unknown>;
}
function isClosable(value: unknown): value is Closable {
  return (
    typeof value === "object" &&
    value !== null &&
    "close" in value &&
    typeof value.close === "function"
  );
}
function isPublisherStorage(value: unknown): value is PublisherStorage {
  return (
    typeof value === "object" &&
    value !== null &&
    "get" in value &&
    typeof value.get === "function" &&
    "put" in value &&
    typeof value.put === "function" &&
    "delete" in value &&
    typeof value.delete === "function" &&
    "sync" in value &&
    typeof value.sync === "function" &&
    "withLock" in value &&
    typeof value.withLock === "function"
  );
}

type Connection<
  Services extends ServiceFacts,
  Name extends Names<Services>,
> = TnlStreamConnectionRegistry[Services[Name]["protocol"]];

/** deployment handles own isolated go runtimes and load them on demand. */
export interface StreamDeployment<Services extends ServiceFacts> {
  connect<Name extends Names<Services>>(name: Name): Promise<Connection<Services, Name>>;
  client<Name extends Names<Services>, Client>(
    name: Name,
    options: TnlClientOptions<Connection<Services, Name>, Client>,
  ): TnlClientFactory<Client>;
  /**
   * publish a fetch handler through go's existing service-run owner. browser
   * storage defaults to indexeddb and web locks; workers supply private durable
   * storage, normally through the durable object factory. socket upgrades,
   * get/head bodies, targetHostname and native telemetry are not supported.
   * handlers and body sources must settle after request cancellation; close
   * joins their actual cleanup rather than abandoning live callbacks.
   */
  publish<Name extends HTTPNames<Services>>(
    name: Name,
    handler: FetchHandler,
    options?: NamedPublicationOptions,
  ): Promise<Publication>;
  publish(handler: FetchHandler, options?: TemporaryPublicationOptions): Promise<Publication>;
  close(): Promise<void>;
}

export type StreamClientOptions<Services extends ServiceFacts> = {
  readonly controlUrl?: string;
  /** application-owned private storage; browsers otherwise use indexeddb. */
  readonly publisherStorage?: PublisherStorage;
} & (
  | (DeploymentOptions<Services> & { readonly workload?: never })
  | {
      readonly project: string;
      readonly services: Services;
      readonly token?: never;
      readonly workload: PortableWorkloadOptions;
    }
);

export interface PortableWorkloadOptions {
  readonly name: string;
  readonly sourceFingerprint: string;
  /** return a fresh assertion when called, and stop pending I/O when aborted. */
  readonly assertion: (signal: AbortSignal) => string | PromiseLike<string>;
}

export type RuntimeKind = "connector" | "publisher";

// only durable owners supply this context. request-local workers never share a
// live go runtime, and the context does not confer publisher authority.
export interface StreamRuntimeContext {
  readonly storageHost?: PublisherStorageHost;
  readonly signal?: AbortSignal;
}

const optionsSchema = z
  .strictObject({
    project: z
      .string()
      .regex(/^[^/]+\/[^/]+$/)
      .exactOptional(),
    token: z
      .string()
      .min(1)
      .max(32 << 10)
      .exactOptional(),
    services: z
      .record(serviceNameSchema, z.strictObject({ protocol: protocolSchema }))
      .refine((value) => Object.keys(value).length <= 32)
      .exactOptional(),
    publisherStorage: z.custom<PublisherStorage>(isPublisherStorage).exactOptional(),
    controlUrl: z.string().min(1).max(1024).exactOptional(),
    workload: z
      .strictObject({
        name: serviceNameSchema,
        sourceFingerprint: z.string().regex(/^[0-9a-f]{64}$/),
        assertion: z.custom<PortableWorkloadOptions["assertion"]>(
          (value) => typeof value === "function",
        ),
      })
      .exactOptional(),
  })
  .refine((value) =>
    value.workload === undefined
      ? value.services !== undefined || value.project !== undefined
      : value.project !== undefined &&
        value.token === undefined &&
        value.services !== undefined &&
        Object.keys(value.services).length > 0,
  );
const metadataSchema = z.strictObject({
  key: z.string().min(1).max(4096),
  protocol: protocolSchema,
  hostname: hostnameSchema,
});

function isDeployment(value: unknown): value is WasmDeployment {
  return (
    typeof value === "object" &&
    value !== null &&
    "connect" in value &&
    typeof value.connect === "function" &&
    "close" in value &&
    typeof value.close === "function"
  );
}
function isConnection(value: unknown): value is WasmConnection {
  return (
    typeof value === "object" &&
    value !== null &&
    "metadata" in value &&
    "open" in value &&
    typeof value.open === "function" &&
    "fetch" in value &&
    typeof value.fetch === "function" &&
    "close" in value &&
    typeof value.close === "function"
  );
}

function bridgeError(error: unknown): TnlError {
  // arbitrary go/host errors can contain a credential or response body. neither
  // their message nor their cause is part of the public binding error.
  if (typeof error === "object" && error !== null && "code" in error) {
    switch (error.code) {
      case "sdk.authentication_required":
      case "sdk.workload_assertion_unavailable":
      case "sdk.configuration_invalid":
      case "sdk.connection_unavailable":
      case "sdk.client_capacity":
      case "sdk.cleanup_failed":
      case "sdk.wasm_invalid":
      case "sdk.wasm_unavailable":
        return new TnlError(error.code);
    }
  }
  return new TnlError("sdk.connection_unavailable");
}

function throwFailures(results: PromiseSettledResult<unknown>[], ignored?: unknown): void {
  const errors = [
    ...new Set(
      results.flatMap((result) =>
        result.status === "rejected" && result.reason !== ignored ? [result.reason as unknown] : [],
      ),
    ),
  ];
  if (errors.length === 1) throw errors[0];
  if (errors.length > 1) throw new AggregateError(errors, "deployment cleanup failed");
}

/**
 * explicit portable credentials or a request-scoped workload assertion.
 * no process environment, filesystem, installed owner, or local discovery.
 */
export function createStreamClient<const Services extends ServiceFacts = Record<never, never>>(
  options: StreamClientOptions<Services>,
  loadRuntime: (kind: RuntimeKind) => Promise<WasmRuntime>,
  context: StreamRuntimeContext = {},
) {
  const parsed = optionsSchema.safeParse(options);
  if (!parsed.success) throw new TnlError("sdk.configuration_invalid");
  const { project, token, publisherStorage, workload, controlUrl } = parsed.data;
  const protocols = new Map(
    Object.entries(parsed.data.services ?? {}).map(([name, service]) => [name, service.protocol]),
  );
  return Object.freeze({
    deployment(name: string): StreamDeployment<Services> {
      if (name === "local") throw new TnlError("sdk.capability_unsupported");
      if (
        (!serviceNameSchema.safeParse(name).success && !/^dpl_[A-Za-z0-9]{22}$/.test(name)) ||
        project === undefined ||
        (token === undefined && workload === undefined)
      )
        throw new TnlError("sdk.configuration_invalid");
      const selectedProject = project;
      const credential = token;
      const closedError = new TnlError("sdk.client_closed");
      const lifetime = new AbortController();
      const externalAbort = () => lifetime.abort();
      context.signal?.addEventListener("abort", externalAbort, { once: true });
      if (context.signal?.aborted) externalAbort();
      const pending = new Set<Promise<unknown>>();
      const publicationPending = new Set<Promise<unknown>>();
      const factories = new Set<{ close(): Promise<void> }>();
      const connections = new Set<Closable>();
      const invalidStreams = new Set<Closable>();
      const streams = new Set<TnlTLSStream>();
      const publications = new Set<PortablePublication>();
      const runtimes = new Map<RuntimeKind, WasmRuntime>();
      const startingRuntimes = new Map<RuntimeKind, Promise<WasmRuntime>>();
      let backend: Closable | undefined;
      let loading: Promise<WasmDeployment> | undefined;
      let storageHost = context.storageHost;
      let ownedStorage: ReturnType<typeof createBrowserPublisherStorage> | undefined;
      let closed = false;
      let closing: Promise<void> | undefined;
      let backendClosed = false;

      function track<Value>(work: Promise<Value>): Promise<Value> {
        pending.add(work);
        void work.then(
          () => pending.delete(work),
          () => pending.delete(work),
        );
        return work;
      }
      function validate(service: string) {
        if (closed) throw closedError;
        const protocol = protocols.get(service);
        if (protocol === undefined) throw new TnlError("sdk.configuration_invalid");
        return protocol;
      }
      function ownedRuntime(kind: RuntimeKind): Promise<WasmRuntime> {
        const existing = startingRuntimes.get(kind);
        if (existing !== undefined) return existing;
        const starting = loadRuntime(kind).then((value) => {
          runtimes.set(kind, value);
          if (closed) throw closedError;
          return value;
        });
        startingRuntimes.set(kind, starting);
        return starting;
      }
      function publicationStorage(): PublisherStorageHost {
        if (storageHost === undefined) {
          const storage = publisherStorage ?? (ownedStorage ??= createBrowserPublisherStorage());
          storageHost = createPublisherStorageHost(storage);
        }
        return storageHost;
      }
      function selected(): Promise<WasmDeployment> {
        loading ??= (async () => {
          const current = await ownedRuntime("connector");
          if (typeof current.bridge.createDeployment !== "function")
            throw new TnlError("sdk.wasm_invalid");
          const value = await current.bridge.createDeployment(
            // registered credentials may include publish-only facts; workload
            // exchange instead requests the exact set of selected names.
            {
              project: selectedProject,
              name,
              ...(controlUrl === undefined ? {} : { controlUrl }),
              ...(credential === undefined ? {} : { credential }),
              ...(workload === undefined
                ? { services: [] }
                : {
                    workload: {
                      name: workload.name,
                      sourceFingerprint: workload.sourceFingerprint,
                    },
                    services: [...protocols.keys()],
                  }),
            },
            {
              fetch: globalThis.fetch.bind(globalThis),
              WebSocket: globalThis.WebSocket,
              ...(workload === undefined
                ? {}
                : {
                    assertion: async (signal: AbortSignal) => workload.assertion(signal),
                  }),
            },
            lifetime.signal,
          );
          if (isClosable(value)) backend = value;
          if (!isDeployment(value)) throw new TnlError("sdk.wasm_invalid");
          if (closed) throw closedError;
          return value;
        })().catch((error: unknown) => {
          if (error === closedError) throw error;
          if (error instanceof TnlError) throw new TnlError(error.code);
          if (error instanceof Error && error.name === "AbortError")
            throw new DOMException("connector operation canceled", "AbortError");
          throw bridgeError(error);
        });
        return loading;
      }
      function operationError(error: unknown, signal: AbortSignal): Error {
        if (error === closedError) return closedError;
        if (
          signal.aborted &&
          (error === undefined || (error instanceof Error && error.name === "AbortError"))
        ) {
          if (closed) return closedError;
          return new DOMException("connector operation canceled", "AbortError");
        }
        // a concurrent stop must not erase an independent operation/cleanup
        // failure. go marks cancellation with AbortError, not arbitrary text.
        return bridgeError(error);
      }
      function settings(raw: WasmConnection, metadata: z.output<typeof metadataSchema>) {
        const origin: `https://${string}` = `https://${metadata.hostname}`;
        const open = (options?: Readonly<{ signal?: AbortSignal }>) => {
          if (closed) return Promise.reject(closedError);
          if (streams.size + invalidStreams.size + pending.size >= 64)
            return Promise.reject(new TnlError("sdk.client_capacity"));
          const signal =
            options?.signal === undefined
              ? lifetime.signal
              : AbortSignal.any([lifetime.signal, options.signal]);
          return track(
            (async () => {
              signal.throwIfAborted();
              const value = await raw.open(signal);
              if (!isWasmByteStream(value)) {
                if (isClosable(value)) invalidStreams.add(value);
                throw new TnlError("sdk.wasm_invalid");
              }
              const stream = wasmStream(value, signal, () => streams.delete(stream));
              streams.add(stream);
              if (signal.aborted) {
                await stream.close();
                throw operationError(undefined, signal);
              }
              if (metadata.protocol !== "tcp" && metadata.protocol !== "mysql")
                await stream.startTls();
              return stream;
            })().catch((error: unknown) => {
              throw operationError(error, signal);
            }),
          );
        };
        const fetch: TnlFetch = (input, init) => {
          if (closed) return Promise.reject(closedError);
          if (pending.size >= 64) return Promise.reject(new TnlError("sdk.client_capacity"));
          return track(
            (async () => {
              let request: Request;
              try {
                const requestOptions: RequestInit & { duplex?: "half" } = {
                  ...init,
                  ...(init?.body instanceof ReadableStream ? { duplex: "half" } : {}),
                };
                request = new Request(
                  input instanceof Request ? input : new URL(input.toString(), origin),
                  requestOptions,
                );
              } catch {
                throw new TnlError("sdk.configuration_invalid");
              }
              const url = new URL(request.url);
              if (url.origin !== origin || url.username !== "" || url.password !== "") {
                const rejected = new TnlError("sdk.configuration_invalid");
                try {
                  await request.body?.cancel();
                } catch {
                  throw new AggregateError(
                    [rejected, new TnlError("sdk.cleanup_failed")],
                    "request setup and cleanup failed",
                  );
                }
                throw rejected;
              }
              const signal = AbortSignal.any([lifetime.signal, request.signal]);
              try {
                signal.throwIfAborted();
                const value = await raw.fetch(
                  new Request(request, { signal, redirect: "manual" }),
                  signal,
                );
                if (!(value instanceof Response)) throw new TnlError("sdk.wasm_invalid");
                return value;
              } catch (error) {
                throw operationError(error, signal);
              }
            })(),
          );
        };
        switch (metadata.protocol) {
          case "http":
            return Object.freeze({ url: origin, fetch, open });
          case "kubernetes":
            return Object.freeze({ server: origin, fetch, open });
          default:
            return Object.freeze({ open });
        }
      }
      function acquire<Name extends Names<Services>>(service: Name) {
        const protocol = validate(service);
        if (pending.size >= 64) throw new TnlError("sdk.client_capacity");
        return track(
          (async () => {
            try {
              const value = await (await selected()).connect(service, lifetime.signal);
              if (isClosable(value)) connections.add(value);
              if (!isConnection(value)) throw new TnlError("sdk.wasm_invalid");
              if (connections.size > 64) {
                try {
                  await value.close();
                  connections.delete(value);
                } catch {
                  throw new TnlError("sdk.cleanup_failed");
                }
                throw new TnlError("sdk.client_capacity");
              }
              const metadata = metadataSchema.safeParse(value.metadata);
              if (!metadata.success || metadata.data.protocol !== protocol)
                throw new TnlError("sdk.wasm_invalid");
              if (closed) throw closedError;
              // metadata was validated against both the bridge schema and this
              // exact declared name/protocol before the generic indexed result.
              return {
                key: metadata.data.key,
                connection: settings(value, metadata.data) as Connection<Services, Name>,
              };
            } catch (error) {
              throw operationError(error, lifetime.signal);
            }
          })(),
        );
      }
      return Object.freeze({
        async connect<Name extends Names<Services>>(service: Name) {
          return (await acquire(service)).connection;
        },
        client<Name extends Names<Services>, Client>(
          service: Name,
          driver: TnlClientOptions<Connection<Services, Name>, Client>,
        ) {
          validate(service);
          if (factories.size >= 64) throw new TnlError("sdk.client_capacity");
          const factory = clientFactory(() => acquire(service), driver);
          const close = factory.close.bind(factory);
          factory.close = async () => {
            await close();
            factories.delete(factory);
          };
          factories.add(factory);
          return factory;
        },
        async publish(
          first: string | FetchHandler,
          second?: FetchHandler | TemporaryPublicationOptions,
          third?: NamedPublicationOptions,
        ): Promise<Publication> {
          if (closed) throw closedError;
          if (credential === undefined) throw new TnlError("sdk.authentication_required");
          if (publications.size + pending.size >= 64) throw new TnlError("sdk.client_capacity");
          const service = typeof first === "string" ? first : undefined;
          const handler = typeof first === "string" ? second : first;
          if (
            typeof handler !== "function" ||
            (service !== undefined &&
              (!serviceNameSchema.safeParse(service).success ||
                (protocols.size > 0 && protocols.get(service) !== "http"))) ||
            (service === undefined && (typeof second === "function" || third !== undefined))
          )
            throw new TnlError("sdk.configuration_invalid");
          const chosen =
            service === undefined ? (typeof second === "function" ? undefined : second) : third;
          const parsed = portablePublicationOptions(chosen ?? {}, service !== undefined);
          const signal =
            parsed.signal === undefined
              ? lifetime.signal
              : AbortSignal.any([lifetime.signal, parsed.signal]);
          const work = (async () => {
            if (signal.aborted) throw operationError(undefined, signal);
            const storage = publicationStorage();
            const current = await ownedRuntime("publisher");
            return publishPortable({
              bridge: current.bridge,
              selection: {
                project: selectedProject,
                deployment: name,
                credential,
                ...(service === undefined ? { temporary: parsed.temporary } : { service }),
              },
              handler,
              storage,
              signal,
              certificate: parsed.certificate,
              retain: (publication) => publications.add(publication),
              release: (publication) => publications.delete(publication),
            });
          })().catch((error: unknown) => {
            if (closed && error instanceof Error && error.name === "AbortError") throw closedError;
            throw error;
          });
          publicationPending.add(work);
          void work.then(
            () => publicationPending.delete(work),
            () => publicationPending.delete(work),
          );
          return track(work);
        },
        close(): Promise<void> {
          closed = true;
          context.signal?.removeEventListener("abort", externalAbort);
          const stoppingPublications = [...publications].map((publication) => publication.close());
          lifetime.abort(closedError);
          closing ??= (async () => {
            const joining = [...pending];
            const publicationWork = new Set(publicationPending);
            // stop established streams immediately, including those held by a
            // driver whose own close is still waiting on a blocked read.
            const stopped = [...streams].map((stream) => stream.close());
            const joined = await Promise.allSettled(joining);
            const resourceResults = await Promise.allSettled([
              ...stopped,
              ...[...streams].map((stream) => stream.close()),
              ...[...factories].map(async (factory) => {
                await factory.close();
                factories.delete(factory);
              }),
              ...[...connections].map(async (connection) => {
                try {
                  await connection.close();
                  connections.delete(connection);
                } catch {
                  throw new TnlError("sdk.cleanup_failed");
                }
              }),
              ...[...invalidStreams].map(async (stream) => {
                try {
                  await stream.close();
                  invalidStreams.delete(stream);
                } catch {
                  throw new TnlError("sdk.cleanup_failed");
                }
              }),
            ]);
            const publicationResults = await Promise.allSettled([
              ...stoppingPublications,
              ...[...publications].map((publication) => publication.close()),
            ]);
            for (const publication of publications)
              if (publication.joined) publications.delete(publication);
            if (backend !== undefined && !backendClosed) {
              try {
                await backend.close();
                backendClosed = true;
              } catch {
                resourceResults.push({
                  status: "rejected",
                  reason: new TnlError("sdk.cleanup_failed"),
                });
              }
            }
            const results = [...joined, ...resourceResults, ...publicationResults];
            const nonPublicationResults = [
              ...joined.filter((_, index) => {
                const work = joining[index];
                return work === undefined || !publicationWork.has(work);
              }),
              ...resourceResults,
            ];
            // failed connector/driver closes retain live callbacks for retry.
            // publication failures can exit only after their joined result;
            // every failure still remains in results for the caller.
            const ownersClosed = nonPublicationResults.every(
              (result) => result.status === "fulfilled" || result.reason === closedError,
            );
            if (
              ownersClosed &&
              publications.size === 0 &&
              backendClosed === (backend !== undefined)
            ) {
              results.push(
                ...(await Promise.allSettled(
                  [...runtimes].map(async ([kind, runtime]) => {
                    try {
                      await runtime.bridge.close();
                      await runtime.exited;
                      runtimes.delete(kind);
                    } catch {
                      throw new TnlError("sdk.cleanup_failed");
                    }
                  }),
                )),
              );
            }
            if (runtimes.size === 0 && ownedStorage !== undefined) {
              try {
                await ownedStorage.close();
                ownedStorage = undefined;
              } catch {
                results.push({
                  status: "rejected",
                  reason: new TnlError("sdk.publication_cleanup_failed"),
                });
              }
            }
            throwFailures(results, closedError);
          })().finally(() => {
            closing = undefined;
          });
          return closing;
        },
      });
    },
  });
}
