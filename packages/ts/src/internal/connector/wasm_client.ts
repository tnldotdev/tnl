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
import { loadWasm, type WasmRuntime } from "./wasm_loader.js";
import type { WasmConnection, WasmDeployment } from "./wasm_abi.js";
import { isWasmByteStream, wasmStream } from "./wasm_stream.js";

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

type Names<Services extends ServiceFacts> = Extract<keyof Services, string>;
type Connection<
  Services extends ServiceFacts,
  Name extends Names<Services>,
> = TnlStreamConnectionRegistry[Services[Name]["protocol"]];

/** browser/worker deployment handles own one isolated go runtime each. */
export interface StreamDeployment<Services extends ServiceFacts> {
  connect<Name extends Names<Services>>(name: Name): Promise<Connection<Services, Name>>;
  client<Name extends Names<Services>, Client>(
    name: Name,
    options: TnlClientOptions<Connection<Services, Name>, Client>,
  ): TnlClientFactory<Client>;
  /** publication is native-only in this connector release. */
  publish(...args: readonly unknown[]): Promise<never>;
  close(): Promise<void>;
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
  })
  .refine((value) => value.services !== undefined || value.project !== undefined);
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
 * explicit portable credentials only: no process environment, filesystem,
 * provider token acquisition, installed owner, or local target discovery.
 */
export function createStreamClient<const Services extends ServiceFacts = Record<never, never>>(
  options: { project?: string; services?: Services; token?: string },
  module?: WebAssembly.Module,
) {
  const parsed = optionsSchema.safeParse(options);
  if (!parsed.success) throw new TnlError("sdk.configuration_invalid");
  const { project, token } = parsed.data;
  const protocols = new Map(
    Object.entries(parsed.data.services ?? {}).map(([name, service]) => [name, service.protocol]),
  );
  return Object.freeze({
    deployment(name: string): StreamDeployment<Services> {
      if (name === "local") throw new TnlError("sdk.capability_unsupported");
      if (
        (!serviceNameSchema.safeParse(name).success && !/^dpl_[A-Za-z0-9]{22}$/.test(name)) ||
        project === undefined ||
        token === undefined
      )
        throw new TnlError("sdk.configuration_invalid");
      const selectedProject = project;
      const credential = token;
      const closedError = new TnlError("sdk.client_closed");
      const lifetime = new AbortController();
      const pending = new Set<Promise<unknown>>();
      const factories = new Set<{ close(): Promise<void> }>();
      const connections = new Set<Closable>();
      const invalidStreams = new Set<Closable>();
      const streams = new Set<TnlTLSStream>();
      let runtime: WasmRuntime | undefined;
      let backend: Closable | undefined;
      let loading: Promise<WasmDeployment> | undefined;
      let closed = false;
      let closing: Promise<void> | undefined;
      let runtimeClosed = false;
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
      function selected(): Promise<WasmDeployment> {
        loading ??= (async () => {
          runtime = await loadWasm(module);
          if (closed) throw closedError;
          const value = await runtime.bridge.createDeployment(
            // facts include publish-only services. connect authorizes the exact
            // requested name, not every declaration in the project.
            { project: selectedProject, name, credential, services: [] },
            { fetch: globalThis.fetch.bind(globalThis), WebSocket: globalThis.WebSocket },
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
                request = new Request(
                  input instanceof Request ? input : new URL(input.toString(), origin),
                  init,
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
        async publish(): Promise<never> {
          if (closed) throw closedError;
          throw new TnlError("sdk.capability_unsupported");
        },
        close(): Promise<void> {
          closed = true;
          lifetime.abort(closedError);
          closing ??= (async () => {
            const joining = [...pending];
            // stop established streams immediately, including those held by a
            // driver whose own close is still waiting on a blocked read.
            const stopped = [...streams].map((stream) => stream.close());
            const joined = await Promise.allSettled(joining);
            const results = [
              ...joined,
              ...(await Promise.allSettled([
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
              ])),
            ];
            if (backend !== undefined && !backendClosed) {
              try {
                await backend.close();
                backendClosed = true;
              } catch {
                results.push({ status: "rejected", reason: new TnlError("sdk.cleanup_failed") });
              }
            }
            // do not exit go after a failed owned close: a retry needs its live
            // callbacks. successful closes never repeat on a later attempt.
            const ownersClosed = results.every(
              (result) => result.status === "fulfilled" || result.reason === closedError,
            );
            if (
              ownersClosed &&
              backendClosed === (backend !== undefined) &&
              runtime !== undefined &&
              !runtimeClosed
            ) {
              try {
                await runtime.bridge.close();
                await runtime.exited;
                runtimeClosed = true;
              } catch {
                results.push({ status: "rejected", reason: new TnlError("sdk.cleanup_failed") });
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
