import * as z from "zod";
import { TnlError } from "./errors.js";
import type { TnlRatePeriod } from "./config.gen.js";
import type { FetchHandler } from "./internal/publisher/fetch_types.js";
import type {
  NamedPublicationOptions,
  Publication,
  TemporaryPublicationOptions,
  ServiceCertificateSource,
} from "./internal/publisher/publication.js";
import {
  createDurableObjectPublisherStorage,
  type PublisherSQLiteStorage,
} from "./internal/portable/storage-durable-object.js";
import {
  PublisherStorageError,
  storageBytes,
  type PublisherStorage,
} from "./internal/portable/storage.js";
import {
  createPublisherStorageHost,
  type PublisherStorageHost,
} from "./internal/portable/storage-host.js";

export { createDurableObjectPublisherStorage, createPublisherStorageHost };
export type { PublisherSQLiteStorage, PublisherStorage, PublisherStorageHost };
export {
  PublisherStorageError,
  type PublisherStorageErrorCode,
} from "./internal/portable/storage.js";

export interface DurableObjectPublisherState {
  readonly storage: PublisherSQLiteStorage & {
    setAlarm(scheduledTime: number | Date): Promise<void>;
    deleteAlarm(): Promise<void>;
  };
  waitUntil(promise: Promise<unknown>): void;
}

export interface DurablePublicationConfiguration {
  readonly project: string;
  readonly deployment: string;
  readonly service?: string;
  // request signals and credentials are deliberately absent from durable intent.
  readonly options?: Omit<TemporaryPublicationOptions, "signal" | "certificate">;
}

// an existing deployment satisfies this interface. the adapter does not create a
// second publication engine; its factory supplies a fresh authorized deployment.
export interface DurablePublisherDeployment {
  publish(
    name: string,
    handler: FetchHandler,
    options?: NamedPublicationOptions,
  ): Promise<Publication>;
  publish(handler: FetchHandler, options?: TemporaryPublicationOptions): Promise<Publication>;
  close(): Promise<void>;
}

export interface DurableObjectPublisherOptions {
  readonly configuration: DurablePublicationConfiguration;
  // certificate sources are live secrets, not serializable durable intent.
  readonly certificate?: ServiceCertificateSource;
  // load an imported publisher identity from deployed secrets only when this
  // owner's protected identity record is absent. go validates its authority.
  readonly identity: () => Uint8Array | Promise<Uint8Array>;
  readonly handler: (
    configuration: DurablePublicationConfiguration,
  ) => FetchHandler | Promise<FetchHandler>;
  readonly createDeployment: (context: {
    readonly configuration: DurablePublicationConfiguration;
    readonly identity: Uint8Array;
    readonly storage: PublisherStorage;
    readonly storageHost: PublisherStorageHost;
    readonly signal: AbortSignal;
  }) => DurablePublisherDeployment | Promise<DurablePublisherDeployment>;
  readonly storageNamespace?: string;
  readonly restartIntervalMs?: number;
}

export type DurableObjectWasmPublisherOptions = Omit<
  DurableObjectPublisherOptions,
  "createDeployment"
>;

const publicationOptionsSchema = z.strictObject({
  public: z.boolean().exactOptional(),
  targetHostname: z.string().min(1).max(253).exactOptional(),
  telemetry: z.boolean().exactOptional(),
  requirePostQuantum: z.boolean().exactOptional(),
  access: z
    .union([
      z.enum(["restricted", "anonymous"]),
      z.strictObject({
        mode: z.enum(["restricted", "anonymous"]).exactOptional(),
        ip: z.array(z.string().min(1).max(64)).min(1).max(32).exactOptional(),
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
const configurationSchema = z
  .strictObject({
    project: z.string().min(1).max(253),
    deployment: z.string().min(1).max(253),
    service: z.string().min(1).max(253).exactOptional(),
    options: publicationOptionsSchema.exactOptional(),
  })
  .refine(
    (value) =>
      value.service === undefined ||
      value.options === undefined ||
      Object.keys(value.options).every((key) => ["targetHostname", "telemetry"].includes(key)),
  );
const intentSchema = z.strictObject({
  version: z.literal(1),
  status: z.enum(["running", "stopped"]),
  configuration: configurationSchema,
});
type Intent = z.output<typeof intentSchema>;
const intentKey = "@tnl/publisher-owner/v1";
const identityKey = "@tnl/publisher-identity/v1";

interface RunningPublication {
  readonly revision: number;
  readonly controller: AbortController;
  deployment?: DurablePublisherDeployment;
  publication?: Publication;
}

// create one owner per Durable Object instance, not per request, and forward
// its alarm() to this owner. the attached SQLite database retains intent,
// identity, and certificate records across restarts. a wake rebuilds the
// handler and connections; outbound WebSockets are not hibernated, and
// in-flight requests are not resumed.
export class DurableObjectPublisher {
  readonly ready: Promise<void>;
  readonly #state: DurableObjectPublisherState;
  readonly #options: DurableObjectPublisherOptions;
  readonly #configuration: Intent["configuration"];
  readonly #storage: PublisherStorage;
  readonly #storageHost: PublisherStorageHost;
  readonly #interval: number;
  #intent: Intent | undefined;
  #revision = 0;
  #running: RunningPublication | undefined;
  #intentQueue: Promise<void>;
  #runtimeQueue: Promise<void> = Promise.resolve();
  readonly #completions = new WeakMap<Publication, Promise<void>>();

  constructor(state: DurableObjectPublisherState, options: DurableObjectPublisherOptions) {
    const configuration = configurationSchema.safeParse(options.configuration);
    const interval = options.restartIntervalMs ?? 60_000;
    if (
      !configuration.success ||
      typeof options.identity !== "function" ||
      typeof options.handler !== "function" ||
      typeof options.createDeployment !== "function" ||
      !Number.isSafeInteger(interval) ||
      interval < 1000 ||
      interval > 24 * 60 * 60 * 1000
    )
      throw new TnlError("sdk.configuration_invalid");
    if (
      typeof state?.waitUntil !== "function" ||
      typeof state.storage?.setAlarm !== "function" ||
      typeof state.storage.deleteAlarm !== "function"
    )
      throw new PublisherStorageError();
    this.#state = state;
    this.#options = options;
    this.#configuration = configuration.data;
    this.#interval = interval;
    this.#storage = createDurableObjectPublisherStorage(state.storage, options.storageNamespace);
    this.#storageHost = createPublisherStorageHost(this.#storage);
    this.#intentQueue = this.#load();
    // waitUntil keeps the finite startup work alive past the request, not the
    // lifetime of the publication. the object instance owns the live runtime.
    this.ready = this.resume();
    void this.ready.catch(() => {});
  }

  start(): Promise<Publication> {
    return this.#retain(this.#start());
  }

  async #start(): Promise<Publication> {
    await this.#serializeIntent(async () => {
      // set the alarm before saving running intent. if the object restarts
      // between these writes, the alarm can still wake it to read the prior intent.
      await this.#arm();
      const next: Intent = {
        version: 1,
        status: "running",
        configuration: this.#configuration,
      };
      await this.#save(next);
      if (JSON.stringify(this.#intent) !== JSON.stringify(next)) {
        this.#revision++;
        this.#running?.controller.abort();
      }
      this.#intent = next;
    });
    const revision = this.#revision;
    const publication = await this.#reconcile();
    if (publication === undefined || revision !== this.#revision)
      throw new DOMException("publication was stopped", "AbortError");
    const completion = this.#completions.get(publication);
    if (completion === undefined) throw new TnlError("sdk.publication_failed");
    return Object.freeze({
      ...(publication.url === undefined ? {} : { url: publication.url }),
      close: () => this.#retain(this.#stop(revision)),
      wait: () => completion,
      [Symbol.asyncDispose]: () => this.#retain(this.#stop(revision)),
    });
  }

  stop(): Promise<void> {
    return this.#retain(this.#stop());
  }

  // resume never changes stopped or absent intent to running. it is safe to
  // call for an ordinary incoming request as well as during construction.
  resume(): Promise<void> {
    return this.#retain(this.#resume());
  }

  async #resume(): Promise<void> {
    await this.#serializeIntent(async () => {
      if (this.#intent?.status === "running") await this.#arm();
    });
    await this.#reconcile();
  }

  async alarm(): Promise<void> {
    await this.resume();
  }

  #retain<T>(operation: Promise<T>): Promise<T> {
    this.#state.waitUntil(
      operation.then(
        () => {},
        () => {},
      ),
    );
    return operation;
  }

  async #load(): Promise<void> {
    const bytes = await this.#storage.get(intentKey);
    if (bytes === undefined) return;
    let value: unknown;
    try {
      value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      throw new PublisherStorageError("sdk.publisher_storage_invalid");
    }
    const intent = intentSchema.safeParse(value);
    if (!intent.success) throw new PublisherStorageError("sdk.publisher_storage_invalid");
    this.#intent = intent.data;
  }

  #serializeIntent<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.#intentQueue.then(operation);
    // a corrupt initial record must remain a failure, not silently become an
    // empty owner after a later request. later operation failures are retryable.
    this.#intentQueue = result.then(
      () => {},
      () => this.#load(),
    );
    void this.#intentQueue.catch(() => {});
    return result;
  }

  async #save(intent: Intent): Promise<void> {
    await this.#storage.put(intentKey, new TextEncoder().encode(JSON.stringify(intent)));
    await this.#storage.sync(intentKey);
  }

  async #arm(): Promise<void> {
    try {
      await this.#state.storage.setAlarm(Date.now() + this.#interval);
    } catch {
      throw new PublisherStorageError();
    }
  }

  async #stop(expectedRevision?: number): Promise<void> {
    const failures: Error[] = [];
    await this.#serializeIntent(async () => {
      if (expectedRevision !== undefined && expectedRevision !== this.#revision) return;
      const next: Intent = {
        version: 1,
        status: "stopped",
        configuration: this.#intent?.configuration ?? this.#configuration,
      };
      try {
        // persist before touching live sockets. an alarm racing this write must
        // never turn a successful stop back into a publication after restart.
        await this.#save(next);
      } catch {
        failures.push(new PublisherStorageError());
      }
      this.#intent = next;
      this.#revision++;
      this.#running?.controller.abort();
      try {
        await this.#state.storage.deleteAlarm();
      } catch {
        failures.push(new PublisherStorageError());
      }
    });
    try {
      await this.#reconcile();
    } catch (error) {
      appendCleanupFailures(failures, error);
    }
    throwFailures(failures);
  }

  #reconcile(): Promise<Publication | undefined> {
    const result = this.#runtimeQueue.then(async () => {
      if (this.#intent?.status !== "running") {
        await this.#closeRunning();
        return undefined;
      }
      if (this.#running?.revision === this.#revision && this.#running.publication !== undefined)
        return this.#running.publication;
      const revision = this.#revision;
      await this.#closeRunning();
      // intent can change while a retained runtime's cleanup is joining. never
      // allocate a fresh controller for an intent retired during that wait.
      if (this.#intent?.status !== "running" || this.#revision !== revision) return undefined;
      const running: RunningPublication = {
        revision,
        controller: new AbortController(),
      };
      const configuration = this.#intent.configuration;
      this.#running = running;
      try {
        const handler = await this.#options.handler(structuredClone(configuration));
        if (typeof handler !== "function") throw new TnlError("sdk.configuration_invalid");
        if (running.controller.signal.aborted) return undefined;
        const identity = await this.#storage.withLock(
          identityKey,
          async () => {
            const saved = await this.#storage.get(identityKey);
            if (saved !== undefined) return saved;
            const imported = storageBytes(await this.#options.identity());
            if (imported.byteLength === 0)
              throw new PublisherStorageError("sdk.publisher_storage_invalid");
            await this.#storage.put(identityKey, imported);
            await this.#storage.sync(identityKey);
            return imported;
          },
          running.controller.signal,
        );
        if (running.controller.signal.aborted) {
          await this.#closeRunning();
          return undefined;
        }
        running.deployment = await this.#options.createDeployment({
          configuration: structuredClone(configuration),
          identity,
          storage: this.#storage,
          storageHost: this.#storageHost,
          signal: running.controller.signal,
        });
        if (running.controller.signal.aborted) {
          await this.#closeRunning();
          return undefined;
        }
        const options = {
          ...structuredClone(configuration.options),
          ...(this.#options.certificate === undefined
            ? {}
            : { certificate: this.#options.certificate }),
          signal: running.controller.signal,
        };
        running.publication =
          configuration.service === undefined
            ? await running.deployment.publish(handler, options)
            : await running.deployment.publish(configuration.service, handler, options);
        if (running.controller.signal.aborted) {
          await this.#closeRunning();
          return undefined;
        }
        // the owner retains the deployment and handle after start() returns.
        // a finite completion retires its resources; the already-durable alarm
        // retries a fresh authorized runtime rather than replaying live state.
        const completion = running.publication.wait().then(
          () => this.#retain(this.#ended(running)),
          async () => {
            const failures: Error[] = [new TnlError("sdk.publication_failed")];
            try {
              await this.#retain(this.#ended(running));
            } catch (error) {
              appendCleanupFailures(failures, error);
            }
            throwFailures(failures);
          },
        );
        this.#completions.set(running.publication, completion);
        void completion.catch(() => {});
        return running.publication;
      } catch {
        const failures: Error[] = [new TnlError("sdk.publication_failed")];
        try {
          await this.#closeRunning();
        } catch (error) {
          appendCleanupFailures(failures, error);
        }
        throwFailures(failures);
        return undefined;
      }
    });
    this.#runtimeQueue = result.then(
      () => {},
      () => {},
    );
    return result;
  }

  async #ended(running: RunningPublication): Promise<void> {
    const cleanup = this.#runtimeQueue.then(async () => {
      if (this.#running === running) await this.#closeRunning();
    });
    this.#runtimeQueue = cleanup.catch(() => {});
    await cleanup;
  }

  async #closeRunning(): Promise<void> {
    const running = this.#running;
    if (running === undefined) return;
    running.controller.abort();
    const failures: Error[] = [];
    try {
      await running.publication?.close();
    } catch {
      failures.push(new TnlError("sdk.publication_cleanup_failed"));
    }
    try {
      await running.deployment?.close();
    } catch {
      failures.push(new TnlError("sdk.publication_cleanup_failed"));
    }
    if (failures.length === 0) this.#running = undefined;
    throwFailures(failures);
  }
}

function throwFailures(failures: readonly Error[]): void {
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1)
    throw new AggregateError(failures, "publisher operation and cleanup failed");
}

function appendCleanupFailures(failures: Error[], error: unknown): void {
  const count = error instanceof AggregateError ? error.errors.length : 1;
  for (let index = 0; index < count; index++)
    failures.push(new TnlError("sdk.publication_cleanup_failed"));
}
