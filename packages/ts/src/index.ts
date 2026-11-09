import { developmentPort } from "./internal/publisher/port.js";
import { loadConnection } from "./internal/connector/connection_bridge.js";
import { serviceMetadata } from "./internal/project/service_metadata.js";
import {
  parseRuntimePayload,
  parseProjectRuntime,
  type ProjectMetadata,
  type ProjectRuntime,
} from "./internal/project/runtime.js";
import { TnlError } from "./errors.js";
import { httpResources } from "./internal/connector/http_resource.js";
import type { TnlHTTPConnection } from "./client.js";
import type { PrepareOptions, PreparedService } from "./internal/publisher/app.js";
import type { PublishOptions } from "./internal/publisher/publish.js";
import type { Publication } from "./internal/publisher/publication.js";
export type {
  Publication,
  PublicationStatus,
  PublicationEvent,
} from "./internal/publisher/publication.js";
import type { LocalHTTPServer } from "./internal/publisher/register.js";
import type { FetchHandler } from "./internal/publisher/fetch_types.js";
import type {
  TnlConnection,
  TnlConnectionHandle,
  TnlProjectFromConfig,
  TnlResolvedConfig,
  TnlServiceNames,
  TnlService,
  TnlProtocolRegistry,
  TnlConnectionRegistry,
  TnlClientFactory,
  TnlClientOptions,
  TnlOptions,
} from "./project.js";
export type * from "./project.js";
export type { PrepareOptions, PreparedService } from "./internal/publisher/app.js";
export type {
  PublishOptions,
  PublisherCredentialFile,
  PublisherIdentityID,
} from "./internal/publisher/publish.js";
export type { FetchHandler } from "./internal/publisher/fetch_types.js";
export { TnlError, type TnlErrorCode } from "./errors.js";

/** extended by the portable `.tnl/generated/project.d.ts` declaration. */
export interface TnlProjectConfig {}

type Config = TnlProjectConfig extends { config: infer Input }
  ? TnlResolvedConfig<Input>
  : { services: Record<string, { protocol: keyof TnlProtocolRegistry }> };
type RegisteredTnlProject = keyof TnlProjectConfig extends never
  ? {
      services: Readonly<
        Record<string, TnlService<{ protocol: keyof TnlProtocolRegistry }> | undefined>
      >;
    }
  : TnlProjectFromConfig<Config>;

export type TnlRuntime = Readonly<
  Partial<Omit<ProjectMetadata, "services">> &
    Partial<Omit<RegisteredTnlProject, "publisherGroups" | "workloads" | "services">> & {
      services: RegisteredTnlProject["services"];
      readonly port: number;
      readonly dev: boolean;
      prepare(options?: PrepareOptions): Promise<PreparedService>;
      publish(
        server: LocalHTTPServer | FetchHandler,
        options?: PublishOptions,
      ): Promise<Publication>;
      connect<Name extends TnlServiceNames<Config>>(
        name: Name,
      ): TnlConnectionHandle<TnlConnection<Config, Name>>;
      client<Name extends TnlServiceNames<Config>, Client>(
        name: Name,
        options: TnlClientOptions<TnlConnection<Config, Name>, Client>,
      ): TnlClientFactory<Client>;
    }
>;

export type TnlInstance = Omit<
  Pick<TnlRuntime, "connect" | "client" | "services" | "prepare" | "publish">,
  "connect" | "client"
> & {
  connect: ((resource: `https://${string}`) => TnlHTTPConnection) & TnlRuntime["connect"];
  client: (<Client>(
    resource: `https://${string}`,
    options: TnlClientOptions<TnlHTTPConnection, Client>,
  ) => TnlClientFactory<Client>) &
    TnlRuntime["client"];
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
};

/** construct an isolated native connection scope without starting native work. */
export function createTnl(options: TnlOptions = {}): TnlInstance {
  const {
    createConnectionScope,
    closeConnectionScope,
    connectionHandle,
    connectionClient,
    usesWorkload,
  } = loadConnection();
  const scope = createConnectionScope(options);
  if (options.credential !== undefined && options.workload !== undefined)
    throw new TnlError("sdk.configuration_invalid");
  const http = options.credential === undefined ? undefined : httpResources(options.credential);
  const explicitServer = options.server;
  const workloadSelected =
    scope.workload !== undefined || usesWorkload(scope.key, scope.runtime, false);
  const checkPublisher = () => {
    // current workload grants authorize visiting only; never use a human publisher.
    if (http !== undefined) throw new TnlError("sdk.credential_denied");
    if (workloadSelected) throw new TnlError("sdk.workload_denied");
  };
  let project: ProjectRuntime | undefined;
  const update = (next: ProjectRuntime) => {
    project = next;
  };
  const owned = new Set<{ close(): Promise<void> }>();
  const pending = new Set<Promise<unknown>>();
  const lifetime = new AbortController();
  let closed = false;
  let closing: Promise<void> | undefined;
  const check = () => {
    if (closed) throw new TnlError("sdk.client_closed");
  };
  const own = <Value extends { close(): Promise<void> }>(
    start: () => Promise<Value>,
  ): Promise<Value> => {
    check();
    const work = Promise.resolve().then(async () => {
      check();
      const value = await start();
      owned.add(value);
      check();
      return value;
    });
    pending.add(work);
    void work.then(
      () => pending.delete(work),
      () => pending.delete(work),
    );
    return work;
  };
  const close = (): Promise<void> => {
    closed = true;
    scope.closed = true;
    http?.fence();
    lifetime.abort(new TnlError("sdk.client_closed"));
    if (closing !== undefined) return closing;
    closing = (async () => {
      await Promise.allSettled(pending);
      const results = await Promise.allSettled([...owned].map((value) => value.close()));
      const failures = results.flatMap((result) =>
        result.status === "rejected" ? [result.reason as unknown] : [],
      );
      if (failures.length > 0) throw new AggregateError(failures, "publication cleanup failed");
      await http?.close();
      await closeConnectionScope(scope);
      owned.clear();
    })().catch((error: unknown) => {
      closing = undefined;
      throw error;
    });
    return closing;
  };
  scope.cleanup = close;
  return Object.freeze({
    get services() {
      return serviceMetadata(project);
    },
    connect: (name: string) => {
      check();
      if (http !== undefined) {
        if (!name.startsWith("https://")) throw new TnlError("sdk.credential_denied");
        return http.connect(name as `https://${string}`);
      }
      if (name.startsWith("https://")) throw new TnlError("sdk.authentication_required");
      return connectionHandle(name, update, scope);
    },
    client: <Client>(
      name: string,
      settings: TnlClientOptions<TnlConnectionRegistry[keyof TnlConnectionRegistry], Client>,
    ) => {
      check();
      if (http !== undefined) {
        if (!name.startsWith("https://")) throw new TnlError("sdk.credential_denied");
        return http.client(name as `https://${string}`, settings);
      }
      if (name.startsWith("https://")) throw new TnlError("sdk.authentication_required");
      return connectionClient(name, settings, update, scope);
    },
    prepare: (settings: PrepareOptions = {}) =>
      own(async () => {
        checkPublisher();
        if (explicitServer !== undefined) throw new TnlError("sdk.configuration_invalid");
        const { prepareService } = await import("./internal/publisher/app.js");
        const prepared = await prepareService(
          {
            ...settings,
            directory: settings.directory ?? scope.directory,
            ...(settings.stateDir === undefined && scope.environment.TNL_STATE_DIR !== undefined
              ? { stateDir: scope.environment.TNL_STATE_DIR }
              : {}),
          },
          "Bun" in globalThis ? "bun" : "node",
          scope.key,
        );
        update(prepared);
        return prepared;
      }),
    publish: (server: LocalHTTPServer | FetchHandler, settings: PublishOptions = {}) =>
      own(async () => {
        checkPublisher();
        const { publishServer, publishFetch } = await import("./internal/publisher/publish.js");
        const startup = new AbortController();
        const abortStartup = () => startup.abort(lifetime.signal.reason);
        lifetime.signal.addEventListener("abort", abortStartup, { once: true });
        if (lifetime.signal.aborted) abortStartup();
        const selected: PublishOptions = {
          ...settings,
          directory: settings.directory ?? scope.directory,
          ...(settings.stateDir === undefined && scope.environment.TNL_STATE_DIR !== undefined
            ? { stateDir: scope.environment.TNL_STATE_DIR }
            : {}),
          ...(settings.server === undefined && scope.environment.TNL_SERVER !== undefined
            ? { server: scope.environment.TNL_SERVER }
            : {}),
          signal:
            settings.signal === undefined
              ? startup.signal
              : AbortSignal.any([settings.signal, startup.signal]),
        };
        try {
          return await (typeof server === "function"
            ? publishFetch(server, selected)
            : publishServer(server, selected));
        } finally {
          lifetime.signal.removeEventListener("abort", abortStartup);
        }
      }),
    close,
    [Symbol.asyncDispose]: close,
  }) as TnlInstance;
}

declare const process:
  | {
      readonly versions?: { readonly node?: string };
      readonly env?: {
        readonly TNL_PROJECT_RUNTIME?: string;
        readonly BUN_PORT?: string;
        readonly PORT?: string;
        readonly NODE_PORT?: string;
      };
    }
  | undefined;

const serializedRuntime =
  typeof process === "undefined" ? undefined : process.env?.TNL_PROJECT_RUNTIME;

/** Server port and optional browser-safe project metadata for this process. */
// the parser validates the runtime shape; generated project declarations supply
// project-specific service names and literals unavailable to this shared module.
let runtime = parseRuntimePayload(serializedRuntime);
export const tnl = Object.freeze({
  ...runtime,
  get services() {
    return serviceMetadata(runtime);
  },
  port: developmentPort(
    typeof process === "undefined" ? {} : (process.env ?? {}),
    "Bun" in globalThis,
  ),
  dev: runtime?.dev ?? false,
  async prepare(options: PrepareOptions = {}): Promise<PreparedService> {
    if (typeof process === "undefined") throw new TnlError("sdk.configuration_invalid");
    const { prepareService } = await import("./internal/publisher/app.js");
    const prepared = await prepareService(options, "Bun" in globalThis ? "bun" : "node");
    if (options.directory === undefined) runtime = prepared;
    return prepared;
  },
  async publish(
    server: LocalHTTPServer | FetchHandler,
    options: PublishOptions = {},
  ): Promise<Publication> {
    if (typeof process === "undefined") throw new TnlError("sdk.configuration_invalid");
    const { publishServer, publishFetch } = await import("./internal/publisher/publish.js");
    return typeof server === "function"
      ? publishFetch(server, options)
      : publishServer(server, options);
  },
  connect(name: string) {
    if (typeof process === "undefined" || typeof process.versions?.node !== "string")
      throw new TnlError("sdk.connection_server_only");
    const { connectionHandle } = loadConnection();
    return connectionHandle(name, (project) => {
      runtime =
        runtime === undefined
          ? project
          : parseProjectRuntime({
              ...runtime,
              services: { ...runtime.services, ...project.services },
            });
    });
  },
  client<Client>(
    name: string,
    options: TnlClientOptions<TnlConnectionRegistry[keyof TnlConnectionRegistry], Client>,
  ) {
    if (typeof process === "undefined" || typeof process.versions?.node !== "string")
      throw new TnlError("sdk.connection_server_only");
    const { connectionClient } = loadConnection();
    return connectionClient(name, options, (project) => {
      runtime =
        runtime === undefined
          ? project
          : parseProjectRuntime({
              ...runtime,
              services: { ...runtime.services, ...project.services },
            });
    });
  },
}) as unknown as TnlRuntime;
