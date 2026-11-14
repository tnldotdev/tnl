import { execFile } from "node:child_process";
import { connect as connectTCP } from "node:net";
import * as z from "zod";
import { TnlError } from "../../errors.js";
import type {
  TnlClientFactory,
  TnlClientOptions,
  TnlFetch,
  TnlNativeTLSOptions,
  TnlConnectionRegistry,
} from "../../project.js";
import { clientFactory } from "./client_factory.js";
import type { ConnectionSnapshot } from "./snapshot.js";
import { resolveNativeBinary } from "../native/launcher.js";
import { protocolSchema, serviceNameSchema } from "../values.js";
import type { ServiceProtocol } from "../project/runtime.js";
import { deploymentConnector } from "./connection.js";
import { captureWorkload, usesWorkload } from "./workload/provider.js";
import { boundManagement } from "./management.js";
import type { LocalHTTPServer } from "../publisher/register.js";
import type { FetchHandler } from "../publisher/fetch_types.js";
import type {
  Publication,
  NamedPublicationOptions,
  TemporaryPublicationOptions,
  PublicationSelection,
} from "../publisher/publication.js";

export type ServiceFacts = Readonly<Record<string, Readonly<{ protocol: ServiceProtocol }>>>;
type Names<Services extends ServiceFacts> = Extract<keyof Services, string>;
type HTTPNames<Services extends ServiceFacts> = keyof Services extends never
  ? string
  : {
      [Name in Names<Services>]: Services[Name]["protocol"] extends "http" ? Name : never;
    }[Names<Services>];
type Connection<
  Services extends ServiceFacts,
  Name extends Names<Services>,
  Local extends boolean,
> = (Local extends true
  ? LocalConnectionRegistry
  : TnlConnectionRegistry)[Services[Name]["protocol"]];

export interface LocalPostgresConnection {
  readonly host: string;
  readonly port: number;
  readonly ssl: false | TnlNativeTLSOptions;
}

export type LocalConnectionRegistry = {
  postgres: LocalPostgresConnection;
  mysql: Readonly<{
    host: string;
    port: number;
    ssl: false | (TnlNativeTLSOptions & { readonly verifyIdentity: true });
    stream: () => import("node:net").Socket;
  }>;
  tcp: Readonly<{ host: string; port: number; ssl?: TnlNativeTLSOptions }>;
  http: Readonly<{ url: `${"http" | "https"}://${string}`; fetch: TnlFetch }>;
  kubernetes: Readonly<{
    server: `https://${string}`;
    kubeconfig: string;
    context: string;
  }>;
};
export type LocalDeployment<Services extends ServiceFacts> = Deployment<Services, true>;

export interface Deployment<Services extends ServiceFacts, Local extends boolean = false> {
  publish<Name extends HTTPNames<Services>>(
    name: Name,
    server: LocalHTTPServer | FetchHandler,
    options?: NamedPublicationOptions,
  ): Promise<Publication>;
  publish(
    server: LocalHTTPServer | FetchHandler,
    options?: TemporaryPublicationOptions,
  ): Promise<Publication>;
  connect<Name extends Names<Services>>(name: Name): Promise<Connection<Services, Name, Local>>;
  client<Name extends Names<Services>, Client>(
    name: Name,
    options: TnlClientOptions<Connection<Services, Name, Local>, Client>,
  ): TnlClientFactory<Client>;
  close(): Promise<void>;
}

const sslSchema = z.strictObject({
  servername: z.string().min(1).max(253),
  rejectUnauthorized: z.literal(true),
  ca: z
    .string()
    .min(1)
    .max(1 << 20)
    .exactOptional(),
});
const localFields = {
  schema: z.literal(1),
  host: z.union([z.ipv4().refine((value) => value.startsWith("127.")), z.literal("::1")]),
  port: z.number().int().min(1).max(65535),
  binding: z.string().regex(/^[0-9a-f]{64}$/),
};
const localConnectionSchema = z
  .discriminatedUnion("protocol", [
    z.strictObject({ ...localFields, protocol: z.literal("postgres"), ssl: sslSchema.optional() }),
    z.strictObject({ ...localFields, protocol: z.literal("mysql"), ssl: sslSchema.optional() }),
    z.strictObject({ ...localFields, protocol: z.literal("tcp"), ssl: sslSchema.optional() }),
    z.strictObject({
      ...localFields,
      protocol: z.literal("http"),
      ssl: sslSchema.optional(),
      url: z.url(),
    }),
    z.strictObject({
      ...localFields,
      protocol: z.literal("kubernetes"),
      ssl: sslSchema,
      server: z.url(),
      kubeconfig: z.string().min(1).max(4096),
      context: z.string().min(1).max(1024),
    }),
  ])
  .refine((value) => {
    if (value.protocol === "http") {
      const url = new URL(value.url);
      return (
        value.url === `${url.protocol}//${url.hostname}:${value.port}` &&
        url.pathname === "/" &&
        !url.search &&
        !url.hash &&
        url.protocol === (value.ssl === undefined ? "http:" : "https:") &&
        url.hostname.replace(/^\[|\]$/g, "") === (value.ssl?.servername ?? value.host) &&
        Number(url.port || (url.protocol === "https:" ? 443 : 80)) === value.port
      );
    }
    if (value.protocol === "kubernetes") {
      const url = new URL(value.server);
      return (
        value.server === `https://${url.hostname}:${value.port}` &&
        url.pathname === "/" &&
        !url.search &&
        !url.hash &&
        url.protocol === "https:" &&
        url.hostname.replace(/^\[|\]$/g, "") === value.host &&
        Number(url.port || 443) === value.port
      );
    }
    return true;
  });

// the native process owns config evaluation and exact Docker/worktree discovery.
// this operation never reads a control credential or starts a tunnel owner.
async function localConnection(
  binary: string,
  directory: string,
  name: string,
  protocol: ServiceProtocol,
  environment: NodeJS.ProcessEnv,
) {
  const value = await new Promise<string>((resolve, reject) => {
    execFile(
      binary,
      [
        "runtime",
        "connections",
        "local",
        "--directory",
        directory,
        "--service",
        name,
        "--protocol",
        protocol,
      ],
      {
        encoding: "utf8",
        timeout: 15_000,
        maxBuffer: 2 << 20,
        env: environment,
      },
      (error, stdout) => {
        if (error !== null) reject(new TnlError("sdk.local_connection_unavailable"));
        else resolve(stdout);
      },
    );
  });
  try {
    const snapshot = localConnectionSchema.parse(JSON.parse(value));
    if (snapshot.protocol !== protocol) throw new Error("protocol changed during selection");
    return { key: snapshot.binding, snapshot };
  } catch {
    throw new TnlError("sdk.response_invalid");
  }
}

/** construct explicit deployment handles from portable service names and protocols. */
export function createClient<const Services extends ServiceFacts = Record<never, never>>(options: {
  project?: string;
  services?: Services;
  token?: string;
}) {
  const parsed = z
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
    .refine((value) => value.services !== undefined || value.project !== undefined)
    .safeParse(options);
  if (!parsed.success) throw new TnlError("sdk.configuration_invalid");
  const protocols = new Map(
    Object.entries(parsed.data.services ?? {}).map(([name, service]) => [name, service.protocol]),
  );
  const project = parsed.data.project;
  const token = parsed.data.token ?? process.env.TNL_TOKEN;
  const management = boundManagement(project, token);
  return Object.freeze({
    ...management,
    deployment<Selected extends string>(
      name: Selected,
    ): Deployment<Services, Selected extends "local" ? true : false> {
      if (!serviceNameSchema.safeParse(name).success && !/^dpl_[A-Za-z0-9]{22}$/.test(name))
        throw new TnlError("sdk.configuration_invalid");
      const mounted = token === undefined ? process.env.TNL_CONNECTION_HANDLE : undefined;
      const source = captureWorkload();
      const workload =
        token === undefined && mounted === undefined && usesWorkload(undefined, source)
          ? source
          : undefined;
      if (
        name !== "local" &&
        (project === undefined ||
          (token === undefined && mounted === undefined && workload === undefined))
      )
        throw new TnlError("sdk.configuration_invalid");
      const directory = process.cwd();
      let binary: string | undefined;
      const environment = { ...process.env };
      const connector =
        name === "local"
          ? undefined
          : deploymentConnector({
              project: project ?? "",
              ...(token === undefined ? {} : { token }),
              ...(mounted === undefined ? {} : { handle: mounted }),
              ...(workload === undefined ? {} : { workload }),
              name,
              services: [...protocols.keys()],
            });
      const closedError = new TnlError("sdk.client_closed");
      const pending = new Set<Promise<unknown>>();
      const factories = new Set<{ close(): Promise<void> }>();
      const requests = new Set<Promise<unknown>>();
      const httpFetches = new Map<string, TnlFetch & { close(): Promise<void> }>();
      const publications = new Set<Publication>();
      const failedPublications = new Set<() => Promise<void>>();
      const publicationLifetime = new AbortController();
      let closed = false;
      let closing: Promise<void> | undefined;
      const validate = (service: string) => {
        if (closed) throw closedError;
        const protocol = protocols.get(service);
        if (protocol === undefined) throw new TnlError("sdk.configuration_invalid");
        return protocol;
      };
      const connectionSettings = (snapshot: z.output<typeof localConnectionSchema>) => {
        switch (snapshot.protocol) {
          case "tcp":
            return Object.freeze({
              host: snapshot.host,
              port: snapshot.port,
              ...(snapshot.ssl === undefined ? {} : { ssl: Object.freeze(snapshot.ssl) }),
            });
          case "postgres":
            return Object.freeze({
              host: snapshot.host,
              port: snapshot.port,
              ssl: snapshot.ssl === undefined ? false : Object.freeze(snapshot.ssl),
            });
          case "mysql":
            return Object.freeze({
              host: snapshot.ssl?.servername ?? snapshot.host,
              port: snapshot.port,
              ssl:
                snapshot.ssl === undefined
                  ? false
                  : { ...snapshot.ssl, verifyIdentity: true as const },
              stream: () => connectTCP({ host: snapshot.host, port: snapshot.port }),
            });
          case "kubernetes":
            return Object.freeze({
              server: snapshot.server as `https://${string}`,
              kubeconfig: snapshot.kubeconfig,
              context: snapshot.context,
            });
          case "http": {
            const origin = new URL(snapshot.url).origin as `${"http" | "https"}://${string}`;
            let transport = httpFetches.get(snapshot.binding);
            if (transport === undefined) {
              if (httpFetches.size >= 64) throw new TnlError("sdk.client_capacity");
              const ssl = snapshot.ssl ?? false;
              let managed: Promise<TnlFetch & { close(): Promise<void> }> | undefined;
              const fetch: TnlFetch = async (input, init) => {
                if (closed) throw closedError;
                managed ??= import("./connection.js").then(({ managedFetch }) =>
                  managedFetch(origin, async () =>
                    ssl === false
                      ? {
                          protocol: "http" as const,
                          host: snapshot.host,
                          port: snapshot.port,
                          url: origin as `http://${string}`,
                          ssl: false as const,
                          expires: Number.MAX_SAFE_INTEGER,
                          transportID: snapshot.binding,
                        }
                      : ({
                          protocol: "http",
                          host: snapshot.host,
                          port: snapshot.port,
                          url: origin as `https://${string}`,
                          ssl,
                          expires: Number.MAX_SAFE_INTEGER,
                          transportID: snapshot.binding,
                        } as ConnectionSnapshot),
                  ),
                );
                return (await managed)(input, init);
              };
              transport = Object.assign(fetch, {
                async close() {
                  if (managed !== undefined) await (await managed).close();
                },
              });
              httpFetches.set(snapshot.binding, transport);
            }
            const selected = transport;
            const fetch: TnlFetch = (input, init) => {
              if (closed) return Promise.reject(closedError);
              const work = selected(input, init);
              requests.add(work);
              void work.then(
                () => requests.delete(work),
                () => requests.delete(work),
              );
              return work;
            };
            return Object.freeze({ url: origin, fetch });
          }
        }
      };
      const acquire = <Name extends Names<Services>>(service: Name) => {
        const protocol = validate(service);
        if (pending.size >= 64) throw new TnlError("sdk.connection_unavailable");
        const work = (
          connector === undefined
            ? localConnection(
                (binary ??= resolveNativeBinary()),
                directory,
                service,
                protocol,
                environment,
              ).then((value) => ({
                key: value.key,
                connection: connectionSettings(value.snapshot),
              }))
            : connector.acquire(service).then((value) => {
                if (value.protocol !== protocols.get(service))
                  throw new TnlError("sdk.response_invalid");
                return value;
              })
        ).then(
          (
            value,
          ): {
            key: string;
            connection: Connection<Services, Name, Selected extends "local" ? true : false>;
          } => {
            if (closed) throw closedError;
            return {
              key: value.key,
              connection: value.connection as Connection<
                Services,
                Name,
                Selected extends "local" ? true : false
              >,
            };
          },
        );
        pending.add(work);
        void work.then(
          () => pending.delete(work),
          () => pending.delete(work),
        );
        return work;
      };
      return Object.freeze({
        async publish(
          first: string | LocalHTTPServer | FetchHandler,
          second?: LocalHTTPServer | FetchHandler | TemporaryPublicationOptions,
          third?: NamedPublicationOptions,
        ): Promise<Publication> {
          if (closed) throw closedError;
          if (publications.size + failedPublications.size + pending.size >= 64)
            throw new TnlError("sdk.client_capacity");
          // provider and borrowed connector authority remains connect-only.
          if (name !== "local" && token === undefined)
            throw new TnlError("sdk.configuration_invalid");
          const service = typeof first === "string" ? first : undefined;
          const server = (service === undefined ? first : second) as LocalHTTPServer | FetchHandler;
          const options =
            ((service === undefined ? second : third) as TemporaryPublicationOptions | undefined) ??
            {};
          if (
            service !== undefined &&
            (!serviceNameSchema.safeParse(service).success ||
              (protocols.size > 0 && protocols.get(service) !== "http"))
          )
            throw new TnlError("sdk.configuration_invalid");
          const work = (async () => {
            const { publishServer, publishFetch, validatePublicationOptions } =
              await import("../publisher/publication.js");
            if (closed) throw closedError;
            validatePublicationOptions(options, service !== undefined);
            const selection: PublicationSelection =
              name === "local"
                ? {
                    kind: "local",
                    environment,
                    retainCleanup: (cleanup) => {
                      failedPublications.add(cleanup);
                    },
                    ...(service === undefined ? {} : { service }),
                  }
                : {
                    kind: "deployment",
                    project: project ?? "",
                    name,
                    credential: token ?? "",
                    environment,
                    retainCleanup: (cleanup) => {
                      failedPublications.add(cleanup);
                    },
                    ...(service === undefined ? {} : { service }),
                  };
            const signal =
              options.signal === undefined
                ? publicationLifetime.signal
                : AbortSignal.any([publicationLifetime.signal, options.signal]);
            const captured = {
              ...options,
              directory,
              signal,
              ...(environment.TNL_STATE_DIR === undefined
                ? {}
                : { stateDir: environment.TNL_STATE_DIR }),
            };
            const base = await (typeof server === "function"
              ? publishFetch(server, captured, undefined, selection)
              : publishServer(server, captured, undefined, selection));
            let closingPublication: Promise<void> | undefined;
            const close = () =>
              (closingPublication ??= (async () => {
                const results = await Promise.allSettled([base.close(), base.wait()]);
                if (results[0]?.status === "fulfilled") publications.delete(handle);
                const errors = [
                  ...new Set(
                    results.flatMap((result) =>
                      result.status === "rejected" ? [result.reason as unknown] : [],
                    ),
                  ),
                ];
                if (errors.length === 1) throw errors[0];
                if (errors.length > 1)
                  throw new AggregateError(errors, "publication cleanup failed");
              })().catch((cause: unknown) => {
                closingPublication = undefined;
                throw cause;
              }));
            const handle: Publication = Object.freeze({
              get url() {
                return base.url;
              },
              close,
              wait: () => base.wait(),
              [Symbol.asyncDispose]: close,
            });
            // retain ownership before checking close: a late acknowledgment must
            // remain retryable if its first cleanup attempt fails.
            publications.add(handle);
            if (closed) {
              await close();
              throw closedError;
            }
            return handle;
          })().catch((error: unknown) => {
            if (closed && error instanceof DOMException && error.name === "AbortError")
              throw closedError;
            throw error;
          });
          pending.add(work);
          void work.then(
            () => pending.delete(work),
            () => pending.delete(work),
          );
          return work;
        },
        async connect<Name extends Names<Services>>(service: Name) {
          return (await acquire(service)).connection;
        },
        client<Name extends Names<Services>, Client>(
          service: Name,
          driver: TnlClientOptions<
            Connection<Services, Name, Selected extends "local" ? true : false>,
            Client
          >,
        ) {
          validate(service);
          if (factories.size >= 64) throw new TnlError("sdk.client_capacity");
          const factory = clientFactory(async () => {
            const value = await acquire(service);
            return { key: value.key, connection: value.connection };
          }, driver);
          const close = factory.close.bind(factory);
          factory.close = async () => {
            await close();
            factories.delete(factory);
          };
          factories.add(factory);
          return factory;
        },
        close(): Promise<void> {
          closed = true;
          closing ??= (async () => {
            const stoppingPublications = [...publications].map((publication) =>
              publication.close(),
            );
            publicationLifetime.abort();
            const work = await Promise.allSettled([
              ...pending,
              ...stoppingPublications,
              ...[...failedPublications].map(async (cleanup) => {
                await cleanup();
                failedPublications.delete(cleanup);
              }),
              ...[...factories].map(async (factory) => {
                await factory.close();
                factories.delete(factory);
              }),
              ...requests,
            ]);
            const pools = await Promise.allSettled(
              [...httpFetches.values()].map((value) => value.close()),
            );
            const results = [...work, ...pools];
            const errors = [
              ...new Set(
                results.flatMap((result) =>
                  result.status === "rejected" && result.reason !== closedError
                    ? [result.reason as unknown]
                    : [],
                ),
              ),
            ];
            try {
              await connector?.close();
            } catch (error) {
              errors.push(error);
            }
            if (errors.length === 1) throw errors[0];
            if (errors.length > 1) throw new AggregateError(errors, "deployment cleanup failed");
          })().finally(() => {
            closing = undefined;
          });
          return closing;
        },
      }) as Deployment<Services, Selected extends "local" ? true : false>;
    },
  });
}
