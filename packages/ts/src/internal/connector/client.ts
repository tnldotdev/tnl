import { execFile } from "node:child_process";
import * as z from "zod";
import { TnlError } from "../../errors.js";
import type {
  TnlClientFactory,
  TnlClientOptions,
  TnlNativeTLSOptions,
  TnlConnectionRegistry,
} from "../../project.js";
import { clientFactory } from "./client_factory.js";
import { resolveNativeBinary } from "../native/launcher.js";
import { protocolSchema, serviceNameSchema } from "../values.js";
import type { ServiceProtocol } from "../project/runtime.js";
import { deploymentConnector } from "./connection.js";
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
type Connections = Omit<TnlConnectionRegistry, "postgres"> & { postgres: LocalPostgresConnection };
type Connection<
  Services extends ServiceFacts,
  Name extends Names<Services>,
> = Connections[Services[Name]["protocol"]];

export interface LocalPostgresConnection {
  readonly host: string;
  readonly port: number;
  readonly ssl: false | TnlNativeTLSOptions;
}

export interface Deployment<Services extends ServiceFacts> {
  publish<Name extends HTTPNames<Services>>(
    name: Name,
    server: LocalHTTPServer | FetchHandler,
    options?: NamedPublicationOptions,
  ): Promise<Publication>;
  publish(
    server: LocalHTTPServer | FetchHandler,
    options?: TemporaryPublicationOptions,
  ): Promise<Publication>;
  connect<Name extends Names<Services>>(name: Name): Promise<Connection<Services, Name>>;
  client<Name extends Names<Services>, Client>(
    name: Name,
    options: TnlClientOptions<Connection<Services, Name>, Client>,
  ): TnlClientFactory<Client>;
  close(): Promise<void>;
}

const localConnectionSchema = z.strictObject({
  schema: z.literal(1),
  protocol: z.literal("postgres"),
  host: z.union([z.ipv4().refine((value) => value.startsWith("127.")), z.literal("::1")]),
  port: z.number().int().min(1).max(65535),
  ssl: z
    .strictObject({
      servername: z.string().min(1).max(253),
      rejectUnauthorized: z.literal(true),
      ca: z
        .string()
        .min(1)
        .max(1 << 20)
        .exactOptional(),
    })
    .exactOptional(),
  binding: z.string().regex(/^[0-9a-f]{64}$/),
});

// the native process owns config evaluation and exact Docker/worktree discovery.
// this operation never reads a control credential or starts a tunnel owner.
async function localConnection(
  binary: string,
  directory: string,
  name: string,
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
        "postgres",
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
    const connection: LocalPostgresConnection = Object.freeze({
      host: snapshot.host,
      port: snapshot.port,
      ssl: snapshot.ssl === undefined ? false : Object.freeze(snapshot.ssl),
    });
    return { key: snapshot.binding, connection };
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
    deployment(name: string): Deployment<Services> {
      if (!serviceNameSchema.safeParse(name).success && !/^pgrp_[a-z0-9]{22}$/.test(name))
        throw new TnlError("sdk.configuration_invalid");
      const mounted = token === undefined ? process.env.TNL_CONNECTION_HANDLE : undefined;
      if (
        name !== "local" &&
        (project === undefined || (token === undefined && mounted === undefined))
      )
        throw new TnlError("sdk.configuration_invalid");
      const directory = process.cwd();
      const binary = resolveNativeBinary();
      const environment = { ...process.env };
      const connector =
        name === "local"
          ? undefined
          : deploymentConnector({
              project: project ?? "",
              ...(token === undefined ? {} : { token }),
              ...(mounted === undefined ? {} : { handle: mounted }),
              name,
              services: [...protocols.keys()],
            });
      const closedError = new TnlError("sdk.client_closed");
      const pending = new Set<Promise<unknown>>();
      const factories = new Set<{ close(): Promise<void> }>();
      const publications = new Set<Publication>();
      const publicationLifetime = new AbortController();
      let closed = false;
      let closing: Promise<void> | undefined;
      const validate = (service: string) => {
        if (closed) throw closedError;
        if (!protocols.has(service) || (name === "local" && protocols.get(service) !== "postgres"))
          throw new TnlError("sdk.configuration_invalid");
      };
      const acquire = (service: string) => {
        validate(service);
        if (pending.size >= 64) throw new TnlError("sdk.connection_unavailable");
        const work = (
          connector === undefined
            ? localConnection(binary, directory, service, environment)
            : connector.acquire(service).then((value) => {
                if (value.protocol !== protocols.get(service))
                  throw new TnlError("sdk.response_invalid");
                return value;
              })
        ).then((value) => {
          if (closed) throw closedError;
          return value;
        });
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
          if (name !== "local" && token === undefined)
            throw new TnlError("sdk.configuration_invalid");
          if (publications.size + pending.size >= 64) throw new TnlError("sdk.client_capacity");
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
                ? { kind: "local", environment, ...(service === undefined ? {} : { service }) }
                : {
                    kind: "deployment",
                    project: project ?? "",
                    name,
                    credential: token ?? "",
                    environment,
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
            if (closed) {
              await base.close();
              throw closedError;
            }
            let closing: Promise<void> | undefined;
            const close = () =>
              (closing ??= (async () => {
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
                closing = undefined;
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
            publications.add(handle);
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
        async connect<Name extends Names<Services>>(
          service: Name,
        ): Promise<Connection<Services, Name>> {
          return (await acquire(service)).connection as Connection<Services, Name>;
        },
        client<Name extends Names<Services>, Client>(
          service: Name,
          driver: TnlClientOptions<Connection<Services, Name>, Client>,
        ) {
          validate(service);
          if (factories.size >= 64) throw new TnlError("sdk.client_capacity");
          const factory = clientFactory(async () => {
            const value = await acquire(service);
            return { key: value.key, connection: value.connection as Connection<Services, Name> };
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
          const stoppingPublications = [...publications].map((publication) => publication.close());
          publicationLifetime.abort();
          closing ??= (async () => {
            const results = await Promise.allSettled([
              ...pending,
              ...stoppingPublications,
              ...[...factories].map(async (factory) => {
                await factory.close();
                factories.delete(factory);
              }),
            ]);
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
      });
    },
  });
}
