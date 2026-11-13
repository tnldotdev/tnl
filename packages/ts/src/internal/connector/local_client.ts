import { execFile } from "node:child_process";
import { connect as connectTCP } from "node:net";
import * as z from "zod";
import { TnlError } from "../../errors.js";
import type {
  TnlClientFactory,
  TnlClientOptions,
  TnlFetch,
  TnlNativeTLSOptions,
} from "../../project.js";
import { clientFactory } from "./client_factory.js";
import type { ConnectionSnapshot } from "./snapshot.js";
import { resolveNativeBinary } from "../native/launcher.js";
import { protocolSchema, serviceNameSchema } from "../values.js";
import type { ServiceProtocol } from "../project/runtime.js";

export type ServiceFacts = Readonly<Record<string, Readonly<{ protocol: ServiceProtocol }>>>;
type ServiceNames<Services extends ServiceFacts> = Extract<keyof Services, string>;

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
type ConnectionFor<
  Services extends ServiceFacts,
  Name extends ServiceNames<Services>,
> = LocalConnectionRegistry[Services[Name]["protocol"]];

export interface LocalDeployment<Services extends ServiceFacts> {
  connect<Name extends ServiceNames<Services>>(name: Name): Promise<ConnectionFor<Services, Name>>;
  client<Name extends ServiceNames<Services>, Client>(
    name: Name,
    options: TnlClientOptions<ConnectionFor<Services, Name>, Client>,
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
export function createClient<const Services extends ServiceFacts>(options: { services: Services }) {
  const parsed = z
    .strictObject({
      services: z
        .record(serviceNameSchema, z.strictObject({ protocol: protocolSchema }))
        .refine((value) => Object.keys(value).length <= 32),
    })
    .safeParse(options);
  if (!parsed.success) throw new TnlError("sdk.configuration_invalid");
  const protocols = new Map(
    Object.entries(parsed.data.services).map(([name, service]) => [name, service.protocol]),
  );
  return Object.freeze({
    deployment(name: "local"): LocalDeployment<Services> {
      if (name !== "local") throw new TnlError("sdk.configuration_invalid");
      const directory = process.cwd();
      const binary = resolveNativeBinary();
      const environment = { ...process.env };
      const closedError = new TnlError("sdk.client_closed");
      const pending = new Set<Promise<unknown>>();
      const factories = new Set<{ close(): Promise<void> }>();
      const requests = new Set<Promise<unknown>>();
      const httpFetches = new Map<string, TnlFetch & { close(): Promise<void> }>();
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
      const acquire = <Name extends ServiceNames<Services>>(service: Name) => {
        const protocol = validate(service);
        if (pending.size >= 64) throw new TnlError("sdk.connection_unavailable");
        const work = localConnection(binary, directory, service, protocol, environment).then(
          (value) => {
            if (closed) throw closedError;
            return {
              key: value.key,
              connection: connectionSettings(value.snapshot) as ConnectionFor<Services, Name>,
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
        async connect<Name extends ServiceNames<Services>>(service: Name) {
          return (await acquire(service)).connection;
        },
        client<Name extends ServiceNames<Services>, Client>(
          service: Name,
          driver: TnlClientOptions<ConnectionFor<Services, Name>, Client>,
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
        close(): Promise<void> {
          closed = true;
          closing ??= (async () => {
            const work = await Promise.allSettled([
              ...pending,
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
