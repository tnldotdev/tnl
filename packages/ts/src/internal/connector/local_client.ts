import { execFile } from "node:child_process";
import * as z from "zod";
import { TnlError } from "../../errors.js";
import type { TnlClientFactory, TnlClientOptions, TnlNativeTLSOptions } from "../../project.js";
import { clientFactory } from "./client_factory.js";
import { resolveNativeBinary } from "../native/launcher.js";
import { protocolSchema, serviceNameSchema } from "../values.js";
import type { ServiceProtocol } from "../project/runtime.js";

export type ServiceFacts = Readonly<Record<string, Readonly<{ protocol: ServiceProtocol }>>>;
type PostgresNames<Services extends ServiceFacts> = Extract<
  {
    [Name in keyof Services]: "postgres" extends Services[Name]["protocol"] ? Name : never;
  }[keyof Services],
  string
>;

export interface LocalPostgresConnection {
  readonly host: string;
  readonly port: number;
  readonly ssl: false | TnlNativeTLSOptions;
}

export interface LocalDeployment<Services extends ServiceFacts> {
  connect(name: PostgresNames<Services>): Promise<LocalPostgresConnection>;
  client<Client>(
    name: PostgresNames<Services>,
    options: TnlClientOptions<LocalPostgresConnection, Client>,
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
      let closed = false;
      let closing: Promise<void> | undefined;
      const validate = (service: string) => {
        if (closed) throw closedError;
        if (protocols.get(service) !== "postgres") throw new TnlError("sdk.configuration_invalid");
      };
      const acquire = (service: string) => {
        validate(service);
        if (pending.size >= 64) throw new TnlError("sdk.connection_unavailable");
        const work = localConnection(binary, directory, service, environment).then((value) => {
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
        async connect(service: PostgresNames<Services>) {
          return (await acquire(service)).connection;
        },
        client<Client>(
          service: PostgresNames<Services>,
          driver: TnlClientOptions<LocalPostgresConnection, Client>,
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
            const results = await Promise.allSettled([
              ...pending,
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
