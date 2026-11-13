import type { TnlProtocol } from "./config.js";
import type { ProjectServiceMetadata, ServiceProtocol } from "./internal/project/runtime.js";
import type { NativeTLSOptions } from "./internal/connector/snapshot.js";

/** browser-safe addresses only; native credentials are returned by node methods. */
export type TnlProtocolRegistry = {
  [Protocol in ServiceProtocol]: Omit<
    Extract<ProjectServiceMetadata, { protocol: Protocol }>,
    "paths"
  >;
};

/** native TLS options exist only in the result of a node connection method. */
export type TnlNativeTLSOptions = NativeTLSOptions;

/** standard fetch calls, independent of platform-specific static helpers. */
export type TnlFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface TnlConnectionRegistry {
  postgres: {
    readonly host: "127.0.0.1";
    readonly port: number;
    readonly ssl: TnlNativeTLSOptions;
  };
  mysql: {
    /** mysql2 verifies this hostname; stream dials the native loopback listener. */
    readonly host: string;
    readonly port: number;
    readonly ssl: TnlNativeTLSOptions & { readonly verifyIdentity: true };
    /** a fresh socket for each ordinary mysql2 connection, including pools. */
    readonly stream: () => import("node:net").Socket;
  };
  tcp: { readonly host: "127.0.0.1"; readonly port: number };
  http: { readonly url: `https://${string}`; readonly fetch: TnlFetch };
  kubernetes: {
    readonly server: `https://${string}`;
    readonly kubeconfig: string;
    readonly context: string;
  };
}

/** callbacks adapt ordinary drivers without adding a driver-specific tnl wrapper. */
export type TnlClientOptions<Connection, Client> = Readonly<{
  create(connection: Connection): Client | PromiseLike<Client>;
  close(client: Client): void | PromiseLike<void>;
}>;

/** each call selects current native authority before returning its cached client. */
export type TnlClientFactory<Client> = {
  (): Promise<Client>;
  /** join pending creation and close only this factory's ordinary clients. */
  close(): Promise<void>;
};

type DeepReadonly<Value> = Value extends object
  ? { readonly [Key in keyof Value]: DeepReadonly<Value[Key]> }
  : Value;

export type TnlResolvedConfig<Input> = Input extends (...args: never[]) => infer Result
  ? Awaited<Result>
  : Input;
type Field<Value, Key extends PropertyKey, Fallback = never> = Key extends keyof Value
  ? Value[Key]
  : Fallback;
type Protocol<Service> = Service extends unknown
  ?
      | Extract<Field<Service, "protocol", "http">, TnlProtocol>
      | (undefined extends Field<Service, "protocol", "http"> ? "http" : never)
  : never;
type Mount<Value> = Value extends string
  ? { service: Value; url: `https://${string}`; stripPrefix: boolean }
  : { service: Field<Value, "service">; url: `https://${string}`; stripPrefix: boolean };
type Mounts<Paths> = { readonly [Key in keyof Paths]: Mount<Paths[Key]> };
type HTTPFields<Service> = Service extends { http?: infer HTTP }
  ? HTTP extends unknown
    ? { readonly [Key in keyof HTTP as Key extends "paths" ? Key : never]: Mounts<HTTP[Key]> }
    : {}
  : {};
export type TnlServiceMetadata<Service> = Service extends unknown
  ? DeepReadonly<TnlProtocolRegistry[Protocol<Service>] & HTTPFields<Service>>
  : never;
export type TnlService<Service> =
  | TnlServiceMetadata<NonNullable<Service>>
  | (undefined extends Service ? undefined : never);
type Services<Config> = NonNullable<Field<Config, "services", {}>>;
export type TnlStableServiceNames<Config> = Config extends unknown
  ? string extends keyof Services<Config>
    ? { error: "declare stable service names with TnlConfigForServices before generating" }
    : true
  : never;
type LocalTargets<Config> = Field<
  Field<Field<Config, "deployments", {}>, "local", {}>,
  "targets",
  {}
>;
type ServiceEntries<Config, Values> = {
  readonly [Name in keyof Values]:
    | TnlService<
        NonNullable<Values[Name]> &
          Pick<
            Field<LocalTargets<Config>, Name, {}>,
            "http" & keyof Field<LocalTargets<Config>, Name, {}>
          >
      >
    | (undefined extends Values[Name] ? undefined : never);
};
export type TnlServices<Config> = Config extends unknown
  ? string extends keyof Services<Config>
    ? { "declare stable service names with TnlConfigForServices before generating": never }
    : undefined extends Field<Config, "services", {}>
      ? Partial<ServiceEntries<Config, Services<Config>>>
      : ServiceEntries<Config, Services<Config>>
  : never;
type Origins<Values> = {
  readonly [Name in keyof Values]: DeepReadonly<
    | ({ hostname: string; url: `https://${string}` } & Pick<
        NonNullable<Values[Name]>,
        Extract<keyof NonNullable<Values[Name]>, "service" | "path" | "methods">
      >)
    | (undefined extends Values[Name] ? undefined : never)
  >;
};
export type TnlProjectFromConfig<Config> = Config extends unknown
  ? {
      readonly services: TnlServices<Config>;
    } & {
      readonly [Key in keyof Config as Key extends "aliases" | "webhooks" ? Key : never]: Origins<
        Config[Key]
      >;
    } & {
      readonly [Key in keyof Config as Key extends "workloads" ? Key : never]: DeepReadonly<
        Config[Key]
      >;
    } & {
      readonly [Key in keyof Config as Key extends "oauth" ? Key : never]:
        | { readonly hostname: string; readonly url: `https://${string}` }
        | undefined;
    }
  : never;
