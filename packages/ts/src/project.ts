import type { TnlProtocol } from "./config.js";

/** browser-safe addresses only; native credentials are returned by node methods. */
export interface TnlProtocolRegistry {
  http: {
    protocol: "http";
    hostname: string;
    port: number;
    public: boolean;
    url: `https://${string}`;
  };
  postgres: { protocol: "postgres"; hostname: string; port: number; public: boolean };
  mysql: { protocol: "mysql"; hostname: string; port: number; public: boolean };
  tcp: { protocol: "tcp"; hostname: string; port: number; public: boolean };
  kubernetes: {
    protocol: "kubernetes";
    hostname: string;
    port: number;
    public: boolean;
    url: `https://${string}`;
  };
}

/** native TLS options exist only in the result of a node connection method. */
export interface TnlNativeTLSOptions {
  readonly servername: string;
  readonly rejectUnauthorized: true;
  /** omitted by default so native clients use webpki server roots. */
  readonly ca?: string;
}

/** standard fetch calls, independent of platform-specific static helpers. */
export type TnlFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface TnlConnectionRegistry {
  postgres: {
    readonly host: "127.0.0.1";
    readonly port: number;
    readonly ssl: TnlNativeTLSOptions;
  };
  mysql: {
    readonly host: "127.0.0.1";
    readonly port: number;
    readonly ssl: TnlNativeTLSOptions;
  };
  tcp: { readonly host: "127.0.0.1"; readonly port: number };
  http: { readonly url: `https://${string}`; readonly fetch: TnlFetch };
  kubernetes: {
    readonly server: `https://${string}`;
    readonly kubeconfig: string;
    readonly context: string;
  };
}

/** await to prepare or refresh; synchronous reads require a prepared connection. */
export type TnlConnectionHandle<Settings> = Settings & PromiseLike<Settings>;

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
type ServiceEntries<Values> = { readonly [Name in keyof Values]: TnlService<Values[Name]> };
export type TnlServices<Config> = Config extends unknown
  ? string extends keyof Services<Config>
    ? { "declare stable service names with TnlConfigForServices before generating": never }
    : undefined extends Field<Config, "services", {}>
      ? Partial<ServiceEntries<Services<Config>>>
      : ServiceEntries<Services<Config>>
  : never;
export type TnlServiceNames<Config> = Config extends unknown
  ? Extract<keyof Services<Config>, string>
  : never;
export type TnlConnection<Config, Name extends TnlServiceNames<Config>> = Config extends unknown
  ? Name extends keyof Services<Config>
    ? TnlConnectionRegistry[Protocol<NonNullable<Services<Config>[Name]>>]
    : never
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
      readonly [Key in keyof Config as Key extends "publishers" | "ci" ? Key : never]: DeepReadonly<
        Config[Key]
      >;
    } & {
      readonly [Key in keyof Config as Key extends "oauth" ? Key : never]:
        | { readonly hostname: string; readonly url: `https://${string}` }
        | undefined;
    }
  : never;
