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
  servername: string;
  rejectUnauthorized: true;
  /** omitted by default so native clients use webpki server roots. */
  ca?: string;
  /** supplied by the native sdk only when the selected admission needs mtls. */
  cert?: string;
  key?: string;
}

export interface TnlConnectionRegistry {
  postgres: {
    host: string;
    port: number;
    ssl: TnlNativeTLSOptions;
  };
  mysql: {
    host: string;
    port: number;
    ssl: TnlNativeTLSOptions;
  };
  tcp: { host: string; port: number };
  http: { url: `https://${string}`; fetch: typeof fetch };
  kubernetes: { server: `https://${string}`; kubeconfig: string };
}

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
type Mounts<Paths> = { -readonly [Key in keyof Paths]: Mount<Paths[Key]> };
type HTTPFields<Service> = Service extends { http?: infer HTTP }
  ? HTTP extends unknown
    ? { -readonly [Key in keyof HTTP as Key extends "paths" ? Key : never]: Mounts<HTTP[Key]> }
    : {}
  : {};
export type TnlServiceMetadata<Service> = Service extends unknown
  ? TnlProtocolRegistry[Protocol<Service>] & HTTPFields<Service>
  : never;
export type TnlService<Service> = TnlServiceMetadata<NonNullable<Service>>;
type Services<Config> = NonNullable<Field<Config, "services", {}>>;
export type TnlStableServiceNames<Config> = Config extends unknown
  ? string extends keyof Services<Config>
    ? { error: "declare stable service names with TnlConfigForServices before generating" }
    : true
  : never;
type ServiceEntries<Values> = { -readonly [Name in keyof Values]: TnlService<Values[Name]> };
export type TnlServices<Config> = Config extends unknown
  ? string extends keyof Services<Config>
    ? { "declare stable service names with TnlConfigForServices before generating": never }
    : undefined extends Field<Config, "services", {}>
      ? Partial<ServiceEntries<Services<Config>>>
      : ServiceEntries<Services<Config>>
  : never;
export type TnlServiceNames<Config> = Config extends unknown
  ? string extends keyof Services<Config>
    ? never
    : Extract<keyof Services<Config>, string>
  : never;
export type TnlConnection<Config, Name extends TnlServiceNames<Config>> = Config extends unknown
  ? Name extends keyof Services<Config>
    ? TnlConnectionRegistry[Protocol<NonNullable<Services<Config>[Name]>>]
    : never
  : never;
type Origins<Values> = {
  -readonly [Name in keyof Values]: { hostname: string; url: `https://${string}` } & Pick<
    Values[Name],
    Extract<keyof Values[Name], "service" | "path" | "methods">
  >;
};
export type TnlProjectFromConfig<Config> = Config extends unknown
  ? {
      services: TnlServices<Config>;
    } & {
      -readonly [Key in keyof Config as Key extends "aliases" | "webhooks" ? Key : never]: Origins<
        Config[Key]
      >;
    } & {
      -readonly [Key in keyof Config as Key extends "publishers" | "ci" ? Key : never]: Config[Key];
    } & {
      -readonly [Key in keyof Config as Key extends "oauth" ? Key : never]:
        | { hostname: string; url: `https://${string}` }
        | undefined;
    }
  : never;
