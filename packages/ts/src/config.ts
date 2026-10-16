import type { TnlConfig, TnlConfigInput, TnlConfigContext } from "./config.gen.js";

export type * from "./config.gen.js";

type HTTPServiceNames<Config> = Config extends { readonly services: infer Services }
  ? Extract<
      {
        [Name in keyof Services]: "protocol" extends keyof Services[Name]
          ? Services[Name]["protocol"] extends "http" | undefined
            ? Name
            : never
          : Name;
      }[keyof Services],
      string
    >
  : never;

type ObjectReference<Names extends string> = { readonly service: Names };
type WebhookService<Config> = Config extends { readonly services: infer Services }
  ? keyof Services extends never
    ? ""
    : HTTPServiceNames<Config>
  : "";

type TargetReferences<Config> = {
  [Field in keyof Config as Field extends "aliases" | "webhooks" ? Field : never]: {
    [Name in keyof Config[Field]]: ObjectReference<
      Field extends "webhooks" ? WebhookService<Config> : HTTPServiceNames<Config>
    >;
  };
} & {
  [Field in keyof Config as Field extends "services" ? Field : never]: {
    [Name in keyof Config[Field]]: {
      [HTTP in keyof Config[Field][Name] as HTTP extends "http" ? HTTP : never]: {
        [Paths in keyof Config[Field][Name][HTTP] as Paths extends "paths" ? Paths : never]: {
          [
            Prefix in keyof Config[Field][Name][HTTP][Paths]
          ]: Config[Field][Name][HTTP][Paths][Prefix] extends string
            ? Exclude<HTTPServiceNames<Config>, Name>
            : ObjectReference<Exclude<HTTPServiceNames<Config>, Name>>;
        };
      };
    };
  };
};

type Service = NonNullable<NonNullable<TnlConfig["services"]>[string]>;
export type TnlServiceConfig = Service;
export type TnlServiceTarget = NonNullable<Service["target"]>;
export type TnlPublisher = NonNullable<TnlConfig["publisher"]>;
export type TnlProtocol = NonNullable<Service["protocol"]>;
type Alias = NonNullable<NonNullable<TnlConfig["aliases"]>[string]>;
type Webhook = NonNullable<NonNullable<TnlConfig["webhooks"]>[string]>;
type HTTP = NonNullable<Extract<Service, { protocol?: "http" }>["http"]>;
type ServiceForNames<Names extends string, Name extends Names, Member = Service> = Member extends {
  protocol?: "http";
}
  ? Omit<Member, "http"> & {
      http?: Omit<HTTP, "paths"> & {
        paths?: Record<
          string,
          | Exclude<NoInfer<Names>, Name>
          | {
              service: Exclude<NoInfer<Names>, Name>;
              stripPrefix?: boolean;
            }
        >;
      };
    }
  : Member;

/**
 * project configuration whose service references are restricted to Names.
 * the generated TnlConfig describes the file shape, so its service fields are
 * strings; use defineConfig to infer Names from the configured service keys.
 */
export type TnlConfigForServices<Names extends string> = Omit<
  TnlConfig,
  "services" | "aliases" | "webhooks"
> & {
  services?: {
    [Name in Names]: ServiceForNames<Names, Name>;
  };
  aliases?: Record<string, Omit<Alias, "service"> & { service: NoInfer<Names> }>;
  webhooks?: Record<
    string,
    Omit<Webhook, "service"> & { service: NoInfer<[Names] extends [never] ? "" : Names> }
  >;
};

/** infer config literals and check HTTP references. */
// check factories after inferring their const return. intersecting the return
// with its reference constraints widens async discriminants before inference.
// keep this overload first so zero-argument factories receive the same context.
export function defineConfig<const Config extends TnlConfig>(
  config: ((context: TnlConfigContext) => Config | Promise<Config>) &
    NoInfer<[Config] extends [TargetReferences<Config>] ? unknown : never>,
): (context: TnlConfigContext) => Config | Promise<Config>;
export function defineConfig<const Config extends TnlConfig>(
  config: Config & NoInfer<TargetReferences<Config>>,
): Config;
export function defineConfig(config: TnlConfigInput): TnlConfigInput {
  return config;
}
