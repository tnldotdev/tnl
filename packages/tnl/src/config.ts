import type { TnlConfig, TnlConfigInput, TnlConfigContext } from "./config.gen.js";

export type * from "./config.gen.js";

type ServiceNames<Config> = Config extends { readonly services: infer Services }
  ? Extract<keyof Services, string>
  : never;

type ObjectReference<Names> = { readonly service: Names };

type TargetReferences<Config> = {
  [Field in keyof Config as Field extends "aliases" | "webhooks" ? Field : never]: {
    [Name in keyof Config[Field]]: ObjectReference<
      Field extends "webhooks"
        ? [ServiceNames<Config>] extends [never]
          ? ""
          : ServiceNames<Config>
        : ServiceNames<Config>
    >;
  };
} & {
  [Field in keyof Config as Field extends "services" ? Field : never]: {
    [Name in keyof Config[Field]]: {
      [Paths in keyof Config[Field][Name] as Paths extends "paths" ? Paths : never]: {
        [
          Prefix in keyof Config[Field][Name][Paths]
        ]: Config[Field][Name][Paths][Prefix] extends string
          ? Exclude<ServiceNames<Config>, Name>
          : ObjectReference<Exclude<ServiceNames<Config>, Name>>;
      };
    };
  };
};

type Service = NonNullable<NonNullable<TnlConfig["services"]>[string]>;
type Alias = NonNullable<NonNullable<TnlConfig["aliases"]>[string]>;
type Webhook = NonNullable<NonNullable<TnlConfig["webhooks"]>[string]>;

// infer names from service keys only, then contextually type factory references.
// this avoids widening a returned literal service name to an unchecked string.
type FactoryConfig<Names extends string> = Omit<TnlConfig, "services" | "aliases" | "webhooks"> & {
  services?: {
    [Name in Names]: Omit<Service, "paths"> & {
      paths?: Record<
        string,
        | Exclude<NoInfer<Names>, Name>
        | {
            service: Exclude<NoInfer<Names>, Name>;
            stripPrefix?: boolean;
          }
      >;
    };
  };
  aliases?: Record<string, Omit<Alias, "service"> & { service: NoInfer<Names> }>;
  webhooks?: Record<
    string,
    Omit<Webhook, "service"> & { service: NoInfer<Names> | ([Names] extends [never] ? "" : never) }
  >;
};

/** checks literal service references while preserving the config or factory type. */
export function defineConfig<const Config extends TnlConfig>(
  config: Config & NoInfer<TargetReferences<Config>>,
): Config;
export function defineConfig<const Names extends string = never>(
  config: (context: TnlConfigContext) => FactoryConfig<Names> | Promise<FactoryConfig<Names>>,
): (context: TnlConfigContext) => FactoryConfig<Names> | Promise<FactoryConfig<Names>>;
export function defineConfig(config: TnlConfigInput): TnlConfigInput {
  return config;
}
