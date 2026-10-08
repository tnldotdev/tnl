import type { TnlConfig, TnlConfigInput, TnlConfigContext } from "./config.gen.js";

export type * from "./config.gen.js";

type ServiceNames<Config> = Config extends { readonly services: infer Services }
  ? Extract<keyof Services, string>
  : never;

type ObjectReference<Names extends string> = { readonly service: Names };
type WebhookService<Names extends string> = [Names] extends [never] ? "" : Names;

type TargetReferences<Config> = {
  [Field in keyof Config as Field extends "aliases" | "webhooks" ? Field : never]: {
    [Name in keyof Config[Field]]: ObjectReference<
      Field extends "webhooks" ? WebhookService<ServiceNames<Config>> : ServiceNames<Config>
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
  webhooks?: Record<string, Omit<Webhook, "service"> & { service: NoInfer<WebhookService<Names>> }>;
};

/** infer service keys and reject unknown alias, webhook, or path-mount references. */
export function defineConfig<const Config extends TnlConfig>(
  config: Config & NoInfer<TargetReferences<Config>>,
): Config;
export function defineConfig<const Names extends string = never>(
  config: (
    context: TnlConfigContext,
  ) => TnlConfigForServices<Names> | Promise<TnlConfigForServices<Names>>,
): (
  context: TnlConfigContext,
) => TnlConfigForServices<Names> | Promise<TnlConfigForServices<Names>>;
export function defineConfig(config: TnlConfigInput): TnlConfigInput {
  return config;
}
