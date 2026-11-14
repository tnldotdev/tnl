import type { TnlConfig, TnlConfigInput, TnlConfigContext } from "./config.gen.js";

export type * from "./config.gen.js";

type Field<Value, Key extends PropertyKey, Fallback = never> = Key extends keyof Value
  ? NonNullable<Value[Key]>
  : Fallback;
type Services<Config> = Field<Config, "services", {}>;
type Deployments<Config> = Field<Config, "deployments", {}>;
type Targets<Config, Deployment extends PropertyKey> = Field<
  Field<Deployments<Config>, Deployment>,
  "targets",
  {}
>;
type HTTPNames<Config, Deployment extends PropertyKey> = Extract<
  {
    [Name in keyof Targets<Config, Deployment>]: Field<
      Field<Services<Config>, Name>,
      "protocol",
      "http"
    > extends "http"
      ? Name
      : never;
  }[keyof Targets<Config, Deployment>],
  string
>;
type PublicLocalHTTPNames<Config> = Extract<
  {
    [Name in keyof Targets<Config, "local">]: Targets<Config, "local">[Name] extends {
      readonly publicURL: object;
    }
      ? Name
      : never;
  }[keyof Targets<Config, "local">],
  HTTPNames<Config, "local">
>;
type Reference<Names extends string> = { readonly service: Names };
type ProtocolTarget<Protocol> = Protocol extends "http"
  ? { readonly type?: "app" | "address" | "compose" | "docker" }
  : Protocol extends "kubernetes"
    ?
        | { readonly type: "eks" }
        | { readonly type?: "address"; readonly address: string | number; readonly tls: object }
    :
        | { readonly type?: "address"; readonly address: string | number }
        | { readonly type: "compose" | "docker" }
        | (Protocol extends "postgres" | "mysql" ? { readonly type: "rds" } : never);
type BindingReferences<
  Config,
  Deployment extends PropertyKey,
  Name extends PropertyKey,
  Binding,
> = {
  [Key in keyof Binding as Key extends "http" ? Key : never]: {
    [HTTP in keyof Binding[Key]]: HTTP extends "paths"
      ? {
          [Prefix in keyof Binding[Key][HTTP]]: Binding[Key][HTTP][Prefix] extends string
            ? Exclude<HTTPNames<Config, Deployment>, Name>
            : Reference<Exclude<HTTPNames<Config, Deployment>, Name>>;
        }
      : Binding[Key][HTTP];
  };
} & ProtocolTarget<Field<Field<Services<Config>, Name>, "protocol", "http">> &
  (Field<Field<Services<Config>, Name>, "protocol", "http"> extends "http"
    ? Deployment extends "local"
      ? unknown
      : {
          readonly http?: { readiness?: never; paths?: never; open?: never };
        }
    : { readonly publicURL?: never; readonly http?: never }) &
  (Deployment extends "local"
    ? { readonly public?: never }
    : Binding extends { readonly publicURL: object }
      ? {
          readonly type?: "app" | "address";
          readonly publicURL?: { readonly ephemeral?: false };
          readonly http?: { readonly access?: never; readonly limits?: never };
        }
      : ({ readonly address: string | number } | { readonly type: "eks" | "rds" }) & {
          readonly type?: "address" | "eks" | "rds";
        });

type TargetReferences<Config> = { [Key in Exclude<keyof Config, keyof TnlConfig>]: never } & {
  [Key in keyof Config as Key extends "services" ? Key : never]: {
    [Name in keyof Config[Key]]: {
      [Extra in Exclude<keyof Config[Key][Name], "protocol">]: never;
    };
  };
} & {
  [Key in keyof Config as Key extends "deployments" ? Key : never]: {
    [Deployment in keyof Config[Key]]: {
      [Property in keyof Config[Key][Deployment]]: Property extends "targets"
        ? {
            [Name in keyof Config[Key][Deployment][Property]]: Name extends keyof Services<Config>
              ? BindingReferences<Config, Deployment, Name, Config[Key][Deployment][Property][Name]>
              : never;
          }
        : Deployment extends "local"
          ? never
          : Property extends "description" | "domain" | "public"
            ? Config[Key][Deployment][Property]
            : never;
    };
  };
} & {
  [Key in keyof Config as Key extends "workloads" ? Key : never]: {
    [Name in keyof Config[Key]]: {
      deployment: Exclude<keyof Deployments<Config>, "local">;
      services: readonly Extract<
        keyof Targets<Config, Field<Config[Key][Name], "deployment"> & PropertyKey>,
        keyof Services<Config> & string
      >[];
    };
  };
} & {
  [Key in keyof Config as Key extends "aliases" | "webhooks" ? Key : never]: {
    [Name in keyof Config[Key]]: Reference<PublicLocalHTTPNames<Config>>;
  };
};

export type TnlServiceConfig = NonNullable<NonNullable<TnlConfig["services"]>[string]>;
type Deployment = NonNullable<NonNullable<TnlConfig["deployments"]>[string]>;
export type TnlServiceTarget = NonNullable<NonNullable<Deployment["targets"]>[string]>;
export type TnlProtocol = NonNullable<TnlServiceConfig["protocol"]>;
type Alias = NonNullable<NonNullable<TnlConfig["aliases"]>[string]>;
type Webhook = NonNullable<NonNullable<TnlConfig["webhooks"]>[string]>;
type WorkloadForNames<Policy, Names extends string> = Policy extends unknown
  ? Omit<Policy, "services"> & { services: NoInfer<Names>[] }
  : never;

/** use stable service keys when a factory cannot infer them from a literal. */
export type TnlConfigForServices<Names extends string> = Omit<
  TnlConfig,
  "services" | "deployments" | "aliases" | "webhooks" | "workloads"
> & {
  services?: { [Name in Names]: TnlServiceConfig };
  deployments?: Record<
    string,
    Omit<Deployment, "targets"> & { targets?: Partial<Record<NoInfer<Names>, TnlServiceTarget>> }
  >;
  aliases?: Record<string, Omit<Alias, "service"> & { service: NoInfer<Names> }>;
  webhooks?: Record<
    string,
    Omit<Webhook, "service"> & { service: NoInfer<[Names] extends [never] ? "" : Names> }
  >;
  workloads?: Record<
    string,
    WorkloadForNames<NonNullable<NonNullable<TnlConfig["workloads"]>[string]>, Names>
  >;
};

/** infer declarations and check references within each captured deployment. */
export function defineConfig<const Config extends TnlConfig>(
  config: ((context: TnlConfigContext) => Config | Promise<Config>) &
    NoInfer<[Config] extends [TargetReferences<Config>] ? unknown : never>,
): (context: TnlConfigContext) => Config | Promise<Config>;
export function defineConfig<const Config extends TnlConfig>(
  // factories must use the return-shape overload, not infer an empty object.
  config: Config & NoInfer<TargetReferences<Config>> & { readonly call?: never },
): Config;
export function defineConfig(config: TnlConfigInput): TnlConfigInput {
  return config;
}
