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
type LocalHTTPServiceNames<Config> = Config extends { readonly services: infer Services }
  ? Extract<
      {
        [Name in keyof Services]: Services[Name] extends { readonly publisher: infer Group }
          ? Group extends "local"
            ? Name
            : never
          : Name;
      }[keyof Services],
      HTTPServiceNames<Config>
    >
  : never;
type PublisherNames<Config> =
  | "local"
  | (Config extends { readonly publishers: infer Groups } ? Extract<keyof Groups, string> : never);
type PublisherReference<Config, Service> = Service extends { readonly publisher: infer Group }
  ? {
      readonly publisher: Group extends PublisherNames<Config> ? Group : never;
    } & (Group extends "local"
      ? unknown
      : {
          readonly target: { readonly type: "address" | "eks" | "rds" };
          readonly http?: never;
        })
  : unknown;
type WebhookService<Config> = Config extends { readonly services: infer Services }
  ? Extract<
      {
        [Name in keyof Services]: Services[Name] extends { readonly publicURL: object }
          ? Name
          : never;
      }[keyof Services],
      LocalHTTPServiceNames<Config>
    >
  : never;

type TargetReferences<Config> = {
  [Field in keyof Config as Field extends "workloads" ? Field : never]: {
    [Name in keyof Config[Field]]: {
      services: readonly (Config extends { services: infer Services }
        ? Extract<keyof Services, string>
        : never)[];
    };
  };
} & {
  [Field in keyof Config as Field extends "aliases" | "webhooks" ? Field : never]: {
    [Name in keyof Config[Field]]: ObjectReference<
      Field extends "webhooks" ? WebhookService<Config> : HTTPServiceNames<Config>
    >;
  };
} & {
  [Field in keyof Config as Field extends "services" ? Field : never]: {
    [Name in keyof Config[Field]]: PublisherReference<Config, Config[Field][Name]> & {
      [HTTP in keyof Config[Field][Name] as HTTP extends "http" ? HTTP : never]: {
        [Paths in keyof Config[Field][Name][HTTP] as Paths extends "paths" ? Paths : never]: {
          [
            Prefix in keyof Config[Field][Name][HTTP][Paths]
          ]: Config[Field][Name][HTTP][Paths][Prefix] extends string
            ? Exclude<LocalHTTPServiceNames<Config>, Name>
            : ObjectReference<Exclude<LocalHTTPServiceNames<Config>, Name>>;
        };
      };
    };
  };
} & {
  [Field in keyof Config as Field extends "publishers" ? Field : never]: {
    [Name in keyof Config[Field]]: Name extends "local"
      ? never
      : {
          [
            Key in keyof Config[Field][Name] as Key extends
              | "description"
              | "domain"
              | "public"
              | "aws"
              ? never
              : Key
          ]: never;
        } & {
          [Key in keyof Config[Field][Name] as Key extends "aws" ? Key : never]: {
            [
              Setting in keyof Config[Field][Name][Key] as Setting extends "replicas"
                ? never
                : Setting
            ]: never;
          };
        };
  };
};

type Service = NonNullable<NonNullable<TnlConfig["services"]>[string]>;
export type TnlServiceConfig = Service;
export type TnlServiceTarget = NonNullable<Service["target"]>;
export type TnlProtocol = NonNullable<Service["protocol"]>;
type Alias = NonNullable<NonNullable<TnlConfig["aliases"]>[string]>;
type Webhook = NonNullable<NonNullable<TnlConfig["webhooks"]>[string]>;
type WorkloadForNames<Policy, Names extends string> = Policy extends unknown
  ? Omit<Policy, "services"> & { services: NoInfer<Names>[] }
  : never;
type MemberHTTP<Member> = Member extends { http?: infer HTTP } ? NonNullable<HTTP> : never;
type MemberPaths<Member, Names extends string, Name extends Names> =
  MemberHTTP<Member> extends { paths?: infer Paths }
    ? [NonNullable<Paths>] extends [never]
      ? never
      : Record<
          string,
          | Exclude<NoInfer<Names>, Name>
          | { service: Exclude<NoInfer<Names>, Name>; stripPrefix?: boolean }
        >
    : never;
type ServiceForNames<Names extends string, Name extends Names, Member = Service> = Member extends {
  protocol?: "http";
}
  ? Omit<Member, "http"> & {
      http?: Omit<MemberHTTP<Member>, "paths"> & {
        paths?: MemberPaths<Member, Names, Name>;
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
  "services" | "aliases" | "webhooks" | "workloads"
> & {
  services?: {
    [Name in Names]: ServiceForNames<Names, Name>;
  };
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
