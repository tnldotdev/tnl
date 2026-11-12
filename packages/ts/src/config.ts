import type { TnlConfig, TnlConfigContext } from "./config.gen.js";

export type * from "./config.gen.js";

type Service = NonNullable<NonNullable<TnlConfig["services"]>[string]>;
type Environments = NonNullable<TnlConfig["environments"]>;
type Environment = NonNullable<Environments[string]>;
type LocalEnvironment = NonNullable<Environments["local"]>;
type Target = NonNullable<NonNullable<LocalEnvironment["targets"]>[string]>;
export type TnlServiceConfig = Service;
export type TnlServiceTarget = Target;
export type TnlProtocol = NonNullable<Service["protocol"]>;

type Services<C> = C extends { readonly services: infer S } ? S : never;
type Names<C> = Extract<keyof Services<C>, string>;
type HTTPNames<C> = {
  [N in Names<C>]: Services<C>[N] extends { readonly protocol: infer P }
    ? P extends "http"
      ? N
      : never
    : N;
}[Names<C>];
type LocalTargets<C> = C extends {
  readonly environments: { readonly local: { readonly targets: infer T } };
}
  ? T
  : never;
type PublicNames<C> = {
  [N in Extract<keyof LocalTargets<C>, HTTPNames<C>>]: LocalTargets<C>[N] extends {
    readonly publicURL: object;
  }
    ? N
    : never;
}[Extract<keyof LocalTargets<C>, HTTPNames<C>>];

// recurse into inferred values as well as fresh literals. a union member must
// accept the entire object, so mixed discovery and provider variants cannot pass.
type Exact<Value, Shape> = Value extends object
  ? Shape extends unknown
    ? Value extends Shape
      ? Value extends readonly unknown[]
        ? Shape extends readonly (infer Item)[]
          ? { [I in keyof Value]: Exact<Value[I], Item> }
          : never
        : { [K in keyof Value]: K extends keyof Shape ? Exact<Value[K], Shape[K]> : never }
      : never
    : never
  : Value extends Shape
    ? Value
    : never;

type ReferenceCheck<C> = {
  [F in keyof C]: F extends "aliases" | "webhooks"
    ? { [N in keyof C[F]]: { service: PublicNames<C> } }
    : F extends "environments"
      ? { [E in keyof C[F]]: EnvironmentCheck<C, C[F][E], E> }
      : unknown;
};
type EnvironmentCheck<C, E, Name> = (Name extends "local"
  ? unknown
  : { targets: { [S in Names<C>]: unknown } }) & {
  [F in keyof E]: F extends "targets"
    ? { [S in keyof E[F]]: S extends Names<C> ? TargetCheck<C, E[F][S], S, Name> : never }
    : F extends "workloads"
      ? Name extends "local"
        ? never
        : { [W in keyof E[F]]: { visit: readonly Names<C>[] } }
      : F extends "collection"
        ? C extends { readonly collections: infer Collections }
          ? Extract<keyof Collections, string>
          : never
        : unknown;
};
type TargetCheck<C, T, S, E> = (S extends HTTPNames<C>
  ? unknown
  : T extends { readonly address: unknown } | { readonly discovery: unknown }
    ? unknown
    : never) & {
  [F in keyof T]: F extends "http"
    ? S extends HTTPNames<C>
      ? {
          [H in keyof T[F]]: H extends "paths"
            ? E extends "local"
              ? T extends { readonly publicURL: object }
                ? {
                    [P in keyof T[F][H]]: T[F][H][P] extends string
                      ? Exclude<HTTPNames<C>, S>
                      : { service: Exclude<HTTPNames<C>, S> };
                  }
                : never
              : never
            : H extends "readiness" | "open"
              ? E extends "local"
                ? unknown
                : never
              : unknown;
        }
      : never
    : F extends "publicURL" | "name" | "access" | "inspection"
      ? E extends "local"
        ? F extends "publicURL"
          ? S extends HTTPNames<C>
            ? unknown
            : never
          : unknown
        : never
      : F extends "discovery"
        ? DiscoveryCheck<C, T[F], S, E>
        : F extends "tls"
          ? T extends { readonly discovery: { readonly type: "eks" | "rds" } }
            ? never
            : unknown
          : unknown;
};
type DiscoveryCheck<C, D, S, E> = D extends { readonly type: infer Kind }
  ? Kind extends "eks"
    ? Services<C>[Extract<S, keyof Services<C>>] extends { readonly protocol: "kubernetes" }
      ? unknown
      : never
    : Kind extends "rds"
      ? Services<C>[Extract<S, keyof Services<C>>] extends {
          readonly protocol: "postgres" | "mysql";
        }
        ? unknown
        : never
      : E extends "local"
        ? unknown
        : never
  : never;

type Valid<C> = [C] extends [Exact<C, TnlConfig> & ReferenceCheck<C>] ? true : false;
type Check<C> = Valid<C> extends true ? [] : [invalidConfiguration: never];

export type TnlConfigForServices<N extends string> = Omit<
  TnlConfig,
  "services" | "environments"
> & {
  services?: { [Name in N]: Service };
  environments?: Record<
    string,
    Omit<Environment, "targets"> & { targets?: Partial<Record<NoInfer<N>, Target>> }
  >;
};

// validation is a rest parameter so it cannot widen the inferred factory return
// to TnlConfig. invalid sync and async factories require an impossible argument.
export function defineConfig<const C extends TnlConfig>(
  config: (context: TnlConfigContext) => C | Promise<C>,
  ...check: NoInfer<Check<C>>
): (context: TnlConfigContext) => C | Promise<C>;
export function defineConfig<const C extends TnlConfig>(
  config: C & NoInfer<Exact<C, TnlConfig> & ReferenceCheck<C>>,
): C;
export function defineConfig(config: unknown, ..._check: unknown[]): unknown {
  return config;
}
