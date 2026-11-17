import type { ServiceFacts, TnlClientFactory, TnlClientOptions } from "../../project.js";
import type { FetchHandler } from "../publisher/fetch_types.js";
import type {
  NamedPublicationOptions,
  Publication,
  TemporaryPublicationOptions,
} from "../publisher/publication.js";

export interface DeploymentOptions<Services extends ServiceFacts> {
  readonly project?: string;
  readonly token?: string;
  readonly services?: Services;
}

export type ServiceNames<Services extends ServiceFacts> = keyof Services & string;
export type HTTPNames<Services extends ServiceFacts> = string extends keyof Services
  ? string
  : keyof Services extends never
    ? string
    : {
        [Name in ServiceNames<Services>]: Services[Name]["protocol"] extends "http" ? Name : never;
      }[ServiceNames<Services>];
declare const deploymentTypes: unique symbol;
export interface Deployment<Services extends ServiceFacts, Registry> {
  readonly [deploymentTypes]: { readonly services: Services; readonly connections: Registry };
  close(): Promise<void>;
}

export type Connect<Registry> = <
  Services extends ServiceFacts,
  Name extends ServiceNames<Services>,
>(
  owner: Deployment<Services, Registry>,
  name: Name,
) => Promise<Registry[Services[Name]["protocol"] & keyof Registry]>;

export type DriverClient<Registry> = <
  Services extends ServiceFacts,
  Name extends ServiceNames<Services>,
  Client,
>(
  owner: Deployment<Services, Registry>,
  name: Name,
  driver: TnlClientOptions<Registry[Services[Name]["protocol"] & keyof Registry], Client>,
) => TnlClientFactory<Client>;

export interface Publish<Registry, Server = never> {
  <Services extends ServiceFacts>(
    owner: Deployment<Services, Registry>,
    name: HTTPNames<Services>,
    target: FetchHandler | Server,
    options?: NamedPublicationOptions,
  ): Promise<Publication>;
  <Services extends ServiceFacts>(
    owner: Deployment<Services, Registry>,
    target: FetchHandler | Server,
    options?: TemporaryPublicationOptions,
  ): Promise<Publication>;
}
