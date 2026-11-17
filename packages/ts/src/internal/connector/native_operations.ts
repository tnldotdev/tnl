import type { ServiceFacts, TnlClientOptions, TnlConnectionRegistry } from "../../project.js";
import type { FetchHandler } from "../publisher/fetch_types.js";
import type {
  NamedPublicationOptions,
  TemporaryPublicationOptions,
} from "../publisher/publication.js";
import type { LocalHTTPServer } from "../publisher/register.js";
import {
  createClient,
  type Deployment as NativeOwner,
  type LocalConnectionRegistry,
} from "./client.js";
import type { Deployment, DeploymentOptions, ServiceNames } from "./deployment_types.js";
import { deploymentHandles } from "./operation_handles.js";

type NativeRegistry = TnlConnectionRegistry | LocalConnectionRegistry;
const owners = deploymentHandles<NativeOwner<ServiceFacts, boolean>>();

export function deployment<
  const Name extends string,
  const Services extends ServiceFacts = Record<never, never>,
>(name: Name, options: DeploymentOptions<Services>) {
  const owner = createClient(options).deployment(name);
  return owners.handle<
    Services,
    Name extends "local" ? LocalConnectionRegistry : TnlConnectionRegistry
  >(owner as NativeOwner<ServiceFacts, boolean>);
}

export async function connect<
  Services extends ServiceFacts,
  Registry extends NativeRegistry,
  Name extends ServiceNames<Services>,
>(
  owner: Deployment<Services, Registry>,
  name: Name,
): Promise<Registry[Services[Name]["protocol"]]> {
  return owners.get(owner).connect(name) as Promise<Registry[Services[Name]["protocol"]]>;
}

export function client<
  Services extends ServiceFacts,
  Registry extends NativeRegistry,
  Name extends ServiceNames<Services>,
  Client,
>(
  owner: Deployment<Services, Registry>,
  name: Name,
  driver: TnlClientOptions<Registry[Services[Name]["protocol"]], Client>,
) {
  return owners.get(owner).client(name, {
    create: (connection) => driver.create(connection as Registry[Services[Name]["protocol"]]),
    close: driver.close,
  });
}

export async function publishNative(
  owner: object,
  first: string | FetchHandler | LocalHTTPServer,
  second?: FetchHandler | LocalHTTPServer | TemporaryPublicationOptions,
  third?: NamedPublicationOptions,
) {
  const runtime = owners.get(owner);
  return typeof first === "string"
    ? runtime.publish(first, second as FetchHandler | LocalHTTPServer, third)
    : runtime.publish(first, second as TemporaryPublicationOptions | undefined);
}
