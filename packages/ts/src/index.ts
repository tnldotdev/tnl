import { developmentPort } from "./internal/publisher/port.js";
import { loadConnection, loadEnvironmentClient } from "./internal/connector/connection_bridge.js";
import type { EnvironmentClientOptions } from "./internal/connector/environment_client.js";
import type { ServiceFacts } from "./internal/project/service_facts.js";
import type { SelectedClient } from "./internal/connector/selected_client.js";
export type {
  EnvironmentClientOptions,
  EnvironmentReference,
  IdentitySource,
  IdentitySourceChallenge,
  IdentitySourceReply,
  IdentitySourceSelection,
  OIDCAssertion,
  NativeAcquisition,
} from "./internal/connector/environment_client.js";
import { serviceMetadata } from "./internal/project/service_metadata.js";
import {
  parseRuntimePayload,
  parseProjectRuntime,
  type ProjectMetadata,
  type ProjectServiceMetadata,
} from "./internal/project/runtime.js";
import { TnlError } from "./errors.js";
import type { PrepareOptions, PreparedService } from "./internal/publisher/app.js";
import type { AdHocTunnel, OpenOptions } from "./internal/publisher/open.js";
import type { LocalHTTPServer } from "./internal/publisher/register.js";
import type { FetchHandler } from "./internal/publisher/fetch_types.js";
import type {
  TnlConnectionHandle,
  TnlConnectionRegistry,
  TnlClientFactory,
  TnlClientOptions,
} from "./project.js";
export type * from "./project.js";
export type { PrepareOptions, PreparedService } from "./internal/publisher/app.js";
export type {
  AdHocTunnel,
  OpenOptions,
} from "./internal/publisher/open.js";
export type { FetchHandler } from "./internal/publisher/fetch_types.js";
export { TnlError, type TnlErrorCode } from "./errors.js";

type Settings = TnlConnectionRegistry[keyof TnlConnectionRegistry];

export type TnlRuntime = Readonly<
  Partial<Omit<ProjectMetadata, "services">> & {
    services: Readonly<Record<string, ProjectServiceMetadata | undefined>>;
    readonly port: number;
    readonly dev: boolean;
    prepare(options?: PrepareOptions): Promise<PreparedService>;
    open(server: LocalHTTPServer | FetchHandler, options: OpenOptions): Promise<AdHocTunnel>;
    connect(name: string): TnlConnectionHandle<Settings>;
    client<Client>(
      name: string,
      options: TnlClientOptions<Settings, Client>,
    ): TnlClientFactory<Client>;
    client<const Services extends ServiceFacts>(
      options: EnvironmentClientOptions<Services>,
    ): SelectedClient<Services>;
  }
>;

declare const process:
  | {
      readonly versions?: { readonly node?: string };
      readonly env?: {
        readonly TNL_PROJECT_RUNTIME?: string;
        readonly BUN_PORT?: string;
        readonly PORT?: string;
        readonly NODE_PORT?: string;
      };
    }
  | undefined;

const serializedRuntime =
  typeof process === "undefined" ? undefined : process.env?.TNL_PROJECT_RUNTIME;

/** Server port and optional browser-safe project metadata for this process. */
// runtime endpoints do not establish a caller's compiled service contract.
let runtime = parseRuntimePayload(serializedRuntime);
export const tnl: TnlRuntime = Object.freeze({
  ...runtime,
  get services() {
    return serviceMetadata(runtime);
  },
  port: developmentPort(
    typeof process === "undefined" ? {} : (process.env ?? {}),
    "Bun" in globalThis,
  ),
  dev: runtime?.dev ?? false,
  async prepare(options: PrepareOptions = {}): Promise<PreparedService> {
    if (typeof process === "undefined") throw new TnlError("sdk.configuration_invalid");
    const { prepareService } = await import("./internal/publisher/app.js");
    return prepareService(options, "Bun" in globalThis ? "bun" : "node");
  },
  async open(
    server: LocalHTTPServer | FetchHandler,
    options: OpenOptions,
  ): Promise<AdHocTunnel> {
    if (typeof process === "undefined") throw new TnlError("sdk.configuration_invalid");
    const { openServer, openFetch } = await import("./internal/publisher/open.js");
    return typeof server === "function" ? openFetch(server, options) : openServer(server, options);
  },
  connect(name: string) {
    if (typeof process === "undefined" || typeof process.versions?.node !== "string")
      throw new TnlError("sdk.connection_server_only");
    const { connectionHandle } = loadConnection();
    return connectionHandle(name, (project) => {
      runtime =
        runtime === undefined
          ? project
          : parseProjectRuntime({
              ...runtime,
              services: { ...runtime.services, ...project.services },
            });
    });
  },
  client: createClient,
});

function createClient<const Services extends ServiceFacts>(
  options: EnvironmentClientOptions<Services>,
): SelectedClient<Services>;
function createClient<Client>(
  name: string,
  options: TnlClientOptions<Settings, Client>,
): TnlClientFactory<Client>;
function createClient<const Services extends ServiceFacts, Client>(
  name: string | EnvironmentClientOptions<Services>,
  options?: TnlClientOptions<Settings, Client>,
): SelectedClient<Services> | TnlClientFactory<Client> {
  if (typeof process === "undefined" || typeof process.versions?.node !== "string")
    throw new TnlError("sdk.connection_server_only");
  if (typeof name === "object" && name !== null && options === undefined)
    return loadEnvironmentClient().environmentClient(name);
  if (typeof name !== "string" || options === undefined)
    throw new TnlError("sdk.configuration_invalid");
  const { connectionClient } = loadConnection();
  return connectionClient(name, options, (project) => {
    runtime =
      runtime === undefined
        ? project
        : parseProjectRuntime({
            ...runtime,
            services: { ...runtime.services, ...project.services },
          });
  });
}
