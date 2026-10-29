import { developmentPort } from "./internal/publisher/port.js";
import { loadConnection } from "./internal/connector/connection_bridge.js";
import { serviceMetadata } from "./internal/project/service_metadata.js";
import {
  parseRuntimePayload,
  parseProjectRuntime,
  type ProjectMetadata,
} from "./internal/project/runtime.js";
import { TnlError } from "./errors.js";
import { readTelemetryDisabled } from "./internal/publisher/telemetry.js";
import type { PrepareOptions, PreparedService } from "./internal/publisher/app.js";
import type { AdHocTunnel, OpenOptions } from "./internal/publisher/open.js";
import type { LocalHTTPServer } from "./internal/publisher/register.js";
import type { FetchHandler } from "./internal/publisher/fetch_types.js";
import type {
  TnlConnection,
  TnlConnectionHandle,
  TnlProjectFromConfig,
  TnlResolvedConfig,
  TnlServiceNames,
  TnlService,
  TnlProtocolRegistry,
} from "./project.js";
export type * from "./project.js";
export type { PrepareOptions, PreparedService } from "./internal/publisher/app.js";
export type {
  AdHocTunnel,
  OpenOptions,
  PublisherCredentialFile,
  PublisherIdentityID,
} from "./internal/publisher/open.js";
export type { FetchHandler } from "./internal/publisher/fetch_types.js";
export { TnlError, type TnlErrorCode } from "./errors.js";

/** extended by the portable `.tnl/generated/project.d.ts` declaration. */
export interface TnlProjectConfig {}

type Config = TnlProjectConfig extends { config: infer Input }
  ? TnlResolvedConfig<Input>
  : { services: Record<string, { protocol: keyof TnlProtocolRegistry }> };
type RegisteredTnlProject = keyof TnlProjectConfig extends never
  ? {
      services: Readonly<
        Record<string, TnlService<{ protocol: keyof TnlProtocolRegistry }> | undefined>
      >;
    }
  : TnlProjectFromConfig<Config>;

export type TnlRuntime = Readonly<
  Partial<Omit<ProjectMetadata, "services">> &
    Partial<Omit<RegisteredTnlProject, "publisherGroups" | "workloads" | "services">> & {
      services: RegisteredTnlProject["services"];
      readonly port: number;
      readonly dev: boolean;
      prepare(options?: PrepareOptions): Promise<PreparedService>;
      open(server: LocalHTTPServer | FetchHandler, options?: OpenOptions): Promise<AdHocTunnel>;
      connect<Name extends TnlServiceNames<Config>>(
        name: Name,
      ): TnlConnectionHandle<TnlConnection<Config, Name>>;
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
        readonly TNL_NO_TELEMETRY?: string;
      };
    }
  | undefined;

const serializedRuntime =
  typeof process === "undefined" ? undefined : process.env?.TNL_PROJECT_RUNTIME;

/** Server port and optional browser-safe project metadata for this process. */
// the parser validates the runtime shape; generated project declarations supply
// project-specific service names and literals unavailable to this shared module.
let runtime = parseRuntimePayload(serializedRuntime);
export const tnl = Object.freeze({
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
    const telemetryDisabled = readTelemetryDisabled(process.env?.TNL_NO_TELEMETRY);
    const { prepareService } = await import("./internal/publisher/app.js");
    return prepareService(options, "Bun" in globalThis ? "bun" : "node", telemetryDisabled);
  },
  async open(
    server: LocalHTTPServer | FetchHandler,
    options: OpenOptions = {},
  ): Promise<AdHocTunnel> {
    if (typeof process === "undefined") throw new TnlError("sdk.configuration_invalid");
    const telemetryDisabled = readTelemetryDisabled(process.env?.TNL_NO_TELEMETRY);
    const { openServer, openFetch } = await import("./internal/publisher/open.js");
    return typeof server === "function"
      ? openFetch(server, options, undefined, telemetryDisabled)
      : openServer(server, options, undefined, telemetryDisabled);
  },
  connect(name: string) {
    if (typeof process === "undefined" || typeof process.versions?.node !== "string")
      throw new TnlError("sdk.connection_server_only");
    const { connectionHandle } = loadConnection();
    return connectionHandle(name, (project) => {
      runtime =
        runtime === undefined
          ? project
          : parseProjectRuntime(
              { ...runtime, services: { ...runtime.services, ...project.services } },
              "connected project runtime",
            );
    });
  },
}) as unknown as TnlRuntime;
