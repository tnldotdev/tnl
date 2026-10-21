import { developmentPort } from "./internal/port.js";
import { createRequire } from "node:module";
import { serviceMetadata } from "./internal/service_metadata.js";
import {
  parseRuntimePayload,
  parseProjectRuntime,
  type ProjectMetadata,
} from "./internal/runtime.js";
import { TnlError } from "./errors.js";
import type { PrepareOptions, PreparedService } from "./internal/app.js";
import type { AdHocTunnel, OpenOptions } from "./internal/open.js";
import type { LocalHTTPServer } from "./internal/register.js";
import type { FetchHandler } from "./internal/fetch_types.js";
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
export type { PrepareOptions, PreparedService } from "./internal/app.js";
export type { AdHocTunnel, OpenOptions, PublisherFile, PublisherID } from "./internal/open.js";
export type { FetchHandler } from "./internal/fetch_types.js";
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
    Partial<Omit<RegisteredTnlProject, "publishers" | "workloads" | "services">> & {
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
      };
    }
  | undefined;

const serializedRuntime =
  typeof process === "undefined" ? undefined : process.env?.TNL_PROJECT_RUNTIME;

/** Server port and optional browser-safe project metadata for this process. */
// the parser validates the runtime shape; generated project declarations supply
// project-specific service names and literals unavailable to this shared module.
let runtime = parseRuntimePayload(serializedRuntime);
const loadConnection = createRequire(import.meta.url);
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
    const { prepareService } = await import("./internal/app.js");
    return prepareService(options, "Bun" in globalThis ? "bun" : "node");
  },
  async open(
    server: LocalHTTPServer | FetchHandler,
    options: OpenOptions = {},
  ): Promise<AdHocTunnel> {
    if (typeof process === "undefined") throw new TnlError("sdk.configuration_invalid");
    const { openServer, openFetch } = await import("./internal/open.js");
    return typeof server === "function" ? openFetch(server, options) : openServer(server, options);
  },
  connect(name: string) {
    if (typeof process === "undefined" || typeof process.versions?.node !== "string")
      throw new TnlError("sdk.connection_server_only");
    const { connectionHandle } = loadConnection(
      "./internal/connection.cjs",
    ) as typeof import("./internal/connection.js");
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
