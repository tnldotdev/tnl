import { developmentPort } from "./internal/publisher/port.js";
import { serviceMetadata } from "./internal/project/service_metadata.js";
import { parseRuntimePayload, type ProjectMetadata } from "./internal/project/runtime.js";
import { TnlError } from "./errors.js";
import type { PrepareOptions, PreparedService } from "./internal/publisher/app.js";
import type {
  TnlProjectFromConfig,
  TnlResolvedConfig,
  TnlService,
  TnlProtocolRegistry,
} from "./project.js";
export type * from "./project.js";
export type { PrepareOptions, PreparedService } from "./internal/publisher/app.js";
export type {
  Publication,
  NamedPublicationOptions,
  TemporaryPublicationOptions,
} from "./internal/publisher/publication.js";
export type { FetchHandler } from "./internal/publisher/fetch_types.js";
export { TnlError, type TnlErrorCode } from "./errors.js";
export {
  createClient,
  type ServiceFacts,
  type Deployment,
  type LocalDeployment,
  type LocalPostgresConnection,
  type LocalConnectionRegistry,
} from "./internal/connector/client.js";

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
    Partial<Omit<RegisteredTnlProject, "workloads" | "services">> & {
      services: RegisteredTnlProject["services"];
      readonly port: number;
      readonly dev: boolean;
      prepare(options?: PrepareOptions): Promise<PreparedService>;
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
const runtime = parseRuntimePayload(serializedRuntime);
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
    const { prepareService } = await import("./internal/publisher/app.js");
    return prepareService(options, "Bun" in globalThis ? "bun" : "node");
  },
}) as unknown as TnlRuntime;
