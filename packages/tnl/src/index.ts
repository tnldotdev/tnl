import { developmentPort } from "./internal/port.js";
import { parseRuntimePayload, type ProjectMetadata } from "./internal/runtime.js";
import type { LocalHTTPServer } from "./internal/register.js";
import { TnlError } from "./errors.js";
import type { PrepareOptions, PreparedService } from "./internal/app.js";
export type { PrepareOptions, PreparedService } from "./internal/app.js";
export { TnlError, type TnlErrorCode } from "./errors.js";

/** Extended with service types from the generated `.tnl/project.d.ts` file. */
export interface TnlProjectMetadata {}

type RegisteredTnlProject = keyof TnlProjectMetadata extends never
  ? ProjectMetadata
  : Readonly<TnlProjectMetadata>;

export type TnlRuntime = Readonly<
  Partial<RegisteredTnlProject> & {
    readonly port: number;
    readonly dev: boolean;
    register(server: LocalHTTPServer): Promise<void>;
    prepare(options?: PrepareOptions): Promise<PreparedService>;
  }
>;

declare const process:
  | {
      readonly env?: {
        readonly TNL_PROJECT_RUNTIME?: string;
        readonly TNL_DEV_PROTOCOL?: string;
        readonly TNL_DEV_PORT?: string;
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
export const tnl: TnlRuntime = Object.freeze({
  ...runtime,
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
  async register(server: LocalHTTPServer): Promise<void> {
    if (typeof process === "undefined") {
      throw new TnlError("sdk.configuration_invalid");
    }
    const { registerServer } = await import("./internal/register.js");
    await registerServer(server);
  },
});
