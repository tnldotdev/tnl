import { parseRuntimePayload } from "./internal/runtime.js";
import { serviceMetadata } from "./internal/service_metadata.js";
import type { TnlRuntime } from "./index.js";
import { TnlError } from "./errors.js";
export { TnlError, type TnlErrorCode } from "./errors.js";

declare const process: { readonly env?: { readonly TNL_PROJECT_RUNTIME?: string } } | undefined;

const runtime = parseRuntimePayload(
  typeof process === "undefined" ? undefined : process.env?.TNL_PROJECT_RUNTIME,
);

/** Browser-safe project metadata; listener registration is server-only. */
export const tnl = Object.freeze({
  ...runtime,
  get services() {
    return serviceMetadata(runtime);
  },
  port: 3000,
  dev: runtime?.dev ?? false,
  async prepare(): Promise<never> {
    throw new TnlError("sdk.configuration_invalid");
  },
  async open(): Promise<never> {
    throw new TnlError("sdk.configuration_invalid");
  },
  async connect(): Promise<never> {
    throw new TnlError("sdk.connection_unavailable");
  },
}) as unknown as TnlRuntime;
