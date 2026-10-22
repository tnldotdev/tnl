import { parseRuntimePayload } from "./internal/project/runtime.js";
import { serviceMetadata } from "./internal/project/service_metadata.js";
import type { TnlRuntime } from "./index.js";
import { TnlError } from "./errors.js";
import { awaitableConnection } from "./internal/connector/awaitable_connection.js";
export type * from "./project.js";
export type { TnlRuntime, TnlProjectConfig } from "./index.js";
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
  connect() {
    return awaitableConnection(
      () => {
        throw new TnlError("sdk.connection_server_only");
      },
      async () => {
        throw new TnlError("sdk.connection_server_only");
      },
    );
  },
}) as unknown as TnlRuntime;
