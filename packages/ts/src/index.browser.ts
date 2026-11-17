import { parseRuntimePayload } from "./internal/project/runtime.js";
import { serviceMetadata } from "./internal/project/service_metadata.js";
import type { TnlRuntime } from "./index.js";
import { TnlError } from "./errors.js";
import { createStreamClient, type StreamClientOptions } from "./internal/connector/wasm_client.js";
import type { ServiceFacts } from "./project.js";
export type * from "./project.js";
export type { TnlStreamConnectionRegistry as TnlConnectionRegistry } from "./project.js";
export type { TnlRuntime, TnlProjectConfig } from "./index.js";
export { TnlError, type TnlErrorCode } from "./errors.js";
export { response } from "./response.js";
export { createBrowserPublisherStorage } from "./internal/portable/storage-browser.js";
export {
  PublisherStorageError,
  type PublisherStorage,
  type PublisherStorageErrorCode,
} from "./internal/portable/storage.js";
export type { FetchHandler } from "./internal/publisher/fetch_types.js";
export type {
  Publication,
  NamedPublicationOptions,
  TemporaryPublicationOptions,
} from "./internal/publisher/publication.js";
export type {
  LocalDeployment,
  LocalPostgresConnection,
  LocalConnectionRegistry,
} from "./internal/connector/client.js";
export type { StreamDeployment as Deployment } from "./internal/connector/wasm_client.js";

export function createClient<const Services extends ServiceFacts = Record<never, never>>(
  options: StreamClientOptions<Services>,
) {
  return createStreamClient(options);
}

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
}) as unknown as TnlRuntime;
