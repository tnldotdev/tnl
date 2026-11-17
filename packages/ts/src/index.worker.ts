import module from "./wasm/tnl.wasm";
import { createStreamClient, type StreamClientOptions } from "./internal/connector/wasm_client.js";
import type { ServiceFacts } from "./project.js";

export {
  tnl,
  TnlError,
  response,
  createBrowserPublisherStorage,
  PublisherStorageError,
} from "./index.browser.js";
export type {
  TnlRuntime,
  TnlProjectConfig,
  TnlErrorCode,
  PublisherStorage,
  PublisherStorageErrorCode,
  Publication,
  NamedPublicationOptions,
  TemporaryPublicationOptions,
  FetchHandler,
} from "./index.browser.js";
export type * from "./project.js";
export type { TnlStreamConnectionRegistry as TnlConnectionRegistry } from "./project.js";
export type { StreamDeployment as Deployment } from "./internal/connector/wasm_client.js";

// workerd imports a precompiled module. compilation/fetch is never attempted in
// a request; each deployment still starts and owns its own go instance.
export function createClient<const Services extends ServiceFacts = Record<never, never>>(
  options: StreamClientOptions<Services>,
) {
  return createStreamClient(options, module);
}
