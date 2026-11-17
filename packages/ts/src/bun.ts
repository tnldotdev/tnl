import type { TnlConnectionRegistry } from "./project.js";
import type { Publish } from "./internal/connector/deployment_types.js";
import type { LocalConnectionRegistry } from "./internal/connector/client.js";
import { publishNative } from "./internal/connector/native_operations.js";
import type { BunHTTPServer } from "./internal/publisher/register.js";

export * from "./index.js";
export { tnl } from "./internal/project/native_runtime.js";
export type {
  TnlRuntime,
  PrepareOptions,
  PreparedService,
} from "./internal/project/native_runtime.js";
export { deployment, connect, client } from "./internal/connector/native_operations.js";
export type {
  LocalConnectionRegistry,
  LocalPostgresConnection,
} from "./internal/connector/client.js";

export const publish: Publish<TnlConnectionRegistry | LocalConnectionRegistry, BunHTTPServer> =
  publishNative;
