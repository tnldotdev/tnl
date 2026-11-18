import { publishNative, type NativePublish } from "./internal/connector/native_operations.js";
import type { BunHTTPServer } from "./internal/publisher/register.js";

export * from "./index.js";
export { tnl } from "./internal/project/native_runtime.js";
export type {
  TnlRuntime,
  PrepareOptions,
  PreparedService,
} from "./internal/project/native_runtime.js";
export { deployment, connect, client } from "./internal/connector/native_operations.js";
export {
  publisher,
  type Publisher,
  type PublisherOptions,
} from "./internal/publisher/native_publisher.js";
export type {
  LocalConnectionRegistry,
  LocalPostgresConnection,
} from "./internal/connector/client.js";

export const publish: NativePublish<BunHTTPServer> = publishNative;
