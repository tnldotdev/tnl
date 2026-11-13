// this entry point contains only generated Fetch operations and their contracts.
// it must not import native process, project configuration, or credential stores.
export { createClient, createConfig } from "./internal/management/client/index.js";
export { deployments, publishers } from "./internal/management/sdk.gen.js";
export type * from "./internal/management/types.gen.js";
