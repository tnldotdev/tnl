// this entry point contains only generated Fetch operations and their contracts.
// it must not import native process, project configuration, or credential stores.
export {
  createClient as createControlClient,
  createConfig,
} from "./internal/management/client/index.js";
export {
  createDeployment,
  deleteDeployment,
  getDeployment,
  listDeployments,
  updateDeployment,
  createDeploymentPublisherEnrollment as createPublisherEnrollment,
  getDeploymentPublisher as getPublisher,
  listDeploymentPublishers as listPublishers,
  revokeDeploymentPublisher as revokePublisher,
} from "./internal/management/sdk.gen.js";
export type * from "./internal/management/types.gen.js";
