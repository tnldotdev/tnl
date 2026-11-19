export type * from "./project.js";
export type { Deployment, DeploymentOptions } from "./internal/connector/deployment_types.js";
export type { FetchHandler } from "./internal/publisher/fetch_types.js";
export type {
  Publication,
  PublicationRun,
  NamedPublicationOptions,
  TemporaryPublicationOptions,
  ServiceCertificate,
  ServiceCertificateSource,
} from "./internal/publisher/publication.js";
export { TnlError, type TnlErrorCode } from "./errors.js";
export { response } from "./response.js";

/** extended by `.tnl/generated/project.d.ts` for all runtime paths. */
export interface TnlProjectConfig {}
