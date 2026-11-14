// generated from contracts/control/public/v1 with @hey-api/openapi-ts; do not edit.

import type {
  Client,
  ClientMeta,
  Options as Options2,
  RequestResult,
  TDataShape,
} from "./client/index.js";
import type {
  CreateDeploymentData,
  CreateDeploymentErrors,
  CreateDeploymentPublisherEnrollmentData,
  CreateDeploymentPublisherEnrollmentErrors,
  CreateDeploymentPublisherEnrollmentResponses,
  CreateDeploymentResponses,
  DeleteDeploymentData,
  DeleteDeploymentErrors,
  DeleteDeploymentResponses,
  GetDeploymentData,
  GetDeploymentErrors,
  GetDeploymentPublisherData,
  GetDeploymentPublisherErrors,
  GetDeploymentPublisherResponses,
  GetDeploymentResponses,
  ListDeploymentPublishersData,
  ListDeploymentPublishersErrors,
  ListDeploymentPublishersResponses,
  ListDeploymentsData,
  ListDeploymentsErrors,
  ListDeploymentsResponses,
  RevokeDeploymentPublisherData,
  RevokeDeploymentPublisherErrors,
  RevokeDeploymentPublisherResponses,
  UpdateDeploymentData,
  UpdateDeploymentErrors,
  UpdateDeploymentResponses,
} from "./types.gen.js";
import {
  createDeploymentPublisherEnrollmentResponseSchema,
  createDeploymentResponseSchema,
  deleteDeploymentResponseSchema,
  getDeploymentPublisherResponseSchema,
  getDeploymentResponseSchema,
  listDeploymentPublishersResponseSchema,
  listDeploymentsResponseSchema,
  revokeDeploymentPublisherResponseSchema,
  updateDeploymentResponseSchema,
} from "./zod.gen.js";

export type Options<
  TData extends TDataShape = TDataShape,
  ThrowOnError extends boolean = boolean,
  TResponse = unknown,
> = Options2<Omit<TData, "headers">, ThrowOnError, TResponse> &
  (TData extends { headers: infer THeaders }
    ? { headers: THeaders | Headers | [string, string][] }
    : unknown) & {
    /**
     * You can provide a client instance returned by `createClient()` instead of
     * individual options. This might be also useful if you want to implement a
     * custom client.
     */
    client: Client;
    /**
     * You can pass arbitrary values through the `meta` object. This can be
     * used to access values that aren't defined as part of the SDK function.
     */
    meta?: keyof ClientMeta extends never ? Record<string, unknown> : ClientMeta;
  };

export class deployments {
  /**
   * List authorized deployments
   *
   * List authorized deployments in bytewise ID order. Current managers see this project's deployments. Management credentials see only approved deployments containing approved services, with other targets/services omitted; filtering precedes pagination. No publisher credentials or enrollment secrets are returned.
   */
  public static list<ThrowOnError extends boolean = false>(
    options: Options<ListDeploymentsData, ThrowOnError>,
  ): RequestResult<ListDeploymentsResponses, ListDeploymentsErrors, ThrowOnError> {
    return options.client.get<ListDeploymentsResponses, ListDeploymentsErrors, ThrowOnError>({
      responseValidator: async (data) => await listDeploymentsResponseSchema.parseAsync(data),
      security: [
        {
          key: "bearerAuth",
          scheme: "bearer",
          type: "http",
        },
      ],
      url: "/v1/projects/{project_key}/deployments",
      ...options,
      headers:
        options.headers instanceof Headers || Array.isArray(options.headers)
          ? Object.fromEntries(new Headers(options.headers))
          : options.headers,
    });
  }

  /**
   * Create a saved deployment
   *
   * Create a deployment using existing logical project declarations. Requires a current team manager or a deployment-management credential explicitly approving all current/future deployments and every submitted service. The original Idempotency-Key is scoped to the acting person or machine identity and recovers the same committed deployment; a deleted deployment is never recreated by replay. Does not grant connect or publish capabilities.
   */
  public static create<ThrowOnError extends boolean = false>(
    options: Options<CreateDeploymentData, ThrowOnError>,
  ): RequestResult<CreateDeploymentResponses, CreateDeploymentErrors, ThrowOnError> {
    return options.client.post<CreateDeploymentResponses, CreateDeploymentErrors, ThrowOnError>({
      responseValidator: async (data) => await createDeploymentResponseSchema.parseAsync(data),
      security: [
        {
          key: "bearerAuth",
          scheme: "bearer",
          type: "http",
        },
      ],
      url: "/v1/projects/{project_key}/deployments",
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers instanceof Headers || Array.isArray(options.headers)
          ? Object.fromEntries(new Headers(options.headers))
          : options.headers),
      },
    });
  }

  /**
   * Retire a deployment
   *
   * Retire this deployment's saved services, enrollments, and publishers. Requires a current manager or management approval for the deployment and every binding it removes, plus the latest strong ETag. A filtered read is not permission to delete unapproved services. Sibling deployments and logical declarations are preserved.
   */
  public static delete<ThrowOnError extends boolean = false>(
    options: Options<DeleteDeploymentData, ThrowOnError>,
  ): RequestResult<DeleteDeploymentResponses, DeleteDeploymentErrors, ThrowOnError> {
    return options.client.delete<DeleteDeploymentResponses, DeleteDeploymentErrors, ThrowOnError>({
      responseValidator: async (data) => await deleteDeploymentResponseSchema.parseAsync(data),
      security: [
        {
          key: "bearerAuth",
          scheme: "bearer",
          type: "http",
        },
      ],
      url: "/v1/projects/{project_key}/deployments/{deployment}",
      ...options,
      headers:
        options.headers instanceof Headers || Array.isArray(options.headers)
          ? Object.fromEntries(new Headers(options.headers))
          : options.headers,
    });
  }

  /**
   * Read one deployment
   *
   * Read a saved deployment with current manager or scoped deployment-management authority. Management credentials see only approved services/targets and cannot read unrelated deployments. The ETag still represents the whole deployment.
   */
  public static get<ThrowOnError extends boolean = false>(
    options: Options<GetDeploymentData, ThrowOnError>,
  ): RequestResult<GetDeploymentResponses, GetDeploymentErrors, ThrowOnError> {
    return options.client.get<GetDeploymentResponses, GetDeploymentErrors, ThrowOnError>({
      responseValidator: async (data) => await getDeploymentResponseSchema.parseAsync(data),
      security: [
        {
          key: "bearerAuth",
          scheme: "bearer",
          type: "http",
        },
      ],
      url: "/v1/projects/{project_key}/deployments/{deployment}",
      ...options,
      headers:
        options.headers instanceof Headers || Array.isArray(options.headers)
          ? Object.fromEntries(new Headers(options.headers))
          : options.headers,
    });
  }

  /**
   * Update selected deployment targets
   *
   * Update selected existing targets/TLS on the same records used by manager apply. Requires a current manager or management approval for this deployment and every submitted service, plus the latest strong ETag. Omitted targets and policies remain unchanged. Stale conditions fail with 412; a missing condition fails with 428.
   */
  public static update<ThrowOnError extends boolean = false>(
    options: Options<UpdateDeploymentData, ThrowOnError>,
  ): RequestResult<UpdateDeploymentResponses, UpdateDeploymentErrors, ThrowOnError> {
    return options.client.patch<UpdateDeploymentResponses, UpdateDeploymentErrors, ThrowOnError>({
      responseValidator: async (data) => await updateDeploymentResponseSchema.parseAsync(data),
      security: [
        {
          key: "bearerAuth",
          scheme: "bearer",
          type: "http",
        },
      ],
      url: "/v1/projects/{project_key}/deployments/{deployment}",
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers instanceof Headers || Array.isArray(options.headers)
          ? Object.fromEntries(new Headers(options.headers))
          : options.headers),
      },
    });
  }
}

export class publishers {
  /**
   * Approve scoped publisher enrollment
   *
   * Approve bounded publisher setup for selected existing services. Requires a current team manager or management approval for this deployment and every selected service. Setup cannot outlive the management grant. The original request key is scoped to the acting person or machine and recovers the same secret only while current authority, captured bindings, deadline, and remaining capacity are valid. Does not create AWS resources or grant general management/connect/namespace authority. Redeem through the existing deployment-publisher enrollment exchange.
   */
  public static createEnrollment<ThrowOnError extends boolean = false>(
    options: Options<CreateDeploymentPublisherEnrollmentData, ThrowOnError>,
  ): RequestResult<
    CreateDeploymentPublisherEnrollmentResponses,
    CreateDeploymentPublisherEnrollmentErrors,
    ThrowOnError
  > {
    return options.client.post<
      CreateDeploymentPublisherEnrollmentResponses,
      CreateDeploymentPublisherEnrollmentErrors,
      ThrowOnError
    >({
      responseValidator: async (data) =>
        await createDeploymentPublisherEnrollmentResponseSchema.parseAsync(data),
      security: [
        {
          key: "bearerAuth",
          scheme: "bearer",
          type: "http",
        },
      ],
      url: "/v1/projects/{project_key}/deployments/{deployment}/publisher-enrollments",
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers instanceof Headers || Array.isArray(options.headers)
          ? Object.fromEntries(new Headers(options.headers))
          : options.headers),
      },
    });
  }

  /**
   * List a deployment's publishers
   *
   * List authorized publishers in this deployment, including revoked identities and retained observations. A management credential sees only scoped publishers whose entire captured service/protocol approval it covers; filtering precedes pagination. Legacy whole-deployment publishers require a current manager. No enrollment secrets or targets are returned.
   */
  public static list<ThrowOnError extends boolean = false>(
    options: Options<ListDeploymentPublishersData, ThrowOnError>,
  ): RequestResult<
    ListDeploymentPublishersResponses,
    ListDeploymentPublishersErrors,
    ThrowOnError
  > {
    return options.client.get<
      ListDeploymentPublishersResponses,
      ListDeploymentPublishersErrors,
      ThrowOnError
    >({
      responseValidator: async (data) =>
        await listDeploymentPublishersResponseSchema.parseAsync(data),
      security: [
        {
          key: "bearerAuth",
          scheme: "bearer",
          type: "http",
        },
      ],
      url: "/v1/projects/{project_key}/deployments/{deployment}/publishers",
      ...options,
      headers:
        options.headers instanceof Headers || Array.isArray(options.headers)
          ? Object.fromEntries(new Headers(options.headers))
          : options.headers,
    });
  }

  /**
   * Revoke one deployment publisher
   *
   * Revoke exactly this publisher identity, its grants, leases, and current publications. Requires a current manager or management approval covering this deployment and the publisher's entire captured service/protocol scope. Legacy whole-deployment publishers require a manager. Repetition is safe; the last observation is retained. Siblings and shared enrollment capacity are unchanged. Apply and enrollment replay cannot restore the revoked identity.
   */
  public static revoke<ThrowOnError extends boolean = false>(
    options: Options<RevokeDeploymentPublisherData, ThrowOnError>,
  ): RequestResult<
    RevokeDeploymentPublisherResponses,
    RevokeDeploymentPublisherErrors,
    ThrowOnError
  > {
    return options.client.delete<
      RevokeDeploymentPublisherResponses,
      RevokeDeploymentPublisherErrors,
      ThrowOnError
    >({
      responseValidator: async (data) =>
        await revokeDeploymentPublisherResponseSchema.parseAsync(data),
      security: [
        {
          key: "bearerAuth",
          scheme: "bearer",
          type: "http",
        },
      ],
      url: "/v1/projects/{project_key}/deployments/{deployment}/publishers/{publisher}",
      ...options,
      headers:
        options.headers instanceof Headers || Array.isArray(options.headers)
          ? Object.fromEntries(new Headers(options.headers))
          : options.headers,
    });
  }

  /**
   * Read one deployment publisher
   *
   * Read one publisher's captured scope and observation with exact deployment ownership. Requires a current manager or management approval covering this deployment and the publisher's entire captured service/protocol scope. Legacy whole-deployment publishers require a manager.
   */
  public static get<ThrowOnError extends boolean = false>(
    options: Options<GetDeploymentPublisherData, ThrowOnError>,
  ): RequestResult<GetDeploymentPublisherResponses, GetDeploymentPublisherErrors, ThrowOnError> {
    return options.client.get<
      GetDeploymentPublisherResponses,
      GetDeploymentPublisherErrors,
      ThrowOnError
    >({
      responseValidator: async (data) =>
        await getDeploymentPublisherResponseSchema.parseAsync(data),
      security: [
        {
          key: "bearerAuth",
          scheme: "bearer",
          type: "http",
        },
      ],
      url: "/v1/projects/{project_key}/deployments/{deployment}/publishers/{publisher}",
      ...options,
      headers:
        options.headers instanceof Headers || Array.isArray(options.headers)
          ? Object.fromEntries(new Headers(options.headers))
          : options.headers,
    });
  }
}
