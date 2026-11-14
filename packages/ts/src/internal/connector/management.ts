import { TnlError } from "../../errors.js";
import { createClient, deployments, publishers } from "../../http.js";
import type { Client } from "../management/client/index.js";
import type {
  CreateDeploymentRequest,
  UpdateDeploymentRequest,
  CreateDeploymentPublisherEnrollmentRequest,
  Deployment,
} from "../../http.js";
import { deploymentAccess } from "./connection.js";

export type SavedDeployment = Deployment & { readonly etag: string };
export interface CreationOptions {
  readonly idempotencyKey: string;
}
export interface MutationOptions {
  readonly ifMatch: string;
}
export interface PageOptions {
  readonly after?: string;
  readonly limit?: number;
}

function saved(value: Deployment, response: Response): SavedDeployment {
  const etag = response.headers.get("etag");
  if (etag === null || !/^"[0-9]+"$/.test(etag)) throw new TnlError("sdk.response_invalid");
  return Object.freeze({ ...value, etag });
}

// bind only selection and native credential acquisition. all HTTP operations,
// wire types, validation, response/error handling remain stock generated code.
export function boundManagement(project: string | undefined, token: string | undefined) {
  let current: Awaited<ReturnType<typeof deploymentAccess>> | undefined;
  let loading: Promise<Awaited<ReturnType<typeof deploymentAccess>>> | undefined;
  let client: Client | undefined;
  const access = async () => {
    if (project === undefined || token === undefined)
      throw new TnlError("sdk.configuration_invalid");
    if (current !== undefined && current.expires_at > Date.now() + 30_000) return current;
    loading ??= deploymentAccess(project, token)
      .then((value) => {
        if (
          current !== undefined &&
          (value.server !== current.server ||
            value.team_id !== current.team_id ||
            value.project_key !== current.project_key)
        )
          throw new TnlError("sdk.response_invalid");
        current = value;
        return value;
      })
      .finally(() => {
        loading = undefined;
      });
    return loading;
  };
  const options = async () => {
    const selected = await access();
    client ??= createClient({ baseUrl: selected.server, auth: async () => (await access()).token });
    return {
      client,
      query: { team_id: selected.team_id },
      path: { project_key: selected.project_key },
      throwOnError: true as const,
    };
  };
  return Object.freeze({
    deployments: Object.freeze({
      async create(body: CreateDeploymentRequest, request: CreationOptions) {
        const result = await deployments.create({
          ...(await options()),
          body,
          headers: { "Idempotency-Key": request.idempotencyKey },
        });
        return saved(result.data, result.response);
      },
      async list(page: PageOptions = {}) {
        const selected = await options();
        return (await deployments.list({ ...selected, query: { ...selected.query, ...page } }))
          .data;
      },
      async get(deployment: string) {
        const selected = await options();
        const result = await deployments.get({
          ...selected,
          path: { ...selected.path, deployment },
        });
        return saved(result.data, result.response);
      },
      async update(deployment: string, body: UpdateDeploymentRequest, request: MutationOptions) {
        const selected = await options();
        const result = await deployments.update({
          ...selected,
          path: { ...selected.path, deployment },
          body,
          headers: { "If-Match": request.ifMatch },
        });
        return saved(result.data, result.response);
      },
      async delete(deployment: string, request: MutationOptions) {
        const selected = await options();
        await deployments.delete({
          ...selected,
          path: { ...selected.path, deployment },
          headers: { "If-Match": request.ifMatch },
        });
      },
    }),
    publishers: Object.freeze({
      async createEnrollment(
        deployment: string,
        body: CreateDeploymentPublisherEnrollmentRequest,
        request: CreationOptions,
      ) {
        const selected = await options();
        return (
          await publishers.createEnrollment({
            ...selected,
            path: { ...selected.path, deployment },
            body,
            headers: { "Idempotency-Key": request.idempotencyKey },
          })
        ).data;
      },
      async list(deployment: string, page: PageOptions = {}) {
        const selected = await options();
        return (
          await publishers.list({
            ...selected,
            path: { ...selected.path, deployment },
            query: { ...selected.query, ...page },
          })
        ).data;
      },
      async get(deployment: string, publisher: string) {
        const selected = await options();
        return (
          await publishers.get({ ...selected, path: { ...selected.path, deployment, publisher } })
        ).data;
      },
      async revoke(deployment: string, publisher: string) {
        const selected = await options();
        await publishers.revoke({ ...selected, path: { ...selected.path, deployment, publisher } });
      },
    }),
  });
}
