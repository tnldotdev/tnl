import * as z from "zod";
import { privateTnlError, TnlError } from "../../../errors.js";
import { parseValue } from "../../validation.js";
import { pathTextSchema, serviceNameSchema } from "../../values.js";
import { cancellable } from "../cancellation.js";
import {
  workloadSelectionSchema,
  type WorkloadRequest,
  type WorkloadSelection,
  type SelectionOptions,
} from "./contract.js";

const workloadOptionsSchema = z
  .union([
    z.strictObject({
      name: serviceNameSchema,
      token: z.custom<() => Promise<string>>((value) => typeof value === "function"),
      tokenFile: z.undefined().optional(),
    }),
    z.strictObject({
      name: serviceNameSchema,
      tokenFile: pathTextSchema,
      token: z.undefined().optional(),
    }),
    z.strictObject({
      name: serviceNameSchema,
      token: z.undefined().optional(),
      tokenFile: z.undefined().optional(),
    }),
  ])
  .readonly();

export type WorkloadConfiguration = z.output<typeof workloadOptionsSchema>;

export function parseWorkload(options: unknown): WorkloadConfiguration {
  return parseValue(workloadOptionsSchema, options, "sdk.workload_required");
}

export function workloadRuntime(): WorkloadRequest["runtime"] {
  return {
    ...(process.env.TNL_WORKLOAD === undefined ? {} : { workload: process.env.TNL_WORKLOAD }),
    vercel: process.env.VERCEL ?? "",
    fly_app_name: process.env.FLY_APP_NAME ?? "",
    github_actions: process.env.GITHUB_ACTIONS ?? "",
    cloud_run_service: process.env.K_SERVICE ?? "",
    kubernetes_service_host: process.env.KUBERNETES_SERVICE_HOST ?? "",
    gitlab_ci: process.env.GITLAB_CI ?? "",
  };
}

export function usesWorkload(runtime = workloadRuntime(), inheritHandle = true): boolean {
  return (
    (!inheritHandle || process.env.TNL_CONNECTION_HANDLE === undefined) &&
    (runtime.workload !== undefined ||
      runtime.vercel === "1" ||
      Boolean(runtime.fly_app_name) ||
      Boolean(runtime.cloud_run_service) ||
      Boolean(runtime.kubernetes_service_host) ||
      runtime.gitlab_ci === "true" ||
      runtime.github_actions === "true")
  );
}

// only native reads the manifest and chooses acquisition. callbacks and Vercel's
// request context remain in this process; provider environment travels privately.
export async function selectWorkload(
  select: (request: WorkloadRequest) => Promise<unknown>,
  configuration?: WorkloadConfiguration,
  runtime = workloadRuntime(),
): Promise<SelectionOptions> {
  const request: WorkloadRequest = {
    ...(configuration === undefined
      ? {}
      : {
          name: configuration.name,
          callback: configuration.token !== undefined,
          ...(configuration.tokenFile === undefined ? {} : { token_file: configuration.tokenFile }),
        }),
    runtime,
  };
  const selection = parseValue(
    workloadSelectionSchema,
    await select(request),
    "sdk.response_invalid",
  );
  const assertion = await acquireAssertion(selection, AbortSignal.timeout(10_000), configuration);
  return {
    sdk_workload: request,
    sdk_workload_policy: selection.policy,
    sdk_environment: {
      github_actions: process.env.GITHUB_ACTIONS ?? "",
      github_request_url: process.env.ACTIONS_ID_TOKEN_REQUEST_URL ?? "",
      github_request_token: process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ?? "",
      vercel_token_file: process.env.VERCEL_OIDC_TOKEN_FILE ?? "",
      vercel_token: process.env.VERCEL_OIDC_TOKEN ?? "",
      ...(selection.token_env === undefined
        ? {}
        : { token_env: selection.token_env, token_value: process.env[selection.token_env] ?? "" }),
    },
    ...(assertion === undefined ? {} : { assertion }),
  };
}

function boundedAssertion(raw: unknown): string {
  if (typeof raw !== "string") throw new TnlError("sdk.workload_assertion_unavailable");
  const token = raw.trim();
  if (!token || Buffer.byteLength(token) > 32768 || token.includes("\0") || /\s/.test(token))
    throw new TnlError("sdk.workload_assertion_unavailable");
  return token;
}

export async function acquireAssertion(
  selection: Pick<WorkloadSelection, "name" | "source">,
  signal: AbortSignal,
  configuration?: WorkloadConfiguration,
): Promise<string | undefined> {
  const lifetime = AbortSignal.any([signal, AbortSignal.timeout(10_000)]);
  try {
    return await cancellable(lifetime, async () => {
      if (selection.source === "native") return undefined;
      if (selection.source === "callback") {
        if (configuration?.name !== selection.name || configuration.token === undefined)
          throw new TnlError("sdk.workload_assertion_unavailable");
        return boundedAssertion(await configuration.token());
      }
      const { getContext, getVercelOidcToken } = await import("@vercel/oidc");
      const current = getContext().headers?.["x-vercel-oidc-token"];
      if (current === undefined) return undefined;
      boundedAssertion(current);
      // disable development refresh: control decides validity, and missing tokens
      // must never cause CLI login, project discovery, or global token writes.
      return boundedAssertion(
        await getVercelOidcToken({ expirationBufferMs: Number.NEGATIVE_INFINITY }),
      );
    });
  } catch (cause) {
    if (lifetime.aborted) throw lifetime.reason;
    throw privateTnlError("sdk.workload_assertion_unavailable", cause);
  }
}
