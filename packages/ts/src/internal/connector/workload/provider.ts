import * as z from "zod";
import { privateTnlError, TnlError } from "../../../errors.js";
import type { WorkloadOptions } from "../../../workload.js";
import { parseValue } from "../../validation.js";
import { pathTextSchema, serviceNameSchema } from "../../values.js";
import { cancellable } from "../cancellation.js";
import { context, contextKey } from "../context.js";
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
      token: z.custom<NonNullable<WorkloadOptions["token"]>>(
        (value) => typeof value === "function",
      ),
      tokenFile: z.undefined().optional(),
    }),
    z.strictObject({
      name: serviceNameSchema,
      tokenFile: pathTextSchema,
      token: z.undefined().optional(),
    }),
  ])
  .readonly();

export type WorkloadConfiguration = z.output<typeof workloadOptionsSchema>;

export interface WorkloadSource {
  readonly configuration: WorkloadConfiguration | undefined;
  readonly environment: Readonly<NodeJS.ProcessEnv>;
}

export function captureWorkload(key = contextKey()): WorkloadSource {
  return Object.freeze({
    configuration: context.workloads.get(key),
    environment: Object.freeze({ ...process.env }),
  });
}

/** register a fixed request-scoped source, never a mutable current token. */
export function configureWorkload(options: WorkloadOptions): void {
  const selected = parseValue(workloadOptionsSchema, options, "sdk.workload_required");
  const key = contextKey();
  const configuration = context.workloads.get(key);
  if (
    configuration !== undefined &&
    (configuration.name !== selected.name ||
      configuration.token !== selected.token ||
      configuration.tokenFile !== selected.tokenFile)
  )
    throw new TnlError("sdk.workload_required");
  if (configuration === undefined && context.workloads.size >= 32)
    throw new TnlError("sdk.workload_required");
  context.workloads.set(key, selected);
}

export function usesWorkload(key = contextKey(), source = captureWorkload(key)): boolean {
  const environment = source.environment;
  return (
    environment.TNL_CONNECTION_HANDLE === undefined &&
    (environment.TNL_WORKLOAD !== undefined ||
      source.configuration !== undefined ||
      environment.VERCEL === "1" ||
      Boolean(environment.FLY_APP_NAME) ||
      Boolean(environment.K_SERVICE) ||
      Boolean(environment.KUBERNETES_SERVICE_HOST) ||
      environment.GITLAB_CI === "true" ||
      environment.GITHUB_ACTIONS === "true")
  );
}

// only native reads the manifest and chooses acquisition. callbacks and Vercel's
// request context remain in this process; provider environment travels privately.
export async function selectWorkload(
  select: (request: WorkloadRequest) => Promise<unknown>,
  key = contextKey(),
  source = captureWorkload(key),
  expected?: WorkloadRequest["selection"],
): Promise<SelectionOptions> {
  const { configuration, environment } = source;
  const request: WorkloadRequest = {
    ...(expected === undefined ? {} : { selection: expected }),
    ...(configuration === undefined
      ? {}
      : {
          name: configuration.name,
          callback: configuration.token !== undefined,
          ...(configuration.tokenFile === undefined ? {} : { token_file: configuration.tokenFile }),
        }),
    runtime: {
      ...(environment.TNL_WORKLOAD === undefined ? {} : { workload: environment.TNL_WORKLOAD }),
      vercel: environment.VERCEL ?? "",
      fly_app_name: environment.FLY_APP_NAME ?? "",
      github_actions: environment.GITHUB_ACTIONS ?? "",
      cloud_run_service: environment.K_SERVICE ?? "",
      kubernetes_service_host: environment.KUBERNETES_SERVICE_HOST ?? "",
      gitlab_ci: environment.GITLAB_CI ?? "",
    },
  };
  const selection = parseValue(
    workloadSelectionSchema,
    await select(request),
    "sdk.response_invalid",
  );
  const assertion = await acquireAssertion(selection, AbortSignal.timeout(10_000), key, source);
  return {
    sdk_workload: request,
    sdk_workload_policy: selection.policy,
    sdk_environment: {
      github_actions: environment.GITHUB_ACTIONS ?? "",
      github_request_url: environment.ACTIONS_ID_TOKEN_REQUEST_URL ?? "",
      github_request_token: environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN ?? "",
      vercel_token_file: environment.VERCEL_OIDC_TOKEN_FILE ?? "",
      vercel_token: environment.VERCEL_OIDC_TOKEN ?? "",
      ...(selection.token_env === undefined
        ? {}
        : { token_env: selection.token_env, token_value: environment[selection.token_env] ?? "" }),
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
  key = contextKey(),
  source?: WorkloadSource,
): Promise<string | undefined> {
  const configuration = source === undefined ? context.workloads.get(key) : source.configuration;
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
