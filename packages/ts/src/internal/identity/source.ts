import * as path from "node:path";
import * as z from "zod";
import { TnlError } from "../../errors.js";
import type { IdentitySourceSelection } from "./models.gen.js";
import { identitySourceSelectionSchema } from "./validation.js";

export type NativeAcquisition =
  | Readonly<{ method: "token-file"; token_file: string }>
  | Readonly<{ method: "token-env"; token_env: string }>
  | Readonly<{ method: "github-actions" | "fly-machine-api" | "google-metadata"; audience: string }>
  | Readonly<{ method: "vercel-oidc" }>;

export interface OIDCAssertion {
  readonly token: string;
  readonly expiresAt: Date;
}
export type IdentitySource = Readonly<{
  kind: "oidc";
  machine_id: string;
  permission_id?: string;
} & (
  | { assertion(signal: AbortSignal): Promise<OIDCAssertion>; acquisition?: never }
  | { acquisition: NativeAcquisition; assertion?: never }
)>;

export const nativeAcquisitionSchema = z.union([
  z.strictObject({ method: z.literal("token-file"), token_file: z.string().min(1).max(4096).refine((value) => !/[\0\r\n]/.test(value)) }),
  z.strictObject({ method: z.literal("token-env"), token_env: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/) }),
  z.strictObject({ method: z.enum(["github-actions", "fly-machine-api", "google-metadata"]), audience: z.string().min(1).max(1024).refine((value) => value.trim() === value && !/[*?\[\]\0\r\n\t]/.test(value)) }),
  z.strictObject({ method: z.literal("vercel-oidc") }),
]);

export function captureIdentity(source: IdentitySource) {
  if (source === null || typeof source !== "object" || source.kind !== "oidc" || Object.keys(source).some((key) => !["kind", "machine_id", "permission_id", "assertion", "acquisition"].includes(key))) throw new TnlError("sdk.configuration_invalid");
  const selector: IdentitySourceSelection = identitySourceSelectionSchema.parse({ kind: source.kind, machine_id: source.machine_id });
  if ((source.assertion === undefined) === (source.acquisition === undefined)) throw new TnlError("sdk.configuration_invalid");
  if (source.assertion !== undefined) {
    if (typeof source.assertion !== "function") throw new TnlError("sdk.configuration_invalid");
    const callback = source.assertion.bind(source);
    const assertion = async (signal: AbortSignal): Promise<OIDCAssertion> => {
      signal.throwIfAborted();
      const proof = await callback(signal);
      signal.throwIfAborted();
      if (proof === null || typeof proof !== "object" || typeof proof.token !== "string" || proof.token.length < 1 || proof.token.length > 32768 || /[\s\0]/.test(proof.token) || !(proof.expiresAt instanceof Date) || !Number.isFinite(proof.expiresAt.getTime()) || proof.expiresAt.getTime() <= Date.now() + 5_000 || proof.expiresAt.getTime() > Date.now() + 12 * 3600_000) throw new TnlError("sdk.workload_assertion_unavailable");
      return Object.freeze({ token: proof.token, expiresAt: new Date(proof.expiresAt) });
    };
    return Object.freeze({ selector, assertion, startup: Object.freeze({ source: selector }), environment: undefined });
  }
  let acquisition = nativeAcquisitionSchema.parse(source.acquisition);
  if (acquisition.method === "token-file") acquisition = { ...acquisition, token_file: path.resolve(acquisition.token_file) };
  const selected = acquisition;
  const environment = () => {
    const value: Record<string, string> = {};
    switch (selected.method) {
      case "token-env": value.token_env = selected.token_env; value.token_value = process.env[selected.token_env] ?? ""; break;
      case "github-actions": value.github_actions = process.env.GITHUB_ACTIONS ?? ""; value.github_request_url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL ?? ""; value.github_request_token = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ?? ""; break;
      case "vercel-oidc": value.vercel_token_file = process.env.VERCEL_OIDC_TOKEN_FILE ?? ""; value.vercel_token = process.env.VERCEL_OIDC_TOKEN ?? ""; break;
    }
    return value;
  };
  return Object.freeze({ selector, assertion: undefined, startup: Object.freeze({ source: selector, acquisition }), environment });
}
