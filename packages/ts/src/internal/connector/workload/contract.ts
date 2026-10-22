import * as z from "zod";
import { privateTnlError, TnlError, type TnlErrorCode } from "../../../errors.js";
import { validServiceName, type ServiceProtocol } from "../../project/runtime.js";

type Provider = "github" | "vercel" | "fly" | "oidc";
export interface Workload {
  readonly provider: Provider;
  readonly services: readonly string[];
  readonly max_duration_seconds: number;
  readonly acquisition: {
    readonly method:
      | "github-actions"
      | "vercel-oidc"
      | "fly-machine-api"
      | "callback"
      | "token-file";
    readonly audience?: string | undefined;
    readonly token_file?: string | undefined;
  };
}
export interface WorkloadManifest {
  readonly schema: 1;
  readonly server: string;
  readonly team: string;
  readonly project_key: string;
  readonly source_fingerprint: string;
  readonly project_label: string;
  readonly services: Readonly<Record<string, ServiceProtocol>>;
  readonly workloads: Readonly<Record<string, Workload>>;
}
export interface WorkloadGitHubExecution {
  readonly repository_id: string;
  readonly repository_owner_id: string;
  readonly run_id: string;
  readonly run_attempt: string;
  readonly check_run_id: string;
}
interface WorkloadSessionFields {
  readonly id: string;
  readonly credential: string;
  readonly team_id: string;
  readonly project_key: string;
  readonly workload: string;
  readonly subject: { readonly kind: "workload_session"; readonly workload_session_id: string };
  readonly lease_expires_at: string;
  readonly expires_at: string;
  readonly renew_after: string;
  readonly service_ids: readonly string[];
  readonly binding: string;
  readonly assertion_expires_at?: string | undefined;
}
export type WorkloadSession = WorkloadSessionFields &
  (
    | { readonly provider: "github"; readonly github: WorkloadGitHubExecution }
    | { readonly provider: Exclude<Provider, "github">; readonly github?: never }
  );
interface Inventory {
  readonly services: readonly {
    readonly id: string;
    readonly service: string;
    readonly protocol: ServiceProtocol;
    readonly endpoint: {
      readonly hostname: string;
      readonly port: number;
      readonly public: boolean;
    };
    readonly kubernetes_auth?:
      | { readonly provider: "eks"; readonly cluster: string; readonly region: string }
      | undefined;
  }[];
}

const name = z.string().refine(validServiceName);
const value = z
  .string()
  .min(1)
  .max(128)
  .regex(/^\S+$/)
  .refine((s) => [...s].every((c) => c.charCodeAt(0) > 31 && c.charCodeAt(0) !== 127));
const provider = z.enum(["github", "vercel", "fly", "oidc"]);
const protocol = z.enum(["http", "postgres", "mysql", "tcp", "kubernetes"]);
const serviceID = z.string().regex(/^svc_[A-Za-z0-9]{22}$/);
const sessionID = z.string().regex(/^wls_[A-Za-z0-9]{22}$/);
const timestamp = z.iso.datetime({ offset: true });
const unique = (values: readonly string[]) => new Set(values).size === values.length;

const httpsOrigin = z
  .string()
  .max(2048)
  .refine((raw) => {
    try {
      const url = new URL(raw);
      return url.protocol === "https:" && url.origin === raw && !url.username && !url.password;
    } catch {
      return false;
    }
  });
const acquisition = z.strictObject({
  method: z.enum(["github-actions", "vercel-oidc", "fly-machine-api", "callback", "token-file"]),
  audience: z.string().min(1).max(2048).optional(),
  token_file: z
    .string()
    .min(1)
    .max(4096)
    .refine((s) => !s.includes("\0"))
    .optional(),
});
const workload = z.strictObject({
  provider,
  services: z.array(name).min(1).max(32).refine(unique),
  max_duration_seconds: z.number().int().min(1).max(21600),
  acquisition,
});
export const manifestSchema: z.ZodType<WorkloadManifest> = z
  .strictObject({
    schema: z.literal(1),
    server: httpsOrigin,
    team: value,
    project_key: value,
    source_fingerprint: z.string().regex(/^[0-9a-f]{64}$/),
    project_label: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/),
    services: z.record(name, protocol).refine((s) => Object.keys(s).length <= 128),
    workloads: z
      .record(name, workload)
      .refine((w) => Object.keys(w).length > 0 && Object.keys(w).length <= 32),
  })
  .refine((m) =>
    Object.values(m.workloads).every((w) => {
      const a = w.acquisition;
      if (!w.services.every((s) => Object.hasOwn(m.services, s))) return false;
      switch (w.provider) {
        case "vercel":
          return (
            a.method === "vercel-oidc" && a.audience === undefined && a.token_file === undefined
          );
        case "github":
          return (
            a.method === "github-actions" && a.audience === m.server && a.token_file === undefined
          );
        case "fly":
          return (
            a.method === "fly-machine-api" &&
            /^https:\/\/fly\.io\/[a-z0-9-]+$/.test(a.audience ?? "") &&
            a.token_file === undefined
          );
        case "oidc":
          return (
            a.audience !== undefined &&
            ((a.method === "callback" && a.token_file === undefined) ||
              (a.method === "token-file" && a.token_file !== undefined))
          );
      }
    }),
  );

const sessionFields = {
  id: sessionID,
  credential: z.string().regex(/^wlc_[A-Za-z0-9_-]{43}$/),
  team_id: z.string().regex(/^tm_[A-Za-z0-9]{22}$/),
  project_key: value,
  workload: name,
  subject: z.strictObject({ kind: z.literal("workload_session"), workload_session_id: sessionID }),
  lease_expires_at: timestamp,
  expires_at: timestamp,
  renew_after: timestamp,
  service_ids: z.array(serviceID).max(32).refine(unique),
  binding: z.string().regex(/^[0-9a-f]{64}$/),
  assertion_expires_at: timestamp.optional(),
};
const githubID = z.string().regex(/^[1-9][0-9]{0,19}$/);
export const githubExecutionSchema: z.ZodType<WorkloadGitHubExecution> = z.strictObject({
  repository_id: githubID,
  repository_owner_id: githubID,
  run_id: githubID,
  run_attempt: githubID,
  check_run_id: githubID,
});
export const sessionSchema: z.ZodType<WorkloadSession> = z.discriminatedUnion("provider", [
  z.strictObject({
    ...sessionFields,
    provider: z.literal("github"),
    github: githubExecutionSchema,
  }),
  z.strictObject({ ...sessionFields, provider: z.enum(["vercel", "fly", "oidc"]) }),
]);

export const inventorySchema: z.ZodType<Inventory> = z
  .strictObject({
    services: z
      .array(
        z.strictObject({
          id: serviceID,
          service: name,
          protocol,
          endpoint: z.strictObject({
            hostname: z
              .string()
              .min(1)
              .max(253)
              .regex(/^[a-z0-9.-]+$/),
            port: z.number().int().min(1024).max(65535),
            public: z.boolean(),
          }),
          kubernetes_auth: z
            .strictObject({
              provider: z.literal("eks"),
              cluster: z.string().min(1).max(100),
              region: z.string().min(1).max(64),
            })
            .optional(),
        }),
      )
      .max(32),
  })
  .refine(
    ({ services }) => unique(services.map((s) => s.id)) && unique(services.map((s) => s.service)),
  );

export function parseWorkload<Value>(
  schema: z.ZodType<Value>,
  raw: unknown,
  code: TnlErrorCode = "sdk.workload_response_invalid",
): Value {
  const parsed = schema.safeParse(raw);
  if (!parsed.success) throw privateTnlError(code, parsed.error);
  return parsed.data;
}

export function checkSession(
  session: WorkloadSession,
  manifest: WorkloadManifest,
  name: string,
  selected: Workload,
): void {
  const now = Date.now();
  const lease = Date.parse(session.lease_expires_at);
  const expiry = Date.parse(session.expires_at);
  const renew = Date.parse(session.renew_after);
  if (
    session.subject.workload_session_id !== session.id ||
    session.service_ids.length > selected.services.length ||
    (manifest.team.startsWith("tm_") && session.team_id !== manifest.team) ||
    session.project_key !== manifest.project_key ||
    session.workload !== name ||
    session.provider !== selected.provider ||
    lease <= now ||
    lease > now + 91_000 ||
    lease > expiry ||
    expiry > now + Math.min(21600, selected.max_duration_seconds) * 1000 + 1000 ||
    renew > lease ||
    renew > now + 31_000
  )
    throw new TnlError("sdk.workload_response_invalid");
}
