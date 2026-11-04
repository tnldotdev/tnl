import * as z from "zod";
import { TnlError, type TnlErrorCode } from "../../../errors.js";
import { parseValue } from "../../validation.js";
import {
  digestSchema,
  httpsOriginSchema,
  pathTextSchema,
  protocolSchema,
  serviceIDSchema,
  serviceNameSchema,
  workloadSessionIDSchema,
} from "../../values.js";

const valueSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^\S+$/)
  .refine((value) =>
    [...value].every(
      (character) => character.charCodeAt(0) > 31 && character.charCodeAt(0) !== 127,
    ),
  );
const timestampSchema = z.iso.datetime({ offset: true });
const unique = (values: readonly string[]) => new Set(values).size === values.length;
const audienceSchema = z.string().min(1).max(2048);
const workloadFields = {
  services: z.array(serviceNameSchema).min(1).max(32).refine(unique).readonly(),
  max_duration_seconds: z.int().min(1).max(21600),
};
const workloadSchema = z
  .discriminatedUnion("provider", [
    z.strictObject({
      ...workloadFields,
      provider: z.literal("github"),
      acquisition: z
        .strictObject({
          method: z.literal("github-actions"),
          audience: audienceSchema,
        })
        .readonly(),
    }),
    z.strictObject({
      ...workloadFields,
      provider: z.literal("vercel"),
      acquisition: z
        .strictObject({
          method: z.literal("vercel-oidc"),
        })
        .readonly(),
    }),
    z.strictObject({
      ...workloadFields,
      provider: z.literal("fly"),
      acquisition: z
        .strictObject({
          method: z.literal("fly-machine-api"),
          audience: audienceSchema.regex(/^https:\/\/fly\.io\/[a-z0-9-]+$/),
        })
        .readonly(),
    }),
    z.strictObject({
      ...workloadFields,
      provider: z.literal("oidc"),
      acquisition: z
        .discriminatedUnion("method", [
          z.strictObject({ method: z.literal("callback"), audience: audienceSchema }),
          z.strictObject({
            method: z.literal("token-file"),
            audience: audienceSchema,
            token_file: pathTextSchema,
          }),
        ])
        .readonly(),
    }),
  ])
  .readonly();

export const manifestSchema = z
  .strictObject({
    schema: z.literal(1),
    server: httpsOriginSchema.refine((value) => value.length <= 2048),
    team: valueSchema,
    project_key: valueSchema,
    source_fingerprint: digestSchema,
    project_label: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/),
    services: z
      .record(serviceNameSchema, protocolSchema)
      .refine((services) => Object.keys(services).length <= 128)
      .readonly(),
    workloads: z
      .record(serviceNameSchema, workloadSchema)
      .refine(
        (workloads) => Object.keys(workloads).length > 0 && Object.keys(workloads).length <= 32,
      )
      .readonly(),
  })
  .refine((manifest) =>
    Object.values(manifest.workloads).every(
      (workload) =>
        workload.services.every((service) => Object.hasOwn(manifest.services, service)) &&
        (workload.provider !== "github" || workload.acquisition.audience === manifest.server),
    ),
  )
  .readonly();

const sessionFields = {
  id: workloadSessionIDSchema,
  credential: z.templateLiteral(["wlc_", z.string().regex(/^[A-Za-z0-9_-]{43}$/)]),
  team_id: z.templateLiteral(["tm_", z.string().regex(/^[A-Za-z0-9]{22}$/)]),
  project_key: valueSchema,
  workload: serviceNameSchema,
  subject: z
    .strictObject({
      kind: z.literal("workload_session"),
      workload_session_id: workloadSessionIDSchema,
    })
    .readonly(),
  lease_expires_at: timestampSchema,
  expires_at: timestampSchema,
  renew_after: timestampSchema,
  service_ids: z.array(serviceIDSchema).max(32).refine(unique).readonly(),
  binding: digestSchema,
  assertion_expires_at: timestampSchema.optional(),
};
const githubIDSchema = z.string().regex(/^[1-9][0-9]{0,19}$/);
export const githubExecutionSchema = z
  .strictObject({
    repository_id: githubIDSchema,
    repository_owner_id: githubIDSchema,
    run_id: githubIDSchema,
    run_attempt: githubIDSchema,
    check_run_id: githubIDSchema,
  })
  .readonly();
export const sessionSchema = z
  .discriminatedUnion("provider", [
    z.strictObject({
      ...sessionFields,
      provider: z.literal("github"),
      github: githubExecutionSchema,
    }),
    z.strictObject({ ...sessionFields, provider: z.enum(["vercel", "fly", "oidc"]) }),
  ])
  .readonly();

export const inventorySchema = z
  .strictObject({
    services: z
      .array(
        z
          .strictObject({
            id: serviceIDSchema,
            service: serviceNameSchema,
            protocol: protocolSchema,
            endpoint: z
              .strictObject({
                hostname: z
                  .string()
                  .min(1)
                  .max(253)
                  .regex(/^[a-z0-9.-]+$/),
                port: z.int().min(1024).max(65535),
                public: z.boolean(),
              })
              .readonly(),
            kubernetes_auth: z
              .strictObject({
                provider: z.literal("eks"),
                cluster: z.string().min(1).max(100),
                region: z.string().min(1).max(64),
              })
              .readonly()
              .optional(),
          })
          .readonly(),
      )
      .max(32)
      .readonly(),
  })
  .refine(
    ({ services }) =>
      unique(services.map((service) => service.id)) &&
      unique(services.map((service) => service.service)),
  )
  .readonly();

export type Workload = z.output<typeof workloadSchema>;
export type WorkloadManifest = z.output<typeof manifestSchema>;
export type WorkloadGitHubExecution = z.output<typeof githubExecutionSchema>;
export type WorkloadSession = z.output<typeof sessionSchema>;

export function parseWorkload<Value>(
  schema: z.ZodType<Value>,
  raw: unknown,
  code: TnlErrorCode = "sdk.workload_response_invalid",
): Value {
  return parseValue(schema, raw, code);
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
