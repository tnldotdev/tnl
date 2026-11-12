import * as path from "node:path";
import * as z from "zod";
import { projectRuntimeSchema } from "../project/runtime.js";
import { deadlineSchema, digestSchema, pathTextSchema } from "../values.js";
import { connectionSnapshotSchema } from "./snapshot.js";

export interface LocalSelection {
  readonly requested_at?: string;
  readonly sdk_request_handle?: string;
}

// native IPC shapes are defined in internal/connector/runtime/contract.go.
export const environmentReferenceSchema = z
  .strictObject({
    server: z.string().refine((value) => {
      const url = URL.parse(value);
      return url !== null && url.protocol === "https:" && url.origin === value;
    }),
    project_key: z.string().regex(/^[a-z][a-z0-9-]{0,62}$/),
    environment_id: z.string().regex(/^env_[A-Za-z0-9]{22}$/),
  })
  .readonly();
const protocolSchema = z.enum(["http", "tcp", "postgres", "mysql", "kubernetes"]);
export const environmentSelectionSchema = z.strictObject({
  environment: environmentReferenceSchema,
  permission_id: z.string().regex(/^mwp_[A-Za-z0-9]{22}$/),
  services: z
    .record(z.string(), protocolSchema)
    .refine((services) => Object.keys(services).length >= 1 && Object.keys(services).length <= 32),
});
export const environmentBindingSchema = z.strictObject({
  environment: environmentReferenceSchema,
  applied_definition_revision: z.number().int().positive(),
  mutation_revision: z.number().int().positive(),
  services: z.record(
    z.string(),
    z.strictObject({
      service_id: z.string().regex(/^svc_[A-Za-z0-9]{22}$/),
      protocol: protocolSchema,
      endpoint: z.strictObject({
        hostname: z.string(),
        port: z.number().int().min(1).max(65535),
        public: z.boolean(),
      }),
      kubernetes_auth: z.unknown().exactOptional(),
    }),
  ),
});
export const environmentStatusSchema = z.strictObject({
  schema: z.literal(1),
  state: z.literal("ready"),
  pid: z.number().int().positive(),
  expires_at: deadlineSchema,
  project_runtime: projectRuntimeSchema,
  connection_handle: pathTextSchema.refine(path.isAbsolute),
  executable: pathTextSchema.refine(path.isAbsolute),
  environment: environmentBindingSchema,
  kubeconfig: pathTextSchema.exactOptional(),
});

const assertionDeadlineSchema = deadlineSchema.refine(
  (value) => value <= Date.now() + 12 * 3600_000 + 60_000,
);
const sdkOwnerSchema = z.strictObject({
  expires_at: deadlineSchema,
  connection_handle: pathTextSchema.refine(path.isAbsolute),
  executable: pathTextSchema.refine(path.isAbsolute),
});
const verificationSchema = z
  .strictObject({
    digest: digestSchema,
    binding: digestSchema,
    expires_at: assertionDeadlineSchema,
  })
  .transform(({ digest, binding, expires_at }) => ({ digest, binding, expires: expires_at }))
  .readonly();
export const preparedConnectionSchema = z.strictObject({
  schema: z.literal(1),
  project_runtime: projectRuntimeSchema,
  connection: connectionSnapshotSchema,
  verification: verificationSchema.exactOptional(),
  environment: environmentBindingSchema.exactOptional(),
});
export const sdkPreparationSchema = z.union([
  z.strictObject({
    schema: z.literal(1),
    owner: sdkOwnerSchema,
    // the prepared reader validates this once, including metadata binding.
    prepared: z.unknown().nonoptional(),
  }),
  z.strictObject({
    schema: z.literal(1),
    reason: z.string(),
    sdk_retained_start_failure: z.boolean().exactOptional(),
    sdk_failure_handle: z.string().exactOptional(),
    sdk_owner_handle: pathTextSchema.exactOptional(),
  }),
]);
export const connectionHandleSchema = z.strictObject({
  schema: z.literal(1),
  url: z
    .templateLiteral(["http://127.0.0.1:", z.string().regex(/^[1-9][0-9]{0,4}$/)])
    .refine((value) => {
      const url = URL.parse(value);
      return url !== null && url.origin === value && Number(url.port) <= 65535;
    }),
  key: digestSchema,
  directory: z.string().refine(path.isAbsolute),
  config_digest: digestSchema,
  expires_at: deadlineSchema,
  executable: z.unknown().nonoptional(),
});
