import * as path from "node:path";
import * as z from "zod";
import { projectRuntimeSchema } from "../project/runtime.js";
import { deadlineSchema, digestSchema, pathTextSchema } from "../values.js";
import { connectionSnapshotSchema } from "./snapshot.js";

const assertionDeadlineSchema = deadlineSchema.refine(
  (value) => value <= Date.now() + 12 * 3600_000 + 60_000,
);
export const stoppedOwnerSchema = z.strictObject({
  schema: z.literal(1),
  state: z.literal("stopped"),
});
export const workloadIdentitySchema = z.strictObject({
  schema: z.literal(1),
  binding: digestSchema,
  assertion_expires_at: assertionDeadlineSchema.exactOptional(),
});
// capture the cleanup capability before validating the rest of a startup reply.
export const startupHandleSchema = z.object({
  connection_handle: pathTextSchema.refine(path.isAbsolute),
});
export const startedOwnerSchema = z.strictObject({
  schema: z.literal(1),
  state: z.literal("ready"),
  pid: z.int().positive(),
  expires_at: deadlineSchema,
  project_runtime: projectRuntimeSchema,
  connection_handle: pathTextSchema.refine(path.isAbsolute),
  executable: z.string().refine(path.isAbsolute),
  kubeconfig: z.string().refine(path.isAbsolute).exactOptional(),
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
});
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
  workload: z.unknown().optional(),
  team_id: z.unknown().optional(),
});
