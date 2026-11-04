import path from "node:path";
import * as z from "zod";
import { ActionError } from "./errors.js";
import { projectRuntimeSchema } from "../../packages/ts/src/internal/project/runtime.js";
import {
  deadlineSchema,
  httpsOriginSchema,
  serviceNameSchema,
} from "../../packages/ts/src/internal/values.js";

const text = z.string().min(1).max(4096);
const absolute = text.refine((value) => path.isAbsolute(value));
export const contextSchema = z
  .strictObject({
    schema: z.literal(1),
    directory: absolute,
    config_digest: z.string().regex(/^[a-f0-9]{64}$/),
    server: httpsOriginSchema.refine((value) => value.length <= 4096),
    audience: text,
    team_id: text,
    project_key: text,
    source_id: text,
    worktree_key: text,
    project_label: text,
    workload: serviceNameSchema,
    services: z
      .array(serviceNameSchema)
      .min(1)
      .max(32)
      .refine((values) => new Set(values).size === values.length),
  })
  .refine((context) => context.audience === context.server);
export const readySchema = z.object({
  schema: z.literal(1),
  state: z.literal("ready"),
  pid: z.number().int().positive(),
  expires_at: deadlineSchema.refine((expires) => expires <= Date.now() + 6 * 60 * 60 * 1000),
  executable: absolute,
  connection_handle: absolute,
  project_runtime: projectRuntimeSchema,
  kubeconfig: absolute.optional(),
});
export const cleanupSchema = z.strictObject({
  session: absolute,
  binary: absolute,
  handle: absolute.optional(),
  start_attempted: z.literal(true).optional(),
});
export type Cleanup = z.output<typeof cleanupSchema>;

export function inside(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return (
    relative !== "" &&
    !relative.startsWith(`..${path.sep}`) &&
    relative !== ".." &&
    !path.isAbsolute(relative)
  );
}

export function checkCapabilities(value: unknown): void {
  const result = z
    .object({
      schema: z.literal(1),
      capabilities: z.array(z.string()),
      workload_private: z.literal(true),
      opaque_private_preflight: z.literal(true),
      team_names: z.literal("saved_policy"),
    })
    .safeParse(value);
  if (
    !result.success ||
    !["context", "start", "status", "stop"].every((name) => result.data.capabilities.includes(name))
  ) {
    throw new ActionError("TNL_ACTION_CAPABILITIES_INVALID", {
      cause: result.success ? undefined : result.error,
    });
  }
}
