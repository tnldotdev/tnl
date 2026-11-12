import path from "node:path";
import * as z from "zod";
import { ActionError } from "./errors.js";
import { projectRuntimeSchema } from "../../packages/ts/src/internal/project/runtime.js";
import { environmentBindingSchema } from "../../packages/ts/src/internal/connector/contract.js";
import {
  deadlineSchema,
} from "../../packages/ts/src/internal/values.js";

const text = z.string().min(1).max(4096);
const absolute = text.refine((value) => path.isAbsolute(value));
export const readySchema = z.object({
  schema: z.literal(1),
  state: z.literal("ready"),
  pid: z.number().int().positive(),
  expires_at: deadlineSchema.refine((expires) => expires <= Date.now() + 6 * 60 * 60 * 1000),
  executable: absolute,
  connection_handle: absolute,
  project_runtime: projectRuntimeSchema,
  environment: environmentBindingSchema,
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
      environment_visitors: z.literal(true),
    })
    .safeParse(value);
  if (
    !result.success ||
    !["environment-start", "status", "stop"].every((name) => result.data.capabilities.includes(name))
  ) {
    throw new ActionError("TNL_ACTION_CAPABILITIES_INVALID", {
      cause: result.success ? undefined : result.error,
    });
  }
}
