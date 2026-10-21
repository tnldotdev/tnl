import path from "node:path";
import * as z from "zod";
import { ActionError } from "./errors.js";

const text = z.string().min(1).max(4096);
const absolute = text.refine((value) => path.isAbsolute(value));
export const serviceKey = z
  .string()
  .regex(/^[a-z](?:[a-z0-9-]*[a-z0-9])?$/)
  .max(32);
export const contextSchema = z.strictObject({
  schema: z.literal(1),
  directory: absolute,
  config_digest: z.string().regex(/^[a-f0-9]{64}$/),
  server: text,
  audience: text,
  team_id: text,
  project_key: text,
  source_id: text,
  worktree_key: text,
  project_label: text,
  ci: serviceKey,
  services: z
    .array(serviceKey)
    .min(1)
    .max(32)
    .refine((values) => new Set(values).size === values.length),
});
const origin = z.strictObject({ hostname: text, url: text });
const publicRuntime = z.strictObject({
  namespace: text,
  dev: z.boolean(),
  worktree: z
    .strictObject({
      label: z.strictObject({
        project: text,
        checkout: text.optional(),
        id: text,
        fullLabel: text,
      }),
    })
    .optional(),
  services: z.record(
    serviceKey,
    z.strictObject({
      protocol: z.enum(["http", "postgres", "mysql", "tcp", "kubernetes"]),
      namespace: text,
      hostname: text,
      port: z.number().int().min(1).max(65535),
      public: z.boolean(),
      url: text.optional(),
      paths: z
        .record(z.string(), z.strictObject({ service: text, url: text, stripPrefix: z.boolean() }))
        .optional(),
    }),
  ),
  oauth: origin.optional(),
  webhooks: z
    .record(z.string(), origin.extend({ service: text, path: text, methods: z.array(text) }))
    .optional(),
  aliases: z.record(z.string(), origin.extend({ service: text })).optional(),
});
export const readySchema = z.object({
  schema: z.literal(1),
  state: z.literal("ready"),
  pid: z.number().int().positive(),
  expires_at: text,
  executable: absolute,
  private_handle: absolute,
  public_runtime: publicRuntime,
  kubeconfig: absolute.optional(),
});
export const cleanupSchema = z.strictObject({
  session: absolute,
  binary: absolute,
  handle: absolute.optional(),
  start_attempted: z.literal(true).optional(),
});
export type Cleanup = z.infer<typeof cleanupSchema>;

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
      team_names: z.literal("applied_binding"),
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
