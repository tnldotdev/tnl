import * as z from "zod";
import { digestSchema, pathTextSchema, serviceNameSchema } from "../../values.js";

export interface WorkloadRequest {
  name?: string;
  callback?: boolean;
  token_file?: string;
  runtime: { workload?: string; vercel?: string; fly_app_name?: string; github_actions?: string };
}

export interface SelectionOptions {
  requested_at?: string;
  assertion?: string;
  sdk_workload?: WorkloadRequest;
  sdk_workload_policy?: string;
  sdk_environment?: {
    github_actions: string;
    github_request_url: string;
    github_request_token: string;
    vercel_token_file: string;
    vercel_token: string;
  };
}

export const workloadSelectionSchema = z.strictObject({
  schema: z.literal(1),
  name: serviceNameSchema,
  directory: pathTextSchema,
  manifest: pathTextSchema,
  policy: digestSchema,
  source: z.enum(["callback", "vercel", "native"]),
});
export type WorkloadSelection = z.output<typeof workloadSelectionSchema>;
