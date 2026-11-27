import * as z from "zod/mini";
import { hostSchema, hostOrigin, releaseIDSchema } from "./host.ts";
import { audienceSchema } from "./report.ts";

const visibleHost = hostSchema.check(z.refine(({ origin }) => hostOrigin(origin)));
export const MAX_FALLBACK_HOSTS = 3;
export const presenceSummary = z.strictObject({
  host: visibleHost,
  startedAt: z.int().check(z.nonnegative()),
  tabs: z.int().check(z.nonnegative()),
  hosts: z.int().check(z.positive()),
  saturated: z.boolean(),
  sampling: z.optional(z.boolean()),
  fallback: z.array(visibleHost).check(z.maxLength(MAX_FALLBACK_HOSTS)),
});
export const audienceSnapshot = z.extend(audienceSchema, {
  releaseID: releaseIDSchema,
  host: visibleHost,
  startedAt: z.int().check(z.nonnegative()),
});
