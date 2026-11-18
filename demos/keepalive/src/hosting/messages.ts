import * as z from "zod";
import { releaseSchema } from "../release.ts";
import { hostingConfig } from "./config.ts";

export const hostCommand = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("start"),
    release: releaseSchema,
    config: hostingConfig,
    first: z.unknown(),
    pageOrigin: z.url({ protocol: /^https?$/ }).refine((value) => new URL(value).origin === value),
  }),
  z.strictObject({ type: z.literal("stop") }),
  z.strictObject({ type: z.literal("replace") }),
]);

export const hostUpdate = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("hosting"),
    origin: z.url(),
    since: z.int(),
    startedAt: z.int(),
    hosts: z.int().positive(),
    filesServed: z.int().nonnegative(),
  }),
  z.strictObject({ type: z.literal("failed") }),
  z.strictObject({ type: z.literal("stopped") }),
]);
export type HostUpdate = z.infer<typeof hostUpdate>;
