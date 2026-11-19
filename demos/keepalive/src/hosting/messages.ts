import * as z from "zod";
import { hostNameSchema } from "../peers/host-names.ts";
import { hostDetailsSchema, hostOrigin, hostSchema, runIDSchema } from "../peers/gossip.ts";
import { releaseSchema } from "../release.ts";
import { PULSE_SECONDS } from "./activity.ts";
import { hostingConfig, invitationSchema } from "../enrollment.ts";

export const hostCommand = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("start"),
    release: releaseSchema,
    files: z.map(z.string(), z.instanceof(ArrayBuffer)),
    config: hostingConfig,
    bootstrap: z.boolean(),
    startupEndsAt: z.int(),
    name: hostNameSchema,
    firstHostToContact: hostSchema.refine(({ origin }) => hostOrigin(origin)).optional(),
    invitation: invitationSchema.optional(),
    pageOrigin: z.url({ protocol: /^https?$/ }).refine((value) => new URL(value).origin === value),
  }),
  z.strictObject({ type: z.literal("stop") }),
]);
export type HostStart = Extract<z.infer<typeof hostCommand>, { type: "start" }>;

export const hostUpdate = z.discriminatedUnion("type", [
  z
    .strictObject({
      type: z.literal("hosting"),
      origin: z.url(),
      since: z.int(),
      endsAt: z.int(),
      startedAt: z.int(),
      hosts: z.int().positive(),
      runID: runIDSchema,
      tabs: z.int().nonnegative(),
      localTabs: z.int().nonnegative(),
      roster: z
        .array(
          hostDetailsSchema.extend({
            runID: runIDSchema,
            left: z.boolean(),
            startingUntil: z.int().nonnegative(),
          }),
        )
        .max(257),
    })
    .refine(({ localTabs, tabs }) => localTabs <= tabs),
  z.strictObject({
    type: z.literal("activity"),
    second: z.int().nonnegative(),
    pulse: z
      .string()
      .length(PULSE_SECONDS)
      .regex(/^[_|]+$/),
    requests: z.int().nonnegative(),
  }),
  z.strictObject({ type: z.literal("failed") }),
  z.strictObject({
    type: z.literal("stopped"),
    expired: z.boolean(),
    requests: z.int().nonnegative(),
  }),
]);
export type HostUpdate = z.infer<typeof hostUpdate>;
