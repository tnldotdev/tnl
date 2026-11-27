import * as z from "zod/mini";
import { hostNameSchema } from "../peers/host-names.ts";
import { hostOrigin, hostSchema, runIDSchema } from "../peers/host.ts";
import { releaseSchema } from "../release.ts";
import { PULSE_SECONDS } from "./activity.ts";
import { hostingConfig, invitationSchema } from "../enrollment.ts";
import { inheritedCertificate } from "./certificate.ts";

export const hostCommand = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("start"),
    release: releaseSchema,
    files: z.map(z.string(), z.instanceof(ArrayBuffer)),
    config: hostingConfig,
    requestID: z.uuid(),
    inherited: z.optional(inheritedCertificate),
    bootstrap: z.boolean(),
    startupEndsAt: z.int(),
    name: hostNameSchema,
    firstHostToContact: z.optional(hostSchema.check(z.refine(({ origin }) => hostOrigin(origin)))),
    invitation: z.optional(invitationSchema),
    pageOrigin: z
      .url({ protocol: /^https?$/ })
      .check(z.refine((value) => new URL(value).origin === value)),
  }),
  z.strictObject({ type: z.literal("stop") }),
]);
export type HostStart = Extract<z.infer<typeof hostCommand>, { type: "start" }>;

export const hostUpdate = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("published"),
    host: hostSchema.check(z.refine(({ origin }) => hostOrigin(origin))),
  }),
  z
    .strictObject({
      type: z.literal("hosting"),
      origin: z.url(),
      since: z.int(),
      endsAt: z.int(),
      startedAt: z.int(),
      hosts: z.int().check(z.positive()),
      saturated: z.boolean(),
      runID: runIDSchema,
      tabs: z.int().check(z.nonnegative()),
      localTabs: z.int().check(z.nonnegative()),
    })
    .check(z.refine(({ localTabs, tabs }) => localTabs <= tabs)),
  z.strictObject({
    type: z.literal("activity"),
    second: z.int().check(z.nonnegative()),
    pulse: z.string().check(z.length(PULSE_SECONDS), z.regex(/^[_|]+$/)),
    requests: z.int().check(z.nonnegative()),
  }),
  z.strictObject({ type: z.literal("failed") }),
  z.strictObject({
    type: z.literal("stopped"),
    expired: z.boolean(),
    requests: z.int().check(z.nonnegative()),
  }),
]);
export type HostUpdate = z.infer<typeof hostUpdate>;
