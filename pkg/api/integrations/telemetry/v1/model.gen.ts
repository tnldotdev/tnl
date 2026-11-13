// generated from contracts/integrations/telemetry/v1/openapi.yaml with @hey-api/openapi-ts; do not edit.

import * as z from "zod";

export const clientSchema = z.strictObject({
  version: z.string().min(1).max(64),
  os: z.enum(["darwin", "linux", "windows", "other"]),
  arch: z.enum(["amd64", "arm64", "other"]),
  ci: z.boolean(),
});

export const publicationReadySchema = z.strictObject({
  server_kind: z.enum(["hosted", "self_hosted"]),
  publish_mode: z.enum(["app", "demo"]),
  framework: z.enum(["vite", "next", "other"]).optional(),
});

export const integrationOutcomeSchema = z.strictObject({
  kind: z.enum(["oauth", "webhook"]),
  outcome: z.enum(["ready", "redirected", "reached_receiver"]),
  delivery: z.enum(["fanout", "selected"]).optional(),
});

export const operationSchema = z.enum(["relay_connect", "direct_connect", "fallback", "recovery"]);

export const pathSchema = z.enum(["quic", "tls_tcp", "direct_udp"]);

export const outcomeSchema = z.enum(["succeeded", "failed", "canceled"]);

export const commandOutcomeSchema = z.strictObject({
  command: z.enum([
    "init",
    "login",
    "logout",
    "publish",
    "status",
    "watch",
    "wait",
    "connect",
    "inspect",
    "alias",
    "webhook",
    "config",
    "team",
    "domain",
    "url",
    "share",
    "feedback",
    "publisher",
    "apply",
    "admin",
    "other",
  ]),
  action: z
    .enum([
      "list",
      "show",
      "inspect",
      "create",
      "update",
      "delete",
      "get",
      "set",
      "add",
      "remove",
      "use",
      "release",
      "revoke",
      "current",
      "members",
      "join",
      "leave",
      "accept",
      "path",
      "check",
      "generate",
      "set-role",
      "reply",
      "resolve",
      "reopen",
      "watch",
      "status",
      "drain",
      "allow",
      "block",
      "start",
      "stop",
      "install",
      "uninstall",
      "other",
    ])
    .optional(),
  outcome: outcomeSchema,
  failure_stage: z
    .enum(["setup", "command", "authentication", "local_service", "public_url"])
    .optional(),
  diagnostic_code: z
    .string()
    .regex(/^TNL_[A-Z_]{1,64}$/)
    .optional(),
});

export const durationSchema = z.enum(["lt_1s", "lt_10s", "lt_1m", "longer"]);

export const measurementSchema = z.strictObject({
  operation: operationSchema,
  path: pathSchema,
  outcome: outcomeSchema,
  duration: durationSchema.optional(),
  count: z.int().gte(1).lte(1000000000),
});

export const transportReportSchema = z.strictObject({
  role: z.enum(["publisher", "connector"]),
  measurements: z.array(measurementSchema).min(1).max(144),
});

export const eventIdSchema = z.string().regex(/^tev_[A-Za-z0-9]{22}$/);

export const commandEventSchema = z.strictObject({
  event_id: eventIdSchema,
  event_version: z.literal(1),
  name: z.enum(["command.outcome"]),
  payload: commandOutcomeSchema,
});

export const readyEventSchema = z.strictObject({
  event_id: eventIdSchema,
  event_version: z.literal(1),
  name: z.enum(["tunnel.ready"]),
  payload: publicationReadySchema,
});

export const demoEventSchema = z.strictObject({
  event_id: eventIdSchema,
  event_version: z.literal(1),
  name: z.enum(["demo.first_ping"]),
  payload: z.strictObject({}),
});

export const integrationEventSchema = z.strictObject({
  event_id: eventIdSchema,
  event_version: z.literal(1),
  name: z.enum(["integration.outcome"]),
  payload: integrationOutcomeSchema,
});

export const transportEventSchema = z.strictObject({
  event_id: eventIdSchema,
  event_version: z.literal(1),
  name: z.enum(["transport.report"]),
  payload: transportReportSchema,
});

export const eventSchema = z.discriminatedUnion("name", [
  commandEventSchema.extend({ name: z.literal("command.outcome") }),
  readyEventSchema.extend({ name: z.literal("tunnel.ready") }),
  demoEventSchema.extend({ name: z.literal("demo.first_ping") }),
  integrationEventSchema.extend({ name: z.literal("integration.outcome") }),
  transportEventSchema.extend({ name: z.literal("transport.report") }),
]);

export const collectedEventSchema = z.strictObject({
  client: clientSchema,
  event: eventSchema,
});

export const batchSchema = z.strictObject({
  schema_version: z.literal(1),
  installation_id: z.string().regex(/^inst_[A-Za-z0-9]{22}$/),
  events: z.array(collectedEventSchema).min(1).max(25),
});
