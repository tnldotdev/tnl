// generated from contracts/integrations/telemetry/v1/openapi.yaml with @hey-api/openapi-ts; do not edit.

import * as z from "zod";

export const Client = z.strictObject({
  version: z.string().min(1).max(64),
  os: z.enum(["darwin", "linux", "windows", "other"]),
  arch: z.enum(["amd64", "arm64", "other"]),
  ci: z.boolean(),
});

export const PublicationReady = z.strictObject({
  server_kind: z.enum(["hosted", "self_hosted"]),
  publish_mode: z.enum(["app", "demo"]),
  framework: z.enum(["vite", "next", "other"]).optional(),
});

export const IntegrationOutcome = z.strictObject({
  kind: z.enum(["oauth", "webhook"]),
  outcome: z.enum(["ready", "redirected", "reached_receiver"]),
  delivery: z.enum(["fanout", "selected"]).optional(),
});

export const Operation = z.enum(["relay_connect", "direct_connect", "fallback", "recovery"]);

export const Path = z.enum(["quic", "tls_tcp", "direct_udp"]);

export const Outcome = z.enum(["succeeded", "failed", "canceled"]);

export const CommandOutcome = z.strictObject({
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
  outcome: Outcome,
  failure_stage: z
    .enum(["setup", "command", "authentication", "local_service", "public_url"])
    .optional(),
  diagnostic_code: z
    .string()
    .regex(/^TNL_[A-Z_]{1,64}$/)
    .optional(),
});

export const Duration = z.enum(["lt_1s", "lt_10s", "lt_1m", "longer"]);

export const Measurement = z.strictObject({
  operation: Operation,
  path: Path,
  outcome: Outcome,
  duration: Duration.optional(),
  count: z.int().gte(1).lte(1000000000),
});

export const TransportReport = z.strictObject({
  role: z.enum(["publisher", "connector"]),
  measurements: z.array(Measurement).min(1).max(144),
});

export const EventId = z.string().regex(/^tev_[A-Za-z0-9]{22}$/);

export const CommandEvent = z.strictObject({
  event_id: EventId,
  event_version: z.literal(1),
  name: z.enum(["command.outcome"]),
  payload: CommandOutcome,
});

export const ReadyEvent = z.strictObject({
  event_id: EventId,
  event_version: z.literal(1),
  name: z.enum(["tunnel.ready"]),
  payload: PublicationReady,
});

export const DemoEvent = z.strictObject({
  event_id: EventId,
  event_version: z.literal(1),
  name: z.enum(["demo.first_ping"]),
  payload: z.strictObject({}),
});

export const IntegrationEvent = z.strictObject({
  event_id: EventId,
  event_version: z.literal(1),
  name: z.enum(["integration.outcome"]),
  payload: IntegrationOutcome,
});

export const TransportEvent = z.strictObject({
  event_id: EventId,
  event_version: z.literal(1),
  name: z.enum(["transport.report"]),
  payload: TransportReport,
});

export const Event_ = z.discriminatedUnion("name", [
  CommandEvent.extend({ name: z.literal("command.outcome") }),
  ReadyEvent.extend({ name: z.literal("tunnel.ready") }),
  DemoEvent.extend({ name: z.literal("demo.first_ping") }),
  IntegrationEvent.extend({ name: z.literal("integration.outcome") }),
  TransportEvent.extend({ name: z.literal("transport.report") }),
]);

export const CollectedEvent = z.strictObject({
  client: Client,
  event: Event_,
});

export const Batch = z.strictObject({
  schema_version: z.literal(1),
  installation_id: z.string().regex(/^inst_[A-Za-z0-9]{22}$/),
  events: z.array(CollectedEvent).min(1).max(25),
});
