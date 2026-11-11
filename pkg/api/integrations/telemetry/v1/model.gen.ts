// generated from contracts/integrations/telemetry/v1; do not edit.

import { z } from "zod";

// <Schemas>
export type Client = z.infer<typeof Client>;
export const Client = z.strictObject({
  version: z.string().min(1).max(64),
  os: z.enum(["darwin", "linux", "windows", "other"]),
  arch: z.enum(["amd64", "arm64", "other"]),
  ci: z.boolean(),
});

export type EventID = z.infer<typeof EventID>;
export const EventID = z.string().regex(new RegExp("^tev_[A-Za-z0-9]{22}$"));

export type Outcome = z.infer<typeof Outcome>;
export const Outcome = z.enum(["succeeded", "failed", "canceled"]);

export type CommandOutcome = z.infer<typeof CommandOutcome>;
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
  diagnostic_code: z.string().regex(new RegExp("^TNL_[A-Z_]{1,64}$")).optional(),
});

export type CommandEvent = z.infer<typeof CommandEvent>;
export const CommandEvent = z.strictObject({
  event_id: EventID,
  event_version: z.literal(1),
  name: z.literal("command.outcome"),
  payload: CommandOutcome,
});

export type PublicationReady = z.infer<typeof PublicationReady>;
export const PublicationReady = z.strictObject({
  server_kind: z.enum(["hosted", "self_hosted"]),
  publish_mode: z.enum(["app", "demo"]),
  framework: z.enum(["vite", "next", "other"]).optional(),
});

export type ReadyEvent = z.infer<typeof ReadyEvent>;
export const ReadyEvent = z.strictObject({
  event_id: EventID,
  event_version: z.literal(1),
  name: z.literal("tunnel.ready"),
  payload: PublicationReady,
});

export type DemoEvent = z.infer<typeof DemoEvent>;
export const DemoEvent = z.strictObject({
  event_id: EventID,
  event_version: z.literal(1),
  name: z.literal("demo.first_ping"),
  payload: z.strictObject({}),
});

export type IntegrationOutcome = z.infer<typeof IntegrationOutcome>;
export const IntegrationOutcome = z.strictObject({
  kind: z.enum(["oauth", "webhook"]),
  outcome: z.enum(["ready", "redirected", "reached_receiver"]),
  delivery: z.enum(["fanout", "selected"]).optional(),
});

export type IntegrationEvent = z.infer<typeof IntegrationEvent>;
export const IntegrationEvent = z.strictObject({
  event_id: EventID,
  event_version: z.literal(1),
  name: z.literal("integration.outcome"),
  payload: IntegrationOutcome,
});

export type Operation = z.infer<typeof Operation>;
export const Operation = z.enum(["relay_connect", "direct_connect", "fallback", "recovery"]);

export type Path = z.infer<typeof Path>;
export const Path = z.enum(["quic", "tls_tcp", "direct_udp"]);

export type Duration = z.infer<typeof Duration>;
export const Duration = z.enum(["lt_1s", "lt_10s", "lt_1m", "longer"]);

export type Measurement = z.infer<typeof Measurement>;
export const Measurement = z.strictObject({
  operation: Operation,
  path: Path,
  outcome: Outcome,
  duration: Duration.optional(),
  count: z.number().int().min(1).max(1000000000),
});

export type TransportReport = z.infer<typeof TransportReport>;
export const TransportReport = z.strictObject({
  role: z.enum(["publisher", "connector"]),
  measurements: z.array(Measurement).min(1).max(144),
});

export type TransportEvent = z.infer<typeof TransportEvent>;
export const TransportEvent = z.strictObject({
  event_id: EventID,
  event_version: z.literal(1),
  name: z.literal("transport.report"),
  payload: TransportReport,
});

export type Event = z.infer<typeof Event>;
export const Event = z.discriminatedUnion("name", [
  CommandEvent.extend({ name: z.literal("command.outcome") }),
  ReadyEvent.extend({ name: z.literal("tunnel.ready") }),
  DemoEvent.extend({ name: z.literal("demo.first_ping") }),
  IntegrationEvent.extend({ name: z.literal("integration.outcome") }),
  TransportEvent.extend({ name: z.literal("transport.report") }),
]);

export type Batch = z.infer<typeof Batch>;
export const Batch = z.strictObject({
  schema_version: z.literal(1),
  installation_id: z.string().regex(new RegExp("^inst_[A-Za-z0-9]{22}$")),
  client: Client,
  events: z.array(Event).min(1).max(25),
});

// </Schemas>
