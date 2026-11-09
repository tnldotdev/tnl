import * as z from "zod";
import { TnlError } from "../../errors.js";
import { parseValue } from "../validation.js";
import { hostnameSchema, httpsOriginSchema, timestampSchema } from "../values.js";

const textSchema = z.string().max(4096);
const runNumberSchema = z.int().positive();
const publicationSchema = z.strictObject({
  tunnel_id: textSchema,
  command: z.enum(["publish", "dev"]),
  state: z.enum(["starting", "provisioning", "ready", "draining", "stopped", "failed", "stale"]),
  process_id: runNumberSchema,
  server: textSchema,
  project: textSchema,
  service: textSchema.optional(),
  service_protocol: textSchema.exactOptional(),
  public_url_id: textSchema.exactOptional(),
  publish_run_number: runNumberSchema.exactOptional(),
  public_port: runNumberSchema.exactOptional(),
  hostname: textSchema.exactOptional(),
  public_url: textSchema.exactOptional(),
  target: textSchema.exactOptional(),
  framework: textSchema.exactOptional(),
  started_at: textSchema,
  updated_at: textSchema,
  heartbeat_at: textSchema,
  lease_expires_at: textSchema,
  failure: textSchema.exactOptional(),
});
const observationSchema = z.strictObject({
  registration_id: z.string(),
  run_number: runNumberSchema,
  checked_at: timestampSchema,
  status: z.int().min(100).max(599).optional(),
  ready: z.boolean(),
  reason: z.string().optional(),
  readiness: z.strictObject({ path: z.string() }),
});
const serviceStatusSchema = z.strictObject({
  project: textSchema.optional(),
  service: z.string(),
  service_protocol: z.literal("http").optional(),
  directory: textSchema,
  tunnel_id: textSchema.optional(),
  public_url: httpsOriginSchema
    .refine((url) => {
      const hostname = URL.parse(url)?.hostname;
      return hostnameSchema.safeParse(hostname).success;
    })
    .optional(),
  registration_id: textSchema.optional(),
  target: textSchema.optional(),
  framework: textSchema.optional(),
  registered: z.boolean(),
  routable: z.boolean(),
  ready: z.boolean(),
  run_number: runNumberSchema.optional(),
  provisioning_stage: textSchema.optional(),
  readiness: z.strictObject({ path: z.string().startsWith("/").max(4096) }),
  observation: observationSchema.optional(),
  failure: textSchema.optional(),
});
const statusSchema = z.strictObject({
  schema_version: z.literal(1),
  project: textSchema,
  cursor: z.string().max(128),
  observed_at: timestampSchema,
  services: z.array(serviceStatusSchema).max(1),
  publications: z.array(publicationSchema).max(64).optional(),
});

function publicationStatus(item: z.output<typeof serviceStatusSchema>) {
  return {
    registered: item.registered,
    routable: item.routable,
    ready: item.ready,
    ...(item.tunnel_id === undefined ? {} : { tunnelID: item.tunnel_id }),
    ...(item.public_url === undefined ? {} : { publicURL: item.public_url }),
    ...(item.run_number === undefined ? {} : { publishRunNumber: item.run_number }),
    ...(item.observation === undefined ? {} : { checkedAt: item.observation.checked_at }),
    ...(item.failure === undefined ? {} : { failure: item.failure }),
  };
}
export type PublicationStatus = Readonly<ReturnType<typeof publicationStatus> & { cursor: string }>;

export function parseStatus(
  value: unknown,
  service: string,
  registrationID: string,
  target: string,
): PublicationStatus | undefined {
  const snapshot = parseValue(statusSchema, value, "sdk.response_invalid");
  const item = snapshot.services[0];
  if (item === undefined) return undefined;
  if (
    snapshot.publications?.some(
      (publication) =>
        publication.service !== service &&
        (item.tunnel_id === undefined || publication.tunnel_id !== item.tunnel_id),
    )
  )
    throw new TnlError("sdk.response_invalid");
  if (
    item.service !== service ||
    (item.ready &&
      (item.observation === undefined ||
        item.observation.registration_id !== registrationID ||
        item.observation.run_number !== item.run_number ||
        item.observation.readiness.path !== item.readiness.path ||
        !item.observation.ready))
  )
    throw new TnlError("sdk.response_invalid");
  if (item.registration_id !== registrationID || item.target !== target) return undefined;
  if (item.routable && (!item.registered || item.run_number === undefined))
    throw new TnlError("sdk.response_invalid");
  return { ...publicationStatus(item), cursor: snapshot.cursor };
}

export function statusCursor(value: unknown): { cursor: string; at: string } {
  const snapshot = parseValue(statusSchema, value, "sdk.response_invalid");
  return { cursor: snapshot.cursor, at: snapshot.observed_at };
}

const eventSchema = z.strictObject({
  cursor: z.string().min(1).max(128),
  type: z.string().min(1).max(128),
  at: timestampSchema,
  service: serviceStatusSchema.optional(),
  snapshot: statusSchema.optional(),
  publication: publicationSchema.optional(),
});

export type PublicationEvent = Readonly<z.output<typeof eventSchema>>;

export function parseEvents(
  value: unknown,
  service: string,
  tunnelID?: string,
): readonly PublicationEvent[] {
  const events = parseValue(z.array(eventSchema).max(4096), value, "sdk.response_invalid");
  for (const event of events) {
    if (
      (event.service !== undefined && event.service.service !== service) ||
      event.snapshot?.services.some((item) => item.service !== service)
    )
      throw new TnlError("sdk.response_invalid");
    const ownIDs = [
      tunnelID,
      event.service?.tunnel_id,
      ...(event.snapshot?.services.map((item) => item.tunnel_id) ?? []),
    ].filter((id) => id !== undefined);
    const publications = [
      ...(event.snapshot?.publications ?? []),
      ...(event.publication === undefined ? [] : [event.publication]),
    ];
    if (
      publications.some(
        (publication) => publication.service !== service && !ownIDs.includes(publication.tunnel_id),
      )
    )
      throw new TnlError("sdk.response_invalid");
  }
  return events;
}
