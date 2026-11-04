import * as path from "node:path";
import * as z from "zod";
import { parseValue } from "../validation.js";
import {
  deadlineSchema,
  hostnameSchema,
  httpsOriginSchema,
  pathTextSchema,
  portSchema,
  transportIDSchema,
} from "../values.js";

const tlsSchema = z
  .strictObject({
    servername: hostnameSchema,
    rejectUnauthorized: z.literal(true),
    // omitted by default so native clients use webpki server roots.
    ca: z
      .string()
      .min(1)
      .max(32 * 1024)
      .exactOptional(),
  })
  .readonly();

const address = {
  schema: z.literal(1),
  host: z.literal("127.0.0.1"),
  port: portSchema,
  expires_at: deadlineSchema,
  transport_id: transportIDSchema.exactOptional(),
};
const http = { ...address, ssl: tlsSchema, url: httpsOriginSchema };

export const connectionSnapshotSchema = z
  .discriminatedUnion("protocol", [
    z.strictObject({ ...address, protocol: z.literal("tcp") }),
    z.strictObject({ ...address, protocol: z.literal("postgres"), ssl: tlsSchema }),
    z.strictObject({ ...address, protocol: z.literal("mysql"), ssl: tlsSchema }),
    z.strictObject({ ...http, protocol: z.literal("http") }),
    z.strictObject({
      ...http,
      protocol: z.literal("kubernetes"),
      kubeconfig: pathTextSchema.refine(path.isAbsolute),
      context: z.templateLiteral(["tnl:", z.string()]).refine((value) => value.length <= 1024),
    }),
  ])
  .refine((value) => !("url" in value) || URL.parse(value.url)?.hostname === value.ssl.servername)
  .transform(({ schema: _schema, expires_at, transport_id, ...value }) => ({
    ...value,
    expires: expires_at,
    ...(transport_id === undefined ? {} : { transportID: transport_id }),
  }))
  .readonly();

export type ConnectionSnapshot = z.output<typeof connectionSnapshotSchema>;
export type NativeTLSOptions = z.output<typeof tlsSchema>;

export function parseConnectionSnapshot(value: unknown): ConnectionSnapshot {
  return parseValue(connectionSnapshotSchema, value, "sdk.response_invalid");
}
