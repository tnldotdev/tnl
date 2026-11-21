import * as z from "zod";
import { hostOrigin, httpsOriginSchema, releaseIDSchema } from "./peers/gossip.ts";

export const CONFIG_PATH = "/__keepalive/config";
export const CREDENTIALS_PATH = "/__keepalive/credentials";
export const INVITATION_PATH = "/__keepalive/invitation";
export const READY_HEADER = "X-Keepalive-Ready";

export const invitationSchema = z.uuid();
export const credentialRequest = z.discriminatedUnion("bootstrap", [
  z.strictObject({ bootstrap: z.literal(true), releaseID: releaseIDSchema, requestID: z.uuid() }),
  z.strictObject({
    bootstrap: z.literal(false),
    releaseID: releaseIDSchema,
    requestID: invitationSchema,
    inviter: httpsOriginSchema.refine((origin) => hostOrigin(origin)),
  }),
]);
export const enrollmentKey = z.string().min(1).max(256);
export const hostingConfig = z.strictObject({
  controlURL: httpsOriginSchema,
  siteOrigin: httpsOriginSchema,
  startHost: z.hostname(),
});
