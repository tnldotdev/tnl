import * as z from "zod/mini";
import { hostOrigin, httpsOriginSchema, releaseIDSchema } from "./peers/host.ts";

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
    inviter: httpsOriginSchema.check(z.refine((origin) => hostOrigin(origin))),
  }),
]);
export const enrollmentKey = z.string().check(z.minLength(1), z.maxLength(256));
export const hostingConfig = z.strictObject({
  controlURL: httpsOriginSchema,
  siteOrigin: httpsOriginSchema,
  startHost: z.hostname(),
});
