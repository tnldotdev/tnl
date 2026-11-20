import * as z from "zod";
import { networkProof } from "./network.ts";
import { httpsOriginSchema, releaseIDSchema } from "./peers/gossip.ts";

export const CONFIG_PATH = "/__keepalive/config";
export const CREDENTIALS_PATH = "/__keepalive/credentials";
export const ADMISSION_PATH = "/__keepalive/admission";

export const invitationSchema = z.uuid();
export const credentialRequest = z.strictObject({
  releaseID: releaseIDSchema,
  requestID: z.uuid(),
  bootstrap: z.boolean().optional(),
});
export const enrollmentKey = z.string().min(1).max(256);
export const hostingConfig = z.strictObject({
  controlURL: httpsOriginSchema,
  siteOrigin: httpsOriginSchema,
  startHost: z.hostname(),
  networkProof,
  hostTarget: z.int().min(3).max(1_000).default(3),
});
