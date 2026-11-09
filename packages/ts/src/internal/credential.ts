import * as z from "zod";
import { parseValue } from "./validation.js";
import { hostnameSchema, httpsOriginSchema } from "./values.js";

const id = (prefix: string) => z.string().regex(new RegExp(`^${prefix}[A-Za-z0-9]{22}$`));
const grantFields = { id: id("pgrant_"), expires_at: z.iso.datetime({ offset: true }).optional() };
const grantSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    ...grantFields,
    operation: z.enum(["visit", "publish"]),
    kind: z.literal("saved_public_url"),
    public_url_id: id("url_"),
  }),
  z.strictObject({
    ...grantFields,
    operation: z.enum(["visit", "publish"]),
    kind: z.literal("service"),
    service_id: id("svc_"),
  }),
  z.strictObject({
    ...grantFields,
    operation: z.literal("allocate"),
    kind: z.literal("namespace"),
    domain_id: id("dom_"),
    namespace: hostnameSchema,
  }),
]);

export function decodeBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function encodeBase64(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

// publisher and visitor runtimes share this exact portable-document boundary.
export const applicationCredentialSchema = z
  .strictObject({
    version: z.literal(1),
    control_url: httpsOriginSchema,
    client_id: id("pub_"),
    key_id: id("pkey_"),
    team_id: z.string().min(1).max(256),
    private_key: z
      .string()
      .length(86)
      .regex(/^[A-Za-z0-9_-]+$/)
      .refine((value) => {
        try {
          const raw = decodeBase64(value);
          return raw.length === 64 && encodeBase64(raw) === value;
        } catch {
          return false;
        }
      }),
    grants: z.array(grantSchema).min(1).max(64),
  })
  .refine((value) => {
    const ids = new Set<string>();
    const bindings = new Set<string>();
    for (const grant of value.grants) {
      const resource =
        grant.kind === "saved_public_url"
          ? grant.public_url_id
          : grant.kind === "service"
            ? grant.service_id
            : grant.domain_id;
      const binding = `${grant.operation}:${resource}`;
      if (ids.has(grant.id) || bindings.has(binding)) return false;
      ids.add(grant.id);
      bindings.add(binding);
    }
    return true;
  });

export function parseApplicationCredential(value: unknown) {
  return parseValue(applicationCredentialSchema, value, "sdk.credential_invalid");
}
