import * as z from "zod";
import type { TnlApplicationCredential } from "../credential.js";
import { TnlError } from "../errors.js";
import { parseApplicationCredential } from "./credential.js";
import { parseValue } from "./validation.js";

export const credentialSchema = z
  .string()
  .min(1)
  .max(2048)
  .refine((value) => {
    const parts = value.split(".");
    if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) return false;
    if (parts[0] === "vsh1" || parts[0] === "vsg1") {
      const prefix = parts[0] === "vsh1" ? "shr_" : "shg_";
      if (!new RegExp(`^${prefix}[A-Za-z0-9]{22}$`).test(parts[1] ?? "") || parts[2]?.length !== 43)
        return false;
      try {
        const secret = parts[2].replaceAll("-", "+").replaceAll("_", "/");
        return atob(secret).length === 32 && btoa(atob(secret)).replaceAll("=", "") === secret;
      } catch {
        return false;
      }
    }
    // signed visitor permissions are opaque here; only the publisher verifies them.
    return parts[0]?.startsWith("ey") === true;
  });

// a string carries either an opaque visitor token or the complete application
// document. invalid explicit input never selects ambient authentication.
export function parseCredentialInput(value: unknown): string | TnlApplicationCredential {
  if (typeof value !== "string") return parseApplicationCredential(value);
  if (value.trimStart().startsWith("{")) {
    if (value.length > 128 * 1024) throw new TnlError("sdk.credential_invalid");
    let document: unknown;
    try {
      document = JSON.parse(value);
    } catch {
      // syntax errors can include private input, so do not retain this cause.
      throw new TnlError("sdk.credential_invalid");
    }
    return parseApplicationCredential(document);
  }
  return parseValue(credentialSchema, value, "sdk.configuration_invalid");
}
