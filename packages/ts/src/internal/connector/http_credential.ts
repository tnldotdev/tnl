import * as z from "zod";

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
