import { TnlError } from "../../errors.js";

// match the native cli's pinned kong boolean environment grammar, without trimming.
export function readTelemetryDisabled(value: string | undefined): boolean {
  if (value === undefined) return false;
  switch (value.toLowerCase()) {
    case "true":
    case "yes":
    case "1":
      return true;
    case "false":
    case "no":
    case "0":
      return false;
    default:
      throw new TnlError("sdk.configuration_invalid");
  }
}
