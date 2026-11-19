import * as z from "zod";
import { TnlError } from "../errors.js";

export type PublisherEnrollment = string | ((signal: AbortSignal) => string | Promise<string>);

export const enrollmentSourceSchema = z.union([
  z.string().min(1).max(256),
  z.custom<Exclude<PublisherEnrollment, string>>((value) => typeof value === "function"),
]);

export function bindEnrollment(
  source: PublisherEnrollment,
  lifetime: AbortSignal,
): () => Promise<string> {
  return async () => {
    const signal = AbortSignal.any([lifetime, AbortSignal.timeout(15_000)]);
    signal.throwIfAborted();
    if (typeof source === "string") return source;
    let listener!: () => void;
    try {
      const aborted = new Promise<never>((_, reject) => {
        listener = () => reject(signal.reason);
        signal.addEventListener("abort", listener, { once: true });
      });
      const value = await Promise.race([
        aborted,
        Promise.resolve().then(() => {
          signal.throwIfAborted();
          return source(signal);
        }),
      ]);
      if (typeof value !== "string" || value.length === 0 || value.length > 256)
        throw new TnlError("sdk.configuration_invalid");
      return value;
    } finally {
      signal.removeEventListener("abort", listener);
    }
  };
}
