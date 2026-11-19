import * as z from "zod";
import { hostnameSchema, httpsOriginSchema, serviceIDSchema } from "./values.js";

export const publicationRunSchema = z.strictObject({
  serviceID: serviceIDSchema,
  serviceRunID: z.string().regex(/^srun_[A-Za-z0-9]{22}$/),
  // preserve the exact counter without JavaScript number rounding.
  runNumber: z
    .string()
    .max(19)
    .regex(/^[1-9][0-9]*$/)
    .refine((value) => value.length < 19 || value <= "9223372036854775807"),
});

export type PublicationRun = Readonly<z.output<typeof publicationRunSchema>>;

export const publisherURLSchema = httpsOriginSchema.refine((url) => {
  const hostname = URL.parse(url)?.hostname;
  return (
    typeof hostname === "string" &&
    /^p-[a-z2-7]{26}\./.test(hostname) &&
    hostnameSchema.safeParse(hostname).success &&
    url === `https://${hostname}`
  );
});
