import * as z from "zod";
import { TnlError } from "../../errors.js";
import { parseValue } from "../validation.js";
import { protocolSchema, serviceNameSchema } from "../values.js";

export type ServiceFacts = Readonly<
  Record<string, Readonly<{ protocol: z.output<typeof protocolSchema> }>>
>;

const serviceFactsSchema = z
  .record(serviceNameSchema, z.strictObject({ protocol: protocolSchema }))
  .refine((services) => Object.keys(services).length <= 128);

// retain the literal input type only after validating an independent data copy.
// neither callers nor discovery can mutate the facts captured by this client.
export function captureServiceFacts<const Services extends ServiceFacts>(
  input: Services,
): Readonly<Services> {
  let owned: Services;
  try {
    owned = structuredClone(input);
  } catch {
    throw new TnlError("sdk.configuration_invalid");
  }
  parseValue(serviceFactsSchema, owned, "sdk.configuration_invalid");
  for (const service of Object.values(owned)) Object.freeze(service);
  return Object.freeze(owned);
}
