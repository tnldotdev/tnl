import * as z from "zod";

export function parseJSON<Output>(
  serialized: string,
  schema: z.ZodType<Output>,
  description: string,
): Output {
  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch (error) {
    throw new Error(`${description} is not valid JSON`, { cause: error });
  }
  return parseValue(value, schema, description);
}

export function parseValue<Output>(
  value: unknown,
  schema: z.ZodType<Output>,
  description: string,
): Output {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new Error(`${description} has an invalid shape: ${z.prettifyError(result.error)}`);
  }
  return result.data;
}
