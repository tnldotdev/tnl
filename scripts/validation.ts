import * as z from "zod";
import { ToolError } from "./errors.ts";

export function parseJSON<Output>(
  serialized: string,
  schema: z.ZodType<Output>,
  description: string,
): Output {
  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch (error) {
    throw new ToolError("tool.input_invalid", { cause: error });
  }
  return parseValue(value, schema, description);
}

export function parseValue<Output>(
  value: unknown,
  schema: z.ZodType<Output>,
  _description: string,
): Output {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new ToolError("tool.input_invalid", { cause: result.error });
  }
  return result.data;
}
