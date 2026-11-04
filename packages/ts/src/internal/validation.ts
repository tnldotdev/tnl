import * as z from "zod";
import { privateTnlError, type TnlErrorCode } from "../errors.js";

// schema issues can contain capabilities or assertions; keep them out of public errors.
export function parseValue<T>(schema: z.ZodType<T>, value: unknown, code: TnlErrorCode): T {
  const result = schema.safeParse(value);
  if (!result.success) throw privateTnlError(code, result.error);
  return result.data;
}
