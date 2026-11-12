import * as z from "zod";
import { sourceSchemas, type IdentitySourceChallenge, type IdentitySourceReply, type IdentitySourceSelection } from "./models.gen.js";

const object = z.record(z.string(), z.unknown());
const strings = z.array(z.string());

// implements the JSON Schema vocabulary used by the generated authority
// components, including their one-of and conditional source/operation bounds.
function matches(value: unknown, raw: unknown): boolean {
  if (typeof raw === "boolean") return raw;
  const schema = object.parse(raw);
  if (typeof schema.$ref === "string") {
    const name = schema.$ref.slice(schema.$ref.lastIndexOf("/") + 1);
    if (!Object.hasOwn(sourceSchemas, name)) return false;
    return matches(value, object.parse(sourceSchemas)[name]);
  }
  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) return false;
  if (schema.const !== undefined && value !== schema.const) return false;
  if (Array.isArray(schema.oneOf) && schema.oneOf.filter((child: unknown) => matches(value, child)).length !== 1) return false;
  if (schema.not !== undefined && matches(value, schema.not)) return false;
  if (schema.if !== undefined) {
    const condition = matches(value, schema.if);
    if (condition && schema.then !== undefined && !matches(value, schema.then)) return false;
    if (!condition && schema.else !== undefined && !matches(value, schema.else)) return false;
  }
  if (schema.type === "string") {
    if (typeof value !== "string") return false;
    const length = [...value].length;
    if (typeof schema.minLength === "number" && length < schema.minLength || typeof schema.maxLength === "number" && length > schema.maxLength) return false;
    if (typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(value)) return false;
    if (schema.format === "date-time" && (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(value) || !Number.isFinite(Date.parse(value)))) return false;
  }
  if (schema.type === "integer" && (typeof value !== "number" || !Number.isSafeInteger(value))) return false;
  if (schema.type === "boolean" && typeof value !== "boolean") return false;
  if (schema.type === "object" || schema.properties !== undefined || schema.required !== undefined) {
    const parsed = object.safeParse(value);
    if (!parsed.success) return false;
    const item = parsed.data;
    const keys = Object.keys(item);
    if (typeof schema.minProperties === "number" && keys.length < schema.minProperties || typeof schema.maxProperties === "number" && keys.length > schema.maxProperties) return false;
    for (const name of strings.parse(schema.required ?? [])) if (!Object.hasOwn(item, name)) return false;
    const properties = object.parse(schema.properties ?? {});
    for (const [name, child] of Object.entries(item)) {
      if (Object.hasOwn(properties, name)) { if (!matches(child, properties[name])) return false; }
      else if (schema.additionalProperties !== undefined && !matches(child, schema.additionalProperties)) return false;
    }
  }
  return true;
}

export const identitySourceSelectionSchema = z.custom<IdentitySourceSelection>((value) => matches(value, sourceSchemas.IdentitySourceSelection));
export const identitySourceChallengeSchema = z.custom<IdentitySourceChallenge>((value) => matches(value, sourceSchemas.IdentitySourceChallenge));
export const identitySourceReplySchema = z.custom<IdentitySourceReply>((value) => matches(value, sourceSchemas.IdentitySourceReply));
