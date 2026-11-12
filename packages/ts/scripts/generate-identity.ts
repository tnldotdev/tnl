import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import * as z from "zod";
import { repositoryGraph } from "../../../scripts/generate/api-contracts.ts";

// both SDKs consume the same defining authority schemas. this generator copies
// no publication- or visitor-private challenge model into either language.
const root = fileURLToPath(new URL("../../../", import.meta.url));
const record = z.record(z.string(), z.unknown());
const bundle = record.parse((await repositoryGraph()).browserBundle("authorityv1", ["controlv1"]));
const all = record.parse(record.parse(bundle.components).schemas);
const schemas: Record<string, unknown> = {};
function include(name: string): void {
  if (Object.hasOwn(schemas, name)) return;
  const schema = all[name];
  if (schema === undefined) throw new Error(`unknown identity source schema: ${name}`);
  schemas[name] = schema;
  function visit(value: unknown): void {
    if (Array.isArray(value)) { for (const child of value) visit(child); return; }
    if (value === null || typeof value !== "object") return;
    const node = record.parse(value);
    if (typeof node.$ref === "string") {
      const prefix = "#/components/schemas/";
      if (!node.$ref.startsWith(prefix)) throw new Error(`nonlocal identity schema: ${node.$ref}`);
      include(node.$ref.slice(prefix.length));
    }
    for (const child of Object.values(node)) visit(child);
  }
  visit(schema);
}
for (const name of ["IdentitySourceSelection", "IdentitySourceChallenge", "IdentitySourceReply"]) include(name);

function type(value: unknown, python: boolean): string {
  const schema = record.parse(value);
  if (typeof schema.$ref === "string") return schema.$ref.slice(schema.$ref.lastIndexOf("/") + 1);
  if (Array.isArray(schema.enum)) {
    const values = schema.enum.map((item: unknown) => JSON.stringify(item)).join(python ? ", " : " | ");
    return python ? `Literal[${values}]` : values;
  }
  switch (schema.type) {
    case "string": return python ? "str" : "string";
    case "integer": case "number": return python ? (schema.type === "integer" ? "int" : "float") : "number";
    case "boolean": return python ? "bool" : "boolean";
    case "object": {
      if (schema.properties !== undefined) throw new Error("identity object must have a defining named schema");
      const child = type(schema.additionalProperties, python);
      return python ? `dict[str, ${child}]` : `Readonly<Record<string, ${child}>>`;
    }
    default: throw new Error(`unsupported identity source schema type: ${JSON.stringify(schema)}`);
  }
}

const ts: string[] = ["// generated from the authority identity-source schemas; do not edit.", ""];
const py: string[] = [
  '"""generated from the authority identity-source schemas; do not edit."""',
  "", "from __future__ import annotations", "", "from typing import Literal, NotRequired, TypedDict", "",
];
for (const name of Object.keys(schemas).sort()) {
  const schema = record.parse(schemas[name]);
  if (schema.properties === undefined) {
    ts.push(`export type ${name} = ${type(schema, false)};`, "");
    py.push(`type ${name} = ${type(schema, true)}`, "");
    continue;
  }
  const properties = record.parse(schema.properties);
  const required = z.array(z.string()).parse(schema.required ?? []);
  ts.push(`export interface ${name} {`);
  py.push(`class ${name}(TypedDict):`);
  for (const [property, value] of Object.entries(properties)) {
    const optional = !required.includes(property);
    ts.push(`  readonly ${JSON.stringify(property)}${optional ? "?" : ""}: ${type(value, false)};`);
    const pyType = type(value, true);
    py.push(`    ${property}: ${optional ? `NotRequired[${pyType}]` : pyType}`);
  }
  ts.push("}", "");
  py.push("", "");
}
const schemaJSON = JSON.stringify(schemas, null, 2) + "\n";
await Promise.all([
  writeFile(root + "packages/ts/src/internal/identity/models.gen.ts", ts.join("\n") + `\nexport const sourceSchemas = ${schemaJSON.trim()} as const;\n`),
  writeFile(root + "packages/py/src/tnl/_identity_models.py", py.join("\n")),
  writeFile(root + "packages/py/src/tnl/_identity_schemas.json", schemaJSON),
]);
