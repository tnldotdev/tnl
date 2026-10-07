import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

const root = fileURLToPath(new URL("../", import.meta.url));
const input = fileURLToPath(new URL("../api/publisher/v1/openapi.yaml", import.meta.url));
const output = fileURLToPath(new URL("../internal/publisherapi/model.gen.ts", import.meta.url));

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("expected an OpenAPI object");
  return value as Record<string, unknown>;
}

function localReferences(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(localReferences);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, item]: [string, unknown]) => [
        key,
        key === "$ref" && typeof item === "string"
          ? item.replace(
              "../../control/v1/openapi.yaml#/components/schemas/",
              "#/components/schemas/",
            )
          : localReferences(item),
      ]),
    );
  return value;
}

// typed-openapi's external-reference bundler can name schemas after their first
// parameter use. give it local named components, using the control source itself.
const publisher = record(parse(readFileSync(input, "utf8")));
const control = record(parse(readFileSync(join(root, "api/control/v1/openapi.yaml"), "utf8")));
const components = record(publisher.components);
const schemas = { ...record(record(control.components).schemas), ...record(components.schemas) };
const bundled = localReferences({ ...publisher, components: { ...components, schemas } });
const temporary = mkdtempSync(join(tmpdir(), "tnl-publisher-contract-"));
try {
  const specification = join(temporary, "openapi.json");
  writeFileSync(specification, JSON.stringify(bundled));
  execFileSync(
    "pnpm",
    [
      "exec",
      "typed-openapi",
      specification,
      "--output",
      output,
      "--runtime",
      "zod",
      "--validation",
      "strict",
      "--tree-shake-schemas",
      "--schemas-only",
      "--no-runtime-types",
    ],
    { cwd: root, stdio: "inherit" },
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
const generated = readFileSync(output, "utf8");
const formatted = execFileSync("pnpm", ["exec", "oxfmt", "--stdin-filepath", output], {
  cwd: root,
  input: "// generated from api/publisher/v1/openapi.yaml; do not edit.\n" + generated,
  encoding: "utf8",
});
writeFileSync(output, formatted);
import { installToolFailureHandler } from "./errors.ts";
installToolFailureHandler(import.meta, "tool.input_invalid");
