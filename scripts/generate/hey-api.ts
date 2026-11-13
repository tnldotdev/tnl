import { createClient, type UserConfig } from "@hey-api/openapi-ts";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { root } from "./api-contracts.ts";

// the destinations also contain Go code, so only copy the generated validator file.
export async function generateValidators(
  document: Record<string, unknown>,
  output: string,
  source: string,
  parser?: UserConfig["parser"],
): Promise<void> {
  const temporary = await mkdtemp(join(tmpdir(), "tnl-hey-api-"));
  try {
    await createClient({
      input: document,
      output: {
        path: temporary,
        header: [`// generated from ${source} with @hey-api/openapi-ts; do not edit.`],
      },
      ...(parser ? { parser } : {}),
      plugins: [
        {
          name: "zod",
          compatibilityVersion: 4,
          definitions: { name: "{{name}}Schema", case: "camelCase" },
          requests: false,
          responses: false,
          exportFromIndex: false,
          $resolvers: {
            number(ctx) {
              // these contracts carry JSON numbers, not coerced bigint values.
              if (ctx.schema.format === "int64" || ctx.schema.format === "uint64") {
                ctx.schema = { ...ctx.schema, format: undefined };
              }
            },
            object(ctx) {
              // reuse the plugin's shape builder for closed inbound objects.
              const additional = ctx.schema.additionalProperties;
              if (additional && additional.type === "never") {
                return ctx.$(ctx.plugin.imports.z).attr("strictObject").call(ctx.nodes.shape(ctx));
              }
              return undefined;
            },
          },
        },
      ],
    });
    const formatted = execFileSync("pnpm", ["exec", "oxfmt", "--stdin-filepath", output], {
      cwd: root,
      input: await readFile(join(temporary, "zod.gen.ts"), "utf8"),
      encoding: "utf8",
    });
    await writeFile(output, formatted);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}
