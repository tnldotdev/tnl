import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { compile } from "json-schema-to-typescript";

const root = path.resolve(import.meta.dirname, "..");
const schema = JSON.parse(await readFile(path.join(root, "schema", "v1.json"), "utf8"));
const keys = JSON.parse(
  await readFile(path.join(root, "internal", "tnlts", "keys.gen.json"), "utf8"),
);
const client = structuredClone(schema.$defs.TNL);
client.$schema = schema.$schema;
client.$defs = {
  Dev: structuredClone(schema.$defs.Dev),
  Publish: structuredClone(schema.$defs.Publish),
};
renameProperties(client, keys);

const generated = await compile(client, "TNL", {
  bannerComment: "",
  format: false,
  style: { singleQuote: false },
});
const declarations = `${generated.trim()}

/** Details about the Git worktree or project directory containing tnl.config.ts. */
export interface TnlWorktree {
  readonly isGit: boolean;
  readonly label: string;
  readonly name: string;
  readonly root: string;
}

/** Values available to a tnl.config.ts configuration factory. */
export interface TnlConfigContext {
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
  readonly worktree: TnlWorktree;
}

export type TnlConfigFactory = (
  context: TnlConfigContext,
) => TNL | Promise<TNL>;

export type TnlConfigInput = TNL | TnlConfigFactory;

/** Provides type checking for an implicit-version-1 tnl.config.ts configuration. */
export declare function defineConfig<const Config extends TnlConfigInput>(config: Config): Config;
`;
await writeFile(path.join(root, "packages", "tnl", "lib", "config.d.ts"), declarations);

function renameProperties(value, mappings) {
  if (Array.isArray(value)) {
    for (const item of value) {
      renameProperties(item, mappings);
    }
    return;
  }
  if (value === null || typeof value !== "object") {
    return;
  }
  if (value.properties !== undefined) {
    for (const [staticName, typeScriptName] of Object.entries(mappings)) {
      if (Object.hasOwn(value.properties, staticName)) {
        value.properties[typeScriptName] = value.properties[staticName];
        delete value.properties[staticName];
      }
    }
  }
  if (Array.isArray(value.required)) {
    value.required = value.required.map((name) => mappings[name] ?? name);
  }
  for (const child of Object.values(value)) {
    renameProperties(child, mappings);
  }
}
