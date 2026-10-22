import assert from "node:assert/strict";
import { readFile, readdir, realpath, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import * as z from "zod";

const root = path.resolve(import.meta.dirname, "../packages/ts");
const schema = z.looseObject({
  name: z.string(),
  version: z.string(),
  license: z.string(),
  dependencies: z.record(z.string(), z.string()).optional(),
});
const seen = new Set<string>();
const entries = new Map<string, string>();

async function visit(file: string, include: boolean): Promise<void> {
  file = await realpath(file);
  if (seen.has(file)) return;
  seen.add(file);
  const manifest = schema.parse(JSON.parse(await readFile(file, "utf8")));
  const directory = path.dirname(file);
  if (include) {
    const names = (await readdir(directory))
      .filter((name) => /^(licen[cs]e|notice)(\.(md|txt))?$/i.test(name))
      .sort();
    assert(
      names.some((name) => /^licen[cs]e/i.test(name)),
      `missing license text: ${manifest.name}`,
    );
    const texts = await Promise.all(
      names.map(async (name) => `${name}\n\n${await readFile(path.join(directory, name), "utf8")}`),
    );
    entries.set(
      `${manifest.name}@${manifest.version}`,
      `package: ${manifest.name}\nversion: ${manifest.version}\nlicense: ${manifest.license}\n\n${texts.join("\n\n")}`,
    );
  }
  const require = createRequire(file);
  for (const name of Object.keys(manifest.dependencies ?? {}).sort()) {
    let resolved: string;
    try {
      resolved = require.resolve(`${name}/package.json`);
    } catch {
      // some packages export code but deliberately hide their manifest.
      let parent = path.dirname(await realpath(require.resolve(name)));
      for (;;) {
        try {
          const candidate = path.join(parent, "package.json");
          const metadata = schema.parse(JSON.parse(await readFile(candidate, "utf8")));
          if (metadata.name === name) {
            resolved = candidate;
            break;
          }
        } catch {
          // walk through dist directories to the actual installed package root.
        }
        const next = path.dirname(parent);
        assert(next !== parent, `cannot resolve license owner: ${name}`);
        parent = next;
      }
    }
    await visit(resolved, true);
  }
}

await visit(path.join(root, "package.json"), false);
const text = [...entries]
  .sort(([a], [b]) => a.localeCompare(b, "en"))
  .map(([, value]) => value)
  .join("\n\n--------------------------------------------------------------------------------\n\n");
await writeFile(
  path.join(root, "dist/third-party-licenses.txt"),
  `tnl node runtime dependency licenses\n\n${text}\n`,
);
