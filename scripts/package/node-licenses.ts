import assert from "node:assert/strict";
import { readFile, readdir, realpath, writeFile } from "node:fs/promises";
import { findPackageJSON } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as z from "zod";

const schema = z.looseObject({
  name: z.string(),
  version: z.string().optional(),
  license: z.string().optional(),
  dependencies: z.record(z.string(), z.string()).optional(),
});
export async function writeDependencyLicenses(root: string, output: string): Promise<void> {
  const seen = new Set<string>();
  const entries = new Map<string, string>();

  async function visit(file: string, include: boolean): Promise<void> {
    file = await realpath(file);
    if (seen.has(file)) return;
    seen.add(file);
    const manifest = schema.parse(JSON.parse(await readFile(file, "utf8")));
    const directory = path.dirname(file);
    if (include) {
      assert(manifest.version && manifest.license, `missing dependency metadata: ${manifest.name}`);
      const names = (await readdir(directory))
        .filter((name) => /^(licen[cs]e|notice)(\.(md|txt))?$/i.test(name))
        .sort();
      assert(
        names.some((name) => /^licen[cs]e/i.test(name)),
        `missing license text: ${manifest.name}`,
      );
      const texts = await Promise.all(
        names.map(
          async (name) => `${name}\n\n${await readFile(path.join(directory, name), "utf8")}`,
        ),
      );
      entries.set(
        `${manifest.name}@${manifest.version}`,
        `package: ${manifest.name}\nversion: ${manifest.version}\nlicense: ${manifest.license}\n\n${texts.join("\n\n")}`,
      );
    }
    for (const name of Object.keys(manifest.dependencies ?? {}).sort()) {
      const resolved = findPackageJSON(name, pathToFileURL(file));
      assert(resolved, `cannot resolve license owner: ${name}`);
      await visit(resolved, true);
    }
  }

  await visit(path.join(root, "package.json"), false);
  const text = [...entries]
    .sort(([a], [b]) => a.localeCompare(b, "en"))
    .map(([, value]) => value)
    .join(
      "\n\n--------------------------------------------------------------------------------\n\n",
    );
  await writeFile(output, `tnl node runtime dependency licenses\n\n${text.trimEnd()}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  const root = path.resolve(import.meta.dirname, "../../packages/ts");
  await writeDependencyLicenses(root, path.join(root, "dist/third-party-licenses.txt"));
}
