import { rm, writeFile } from "node:fs/promises";
import { build } from "esbuild";
import { writeDependencyLicenses } from "../../scripts/package/node-licenses.ts";

await rm("dist", { recursive: true, force: true });
for (const entry of ["main", "post"]) {
  await build({
    entryPoints: [`src/${entry}.ts`],
    outfile: `dist/${entry}/index.mjs`,
    bundle: true,
    minify: true,
    platform: "node",
    format: "esm",
    target: "node24",
    supported: { "template-literal": false },
    banner: {
      js: 'import {createRequire} from "node:module"; const require = createRequire(import.meta.url);',
    },
    legalComments: "inline",
  });
  await writeDependencyLicenses(process.cwd(), `dist/${entry}/licenses.txt`);
}
await writeFile("dist/package.json", '{"type":"module"}\n');
