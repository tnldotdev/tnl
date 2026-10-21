import { execFileSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { build } from "esbuild";

const require = createRequire(import.meta.url);
// ncc's ts-loader uses the removed TypeScript 6 compiler API. transpile with
// the repository's esbuild first; strict type checking remains a separate check.
await build({
  entryPoints: ["src/main.ts", "src/post.ts"],
  bundle: true,
  packages: "external",
  platform: "node",
  format: "esm",
  target: "node24",
  outdir: ".build",
  outExtension: { ".js": ".mjs" },
});
for (const entry of ["main", "post"]) {
  execFileSync(
    process.execPath,
    [
      require.resolve("@vercel/ncc/dist/ncc/cli.js"),
      "build",
      `.build/${entry}.mjs`,
      "--out",
      `dist/${entry}`,
      "--minify",
      "--license",
      "licenses.txt",
    ],
    { stdio: "inherit" },
  );
}
await mkdir("dist", { recursive: true });
await writeFile("dist/package.json", '{"type":"module"}\n');
