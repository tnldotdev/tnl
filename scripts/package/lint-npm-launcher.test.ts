import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { lintNpmLauncher } from "./lint-npm-launcher.ts";

const exports = {
  ".": "./dist/index.js",
  "./another-subpath": {
    types: "./dist/another.d.ts",
    node: { import: "./dist/another.js", require: "./dist/another.cjs" },
    browser: null,
  },
};
const targets = {
  "another.d.ts": "export declare const value: number;\n",
  "another.js": "export const value = 1;\n",
  "another.cjs": "exports.value = 1;\n",
};
let directory: string;

beforeEach(async () => {
  directory = await mkdtemp(path.join(tmpdir(), "tnl-publint-"));
  await mkdir(path.join(directory, "dist"));
  await writeFile(path.join(directory, "dist/index.js"), "export {};\n");
  await Promise.all(
    Object.entries(targets).map(([file, content]) =>
      writeFile(path.join(directory, "dist", file), content),
    ),
  );
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

async function lintPacked(exportMap: unknown, missing?: string): Promise<void> {
  const files = [
    "dist/index.js",
    ...Object.keys(targets)
      .filter((file) => file !== missing)
      .map((file) => `dist/${file}`),
  ];
  await writeFile(
    path.join(directory, "package.json"),
    JSON.stringify({
      name: "tnl-export-fixture",
      version: "1.0.0",
      type: "module",
      license: "BSD-3-Clause",
      exports: exportMap,
      files,
      engines: { node: ">=22.18" },
    }),
  );
  execFileSync("npm", ["pack", "--ignore-scripts", "--silent"], { cwd: directory });
  await lintNpmLauncher(path.join(directory, "tnl-export-fixture-1.0.0.tgz"), new Set(files));
}

it("accepts a packed conditional subpath without a separate export inventory", async () => {
  await expect(lintPacked(exports)).resolves.toBeUndefined();
});

it.each(Object.keys(targets))(
  "rejects the conditional target %s left out of the tarball",
  async (file) => {
    await expect(lintPacked(exports, file)).rejects.toThrow(
      new RegExp(`publint failed.*\\n.*\\./dist/${file.replaceAll(".", "\\.")}`),
    );
  },
);

it("rejects a target outside the packed package", async () => {
  await expect(lintPacked({ ".": "./../outside.js" })).rejects.toThrow(
    /publint failed.*\n.*\.\.\/outside\.js/,
  );
});

it("rejects an export path that publint normalizes but Node rejects", async () => {
  await expect(lintPacked({ ...exports, ".": "./dist/./index.js" })).rejects.toThrow(
    "invalid SDK export target: ./dist/./index.js",
  );
});

it("requires an asset exported only through a custom condition", async () => {
  await expect(
    lintPacked({ ...exports, "./schema": { custom: "./dist/schema.json" } }),
  ).rejects.toThrow("missing SDK export asset: ./dist/schema.json");
});

it("requires the SDK root export", async () => {
  await expect(lintPacked({ "./another-subpath": exports["./another-subpath"] })).rejects.toThrow(
    "the SDK must define a root export",
  );
});
