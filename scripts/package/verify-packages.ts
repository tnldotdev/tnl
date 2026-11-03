import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { assertExportTargets, packageManifestSchema } from "./npm-artifacts.ts";
import { verifyNpmConsumer } from "./npm-consumer.ts";
import { parseJSON } from "./validation.ts";
import { TnlError } from "../../packages/ts/src/errors.ts";
import * as z from "zod";

const run = promisify(execFile);
const root = path.resolve(import.meta.dirname, "../..");
const directory = await mkdtemp(path.join(tmpdir(), "tnl-packages-"));
const packageName = "@tnldotdev/tnl";
const workspace = parseJSON(
  await readFile(path.join(root, "package.json"), "utf8"),
  z.looseObject({ devDependencies: z.record(z.string(), z.string()) }),
  "workspace manifest",
);

try {
  await run("npm", ["pack", "--ignore-scripts", "--pack-destination", directory], {
    cwd: path.join(root, "packages", "ts"),
  });
  const filename = (await readdir(directory)).find((entry) => entry.endsWith(".tgz"));
  if (!filename) {
    throw new Error(`${packageName} did not produce a tarball`);
  }
  const tarball = path.join(directory, filename);
  const { stdout: manifestData } = await run("tar", ["-xOzf", tarball, "package/package.json"]);
  const manifest = parseJSON(manifestData, packageManifestSchema, "packed manifest");
  assert.equal(manifest.name, packageName);
  const { stdout: files } = await run("tar", ["-tzf", tarball]);
  assertExportTargets(
    manifest,
    new Set(
      files
        .trim()
        .split("\n")
        .map((file) => file.replace(/^package\//, "")),
    ),
  );
  assert(!JSON.stringify(manifest).includes("workspace:"));

  await writeFile(
    path.join(directory, "package.json"),
    JSON.stringify({
      private: true,
      dependencies: {
        [packageName]: `file:${tarball}`,
        "drizzle-kit": workspace.devDependencies["drizzle-kit"],
      },
    }),
  );
  await run("pnpm", ["install", "--ignore-scripts"], { cwd: directory });
  // exercise the installed SDK through Drizzle Kit's ordinary TypeScript config
  // loader. without a prepared owner, a synchronous spread must reach the SDK's
  // own diagnostic rather than fail at the CommonJS import boundary.
  await writeFile(
    path.join(directory, "drizzle.config.ts"),
    `import { tnl } from "@tnldotdev/tnl";
import { defineConfig } from "drizzle-kit";
export default defineConfig({
  dialect: "postgresql",
  schema: "./schema.ts",
  dbCredentials: { ...tnl.connect("database"), user: "app", password: "test", database: "app" },
});
`,
  );
  const configPath = path.join(directory, "drizzle.config.ts");
  let configOutput: string;
  try {
    const { stdout, stderr } = await run(
      process.execPath,
      [
        path.join(directory, "node_modules/drizzle-kit/bin.cjs"),
        "generate",
        "--config",
        configPath,
      ],
      { cwd: directory, env: { ...process.env, TNL_CONNECTION_HANDLE: undefined } },
    );
    configOutput = stdout + stderr;
  } catch (error) {
    if (
      error === null ||
      typeof error !== "object" ||
      !("stdout" in error) ||
      !("stderr" in error) ||
      typeof error.stdout !== "string" ||
      typeof error.stderr !== "string"
    )
      throw error;
    configOutput = error.stdout + error.stderr;
  }
  assert(configOutput.includes(new TnlError("sdk.connection_unprepared").message));
  await verifyNpmConsumer(directory);
} finally {
  await rm(directory, { force: true, recursive: true });
}
