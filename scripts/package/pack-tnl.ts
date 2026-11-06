import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, copyFile, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as z from "zod";
import { nativeTargets } from "../../packages/ts/src/internal/native/native-targets.ts";
import { assertExportTargets, packageManifestSchema, type PackedPackage } from "./npm-artifacts.ts";
import { legalFiles, releaseArtifacts, root } from "./release-artifacts.ts";
import { parseJSON } from "./validation.ts";

assert(process.argv[2], "usage: pack-tnl.ts OUTPUT_DIRECTORY [EXPECTED_VERSION]");
const output = path.resolve(process.argv[2]);
const release = await releaseArtifacts(process.argv[3]);
const staging = await mkdtemp(path.join(tmpdir(), "tnl-npm-"));
const packages: PackedPackage[] = [];
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
try {
  for (const target of nativeTargets) {
    const stage = path.join(staging, `${target.platform}-${target.architecture}`);
    await mkdir(path.join(stage, "bin"), { recursive: true });
    const binary = release.binary(
      target.platform,
      target.architecture === "x64" ? "amd64" : target.architecture,
    );
    await copyFile(binary, path.join(stage, "bin/tnl"));
    await chmod(path.join(stage, "bin/tnl"), 0o755);
    await writeFile(
      path.join(stage, "readme.md"),
      `# ${target.packageName}\n\nInstall @tnldotdev/tnl; it selects this binary automatically.\n`,
    );
    await pack(stage, "native", {
      name: target.packageName,
      description: `The ${target.platform} ${target.architecture} binary for tnl.`,
      os: [target.platform],
      cpu: [target.architecture],
      files: ["bin", ...legalFiles],
      preferUnplugged: true,
      tnl: {
        commit: release.commit,
        binarySha256: createHash("sha256")
          .update(await readFile(binary))
          .digest("hex"),
      },
    });
  }
  const stage = path.join(staging, "launcher");
  await mkdir(stage);
  for (const file of ["dist", "readme.md"]) {
    await cp(path.join(root, "packages/ts", file), path.join(stage, file), { recursive: true });
  }
  await chmod(path.join(stage, "dist/bin/tnl.js"), 0o755);
  const manifest = parseJSON(
    await readFile(path.join(root, "packages/ts/package.json"), "utf8"),
    packageManifestSchema,
    "npm manifest",
  );
  await pack(stage, "launcher", {
    ...manifest,
    optionalDependencies: Object.fromEntries(
      nativeTargets.map((t) => [t.packageName, release.version]),
    ),
    tnl: { commit: release.commit },
  });
  await writeFile(
    path.join(output, "tnl-npm-packages.json"),
    JSON.stringify({ version: release.version, commit: release.commit, packages }, null, 2) + "\n",
  );
} finally {
  await rm(staging, { recursive: true, force: true });
}

async function pack(stage: string, kind: PackedPackage["kind"], manifest: Record<string, unknown>) {
  for (const file of legalFiles) await copyFile(path.join(root, file), path.join(stage, file));
  const value = {
    license: "BSD-3-Clause",
    publishConfig: { access: "public" },
    ...manifest,
    version: release.version,
  };
  await writeFile(path.join(stage, "package.json"), JSON.stringify(value, null, 2) + "\n");
  const results = parseJSON(
    execFileSync("npm", ["pack", "--ignore-scripts", "--json", "--pack-destination", output], {
      cwd: stage,
      encoding: "utf8",
    }),
    z.array(
      z.object({
        name: z.string(),
        filename: z.string(),
        integrity: z.string(),
        files: z.array(z.object({ path: z.string() })),
      }),
    ),
    "npm pack",
  );
  const result = results[0];
  assert(results.length === 1 && result, "expected one npm tarball");
  const files = new Set(result.files.map((f) => f.path));
  for (const file of legalFiles) assert(files.has(file), `${result.name} is missing ${file}`);
  if (kind === "launcher") assertExportTargets(packageManifestSchema.parse(value), files);
  packages.push({ name: result.name, kind, tarball: result.filename, integrity: result.integrity });
}
