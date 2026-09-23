import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  chmod,
  copyFile,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import * as z from "zod";
import { nativeTargets } from "../packages/tnl/src/internal/native-targets.ts";
import { packageManifestSchema, type PackedPackage } from "./npm-artifacts.ts";
import { parseJSON } from "./validation.ts";

const releaseMetadataSchema = z.object({ version: z.string(), commit: z.string() });
const artifactSchema = z.object({
  type: z.string(),
  path: z.string(),
  extra: z.optional(z.object({ ID: z.optional(z.string()) })),
  goos: z.optional(z.string()),
  goarch: z.optional(z.string()),
});
const packResultSchema = z.array(
  z.object({
    name: z.string(),
    version: z.string(),
    filename: z.string(),
    integrity: z.string(),
    files: z.array(z.object({ path: z.string() })),
  }),
);

type PackOptions = {
  readonly packageName: string;
  readonly requiredFiles: readonly string[];
} & ({ readonly kind: "native"; readonly binarySha256: string } | { readonly kind: "launcher" });

const execFileAsync = promisify(execFile);
const root = path.resolve(import.meta.dirname, "..");
const outputArgument = process.argv[2];
const expectedVersion = process.argv[3];
assert(outputArgument, "usage: node scripts/pack-tnl.ts OUTPUT_DIRECTORY [EXPECTED_VERSION]");

const outputDirectory = path.resolve(outputArgument);
const metadata = await readJson(path.join(root, "dist", "metadata.json"), releaseMetadataSchema);
const artifacts = await readJson(
  path.join(root, "dist", "artifacts.json"),
  z.array(artifactSchema),
);
assertValidVersion(metadata.version);
if (expectedVersion !== undefined) {
  assert.equal(
    metadata.version,
    expectedVersion,
    "GoReleaser version does not match the release tag",
  );
}
assert.match(metadata.commit, /^[0-9a-f]{40}$/, "GoReleaser metadata has an invalid commit");

const targets = nativeTargets.map(({ platform, architecture, packageName }) => ({
  architecture,
  packageName,
  operatingSystem: platform,
  goArchitecture: architecture === "x64" ? "amd64" : architecture,
  sourceDirectory: `tnl/native/${platform}-${architecture}`,
}));

await rm(outputDirectory, { force: true, recursive: true });
await mkdir(outputDirectory, { recursive: true });
const stagingRoot = await mkdtemp(path.join(tmpdir(), "tnl-npm-packages-"));
const packedPackages: PackedPackage[] = [];

try {
  for (const target of targets) {
    const binaryArtifact = exactlyOne(
      artifacts.filter(
        (artifact) =>
          artifact.type === "Binary" &&
          artifact.extra?.ID === "tnl" &&
          artifact.goos === target.operatingSystem &&
          artifact.goarch === target.goArchitecture,
      ),
      `${target.packageName} binary artifact`,
    );
    const archiveArtifact = exactlyOne(
      artifacts.filter(
        (artifact) =>
          artifact.type === "Archive" &&
          artifact.extra?.ID === "release" &&
          artifact.goos === target.operatingSystem &&
          artifact.goarch === target.goArchitecture,
      ),
      `${target.packageName} archive artifact`,
    );
    const binaryPath = path.resolve(root, binaryArtifact.path);
    const archivePath = path.resolve(root, archiveArtifact.path);
    await access(binaryPath, constants.R_OK | constants.X_OK);
    await access(archivePath, constants.R_OK);

    const binary = await readFile(binaryPath);
    const { stdout: archivedBinary } = await execFileAsync("tar", ["-xOzf", archivePath, "tnl"], {
      encoding: "buffer",
      maxBuffer: 64 * 1024 * 1024,
    });
    assert.deepEqual(
      archivedBinary,
      binary,
      `${target.packageName} binary differs from the release archive`,
    );

    const stage = path.join(stagingRoot, target.sourceDirectory);
    await copyTemplate(target.sourceDirectory, stage, ["package.json", "readme.md"]);
    await copyLegalFiles(stage);
    await mkdir(path.join(stage, "bin"));
    await copyFile(binaryPath, path.join(stage, "bin", "tnl"));
    await chmod(path.join(stage, "bin", "tnl"), 0o755);

    const manifestPath = path.join(stage, "package.json");
    const manifest = await readJson(manifestPath, packageManifestSchema);
    assert.equal(manifest.name, target.packageName);
    assert.deepEqual(manifest.os, [target.operatingSystem]);
    assert.deepEqual(manifest.cpu, [target.architecture]);
    manifest.version = metadata.version;
    const binarySha256 = sha256(binary);
    manifest.tnl = {
      binarySha256,
      commit: metadata.commit,
    };
    await writeJson(manifestPath, manifest);

    packedPackages.push(
      await packAndVerify(stage, {
        binarySha256,
        kind: "native",
        packageName: target.packageName,
        requiredFiles: [
          "LICENSE",
          "NOTICE",
          "readme.md",
          "THIRD_PARTY_LICENSES.txt",
          "bin/tnl",
          "package.json",
        ],
      }),
    );

    if (process.platform === target.operatingSystem && process.arch === target.architecture) {
      const { stdout } = await execFileAsync(path.join(stage, "bin", "tnl"), ["version"]);
      assert.equal(stdout.trim(), `tnl ${metadata.version} (${metadata.commit})`);
    }
  }

  const launcherStage = path.join(stagingRoot, "tnl");
  await copyTemplate("tnl", launcherStage, ["package.json", "readme.md", "dist"]);
  await copyLegalFiles(launcherStage);
  const launcherManifestPath = path.join(launcherStage, "package.json");
  const launcherManifest = await readJson(launcherManifestPath, packageManifestSchema);
  assert.equal(launcherManifest.name, "@tnldotdev/tnl");
  launcherManifest.version = metadata.version;
  launcherManifest.optionalDependencies = Object.fromEntries(
    targets.map((target) => [target.packageName, metadata.version]),
  );
  launcherManifest.tnl = { commit: metadata.commit };
  await writeJson(launcherManifestPath, launcherManifest);
  await chmod(path.join(launcherStage, "dist", "bin", "tnl.js"), 0o755);
  packedPackages.push(
    await packAndVerify(launcherStage, {
      kind: "launcher",
      packageName: "@tnldotdev/tnl",
      requiredFiles: [
        "LICENSE",
        "NOTICE",
        "readme.md",
        "THIRD_PARTY_LICENSES.txt",
        "dist/bin/tnl.d.ts",
        "dist/bin/tnl.js",
        "dist/config.d.ts",
        "dist/config.js",
        "dist/config.gen.d.ts",
        "dist/config.gen.js",
        "dist/internal/dev.d.ts",
        "dist/internal/dev.js",
        "dist/internal/launcher.d.ts",
        "dist/internal/launcher.js",
        "dist/internal/native-targets.d.ts",
        "dist/internal/native-targets.js",
        "dist/internal/runtime.d.ts",
        "dist/internal/runtime.js",
        "dist/index.d.ts",
        "dist/index.js",
        "dist/next.d.ts",
        "dist/next.js",
        "dist/vite.d.ts",
        "dist/vite.js",
        "package.json",
      ],
    }),
  );

  await writeJson(path.join(outputDirectory, "tnl-npm-packages.json"), {
    commit: metadata.commit,
    packages: packedPackages,
    version: metadata.version,
  });
} finally {
  await rm(stagingRoot, { force: true, recursive: true });
}

async function copyTemplate(
  sourceDirectory: string,
  destination: string,
  entries: readonly string[],
): Promise<void> {
  const source = path.join(root, "packages", sourceDirectory);
  await mkdir(destination, { recursive: true });
  for (const entry of entries) {
    await cp(path.join(source, entry), path.join(destination, entry), { recursive: true });
  }
}

async function copyLegalFiles(destination: string): Promise<void> {
  for (const file of ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"]) {
    await copyFile(path.join(root, file), path.join(destination, file));
  }
}

async function packAndVerify(stage: string, options: PackOptions): Promise<PackedPackage> {
  const { stdout } = await execFileAsync(
    "npm",
    ["pack", "--ignore-scripts", "--json", "--pack-destination", outputDirectory],
    { cwd: stage, maxBuffer: 10 * 1024 * 1024 },
  );
  const packResult = exactlyOne(
    parseJSON(stdout, packResultSchema, "npm pack result"),
    `${options.packageName} npm pack result`,
  );
  assert.equal(packResult.name, options.packageName);
  assert.equal(packResult.version, metadata.version);
  const packedFiles = new Set(packResult.files.map((file) => file.path));
  for (const requiredFile of options.requiredFiles) {
    assert(packedFiles.has(requiredFile), `${options.packageName} is missing ${requiredFile}`);
  }
  assert.deepEqual(
    [...packedFiles].sort(),
    [...options.requiredFiles].sort(),
    `${options.packageName} contains unexpected files`,
  );

  const tarball = path.join(outputDirectory, packResult.filename);
  const extractionDirectory = path.join(
    stagingRoot,
    `verify-${options.packageName.replaceAll("/", "-")}`,
  );
  await mkdir(extractionDirectory);
  await execFileAsync("tar", ["-xzf", tarball, "-C", extractionDirectory]);
  const packedManifest = await readJson(
    path.join(extractionDirectory, "package", "package.json"),
    packageManifestSchema,
  );
  assert.equal(packedManifest.version, metadata.version);
  assert(!JSON.stringify(packedManifest).includes("workspace:"));
  for (const lifecycle of ["preinstall", "install", "postinstall"]) {
    assert.equal(
      packedManifest.scripts?.[lifecycle],
      undefined,
      `${options.packageName} must not run ${lifecycle} in consumer projects`,
    );
  }

  if (options.kind === "native") {
    const packedBinary = path.join(extractionDirectory, "package", "bin", "tnl");
    const packedBinaryStat = await stat(packedBinary);
    assert.notEqual(
      packedBinaryStat.mode & 0o111,
      0,
      `${options.packageName} binary is not executable`,
    );
    assert.equal(sha256(await readFile(packedBinary)), options.binarySha256);
  } else {
    assert(packedManifest.exports, "launcher must define public exports");
    assert.deepEqual(Object.keys(packedManifest.exports).sort(), [
      ".",
      "./config",
      "./next",
      "./vite",
    ]);
    assert.deepEqual(
      packedManifest.optionalDependencies,
      Object.fromEntries(targets.map((target) => [target.packageName, metadata.version])),
    );
    const launcherStat = await stat(
      path.join(extractionDirectory, "package", "dist", "bin", "tnl.js"),
    );
    assert.notEqual(launcherStat.mode & 0o111, 0, "@tnldotdev/tnl launcher is not executable");
  }

  return {
    integrity: packResult.integrity,
    kind: options.kind,
    name: options.packageName,
    tarball: packResult.filename,
  };
}

function exactlyOne<T>(values: readonly T[], description: string): T {
  assert.equal(values.length, 1, `expected exactly one ${description}`);
  const [value] = values;
  assert(value !== undefined, `missing ${description}`);
  return value;
}

function assertValidVersion(version: string): void {
  assert.equal(typeof version, "string", "GoReleaser version must be a string");
  const match = version.match(
    /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/,
  );
  assert(match, `GoReleaser version is not npm-compatible SemVer: ${version}`);
  for (const identifier of match[4]?.split(".") ?? []) {
    assert(
      !/^[0-9]+$/.test(identifier) || identifier === "0" || !identifier.startsWith("0"),
      `numeric prerelease identifier has a leading zero: ${identifier}`,
    );
  }
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

async function readJson<Output>(file: string, schema: z.ZodType<Output>): Promise<Output> {
  return parseJSON(await readFile(file, "utf8"), schema, file);
}

async function writeJson(file: string, value: unknown): Promise<void> {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}
