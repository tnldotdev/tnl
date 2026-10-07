import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import * as z from "zod";
import { nativeTargets } from "../packages/tnl/src/internal/native-targets.ts";
import {
  npmPackageMetadataSchema,
  packageManifestSchema,
  type PackedPackage,
} from "./npm-artifacts.ts";
import { compareReleaseVersions } from "./release-version.ts";
import { parseJSON, parseValue } from "./validation.ts";

const registryPackageSchema = z.object({
  "dist-tags": z.optional(z.record(z.string(), z.string())),
  versions: z.optional(
    z.record(
      z.string(),
      z.object({
        dist: z.optional(z.object({ integrity: z.optional(z.string()) })),
      }),
    ),
  ),
});

const execFileAsync = promisify(execFile);
const packageDirectoryArgument = process.argv[2];
const expectedVersion = process.argv[3];
assert(
  packageDirectoryArgument && expectedVersion,
  "usage: node scripts/publish-tnl-packages.ts PACKAGE_DIRECTORY EXPECTED_VERSION",
);

const expectedPackages = [
  ...nativeTargets.map(({ packageName }) => ({ name: packageName, kind: "native" })),
  { name: "@tnldotdev/tnl", kind: "launcher" },
];
const packageDirectory = path.resolve(packageDirectoryArgument);
const metadata = parseJSON(
  await readFile(path.join(packageDirectory, "tnl-npm-packages.json"), "utf8"),
  npmPackageMetadataSchema,
  "npm package metadata",
);
assert.equal(metadata.version, expectedVersion);
assert.deepEqual(
  metadata.packages.map(({ name, kind }) => ({ name, kind })),
  expectedPackages.map(({ name, kind }) => ({ name, kind })),
  "npm artifact does not contain the expected packages in native-first order",
);

const distTag = expectedVersion.includes("-") ? "next" : "latest";
const packages = [];
for (const entry of metadata.packages) {
  packages.push(await verifyLocalPackage(entry));
}

// validate every registry state before creating an immutable package version.
const unpublished = [];
for (const package_ of packages) {
  const registry = await registryPackage(package_.name);
  const taggedVersion = registry?.["dist-tags"]?.[distTag];
  if (typeof taggedVersion === "string") {
    assert(
      compareReleaseVersions(taggedVersion, expectedVersion) <= 0,
      `${package_.name} ${distTag} already points to newer version ${taggedVersion}`,
    );
  }
  const existingIntegrity = registry?.versions?.[expectedVersion]?.dist?.integrity ?? null;
  assert(
    existingIntegrity === null || existingIntegrity === package_.integrity,
    `${package_.name}@${expectedVersion} already exists with different content`,
  );
  if (existingIntegrity === package_.integrity) {
    process.stdout.write(`${package_.name}@${expectedVersion} already has matching content\n`);
  } else {
    unpublished.push(package_);
  }
}

for (const package_ of unpublished) {
  await publish(package_, distTag);
}

async function verifyLocalPackage(entry: PackedPackage): Promise<PackedPackage> {
  // packing checked the package shape; publishing checks that the handed-off tarball is unchanged.
  assert.equal(
    path.basename(entry.tarball),
    entry.tarball,
    `${entry.name} has an unsafe tarball path`,
  );
  assert.match(
    entry.tarball,
    /^tnldotdev-tnl(?:-(?:darwin|linux)-(?:arm64|x64))?-[0-9A-Za-z.-]+\.tgz$/,
  );
  const tarball = path.join(packageDirectory, entry.tarball);
  const data = await readFile(tarball);
  const integrity = `sha512-${createHash("sha512").update(data).digest("base64")}`;
  assert.equal(integrity, entry.integrity, `${entry.name} tarball integrity changed`);

  const { stdout } = await execFileAsync("tar", ["-xOzf", tarball, "package/package.json"], {
    maxBuffer: 1024 * 1024,
  });
  const manifest = parseJSON(stdout, packageManifestSchema, "packed manifest");
  assert.equal(manifest.name, entry.name);
  assert.equal(manifest.version, expectedVersion);
  return { ...entry, integrity, tarball };
}

async function publish(package_: PackedPackage, tag: "next" | "latest"): Promise<void> {
  await execFileAsync("npm", ["publish", package_.tarball, "--access", "public", "--tag", tag]);
  process.stdout.write(`${package_.name}@${expectedVersion} published with ${tag}\n`);
}

async function registryPackage(
  packageName: string,
): Promise<z.infer<typeof registryPackageSchema> | null> {
  const url = new URL(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`);
  url.searchParams.set("cache-bust", String(Date.now()));
  const response = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (response.status === 404) {
    return null;
  }
  assert(response.ok, `npm registry returned ${response.status} for ${packageName}`);
  return parseValue(await response.json(), registryPackageSchema, "npm registry response");
}
import { installToolFailureHandler } from "./errors.ts";
installToolFailureHandler(import.meta, "tool.process_failed");
