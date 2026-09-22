import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import * as z from "zod";
import {
  nativeTargets,
  type NativePlatform,
  type NativeArchitecture,
} from "../packages/tnl/src/internal/native-targets.ts";
import {
  npmPackageMetadataSchema,
  packageManifestSchema,
  type PackedPackage,
} from "./npm-artifacts.ts";
import { parseJSON, parseValue } from "./validation.ts";

type ExpectedPackage =
  | { readonly name: string; readonly kind: "launcher" }
  | {
      readonly name: string;
      readonly kind: "native";
      readonly os: NativePlatform;
      readonly cpu: NativeArchitecture;
    };

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

const expectedPackages: readonly ExpectedPackage[] = [
  ...nativeTargets.map(({ platform, architecture, packageName }): ExpectedPackage => ({
    name: packageName,
    kind: "native",
    os: platform,
    cpu: architecture,
  })),
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
for (const expected of expectedPackages) {
  packages.push(await verifyLocalPackage(expected));
}

// Validate every registry state before creating an immutable package version.
const unpublished = [];
for (const package_ of packages) {
  const registry = await registryPackage(package_.name);
  const taggedVersion = registry?.["dist-tags"]?.[distTag];
  if (typeof taggedVersion === "string") {
    assert(
      compareVersions(taggedVersion, expectedVersion) <= 0,
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

async function verifyLocalPackage(expected: ExpectedPackage): Promise<PackedPackage> {
  const entry = metadata.packages.find(({ name }) => name === expected.name);
  assert(entry !== undefined);
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
  assert.equal(manifest.name, expected.name);
  assert.equal(manifest.version, expectedVersion);
  for (const lifecycle of ["preinstall", "install", "postinstall"]) {
    assert.equal(manifest.scripts?.[lifecycle], undefined);
  }
  if (expected.kind === "native") {
    assert.deepEqual(manifest.os, [expected.os]);
    assert.deepEqual(manifest.cpu, [expected.cpu]);
  } else {
    assert(manifest.exports, "launcher must define public exports");
    assert.deepEqual(Object.keys(manifest.exports).sort(), [".", "./config", "./next", "./vite"]);
    assert.deepEqual(
      manifest.optionalDependencies,
      Object.fromEntries(
        expectedPackages
          .filter(({ kind }) => kind === "native")
          .map(({ name }) => [name, expectedVersion]),
      ),
    );
    assert.deepEqual(manifest.bin, { tnl: "dist/bin/tnl.js" });
  }
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

function compareVersions(left: string, right: string): number {
  const parsedLeft = parseVersion(left);
  const parsedRight = parseVersion(right);
  for (const index of [0, 1, 2] as const) {
    if (parsedLeft.release[index] !== parsedRight.release[index]) {
      return parsedLeft.release[index] < parsedRight.release[index] ? -1 : 1;
    }
  }
  if (parsedLeft.prerelease.length === 0 || parsedRight.prerelease.length === 0) {
    return parsedLeft.prerelease.length === parsedRight.prerelease.length
      ? 0
      : parsedLeft.prerelease.length === 0
        ? 1
        : -1;
  }
  const length = Math.max(parsedLeft.prerelease.length, parsedRight.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftIdentifier = parsedLeft.prerelease[index];
    const rightIdentifier = parsedRight.prerelease[index];
    if (leftIdentifier === undefined || rightIdentifier === undefined) {
      return leftIdentifier === rightIdentifier ? 0 : leftIdentifier === undefined ? -1 : 1;
    }
    if (leftIdentifier === rightIdentifier) {
      continue;
    }
    const leftNumeric = /^[0-9]+$/.test(leftIdentifier);
    const rightNumeric = /^[0-9]+$/.test(rightIdentifier);
    if (leftNumeric && rightNumeric) {
      return Number(leftIdentifier) < Number(rightIdentifier) ? -1 : 1;
    }
    if (leftNumeric !== rightNumeric) {
      return leftNumeric ? -1 : 1;
    }
    return leftIdentifier < rightIdentifier ? -1 : 1;
  }
  return 0;
}

function parseVersion(value: string): {
  release: readonly [number, number, number];
  prerelease: string[];
} {
  const match = value.match(
    /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/,
  );
  assert(match, `invalid npm version ${value}`);
  return {
    release: [Number(match[1]), Number(match[2]), Number(match[3])],
    prerelease: match[4]?.split(".") ?? [],
  };
}
