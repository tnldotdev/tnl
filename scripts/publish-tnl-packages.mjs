import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const packageDirectoryArgument = process.argv[2];
const expectedVersion = process.argv[3];
assert(
  packageDirectoryArgument && expectedVersion,
  "usage: node scripts/publish-tnl-packages.mjs PACKAGE_DIRECTORY EXPECTED_VERSION",
);

const expectedPackages = [
  { name: "@tnldotdev/tnl-darwin-arm64", kind: "native", os: "darwin", cpu: "arm64" },
  { name: "@tnldotdev/tnl-darwin-x64", kind: "native", os: "darwin", cpu: "x64" },
  { name: "@tnldotdev/tnl-linux-arm64", kind: "native", os: "linux", cpu: "arm64" },
  { name: "@tnldotdev/tnl-linux-x64", kind: "native", os: "linux", cpu: "x64" },
  { name: "@tnldotdev/tnl", kind: "launcher" },
];
const packageDirectory = path.resolve(packageDirectoryArgument);
const metadata = JSON.parse(
  await readFile(path.join(packageDirectory, "tnl-npm-packages.json"), "utf8"),
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
    assert.equal(
      taggedVersion,
      expectedVersion,
      `${package_.name}@${expectedVersion} exists but ${distTag} does not select it`,
    );
  }
}

for (const package_ of packages) {
  await publish(package_, distTag);
}

async function verifyLocalPackage(expected) {
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
  const manifest = JSON.parse(stdout);
  assert.equal(manifest.name, expected.name);
  assert.equal(manifest.version, expectedVersion);
  for (const lifecycle of ["preinstall", "install", "postinstall"]) {
    assert.equal(manifest.scripts?.[lifecycle], undefined);
  }
  if (expected.kind === "native") {
    assert.deepEqual(manifest.os, [expected.os]);
    assert.deepEqual(manifest.cpu, [expected.cpu]);
  } else {
    assert.deepEqual(
      manifest.optionalDependencies,
      Object.fromEntries(
        expectedPackages
          .filter(({ kind }) => kind === "native")
          .map(({ name }) => [name, expectedVersion]),
      ),
    );
    assert.deepEqual(manifest.bin, { tnl: "bin/tnl.mjs" });
  }
  return { ...entry, integrity, tarball };
}

async function publish(package_, tag) {
  const before = await registryPackage(package_.name);
  if (before?.versions?.[expectedVersion]?.dist?.integrity === package_.integrity) {
    process.stdout.write(`${package_.name}@${expectedVersion} already has matching content\n`);
    return;
  }

  try {
    await execFileAsync("npm", [
      "publish",
      package_.tarball,
      "--access",
      "public",
      "--provenance",
      "--tag",
      tag,
    ]);
  } catch (error) {
    const registry = await registryPackage(package_.name);
    if (
      registry?.versions?.[expectedVersion]?.dist?.integrity !== package_.integrity ||
      registry?.["dist-tags"]?.[tag] !== expectedVersion
    ) {
      throw error;
    }
  }

  for (let attempt = 0; attempt < 20; attempt += 1) {
    const registry = await registryPackage(package_.name);
    const publishedIntegrity = registry?.versions?.[expectedVersion]?.dist?.integrity ?? null;
    if (
      publishedIntegrity === package_.integrity &&
      registry?.["dist-tags"]?.[tag] === expectedVersion
    ) {
      process.stdout.write(`${package_.name}@${expectedVersion} published with ${tag}\n`);
      return;
    }
    assert(
      publishedIntegrity === null || publishedIntegrity === package_.integrity,
      `${package_.name}@${expectedVersion} was published with unexpected content`,
    );
    await delay(3_000);
  }
  throw new Error(`timed out waiting for ${package_.name}@${expectedVersion} in the npm registry`);
}

async function registryPackage(packageName) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(10_000) });
      if (response.status === 404) {
        return null;
      }
      if (response.status === 429 || response.status >= 500) {
        throw new Error(`npm registry returned ${response.status} for ${packageName}`);
      }
      assert(response.ok, `npm registry returned ${response.status} for ${packageName}`);
      return await response.json();
    } catch (error) {
      if (attempt === 4) {
        throw error;
      }
      await delay(1000 * (attempt + 1));
    }
  }
  throw new Error(`could not read ${packageName} from the npm registry`);
}

function compareVersions(left, right) {
  const parsedLeft = parseVersion(left);
  const parsedRight = parseVersion(right);
  for (let index = 0; index < 3; index += 1) {
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

function parseVersion(value) {
  const match = value.match(
    /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/,
  );
  assert(match, `invalid npm version ${value}`);
  return {
    release: match.slice(1, 4).map(Number),
    prerelease: match[4]?.split(".") ?? [],
  };
}
