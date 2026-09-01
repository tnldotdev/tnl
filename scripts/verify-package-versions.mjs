import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";

const packageName = process.argv[2];
const expectedVersion = process.argv[3];
assert(["dev", "next", "vite"].includes(packageName), "expected a package name");
assert(expectedVersion, "expected a release version argument");

const root = path.resolve(import.meta.dirname, "..");
const manifest = JSON.parse(
  await readFile(path.join(root, "packages", packageName, "package.json"), "utf8"),
);
assert.equal(
  manifest.version,
  expectedVersion,
  `${manifest.name} version must match release ${expectedVersion}`,
);
