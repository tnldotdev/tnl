import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";

const expectedVersion = process.argv[2];
assert(expectedVersion, "expected a release version argument");

const root = path.resolve(import.meta.dirname, "..");
for (const packageName of ["dev", "next", "vite"]) {
  const manifest = JSON.parse(
    await readFile(path.join(root, "packages", packageName, "package.json"), "utf8"),
  );
  assert.equal(
    manifest.version,
    expectedVersion,
    `${manifest.name} version must match release ${expectedVersion}`,
  );
}
