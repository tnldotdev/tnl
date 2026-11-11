import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import * as z from "zod";
import { valid } from "semver";
import { parseJSON } from "../validation.ts";

export const root = path.resolve(import.meta.dirname, "../..");
export const legalFiles = ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"] as const;

export async function releaseArtifacts(expectedVersion?: string) {
  const metadata = parseJSON(
    await readFile(path.join(root, "dist/metadata.json"), "utf8"),
    z.object({ version: z.string(), commit: z.string().regex(/^[a-f0-9]{40}$/) }),
    "GoReleaser metadata",
  );
  assert.equal(valid(metadata.version), metadata.version, "invalid release version");
  if (expectedVersion !== undefined) assert.equal(metadata.version, expectedVersion);
  const artifacts = parseJSON(
    await readFile(path.join(root, "dist/artifacts.json"), "utf8"),
    z.array(
      z.object({
        type: z.string(),
        path: z.string(),
        extra: z.optional(z.object({ ID: z.optional(z.string()) })),
        goos: z.optional(z.string()),
        goarch: z.optional(z.string()),
      }),
    ),
    "GoReleaser artifacts",
  );
  return {
    ...metadata,
    binary(goos: string, goarch: string) {
      const matches = artifacts.filter(
        (a) =>
          a.type === "Binary" && a.extra?.ID === "tnl" && a.goos === goos && a.goarch === goarch,
      );
      assert(matches.length === 1 && matches[0], `expected one tnl binary for ${goos}/${goarch}`);
      const file = path.resolve(root, matches[0].path);
      assert(file.startsWith(path.join(root, "dist") + path.sep), "binary is outside dist");
      return file;
    },
  };
}
