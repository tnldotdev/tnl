import assert from "node:assert/strict";
import * as z from "zod";

export const packageKindSchema = z.enum(["launcher", "native"]);

export const packedPackageSchema = z.object({
  integrity: z.string(),
  kind: packageKindSchema,
  name: z.string(),
  tarball: z.string(),
});

export const npmPackageMetadataSchema = z.object({
  commit: z.string(),
  packages: z.array(packedPackageSchema),
  version: z.string(),
});

export type PackageKind = z.infer<typeof packageKindSchema>;
export type PackedPackage = z.infer<typeof packedPackageSchema>;

// preserve unmodeled npm fields when rewriting or serving a package manifest.
export const packageManifestSchema = z.looseObject({
  name: z.string(),
  version: z.string(),
  license: z.literal("BSD-3-Clause"),
  bin: z.optional(z.record(z.string(), z.string())),
  cpu: z.optional(z.array(z.string())),
  exports: z.optional(z.record(z.string(), z.unknown())),
  optionalDependencies: z.optional(z.record(z.string(), z.string())),
  os: z.optional(z.array(z.string())),
  scripts: z.optional(z.record(z.string(), z.string())),
  tnl: z.optional(z.object({ commit: z.string(), binarySha256: z.optional(z.string()) })),
});

export type PackageManifest = z.infer<typeof packageManifestSchema>;

// check every conditional target, including declarations and browser/require branches
// that a single Node import would not visit. the manifest owns the export inventory.
export function assertExportTargets(
  manifest: PackageManifest,
  packedFiles: ReadonlySet<string>,
): void {
  assert(manifest.exports, `${manifest.name} must define public exports`);
  let targets = 0;
  function visit(value: unknown): void {
    if (typeof value === "string") {
      assert(
        value.startsWith("./") &&
          !value.includes("\\") &&
          value
            .slice(2)
            .split("/")
            .every((part) => !["", ".", "..", "node_modules"].includes(part)),
        `${manifest.name} has an invalid export target: ${value}`,
      );
      assert(packedFiles.has(value.slice(2)), `${manifest.name} is missing export target ${value}`);
      targets++;
    } else if (value !== null) {
      assert(typeof value === "object", `${manifest.name} has an invalid export condition`);
      for (const nested of Object.values(value)) visit(nested);
    }
  }
  visit(manifest.exports);
  assert(targets > 0, `${manifest.name} must define public export targets`);
}
