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

// Preserve unmodeled npm fields when rewriting or serving a package manifest.
export const packageManifestSchema = z.looseObject({
  name: z.string(),
  version: z.string(),
  bin: z.optional(z.record(z.string(), z.string())),
  cpu: z.optional(z.array(z.string())),
  exports: z.optional(z.record(z.string(), z.unknown())),
  optionalDependencies: z.optional(z.record(z.string(), z.string())),
  os: z.optional(z.array(z.string())),
  scripts: z.optional(z.record(z.string(), z.string())),
  tnl: z.optional(z.object({ commit: z.string(), binarySha256: z.optional(z.string()) })),
});

export type PackageManifest = z.infer<typeof packageManifestSchema>;
