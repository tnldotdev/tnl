import { describe, expect, it } from "vitest";
import { assertExportTargets, type PackageManifest } from "./npm-artifacts.ts";

const manifest: PackageManifest = {
  name: "@tnldotdev/tnl",
  version: "0.0.0-development",
  license: "BSD-3-Clause",
  exports: {
    "./another-subpath": {
      types: "./dist/another.d.ts",
      node: { import: "./dist/another.js", require: "./dist/another.cjs" },
      browser: null,
    },
  },
};
const files = ["dist/another.d.ts", "dist/another.js", "dist/another.cjs"];

describe("packed export targets", () => {
  it("accepts new subpaths from the manifest without a separate inventory", () => {
    expect(() => assertExportTargets(manifest, new Set(files))).not.toThrow();
  });

  it.each(files)(
    "requires the conditional target %s even when Node uses another branch",
    (file) => {
      expect(() =>
        assertExportTargets(manifest, new Set(files.filter((entry) => entry !== file))),
      ).toThrow(`missing export target ./${file}`);
    },
  );

  it("rejects targets outside the package even if they appear in the file inventory", () => {
    expect(() =>
      assertExportTargets(
        { ...manifest, exports: { ".": "./../outside.js" } },
        new Set(["../outside.js"]),
      ),
    ).toThrow("invalid export target");
  });
});
