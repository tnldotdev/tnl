import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmod, copyFile, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  nativeTargets,
  type NativeTarget,
} from "../../packages/ts/src/internal/native/native-targets.ts";
import { legalFiles, releaseArtifacts, root } from "./release-artifacts.ts";
import { pythonVersion } from "./python-version.ts";

export function wheelTag(target: Pick<NativeTarget, "platform" | "architecture">): string {
  return target.platform === "darwin"
    ? `macosx_12_0_${target.architecture === "x64" ? "x86_64" : "arm64"}`
    : `manylinux_2_17_${target.architecture === "x64" ? "x86_64" : "aarch64"}`;
}

// keep the tag helper importable without running a build.
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  assert(process.argv[2], "usage: pack-python-wheels.ts OUTPUT_DIRECTORY [EXPECTED_VERSION]");
  const output = path.resolve(process.argv[2]);
  const release = await releaseArtifacts(process.argv[3]);
  const version = pythonVersion(release.version);
  const project = path.join(root, "packages/py");
  const config = await readFile(path.join(project, "pyproject.toml"), "utf8");
  const staging = await mkdtemp(path.join(tmpdir(), "tnl-wheels-"));
  await rm(output, { recursive: true, force: true });
  await mkdir(output, { recursive: true });
  try {
    for (const target of nativeTargets) {
      const stage = path.join(staging, `${target.platform}-${target.architecture}`);
      await mkdir(path.join(stage, "src/tnl/bin"), { recursive: true });
      await cp(path.join(project, "src"), path.join(stage, "src"), {
        recursive: true,
        filter: (file) => !file.includes("__pycache__") && !file.endsWith(".pyc"),
      });
      for (const file of ["readme.md", "hatch_build.py"])
        await copyFile(path.join(project, file), path.join(stage, file));
      for (const file of legalFiles) await copyFile(path.join(root, file), path.join(stage, file));
      const binary = path.join(stage, "src/tnl/bin/tnl");
      await copyFile(
        release.binary(
          target.platform,
          target.architecture === "x64" ? "amd64" : target.architecture,
        ),
        binary,
      );
      await chmod(binary, 0o755);
      await writeFile(
        path.join(stage, "pyproject.toml"),
        config
          .replace('version = "0.0.0.dev0"', `version = "${version}"`)
          .replace(
            'license = "BSD-3-Clause"',
            `license = "BSD-3-Clause"\nlicense-files = ${JSON.stringify(legalFiles)}`,
          ) + `\n[tool.hatch.build.hooks.custom]\ntag = "py3-none-${wheelTag(target)}"\n`,
      );
      execFileSync("uv", ["build", "--wheel", "--out-dir", output, stage], { stdio: "inherit" });
    }
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}
