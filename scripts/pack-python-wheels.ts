import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import * as z from "zod";
import { pythonVersion } from "./python-version.ts";
import { parseJSON } from "./validation.ts";

const execFileAsync = promisify(execFile);
const root = path.resolve(import.meta.dirname, "..");
const outputArgument = process.argv[2];
assert(
  outputArgument,
  "usage: node scripts/pack-python-wheels.ts OUTPUT_DIRECTORY [EXPECTED_VERSION]",
);
const output = path.resolve(outputArgument);
const metadata = parseJSON(
  await readFile(path.join(root, "dist", "metadata.json"), "utf8"),
  z.object({ version: z.string(), commit: z.string().regex(/^[a-f0-9]{40}$/) }),
  "GoReleaser metadata",
);
if (process.argv[3] !== undefined) assert.equal(metadata.version, process.argv[3]);
const version = pythonVersion(metadata.version);
const artifacts = parseJSON(
  await readFile(path.join(root, "dist", "artifacts.json"), "utf8"),
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
const project = parseJSON(
  (
    await execFileAsync("python3", [
      "-c",
      `import json,sys,tomllib
with open(sys.argv[1], "rb") as source:
  value = tomllib.load(source)["project"]
print(json.dumps({key: value[key] for key in ("name", "requires-python", "dependencies")}))`,
      path.join(root, "packages/py/pyproject.toml"),
    ])
  ).stdout,
  z.object({
    name: z.literal("tnldotdev-tnl"),
    "requires-python": z.string(),
    dependencies: z.array(z.string()),
  }),
  "Python package metadata",
);
const readme = await readFile(path.join(root, "packages/py/readme.md"), "utf8");

const targets = [
  { goos: "darwin", goarch: "amd64", tag: "macosx_12_0_x86_64", nodeArch: "x64" },
  { goos: "darwin", goarch: "arm64", tag: "macosx_12_0_arm64", nodeArch: "arm64" },
  { goos: "linux", goarch: "amd64", tag: "manylinux_2_17_x86_64", nodeArch: "x64" },
  { goos: "linux", goarch: "arm64", tag: "manylinux_2_17_aarch64", nodeArch: "arm64" },
] as const;
const legalFiles = ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"] as const;
const distribution = `tnldotdev_tnl-${version}`;
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
const staging = await mkdtemp(path.join(tmpdir(), "tnl-python-wheels-"));
const wheels: { name: string; tag: string; binarySha256: string }[] = [];
try {
  for (const target of targets) {
    const binaryArtifact = exactlyOne(
      artifacts.filter(
        (item) =>
          item.type === "Binary" &&
          item.extra?.ID === "tnl" &&
          item.goos === target.goos &&
          item.goarch === target.goarch,
      ),
    );
    const archiveArtifact = exactlyOne(
      artifacts.filter(
        (item) =>
          item.type === "Archive" &&
          item.extra?.ID === "release" &&
          item.goos === target.goos &&
          item.goarch === target.goarch,
      ),
    );
    const binaryPath = artifactPath(binaryArtifact.path);
    const archivePath = artifactPath(archiveArtifact.path);
    await access(binaryPath, constants.R_OK | constants.X_OK);
    await access(archivePath, constants.R_OK);
    const binary = await readFile(binaryPath);
    const { stdout: archivedBinary } = await execFileAsync("tar", ["-xOzf", archivePath, "tnl"], {
      encoding: "buffer",
      maxBuffer: 64 << 20,
    });
    assert.deepEqual(
      archivedBinary,
      binary,
      `${target.goos}/${target.goarch} archive binary differs`,
    );
    const stage = path.join(staging, target.tag);
    const moduleDir = path.join(stage, "tnl");
    const distInfo = path.join(stage, `${distribution}.dist-info`);
    const licenses = path.join(distInfo, "licenses");
    await mkdir(path.join(moduleDir, "bin"), { recursive: true });
    await mkdir(licenses, { recursive: true });
    const files: string[] = [];
    for (const filename of (await readdir(path.join(root, "packages/py/src/tnl")))
      .filter((name) => name.endsWith(".py"))
      .sort()) {
      const destination = `tnl/${filename}`;
      await copyFile(
        path.join(root, "packages/py/src/tnl", filename),
        path.join(stage, destination),
      );
      files.push(destination);
    }
    assert(files.includes("tnl/__init__.py"), "Python wheel has no importable package");
    await copyFile(binaryPath, path.join(moduleDir, "bin", "tnl"));
    await chmod(path.join(moduleDir, "bin", "tnl"), 0o755);
    files.push("tnl/bin/tnl");
    for (const name of legalFiles) {
      const original = await readFile(path.join(root, name));
      const { stdout: archived } = await execFileAsync("tar", ["-xOzf", archivePath, name], {
        encoding: "buffer",
        maxBuffer: 16 << 20,
      });
      assert.deepEqual(
        archived,
        original,
        `${target.goos}/${target.goarch} archive ${name} differs`,
      );
      const destination = `${distribution}.dist-info/licenses/${name}`;
      await writeFile(path.join(stage, destination), original);
      files.push(destination);
    }
    const metadataPath = `${distribution}.dist-info/METADATA`;
    await writeFile(
      path.join(stage, metadataPath),
      [
        "Metadata-Version: 2.4",
        "Name: tnldotdev-tnl",
        `Version: ${version}`,
        "Summary: public URLs for Python ASGI applications",
        "License-Expression: MIT",
        "Description-Content-Type: text/markdown",
        ...legalFiles.map((name) => `License-File: ${name}`),
        `Requires-Python: ${project["requires-python"]}`,
        ...project.dependencies.map((dependency) => `Requires-Dist: ${dependency}`),
        "",
        readme,
      ].join("\n"),
    );
    files.push(metadataPath);
    const wheelPath = `${distribution}.dist-info/WHEEL`;
    await writeFile(
      path.join(stage, wheelPath),
      [
        "Wheel-Version: 1.0",
        "Generator: tnl wheel packer",
        "Root-Is-Purelib: false",
        `Tag: py3-none-${target.tag}`,
        "",
        "",
      ].join("\n"),
    );
    files.push(wheelPath);
    const recordPath = `${distribution}.dist-info/RECORD`;
    const records = await Promise.all(
      files.sort().map(async (filename) => {
        const contents = await readFile(path.join(stage, filename));
        return `${filename},sha256=${createHash("sha256").update(contents).digest("base64url")},${contents.length}`;
      }),
    );
    await writeFile(path.join(stage, recordPath), [...records, `${recordPath},,`, ""].join("\n"));
    files.push(recordPath);
    const name = `${distribution}-py3-none-${target.tag}.whl`;
    await execFileAsync("zip", ["-X", "-q", path.join(output, name), ...files], { cwd: stage });
    if (process.platform === target.goos && process.arch === target.nodeArch) {
      const { stdout } = await execFileAsync(path.join(moduleDir, "bin", "tnl"), ["version"]);
      assert.equal(stdout.trim(), `tnl ${metadata.version} (${metadata.commit})`);
    }
    wheels.push({
      name,
      tag: target.tag,
      binarySha256: createHash("sha256").update(binary).digest("hex"),
    });
  }
  await writeFile(
    path.join(output, "wheels.json"),
    JSON.stringify(
      { version, releaseVersion: metadata.version, commit: metadata.commit, wheels },
      null,
      2,
    ) + "\n",
  );
} finally {
  await rm(staging, { recursive: true, force: true });
}

function artifactPath(value: string): string {
  const result = path.resolve(root, value);
  assert(
    result.startsWith(path.join(root, "dist") + path.sep),
    "artifact is outside GoReleaser dist",
  );
  return result;
}

function exactlyOne<T>(values: readonly T[]): T {
  assert.equal(values.length, 1, "expected one GoReleaser artifact for each Python wheel");
  const selected = values[0];
  if (selected === undefined) throw new Error("GoReleaser artifact is missing");
  return selected;
}
