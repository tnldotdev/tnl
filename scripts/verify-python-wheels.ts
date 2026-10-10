import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import * as z from "zod";
import { parseJSON } from "./validation.ts";

const execFileAsync = promisify(execFile);
const directory = process.argv[2];
assert(directory, "usage: node scripts/verify-python-wheels.ts WHEEL_DIRECTORY");
const root = path.resolve(directory);
const manifest = parseJSON(
  await readFile(path.join(root, "wheels.json"), "utf8"),
  z.object({
    version: z.string(),
    releaseVersion: z.string(),
    commit: z.string().regex(/^[a-f0-9]{40}$/),
    wheels: z
      .array(
        z.object({
          name: z.string(),
          tag: z.string(),
          binarySha256: z.string().regex(/^[a-f0-9]{64}$/),
        }),
      )
      .length(4),
  }),
  "Python wheel manifest",
);
const tags = [
  "macosx_12_0_x86_64",
  "macosx_12_0_arm64",
  "manylinux_2_17_x86_64",
  "manylinux_2_17_aarch64",
];
assert.deepEqual(manifest.wheels.map((wheel) => wheel.tag).sort(), [...tags].sort());
const distribution = `tnldotdev_tnl-${manifest.version}`;
for (const wheel of manifest.wheels) {
  assert.equal(wheel.name, `${distribution}-py3-none-${wheel.tag}.whl`);
  const file = path.join(root, wheel.name);
  const { stdout: listing } = await execFileAsync("unzip", ["-Z", "-1", file]);
  const entries = listing.trim().split("\n");
  const record = `${distribution}.dist-info/RECORD`;
  assert(entries.includes(record));
  for (const name of ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"]) {
    assert(entries.includes(`${distribution}.dist-info/licenses/${name}`));
  }
  assert(entries.includes("tnl/__init__.py") && entries.includes("tnl/bin/tnl"));
  assert(
    !entries.some(
      (name) => name.includes("__pycache__") || name.endsWith(".pyc") || name === "tnld",
    ),
  );
  const binary = await unzip(file, "tnl/bin/tnl");
  assert.equal(createHash("sha256").update(binary).digest("hex"), wheel.binarySha256);
  const metadata = (await unzip(file, `${distribution}.dist-info/METADATA`)).toString("utf8");
  const wheelMetadata = (await unzip(file, `${distribution}.dist-info/WHEEL`)).toString("utf8");
  assert(metadata.includes(`Version: ${manifest.version}\n`));
  assert(wheelMetadata.includes(`Tag: py3-none-${wheel.tag}\n`));
}

const target =
  process.platform === "darwin"
    ? process.arch === "arm64"
      ? "macosx_12_0_arm64"
      : "macosx_12_0_x86_64"
    : process.arch === "arm64"
      ? "manylinux_2_17_aarch64"
      : "manylinux_2_17_x86_64";
const native = manifest.wheels.find((wheel) => wheel.tag === target);
assert(native, "the Python wheels do not contain this runner's platform");
const environment = await mkdtemp(path.join(tmpdir(), "tnl-python-wheel-check-"));
try {
  await execFileAsync("uv", ["venv", "--python", "python3", environment]);
  const python = path.join(environment, "bin", "python");
  await execFileAsync("uv", ["pip", "install", "--python", python, path.join(root, native.name)], {
    maxBuffer: 1024 * 1024,
  });
  await execFileAsync(
    python,
    [
      "-c",
      `import importlib.metadata, os, pathlib, subprocess, sys, tnl
version, release, commit = sys.argv[1:]
assert importlib.metadata.version("tnldotdev-tnl") == version
binary = pathlib.Path(tnl.__file__).parent / "bin" / "tnl"
assert os.access(binary, os.X_OK)
assert subprocess.check_output([str(binary), "version"], text=True).strip() == f"tnl {release} ({commit})"`,
      manifest.version,
      manifest.releaseVersion,
      manifest.commit,
    ],
    { maxBuffer: 1024 * 1024 },
  );
  await execFileAsync(python, ["-I", path.resolve("packages/py/tests/wheel_smoke.py")], {
    maxBuffer: 1024 * 1024,
    timeout: 30_000,
  });
} finally {
  await rm(environment, { recursive: true, force: true });
}

async function unzip(file: string, name: string): Promise<Buffer> {
  const { stdout } = await execFileAsync("unzip", ["-p", file, name], {
    encoding: "buffer",
    maxBuffer: 64 << 20,
  });
  return stdout;
}
