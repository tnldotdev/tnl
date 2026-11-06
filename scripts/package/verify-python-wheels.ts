import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { nativeTargets } from "../../packages/ts/src/internal/native/native-targets.ts";
import { wheelTag } from "./pack-python-wheels.ts";
import { legalFiles, releaseArtifacts, root } from "./release-artifacts.ts";
import { pythonVersion } from "./python-version.ts";

assert(process.argv[2], "usage: verify-python-wheels.ts WHEEL_DIRECTORY");
const directory = path.resolve(process.argv[2]);
const release = await releaseArtifacts();
const target = nativeTargets.find(
  (t) => t.platform === process.platform && t.architecture === process.arch,
);
assert(target, "unsupported wheel smoke-test platform");
const wheels = (await readdir(directory)).filter((file) => file.endsWith(".whl"));
assert.equal(wheels.length, nativeTargets.length);
for (const file of wheels) {
  const listing = execFileSync("unzip", ["-Z", "-1", path.join(directory, file)], {
    encoding: "utf8",
  });
  for (const name of legalFiles)
    assert(listing.includes(`.dist-info/licenses/${name}\n`), `${file} is missing ${name}`);
}
const wheel = wheels.find((file) => file.endsWith(`-${wheelTag(target)}.whl`));
assert(wheel, "missing current platform wheel");
const environment = await mkdtemp(path.join(tmpdir(), "tnl-wheel-"));
try {
  execFileSync("uv", ["venv", "--python", "python3", environment], { stdio: "inherit" });
  const python = path.join(environment, "bin/python");
  execFileSync("uv", ["pip", "install", "--python", python, path.join(directory, wheel)], {
    stdio: "inherit",
  });
  execFileSync(
    python,
    [
      "-I",
      path.join(root, "packages/py/tests/wheel_smoke.py"),
      pythonVersion(release.version),
      release.version,
      release.commit,
    ],
    { stdio: "inherit", timeout: 30_000 },
  );
} finally {
  await rm(environment, { recursive: true, force: true });
}
