import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "vitest";

const script = readFileSync(new URL("install.sh", import.meta.url), "utf8");
const directories: string[] = [];
afterEach(() => {
  for (const dir of directories.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture(version = "1.2.3") {
  const root = mkdtempSync(join(tmpdir(), "tnl-install-"));
  directories.push(root);
  const tools = join(root, "tools");
  const files = join(root, "files");
  const scratch = join(root, "tmp");
  const dir = join(root, "bin with spaces");
  for (const path of [tools, files, scratch, dir]) mkdirSync(path);
  const executable = (name: string, body: string) => {
    writeFileSync(join(tools, name), `#!/bin/sh\n${body}\n`);
    chmodSync(join(tools, name), 0o755);
  };
  executable(
    "curl",
    `
while [ "$#" -gt 0 ]; do
  case "$1" in --output) output=$2; shift ;; https://*) url=$1 ;; esac
  shift
done
printf '%s\\n' "$url" >> "$FIXTURE/urls"
case "$url" in
  */releases/latest) printf '%s' "$LATEST_RELEASE_URL" ;;
  */checksums.txt) cp "$FIXTURE/checksums.txt" "$output" ;;
  *.tar.gz) cp "$FIXTURE/archive.tar.gz" "$output" ;;
  *) exit 1 ;;
esac`,
  );
  const entries = ["tnl", "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"];
  for (const name of entries) writeFileSync(join(files, name), `fixture ${name}\n`);
  execFileSync("tar", ["-czf", join(root, "archive.tar.gz"), "-C", files, ...entries]);
  const digest = createHash("sha256")
    .update(readFileSync(join(root, "archive.tar.gz")))
    .digest("hex");
  const checksums = ["darwin", "linux"]
    .flatMap((os) =>
      ["amd64", "arm64"].map((arch) => `${digest}  tnl_${version}_${os}_${arch}.tar.gz`),
    )
    .join("\n");
  writeFileSync(join(root, "checksums.txt"), `${checksums}\n`);
  const binary = join(dir, "tnl");
  writeFileSync(binary, "old binary");
  const run = (
    override = "",
    latest = `https://github.com/tnldotdev/tnl/releases/tag/v${version}`,
  ) =>
    spawnSync("sh", [], {
      input: script,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${tools}:${process.env.PATH}`,
        FIXTURE: root,
        LATEST_RELEASE_URL: latest,
        TNL_INSTALL: dir,
        TNL_VERSION: override,
        TMPDIR: scratch,
      },
    });
  return { root, dir, scratch, binary, run, executable, checksums };
}

test("installs GitHub's latest stable release, retains notices, and cleans up", () => {
  const f = fixture();
  const result = f.run();
  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout).toContain("tnl is installed");
  expect(result.stderr).toContain("downloading and verifying");
  expect(readFileSync(f.binary, "utf8")).toBe("fixture tnl\n");
  expect(readFileSync(join(f.root, "urls"), "utf8")).toContain("/releases/download/v1.2.3/");
  expect(readdirSync(join(f.dir, "tnl-notices"))).toEqual([
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_LICENSES.txt",
  ]);
  expect(readdirSync(f.scratch)).toEqual([]);
  expect(readdirSync(f.dir)).toEqual(["tnl", "tnl-notices"]);
});

test("an explicit version skips latest release lookup", () => {
  const f = fixture("1.2.4");
  expect(f.run("v1.2.4").status).toBe(0);
  const urls = readFileSync(join(f.root, "urls"), "utf8");
  expect(urls).toContain("/releases/download/v1.2.4/");
  expect(urls).not.toContain("/releases/latest");
});

test.each([
  "https://github.com/tnldotdev/tnl/releases",
  "https://github.com/tnldotdev/tnl/releases/tag/v1.2.3-rc.1",
])("does not fall back when latest stable resolves to %s", (latest) => {
  const f = fixture();
  const result = f.run("", latest);
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("could not find a stable tnl release");
  expect(result.stdout).toBe("");
  expect(readFileSync(join(f.root, "urls"), "utf8").trim()).toBe(
    "https://github.com/tnldotdev/tnl/releases/latest",
  );
  expect(readFileSync(f.binary, "utf8")).toBe("old binary");
  expect(readdirSync(f.scratch)).toEqual([]);
});

test("a checksum mismatch preserves the existing binary", () => {
  const f = fixture();
  writeFileSync(
    join(f.root, "checksums.txt"),
    f.checksums.replaceAll(/^[0-9a-f]{64}/gm, "0".repeat(64)),
  );
  const result = f.run();
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("checksum");
  expect(result.stdout).toBe("");
  expect(readFileSync(f.binary, "utf8")).toBe("old binary");
  expect(readdirSync(f.scratch)).toEqual([]);
});

test("a failed replacement preserves the binary and removes staging files", () => {
  const f = fixture();
  f.executable("mv", "exit 1");
  const result = f.run();
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("could not install tnl");
  expect(readFileSync(f.binary, "utf8")).toBe("old binary");
  expect(readdirSync(f.scratch)).toEqual([]);
  expect(readdirSync(f.dir)).toEqual(["tnl", "tnl-notices"]);
});
