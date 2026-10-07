import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";

const [tag, checksumsPath, formulaPath, mode] = process.argv.slice(2);
if (
  !tag ||
  !checksumsPath ||
  !formulaPath ||
  !tag.startsWith("v") ||
  (mode !== undefined && mode !== "--render-only")
) {
  throw new Error("usage: node scripts/update-homebrew.ts TAG CHECKSUMS FORMULA [--render-only]");
}

const version = tag.slice(1);
const lines = (await readFile(checksumsPath, "utf8")).trim().split("\n");
const checksum = (platform: string, architecture: string) => {
  const filename = `tnl_${version}_${platform}_${architecture}.tar.gz`;
  const matches = lines.filter((line) => line.trim().endsWith(`  ${filename}`));
  assert.equal(matches.length, 1, `expected one checksum for ${filename}`);
  const hash = matches[0]?.trim().split(/\s+/)[0];
  assert(hash, `missing checksum for ${filename}`);
  assert.match(hash, /^[0-9a-f]{64}$/, `invalid checksum for ${filename}`);
  return hash;
};
const values: Record<string, string> = {
  TAG: tag,
  VERSION: version,
  DARWIN_ARM64: checksum("darwin", "arm64"),
  DARWIN_AMD64: checksum("darwin", "amd64"),
  LINUX_ARM64: checksum("linux", "arm64"),
  LINUX_AMD64: checksum("linux", "amd64"),
};
const template = await readFile(
  path.resolve(import.meta.dirname, "../deploy/tnl.rb.template"),
  "utf8",
);
const formula = template.replace(/\{\{([A-Z0-9_]+)\}\}/g, (_, key: string) => {
  const value = values[key];
  assert(value, `unknown formula placeholder ${key}`);
  return value;
});
await mkdir(path.dirname(formulaPath), { recursive: true });
await writeFile(formulaPath, formula);

const run = promisify(execFile);
await run("ruby", ["-c", formulaPath]);
if (mode !== "--render-only") {
  const endpoint = "repos/tnldotdev/homebrew-tap/contents/Formula/tnl.rb";
  const sha = await run("gh", ["api", endpoint, "--jq", ".sha"])
    .then(({ stdout }) => stdout.trim())
    .catch((error: unknown) => {
      if (
        typeof error !== "object" ||
        error === null ||
        !("stderr" in error) ||
        !String(error.stderr).includes("HTTP 404")
      )
        throw error;
      return "";
    });
  await run("gh", [
    "api",
    endpoint,
    "--method",
    "PUT",
    "-f",
    `message=tnl ${version}`,
    "-f",
    `content=${Buffer.from(formula).toString("base64")}`,
    ...(sha ? ["-f", `sha=${sha}`] : []),
  ]);
}
import { installToolFailureHandler } from "./errors.ts";
installToolFailureHandler(import.meta, "tool.input_invalid");
