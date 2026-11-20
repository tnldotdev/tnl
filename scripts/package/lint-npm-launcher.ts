import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { publint } from "publint";
import { formatMessage } from "publint/utils";
import { packageManifestSchema } from "./npm-artifacts.ts";

export async function lintNpmLauncher(
  tarball: string,
  packedFiles: ReadonlySet<string>,
): Promise<void> {
  const bytes = await readFile(tarball);
  const { messages, pkg } = await publint({
    pack: { tarball: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) },
    level: "error",
    strict: true,
  });
  if (messages.length > 0)
    assert.fail(
      `publint failed for ${tarball}:\n${messages.map((message) => formatMessage(message, pkg)).join("\n")}`,
    );
  const { exports } = packageManifestSchema.parse(pkg);
  assert(exports, "the SDK must define public exports");
  for (const [subpath, target] of Object.entries(exports)) {
    const resolves = checkTarget(target, packedFiles);
    if (subpath === ".") assert(resolves, "the SDK must define a root export target");
  }
  assert(Object.hasOwn(exports, "."), "the SDK must define a root export");
}

// publint checks packed JS and declarations. it can normalize invalid path
// segments and skip non-code assets behind custom conditions.
function checkTarget(target: unknown, packedFiles: ReadonlySet<string>): boolean {
  if (target === null) return false;
  if (typeof target !== "string") {
    assert(target && typeof target === "object", "invalid SDK export condition");
    return Object.values(target)
      .map((child) => checkTarget(child, packedFiles))
      .includes(true);
  }
  assert(
    target.startsWith("./") &&
      !target.includes("\\") &&
      !target.includes("*") &&
      target
        .slice(2)
        .split("/")
        .every((part) => !["", ".", "..", "node_modules"].includes(part)),
    `invalid SDK export target: ${target}`,
  );
  if (!/\.(?:[cm]?js|d\.[cm]?ts)$/.test(target))
    assert(packedFiles.has(target.slice(2)), `missing SDK export asset: ${target}`);
  return true;
}
