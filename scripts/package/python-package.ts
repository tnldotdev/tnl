import assert from "node:assert/strict";
import { copyFile, readdir } from "node:fs/promises";
import path from "node:path";

/** stage the importable package and its PEP 561 marker for platform wheels. */
export async function copyPythonPackage(source: string, destination: string): Promise<string[]> {
  const files = (await readdir(source))
    .filter((name) => name.endsWith(".py") || name === "py.typed")
    .sort();
  assert(files.includes("__init__.py"), "Python wheel has no importable package");
  assert(files.includes("py.typed"), "Python wheel has no PEP 561 type marker");
  for (const name of files) await copyFile(path.join(source, name), path.join(destination, name));
  return files.map((name) => `tnl/${name}`);
}
