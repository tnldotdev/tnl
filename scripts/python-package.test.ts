import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import { copyPythonPackage } from "./python-package.ts";

test("platform wheel staging keeps every Python module and the PEP 561 marker", async () => {
  const stage = await mkdtemp(path.join(tmpdir(), "tnl-python-package-"));
  try {
    const source = path.resolve("packages/py/src/tnl");
    const files = await copyPythonPackage(source, stage);
    expect(files).toContain("tnl/py.typed");
    expect(files).toContain("tnl/_connections.py");
    expect(files).toContain("tnl/__init__.py");
    expect(await readdir(stage)).toEqual(files.map((file) => path.basename(file)));
    for (const file of files) {
      const name = path.basename(file);
      expect(await readFile(path.join(stage, name))).toEqual(
        await readFile(path.join(source, name)),
      );
    }
    const incomplete = path.join(stage, "incomplete");
    await mkdir(incomplete);
    await writeFile(path.join(incomplete, "__init__.py"), "");
    await expect(copyPythonPackage(incomplete, stage)).rejects.toThrow("PEP 561 type marker");
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
});
