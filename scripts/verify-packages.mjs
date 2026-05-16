import { execFile } from "node:child_process";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const root = path.resolve(import.meta.dirname, "..");
const directory = await mkdtemp(path.join(tmpdir(), "tnl-packages-"));
const packageNames = ["@tnldotdev/dev", "@tnldotdev/next", "@tnldotdev/vite"];

try {
  const tarballs = {};
  for (const packageName of packageNames) {
    const before = new Set(await readdir(directory));
    await run("pnpm", ["--filter", packageName, "pack", "--pack-destination", directory], {
      cwd: root,
    });
    const filename = (await readdir(directory)).find(
      (entry) => entry.endsWith(".tgz") && !before.has(entry),
    );
    if (!filename) throw new Error(`${packageName} did not produce a tarball`);
    tarballs[packageName] = `file:${path.join(directory, filename)}`;
  }

  await writeFile(
    path.join(directory, "package.json"),
    JSON.stringify({
      private: true,
      dependencies: {
        ...tarballs,
        next: "16.3.3",
        react: "19.2.8",
        "react-dom": "19.2.8",
        vite: "8.2.2",
      },
    }),
  );
  await writeFile(
    path.join(directory, "pnpm-workspace.yaml"),
    `overrides:\n  "@tnldotdev/dev": "${tarballs["@tnldotdev/dev"]}"\n`,
  );
  await run("pnpm", ["install"], { cwd: directory });
  await run(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `await Promise.all(${JSON.stringify(packageNames)}.map((name) => import(name)));`,
    ],
    { cwd: directory },
  );
} finally {
  await rm(directory, { force: true, recursive: true });
}
