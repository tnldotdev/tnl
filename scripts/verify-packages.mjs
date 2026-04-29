import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const root = path.resolve(import.meta.dirname, "..");
const packages = ["@tnldotdev/dev", "@tnldotdev/next", "@tnldotdev/vite"];
const temporaryDirectory = await mkdtemp(path.join(tmpdir(), "tnl-packages-"));

try {
  await run("pnpm", ["clean"]);
  const tarballs = [];
  for (const packageName of packages) {
    const before = new Set(await readdir(temporaryDirectory));
    await run("pnpm", ["--filter", packageName, "pack", "--pack-destination", temporaryDirectory]);
    const added = (await readdir(temporaryDirectory)).filter(
      (entry) => entry.endsWith(".tgz") && !before.has(entry),
    );
    assert.equal(added.length, 1, `${packageName} did not produce exactly one tarball`);
    const tarball = path.join(temporaryDirectory, added[0]);
    await verifyTarball(packageName, tarball);
    tarballs.push(tarball);
  }

  await verifyConsumer(tarballs);
} finally {
  await run("pnpm", ["clean"]);
  await rm(temporaryDirectory, { force: true, recursive: true });
}

async function verifyTarball(packageName, tarball) {
  const { stdout } = await run("tar", ["-tzf", tarball]);
  const entries = stdout.trim().split("\n");
  for (const required of [
    "package/LICENSE",
    "package/README.md",
    "package/dist/index.d.ts",
    "package/dist/index.js",
    "package/package.json",
  ]) {
    assert(entries.includes(required), `${packageName} tarball is missing ${required}`);
  }

  const forbidden = entries.filter(
    (entry) =>
      entry.startsWith("package/fixtures/") ||
      entry.startsWith("package/src/") ||
      entry.includes(".test.") ||
      entry.includes("test-helper") ||
      entry.includes("type-test") ||
      entry.endsWith("tsconfig.json") ||
      entry.endsWith(".tsbuildinfo"),
  );
  assert.deepEqual(forbidden, [], `${packageName} tarball contains development files`);

  const { stdout: license } = await run("tar", ["-xOzf", tarball, "package/LICENSE"]);
  assert.match(license, /^MIT License\n/);

  const { stdout: manifestText } = await run("tar", ["-xOzf", tarball, "package/package.json"]);
  const manifest = JSON.parse(manifestText);
  assert.equal(manifest.license, "MIT");
  assert(!manifestText.includes("workspace:"), `${packageName} contains a workspace dependency`);
}

async function verifyConsumer(tarballs) {
  const localPackages = Object.fromEntries(
    packages.map((packageName, index) => [packageName, `file:${tarballs[index]}`]),
  );
  await writeFile(
    path.join(temporaryDirectory, "package.json"),
    `${JSON.stringify(
      {
        private: true,
        dependencies: {
          ...localPackages,
          next: "16.3.3",
          react: "19.2.8",
          "react-dom": "19.2.8",
          vite: "8.2.2",
        },
      },
      null,
      2,
    )}\n`,
  );
  await writeFile(
    path.join(temporaryDirectory, "pnpm-workspace.yaml"),
    `overrides:\n  "@tnldotdev/dev": "${localPackages["@tnldotdev/dev"]}"\n`,
  );
  await run("pnpm", ["--dir", temporaryDirectory, "install"]);

  await writeFile(
    path.join(temporaryDirectory, "consumer.ts"),
    `import type { Plugin } from "vite";
import { readDevEnvironment, registerTarget, type RegisteredTnlDevSession, type TnlDevSession } from "@tnldotdev/dev";
import { withTnl, type NextConfigFactory } from "@tnldotdev/next";
import tnl from "@tnldotdev/vite";

const session: TnlDevSession | null = readDevEnvironment({});
const registered: Promise<RegisteredTnlDevSession | null> = registerTarget("vite", 5173, {});
const nextConfig: NextConfigFactory = withTnl(async (_phase, { defaultConfig }) => defaultConfig);
const vitePlugin: Plugin = tnl();

export { nextConfig, registered, session, vitePlugin };
`,
  );
  await writeFile(
    path.join(temporaryDirectory, "tsconfig.json"),
    `${JSON.stringify(
      {
        compilerOptions: {
          lib: ["DOM", "DOM.Iterable", "ESNext"],
          module: "NodeNext",
          moduleResolution: "NodeNext",
          noEmit: true,
          skipLibCheck: true,
          strict: true,
          target: "ES2022",
        },
        files: ["consumer.ts"],
      },
      null,
      2,
    )}\n`,
  );
  await run("pnpm", ["exec", "tsc", "--project", path.join(temporaryDirectory, "tsconfig.json")]);

  await writeFile(
    path.join(temporaryDirectory, "consumer.mjs"),
    `import { readDevEnvironment } from "@tnldotdev/dev";
import { withTnl } from "@tnldotdev/next";
import tnl from "@tnldotdev/vite";

if (readDevEnvironment({}) !== null || typeof withTnl() !== "function" || tnl().name !== "tnl") {
  throw new Error("installed package exports are invalid");
}
`,
  );
  await run(process.execPath, [path.join(temporaryDirectory, "consumer.mjs")], temporaryDirectory);
}

async function run(command, arguments_, cwd = root) {
  try {
    return await execFileAsync(command, arguments_, {
      cwd,
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch (error) {
    if (typeof error === "object" && error !== null) {
      if ("stdout" in error && error.stdout) {
        process.stdout.write(String(error.stdout));
      }
      if ("stderr" in error && error.stderr) {
        process.stderr.write(String(error.stderr));
      }
    }
    throw error;
  }
}
