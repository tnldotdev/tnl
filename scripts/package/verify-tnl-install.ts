import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { npmPackageMetadataSchema } from "./npm-artifacts.ts";
import { parseJSON } from "./validation.ts";

assert(process.argv[2], "usage: verify-tnl-install.ts PACKAGE_DIRECTORY");
const directory = path.resolve(process.argv[2]);
const metadata = parseJSON(
  await readFile(path.join(directory, "tnl-npm-packages.json"), "utf8"),
  npmPackageMetadataSchema,
  "npm packages",
);
const launcher = metadata.packages.find((p) => p.kind === "launcher");
assert(launcher, "missing launcher package");
const overrides = Object.fromEntries(
  metadata.packages
    .filter((p) => p.kind === "native")
    .map((p) => [p.name, `file:${path.join(directory, p.tarball)}`]),
);
for (const manager of ["npm", "pnpm"]) {
  const consumer = await mkdtemp(path.join(tmpdir(), `tnl-${manager}-`));
  try {
    await writeFile(
      path.join(consumer, "package.json"),
      JSON.stringify({
        private: true,
        dependencies: { "@tnldotdev/tnl": `file:${path.join(directory, launcher.tarball)}` },
        overrides,
      }),
    );
    await writeFile(
      path.join(consumer, "pnpm-workspace.yaml"),
      JSON.stringify({ packages: [], autoInstallPeers: false, overrides }),
    );
    execFileSync(
      manager,
      [
        "install",
        "--ignore-scripts",
        ...(manager === "npm" ? ["--legacy-peer-deps", "--no-audit", "--no-fund"] : []),
      ],
      { cwd: consumer, stdio: "inherit" },
    );
    const version = execFileSync(path.join(consumer, "node_modules/.bin/tnl"), ["version"], {
      encoding: "utf8",
    });
    assert.equal(version, `tnl ${metadata.version} (${metadata.commit})\n`);
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `
      import assert from 'node:assert/strict';
      import {createRequire} from 'node:module';
      import {tnl, TnlError} from '@tnldotdev/tnl';
      import {defineConfig} from '@tnldotdev/tnl/config';
      import {withTnl} from '@tnldotdev/tnl/next';
      import vite from '@tnldotdev/tnl/vite';
      import {configureWorkload} from '@tnldotdev/tnl/workload';
      assert.equal(createRequire(import.meta.url)('@tnldotdev/tnl').tnl, tnl);
      assert.equal(typeof TnlError, 'function');
      for (const value of [tnl.prepare, tnl.open, tnl.connect, defineConfig, withTnl, vite, configureWorkload]) assert.equal(typeof value, 'function');
    `,
      ],
      { cwd: consumer, stdio: "inherit" },
    );
  } finally {
    await rm(consumer, { recursive: true, force: true });
  }
}
