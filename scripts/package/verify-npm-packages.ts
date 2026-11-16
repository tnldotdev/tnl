import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { npmPackageMetadataSchema, packageManifestSchema } from "./npm-artifacts.ts";
import { parseJSON } from "../validation.ts";

assert(process.argv[2], "usage: verify-npm-packages.ts PACKAGE_DIRECTORY");
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
for (const entry of metadata.packages.filter((p) => p.kind === "native")) {
  const manifest = parseJSON(
    execFileSync("tar", ["-xOzf", path.join(directory, entry.tarball), "package/package.json"], {
      encoding: "utf8",
    }),
    packageManifestSchema,
    "packed native manifest",
  );
  assert.deepEqual(manifest.repository, { type: "git", url: "https://github.com/tnldotdev/tnl" });
}
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
       import {tnl, TnlError, createClient} from '@tnldotdev/tnl';
      import {defineConfig} from '@tnldotdev/tnl/config';
      import {withTnl} from '@tnldotdev/tnl/next';
      import vite from '@tnldotdev/tnl/vite';
       import {configureWorkload} from '@tnldotdev/tnl/workload';
       import {createClient as createHttpClient, deployments, publishers} from '@tnldotdev/tnl/http';
      const cjs = createRequire(import.meta.url)('@tnldotdev/tnl');
      assert.equal(cjs.tnl, tnl);
      assert.equal(typeof TnlError, 'function');
        for (const value of [tnl.prepare, createClient, defineConfig, withTnl, vite, configureWorkload]) assert.equal(typeof value, 'function');
        assert.equal('open' in tnl, false);
       assert.equal('connect' in tnl || 'client' in tnl, false);
       assert.equal(typeof createHttpClient, 'function');
       for (const value of [deployments.create, deployments.list, deployments.get, deployments.update, deployments.delete, publishers.createEnrollment, publishers.list, publishers.get, publishers.revoke]) assert.equal(typeof value, 'function');
       for (const root of [{tnl, TnlError, createClient}, cjs]) {
          const deployment = root.createClient({project:'team/project', services:{database:{protocol:'postgres'}}}).deployment('local');
          assert.equal(typeof deployment.publish, 'function');
         const getClient = deployment.client('database', {
          create() { throw new Error('factory creation must remain lazy'); },
          close() { throw new Error('unstarted factory has no driver to close'); },
        });
         assert.equal(typeof getClient, 'function');
         await getClient.close();
         await assert.rejects(getClient(), error => error instanceof root.TnlError && error.code === 'sdk.client_closed');
         await deployment.close();
      }
    `,
      ],
      { cwd: consumer, stdio: "inherit" },
    );
    const publicationSmoke = path.join(consumer, "publication-smoke.ts");
    await writeFile(
      publicationSmoke,
      await readFile(
        new URL("../../packages/ts/test/fixtures/package-publication.ts", import.meta.url),
      ),
    );
    execFileSync(process.execPath, [publicationSmoke], {
      cwd: consumer,
      stdio: "inherit",
      timeout: 30_000,
    });
    execFileSync(
      process.execPath,
      [
        "--conditions=browser",
        "--input-type=module",
        "--eval",
        `
      import assert from 'node:assert/strict';
      import {createRequire} from 'node:module';
      const esm = await import('@tnldotdev/tnl');
      const cjs = createRequire(import.meta.url)('@tnldotdev/tnl');
      for (const root of [esm, cjs]) {
        assert.equal('connect' in root.tnl || 'client' in root.tnl, false);
        assert.throws(() => root.createClient({project:'team/project'}), error => error instanceof root.TnlError && error.code === 'sdk.connection_server_only');
      }
    `,
      ],
      { cwd: consumer, stdio: "inherit" },
    );
  } finally {
    await rm(consumer, { recursive: true, force: true });
  }
}
