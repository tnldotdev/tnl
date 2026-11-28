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
  assert.deepEqual(manifest.repository, {
    type: "git",
    url: "https://github.com/madebyentropy/tnl",
  });
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
       import {tnl, TnlError, deployment, client, publish} from '@tnldotdev/tnl/node';
      import {defineConfig} from '@tnldotdev/tnl/config';
      import {withTnl} from '@tnldotdev/tnl/next';
      import vite from '@tnldotdev/tnl/vite';
       import {configureWorkload} from '@tnldotdev/tnl/workload';
       import * as control from '@tnldotdev/tnl/control';
      const cjs = createRequire(import.meta.url)('@tnldotdev/tnl/node');
      assert.equal(cjs.tnl, tnl);
      assert.equal(typeof TnlError, 'function');
        for (const value of [tnl.prepare, deployment, defineConfig, withTnl, vite, configureWorkload]) assert.equal(typeof value, 'function');
        assert.equal('open' in tnl, false);
       assert.equal('connect' in tnl || 'client' in tnl, false);
       for (const name of ['control','createDeployment','listDeployments','getDeployment','updateDeployment','deleteDeployment','createPublisherEnrollment','listPublishers','getPublisher','revokePublisher']) assert.equal(typeof control[name], 'function');
       for (const root of [{tnl, TnlError, deployment, client, publish}, cjs]) {
          const deployment = root.deployment('local', {project:'team/project', services:{database:{protocol:'postgres'}}});
          assert.equal(typeof root.publish, 'function');
         const getClient = root.client(deployment, 'database', {
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
       const esm = await import('@tnldotdev/tnl/browser');
       const cjs = createRequire(import.meta.url)('@tnldotdev/tnl/browser');
       let transportAttempts = 0;
       const unexpectedTransport = () => {
         transportAttempts++;
         throw new Error('unstarted portable clients must not acquire transport');
       };
       globalThis.fetch = unexpectedTransport;
       globalThis.WebSocket = class {
         constructor() { unexpectedTransport(); }
       };
       for (const root of [esm, cjs]) {
         assert.equal('connect' in root.tnl || 'client' in root.tnl, false);
         const options = {project:'team/project', token:'private', services:{database:{protocol:'postgres'}}};
         const deployment = root.deployment('production', options);
         for (const method of ['connect', 'client', 'publish']) assert.equal(typeof root[method], 'function');
         await deployment.close();
         assert.throws(() => root.deployment('local', options), error => error instanceof root.TnlError && error.code === 'sdk.capability_unsupported');
       }
       assert.equal(transportAttempts, 0);
    `,
      ],
      { cwd: consumer, stdio: "inherit" },
    );
  } finally {
    await rm(consumer, { recursive: true, force: true });
  }
}
