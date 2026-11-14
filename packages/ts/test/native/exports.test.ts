import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { expect, test } from "vitest";

const directory = fileURLToPath(new URL("../../", import.meta.url));

test("import and require share errors, workload configuration, and deployment clients", () => {
  execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `
    import assert from 'node:assert/strict';
    import {createRequire} from 'node:module';
    import * as esm from '@tnldotdev/tnl';
    import * as workload from '@tnldotdev/tnl/workload';
    const require = createRequire(import.meta.url);
    const cjs = require('@tnldotdev/tnl');
    assert.equal(cjs.tnl, esm.tnl);
    assert.equal(cjs.TnlError, esm.TnlError);
    assert.equal(esm.tnl.port, 3000);
    assert.equal(esm.tnl.dev, false);
    assert.throws(() => esm.tnl.services, e => e instanceof esm.TnlError && e.code === 'sdk.service_unprepared');
    assert.equal(cjs.createClient, esm.createClient);
    assert.equal(typeof esm.createClient, 'function');
    assert.equal('connect' in esm.tnl, false);
    assert.equal('client' in esm.tnl, false);
    assert.equal('open' in esm.tnl, false);
    const token = async () => 'request-scoped-assertion';
    workload.configureWorkload({name:'worker', token});
    require('@tnldotdev/tnl/workload').configureWorkload({name:'worker', token});
    assert.throws(() => workload.configureWorkload({name:'worker', token:async()=> 'replacement'}), e => e instanceof esm.TnlError && e.code === 'sdk.workload_required');
  `,
    ],
    {
      cwd: directory,
      env: { ...process.env, TNL_PROJECT_RUNTIME: undefined, TNL_CONNECTION_HANDLE: undefined },
    },
  );
});

test("browser exports reject connections without loading native or provider modules", async () => {
  execFileSync(
    process.execPath,
    [
      "--conditions=browser",
      "--input-type=module",
      "--eval",
      `
    import assert from 'node:assert/strict';
    import {createRequire} from 'node:module';
    import * as esm from '@tnldotdev/tnl';
    const cjs = createRequire(import.meta.url)('@tnldotdev/tnl');
    assert.equal(cjs.tnl, esm.tnl);
    assert.equal('connect' in esm.tnl, false);
    assert.equal('client' in esm.tnl, false);
    assert.throws(() => esm.createClient({project:'team/project'}), e => e instanceof esm.TnlError && e.code === 'sdk.connection_server_only');
  `,
    ],
    { cwd: directory },
  );
  for (const contents of [
    'import {tnl} from "@tnldotdev/tnl"; globalThis.project = tnl;',
    'globalThis.project = require("@tnldotdev/tnl").tnl;',
  ]) {
    const result = await build({
      stdin: { contents, resolveDir: directory },
      bundle: true,
      write: false,
      platform: "browser",
      format: "iife",
      metafile: true,
    });
    expect(
      Object.keys(result.metafile.inputs).filter((input) =>
        /internal\/(?:connector\/|native\/)|@vercel|undici/.test(input),
      ),
    ).toEqual([]);
  }
  for (const contents of [
    'import {configureWorkload} from "@tnldotdev/tnl/workload"; configureWorkload({name:"worker", token:async()=>"secret"});',
    'globalThis.workload = require("@tnldotdev/tnl/workload");',
  ]) {
    await expect(
      build({
        stdin: { contents, resolveDir: directory },
        bundle: true,
        write: false,
        platform: "browser",
        logLevel: "silent",
      }),
    ).rejects.toThrow('Could not resolve "@tnldotdev/tnl/workload"');
  }
});
