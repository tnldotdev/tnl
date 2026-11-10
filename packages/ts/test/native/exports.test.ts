import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { expect, test } from "vitest";

const directory = fileURLToPath(new URL("../../", import.meta.url));

test("import and require share errors and lazy handles but own workload instances independently", () => {
  execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `
    import assert from 'node:assert/strict';
    import {createRequire} from 'node:module';
    import * as esm from '@tnldotdev/tnl';
    const require = createRequire(import.meta.url);
    const cjs = require('@tnldotdev/tnl');
    assert.equal(cjs.tnl, esm.tnl);
    assert.equal(cjs.TnlError, esm.TnlError);
    assert.equal(esm.tnl.port, 3000);
    assert.equal(esm.tnl.dev, false);
    assert.throws(() => esm.tnl.services, e => e instanceof esm.TnlError && e.code === 'sdk.service_unprepared');
    const handle = esm.tnl.connect('database');
    assert.equal(typeof handle.then, 'function');
    assert.equal(Object.getOwnPropertyDescriptor(handle, 'then').enumerable, false);
    assert.throws(() => ({...handle}), e => e instanceof esm.TnlError && e.code === 'sdk.connection_unprepared');
    const token = async () => 'request-scoped-assertion';
    assert.equal(cjs.createTnl, esm.createTnl);
    const first=esm.createTnl({credential:{workload:'worker',token}});
    const second=cjs.createTnl({credential:{workload:'worker',token:async()=> 'independent'}});
    assert.notEqual(first,second);
    assert.equal('configureWorkload' in esm,false);
    assert.throws(()=>require('@tnldotdev/tnl/workload'),{code:'ERR_PACKAGE_PATH_NOT_EXPORTED'});
    await assert.rejects(import('@tnldotdev/tnl/workload'),{code:'ERR_PACKAGE_PATH_NOT_EXPORTED'});
    await first.close();
    await second.close();
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
    const handle = esm.tnl.connect('database');
    assert.throws(() => ({...handle}), e => e instanceof esm.TnlError && e.code === 'sdk.connection_server_only');
    await assert.rejects(Promise.resolve(handle), e => e instanceof esm.TnlError && e.code === 'sdk.connection_server_only');
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
        /internal\/(?:connector\/(?!awaitable_connection\.)|native\/)|@vercel|undici/.test(input),
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
