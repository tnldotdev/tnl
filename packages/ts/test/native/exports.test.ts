import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { build } from "esbuild";
import { expect, test, vi } from "vitest";

const directory = fileURLToPath(new URL("../../", import.meta.url));
const compiler = join(
  dirname(createRequire(import.meta.url).resolve("typescript/package.json")),
  "bin/tsc",
);
const nativeInput =
  /node:|internal\/(?:native\/|publisher\/|connector\/(?:client\.|connection[_.]|management\.|workload\/))|@vercel|undici/;

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

test.each(["browser", "worker", "workerd"])(
  "%s consumers resolve portable declarations instead of native socket settings",
  (condition) => {
    execFileSync(
      process.execPath,
      [
        compiler,
        "--ignoreConfig",
        "--strict",
        "--skipLibCheck",
        "--noEmit",
        "--target",
        "es2022",
        "--module",
        "nodenext",
        "--lib",
        "dom,dom.iterable,esnext",
        "--customConditions",
        condition,
        "test/fixtures/portable-consumer.mts",
      ],
      { cwd: directory, stdio: "inherit", timeout: 10_000 },
    );
  },
);

test("browser exports construct portable clients without loading native or provider modules", async () => {
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
    const app = esm.createClient({project:'team/project', token:'private'});
    await app.deployment('production').close();
    assert.throws(() => app.deployment('local'), e => e instanceof esm.TnlError && e.code === 'sdk.capability_unsupported');
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
    expect(Object.keys(result.metafile.inputs).filter((input) => nativeInput.test(input))).toEqual(
      [],
    );
    const output = result.outputFiles[0]?.text;
    expect(output).toBeDefined();
    if (output === undefined) throw new Error("missing browser bundle");
    if (contents.startsWith("import")) expect(output).not.toContain("WebAssembly.instantiate");
    const fetch = vi.fn(() => {
      throw new Error("metadata must not fetch a WASM artifact");
    });
    const instantiate = vi.fn(() => {
      throw new Error("metadata must not instantiate WASM");
    });
    const sandbox = {
      fetch,
      WebAssembly: { instantiate },
      URL,
      Request,
      Response,
      Headers,
      AbortSignal,
      TextEncoder,
      TextDecoder,
    };
    runInNewContext(output, sandbox);
    expect(fetch).not.toHaveBeenCalled();
    expect(instantiate).not.toHaveBeenCalled();
    expect(Reflect.has(sandbox, "Go")).toBe(false);
  }
  const portable = await build({
    stdin: {
      contents:
        'import {createClient} from "@tnldotdev/tnl"; globalThis.app = createClient({project:"team/project", token:"private", services:{db:{protocol:"postgres"}}});',
      resolveDir: directory,
    },
    bundle: true,
    write: false,
    splitting: true,
    outdir: "unused",
    platform: "browser",
    format: "esm",
    metafile: true,
  });
  expect(Object.keys(portable.metafile.inputs).filter((input) => nativeInput.test(input))).toEqual(
    [],
  );
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
