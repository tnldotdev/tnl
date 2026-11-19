import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { build } from "esbuild";
import { build as viteBuild } from "vite";
import { expect, test, vi } from "vitest";
import tnlVite from "@tnldotdev/tnl/vite";

const directory = fileURLToPath(new URL("../../", import.meta.url));
const compiler = join(
  dirname(createRequire(import.meta.url).resolve("typescript/package.json")),
  "bin/tsc",
);
const nativeInput =
  /node:|internal\/(?:native\/|publisher\/|connector\/(?:client\.|connection[_.]|management\.|workload\/))|@vercel|undici/;

test("the package root has no runtime operations or legacy entry points", () => {
  execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `
    import assert from 'node:assert/strict';
    import * as root from '@tnldotdev/tnl';
    assert.deepEqual(Object.keys(root).sort(), ['TnlError', 'response']);
    for (const legacy of ['http', 'durable-object']) {
      await assert.rejects(import('@tnldotdev/tnl/' + legacy), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
    }
  `,
    ],
    { cwd: directory },
  );
});

test("import and require share errors, workload configuration, and deployment clients", () => {
  execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `
    import assert from 'node:assert/strict';
    import {createRequire} from 'node:module';
    import * as esm from '@tnldotdev/tnl/node';
    import * as workload from '@tnldotdev/tnl/workload';
    const require = createRequire(import.meta.url);
    const cjs = require('@tnldotdev/tnl/node');
    assert.equal(cjs.tnl, esm.tnl);
    assert.equal(cjs.TnlError, esm.TnlError);
    assert.equal(esm.tnl.port, 3000);
    assert.equal(esm.tnl.dev, false);
    assert.throws(() => esm.tnl.services, e => e instanceof esm.TnlError && e.code === 'sdk.service_unprepared');
    assert.equal(cjs.deployment, esm.deployment);
    assert.equal(typeof esm.deployment, 'function');
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
    import * as esm from '@tnldotdev/tnl/browser';
    const cjs = createRequire(import.meta.url)('@tnldotdev/tnl/browser');
    assert.equal(cjs.tnl, esm.tnl);
    assert.equal('connect' in esm.tnl, false);
    assert.equal('client' in esm.tnl, false);
    const options = {project:'team/project', token:'private'};
    await esm.deployment('production', options).close();
    assert.throws(() => esm.deployment('local', options), e => e instanceof esm.TnlError && e.code === 'sdk.capability_unsupported');
  `,
    ],
    { cwd: directory },
  );
  for (const contents of [
    'import {tnl} from "@tnldotdev/tnl/browser"; globalThis.project = tnl;',
    'globalThis.project = require("@tnldotdev/tnl/browser").tnl;',
  ]) {
    const result = await build({
      stdin: { contents, resolveDir: directory },
      bundle: true,
      write: false,
      platform: "browser",
      format: "iife",
      logOverride: { "empty-import-meta": "silent" }, // the metadata test never starts a loader
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
        'import {deployment} from "@tnldotdev/tnl/browser"; globalThis.app = deployment("production", {project:"team/project", token:"private", services:{db:{protocol:"postgres"}}});',
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

test("packed consumers only bundle their selected runtime and WASM capability", async () => {
  // resolve the packed package from a separate consumer directory, with the
  // repository's installed dependencies available through the resolver.
  const consumer = await mkdtemp(join(tmpdir(), "tnl-packed-entries-"));
  try {
    const dependencies = join(consumer, "node_modules");
    const packageRoot = join(dependencies, "@tnldotdev/tnl");
    await mkdir(packageRoot, { recursive: true });
    execFileSync("npm", ["pack", "--ignore-scripts", "--pack-destination", consumer], {
      cwd: directory,
      stdio: "pipe",
    });
    const archive = (await readdir(consumer)).find((file) => file.endsWith(".tgz"));
    if (archive === undefined) throw new Error("missing packed SDK");
    execFileSync("tar", [
      "-xzf",
      join(consumer, archive),
      "--strip-components=1",
      "-C",
      packageRoot,
    ]);
    for (const [path, operation, modules] of [
      ["control", "listDeployments", []],
      ["browser", "connect", ["connector.wasm"]],
      ["browser", "publish", ["publisher.wasm"]],
      ["cloudflare", "connect", ["connector.wasm"]],
      ["cloudflare", "TnlPublisher", ["publisher.wasm"]],
    ] as const) {
      const result = await build({
        stdin: {
          contents: `import {${operation}} from "@tnldotdev/tnl/${path}"; globalThis.operation = ${operation};`,
          resolveDir: consumer,
        },
        nodePaths: [join(directory, "node_modules"), join(directory, "../../node_modules")],
        bundle: true,
        write: false,
        format: "esm",
        platform: "browser",
        conditions: path === "cloudflare" ? ["workerd"] : ["browser"],
        external: path === "cloudflare" ? ["cloudflare:workers"] : [],
        loader: { ".wasm": "file" },
        assetNames: "[name]",
        outdir: "unused",
        metafile: true,
        minify: true,
      });
      const outputs = result.outputFiles;
      const text = outputs
        .filter((file) => !file.path.endsWith(".wasm"))
        .map((file) => file.text)
        .join("");
      const found = ["connector.wasm", "publisher.wasm"].filter(
        (file) =>
          outputs.some((output) => output.path.endsWith(`/${file}`)) || text.includes(`/${file}`),
      );
      expect(found, path + ":" + operation).toEqual(modules);
      expect(
        Object.keys(result.metafile.inputs).filter((input) => nativeInput.test(input)),
      ).toEqual([]);
    }
  } finally {
    await rm(consumer, { recursive: true, force: true });
  }
}, 60_000);

test("the Vite integration emits only the browser WASM used by live chunks", async () => {
  const root = await mkdtemp(join(tmpdir(), "tnl-vite-entries-"));
  try {
    await writeFile(join(root, "index.html"), '<script type="module" src="/entry.js"></script>');
    const browser = JSON.stringify(join(directory, "dist/browser.js"));
    for (const [names, modules] of [
      ["tnl", []],
      ["connect", ["connector"]],
      ["publish", ["publisher"]],
      ["connect, publish", ["connector", "publisher"]],
    ] as const) {
      await writeFile(
        join(root, "entry.js"),
        `import { ${names} } from ${browser}; globalThis.used = { ${names} };`,
      );
      const result = await viteBuild({
        root,
        configFile: false,
        logLevel: "silent",
        plugins: [tnlVite()],
        build: { write: false },
      });
      const outputs = (Array.isArray(result) ? result : [result]).flatMap((item) =>
        "output" in item ? item.output : [],
      );
      const assets = outputs.filter((item) => item.type === "asset");
      const wasm = assets.filter((asset) => asset.fileName.endsWith(".wasm"));
      expect(wasm.map((asset) => asset.names[0]?.replace(/\.wasm$/, "")).sort(), names).toEqual(
        modules,
      );
      for (const asset of wasm) {
        expect(
          outputs.some((item) => item.type === "chunk" && item.code.includes(asset.fileName)),
        ).toBe(true);
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}, 60_000);
