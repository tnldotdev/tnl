import { build, type Plugin } from "esbuild";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "../..");
const source = path.join(root, "packages/ts/src");
const output = path.join(root, "packages/ts/dist");

// node 22 supports requiring the shared, synchronous esm error module. keeping
// it external preserves TnlError identity across the lazy bridge and both roots.
function sharedErrors(specifier: string): Plugin {
  return {
    name: "shared-tnl-errors",
    setup(builder) {
      builder.onResolve({ filter: /(?:^|\/)errors\.js$/ }, () => ({
        path: specifier,
        external: true,
      }));
    },
  };
}

const lazyNodeImports: Plugin = {
  name: "lazy-node-imports",
  setup(builder) {
    builder.onResolve({ filter: /^\.\/internal\/publisher\/(app|open)\.js$/ }, (args) =>
      args.kind === "dynamic-import" ? { path: args.path, external: true } : undefined,
    );
  },
};

// the bridge stays external: its relative require is rooted in internal/connector/.
const connectionBridge: Plugin = {
  name: "connection-bridge",
  setup(builder) {
    builder.onResolve({ filter: /^\.\/internal\/connector\/connection_bridge\.js$/ }, (args) => ({
      path: args.path,
      external: true,
    }));
  },
};

for (const entry of ["index", "workload", "internal/connector/connection"]) {
  await build({
    entryPoints: [path.join(source, `${entry}.ts`)],
    outfile: path.join(output, `${entry}.cjs`),
    bundle: true,
    platform: "node",
    target: "node22.18",
    format: "cjs",
    packages: "external",
    define: { "import.meta.url": "__tnlModuleURL" },
    banner: { js: 'const __tnlModuleURL = require("node:url").pathToFileURL(__filename).href;' },
    plugins: [
      sharedErrors(entry === "internal/connector/connection" ? "../../errors.js" : "./errors.js"),
      lazyNodeImports,
      connectionBridge,
    ],
  });
}

// the browser entry has no native imports, including when a bundler chooses
// require under its browser condition.
await build({
  entryPoints: [path.join(source, "index.browser.ts")],
  outfile: path.join(output, "index.browser.cjs"),
  bundle: true,
  platform: "browser",
  target: "es2022",
  format: "cjs",
});
