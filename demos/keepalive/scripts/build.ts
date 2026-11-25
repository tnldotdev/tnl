import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { build } from "esbuild";
import { build as buildPage } from "vite";
import { parseArgs } from "node:util";
import { WASM_PATH, WORKER_PATH, digest, parseRelease, type Asset } from "../src/release.ts";

const demo = path.resolve(import.meta.dirname, "..");
const { values } = parseArgs({ options: { fleet: { type: "string", default: "prod" } } });
if (values.fleet !== "prod" && values.fleet !== "ramp")
  throw new Error("Use --fleet prod or ramp.");
const dist = path.join(demo, values.fleet === "prod" ? "dist" : "dist-ramp");
const define = { KEEPALIVE_FLEET: JSON.stringify(values.fleet) };
const output = path.join(dist, "site");
const wasm = path.join(demo, "../../packages/ts/dist/wasm/publisher.wasm");
const options = { absWorkingDir: demo, bundle: true, format: "esm", minify: true } as const;

await buildPage({
  configFile: path.join(demo, "vite.config.ts"),
  build: { outDir: output },
  define,
});
const index = await readFile(path.join(output, "index.html"), "utf8");
await writeFile(path.join(output, "start.html"), index.replace('id="app"', 'id="app" data-start'));
await mkdir(path.join(output, "hosting/wasm"), { recursive: true });
await Promise.all([
  build({
    ...options,
    entryPoints: ["src/hosting/worker.ts"],
    outfile: path.join(output, WORKER_PATH),
    // a blob Worker has no relative module path. this is the SDK asset base;
    // the worker reads the WASM from its verified local copy, not this URL.
    define: {
      ...define,
      "import.meta.url": "keepaliveModuleURL",
      KEEPALIVE_RAMP_UPLOAD_TRACE: JSON.stringify(values.fleet === "ramp"),
    },
    banner: {
      js: "const keepaliveModuleURL = new URL('/hosting/worker.js', self.location.origin).href;",
    },
  }),
  copyFile(wasm, path.join(output, WASM_PATH)),
]);

const assets = await Promise.all(
  [
    "/app.js",
    "/index.html",
    "/index.css",
    "/favicon.svg",
    "/jetbrains-mono-latin-wght-normal.woff2",
    WORKER_PATH,
    WASM_PATH,
  ].map(async (file): Promise<Asset> => {
    const bytes = await readFile(path.join(output, file));
    return { path: file, size: bytes.byteLength, sha256: await digest(bytes) };
  }),
);
const id = await digest(new TextEncoder().encode(JSON.stringify(assets)));
const release = await parseRelease({ id, assets });
await writeFile(path.join(dist, "release.json"), JSON.stringify(release) + "\n");
await build({
  ...options,
  entryPoints: ["src/edge/worker.ts"],
  outfile: path.join(dist, "worker.mjs"),
  define: {
    ...define,
    KEEPALIVE_RELEASE: JSON.stringify(release),
    KEEPALIVE_RAMP_PROXY_TRACE: JSON.stringify(values.fleet === "ramp"),
  },
});
