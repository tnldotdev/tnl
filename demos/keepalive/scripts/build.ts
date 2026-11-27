import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { build, type BuildOptions } from "esbuild";
import { build as buildPage } from "vite";
import { parseArgs } from "node:util";
import { WASM_PATH, WORKER_PATH } from "../src/release.ts";
import { hostWordsEsbuild } from "./host-words.ts";
import { siteRelease } from "./release.ts";
import { startPage } from "./page.ts";
import { fleets } from "../src/fleets.ts";

const demo = path.resolve(import.meta.dirname, "..");
const { values } = parseArgs({ options: { fleet: { type: "string", default: "prod" } } });
if (values.fleet !== "prod" && values.fleet !== "ramp")
  throw new Error("Use --fleet prod or ramp.");
const dist = path.join(demo, values.fleet === "prod" ? "dist" : "dist-ramp");
const define = { KEEPALIVE_FLEET: JSON.stringify(values.fleet) };
const output = path.join(dist, "site");
const wasm = path.join(demo, "../../packages/ts/dist/wasm/publisher.wasm");
const options = {
  absWorkingDir: demo,
  bundle: true,
  format: "esm",
  minify: true,
  plugins: [hostWordsEsbuild],
} satisfies BuildOptions;

await buildPage({
  configFile: path.join(demo, "vite.config.ts"),
  build: { outDir: output },
  define,
});
const index = await readFile(path.join(output, "index.html"), "utf8");
await writeFile(path.join(output, "start.html"), startPage(index, fleets[values.fleet].site));
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
      KEEPALIVE_RAMP_ORIGIN_TRACE: JSON.stringify(values.fleet === "ramp"),
    },
    banner: {
      js: "const keepaliveModuleURL = new URL('/hosting/worker.js', self.location.origin).href;",
    },
  }),
  copyFile(wasm, path.join(output, WASM_PATH)),
]);

const release = await siteRelease(output);
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
