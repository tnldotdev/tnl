import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { expect, test } from "vitest";

test("browser publishing bundles no native process, listener, IPC, or provider implementation", async () => {
  const result = await build({
    entryPoints: [fileURLToPath(new URL("../../src/index.browser.ts", import.meta.url))],
    bundle: true,
    write: false,
    format: "esm",
    platform: "browser",
    external: ["../../wasm/wasm_exec.js"],
    metafile: true,
  });
  expect(
    Object.keys(result.metafile.inputs).filter((input) =>
      /node:|internal\/(?:native\/|publisher\/|connector\/(?:client\.|connection[_.]|management\.|workload\/))|@vercel|undici/.test(
        input,
      ),
    ),
  ).toEqual([]);
});
