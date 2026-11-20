import { describe, expect, it } from "vitest";
import { assertWasmAssets } from "./npm-artifacts.ts";

describe("packed WASM assets", () => {
  const assets = [
    "dist/wasm/connector.wasm",
    "dist/wasm/publisher.wasm",
    "dist/wasm/wasm_exec.js",
    "dist/wasm/go-license.txt",
    "dist/wasm/third-party-licenses.txt",
    "dist/wasm/build.json",
  ];
  it("requires the module, matching runtime, and license files", () => {
    expect(() => assertWasmAssets(new Set(assets))).not.toThrow();
  });
  it.each(assets)("rejects a package missing %s", (missing) => {
    expect(() => assertWasmAssets(new Set(assets.filter((file) => file !== missing)))).toThrow(
      `missing WASM asset ${missing}`,
    );
  });
});
