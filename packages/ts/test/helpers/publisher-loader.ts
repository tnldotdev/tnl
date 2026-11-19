import type { WasmRuntime } from "../../src/internal/connector/wasm_loader.js";

declare global {
  interface Window {
    publisherRuntimeForTest: WasmRuntime;
  }
}

// only the go boundary is replaced. publication composition and indexeddb are
// the product implementation, including the default storage selection.
export async function loadWasm(): Promise<WasmRuntime> {
  return window.publisherRuntimeForTest;
}
