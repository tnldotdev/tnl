import { TnlError } from "../../errors.js";
import type { WasmBridge } from "./wasm_abi.js";

interface GoRuntime {
  argv: string[];
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}
type GoConstructor = new () => GoRuntime;

function isGoConstructor(value: unknown): value is GoConstructor {
  return typeof value === "function";
}

function isBridge(value: unknown): value is WasmBridge {
  return (
    typeof value === "object" &&
    value !== null &&
    (("createDeployment" in value && typeof value.createDeployment === "function") ||
      ("publish" in value && typeof value.publish === "function")) &&
    "close" in value &&
    typeof value.close === "function"
  );
}

let runtime: Promise<GoConstructor> | undefined;
function goConstructor(): Promise<GoConstructor> {
  runtime ??= import("../../wasm/wasm_exec.js")
    .then(() => {
      const value: unknown = Reflect.get(globalThis, "Go");
      if (!isGoConstructor(value)) throw new TnlError("sdk.wasm_unavailable");
      return value;
    })
    .catch(() => {
      runtime = undefined;
      throw new TnlError("sdk.wasm_unavailable");
    });
  return runtime;
}

// only immutable compiled code is shared. a deployment always receives a fresh
// go scheduler and private callback references, including in a worker isolate.
const compiled = new Map<string, Promise<WebAssembly.Module>>();
export async function compileWasm(response: Response): Promise<WebAssembly.Module> {
  // do not tee the large artifact for a fallback: an unread branch buffers the
  // entire download. invalid wasm cannot be repaired by compiling it twice.
  if (
    typeof WebAssembly.compileStreaming === "function" &&
    response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() === "application/wasm"
  )
    return WebAssembly.compileStreaming(response);
  return WebAssembly.compile(await response.arrayBuffer());
}
function browserModule(url: URL): Promise<WebAssembly.Module> {
  const key = url.href;
  const cached = compiled.get(key);
  if (cached !== undefined) return cached;
  const loading = (async () => {
    const response = await fetch(url, {
      credentials: "omit",
      redirect: "error",
      signal: AbortSignal.timeout(45_000),
    });
    if (!response.ok) throw new TnlError("sdk.wasm_unavailable");
    return compileWasm(response);
  })().catch(() => {
    compiled.delete(key);
    throw new TnlError("sdk.wasm_unavailable");
  });
  compiled.set(key, loading);
  return loading;
}

export interface WasmRuntime {
  readonly bridge: WasmBridge;
  readonly exited: Promise<void>;
}

// go registers synchronously before its first blocking wait. never await
// between clearing, running, capturing, and restoring the registration slot.
export async function startWasm(
  module: WebAssembly.Module,
  Go: GoConstructor,
): Promise<WasmRuntime> {
  try {
    const go = new Go();
    go.argv = ["tnl-wasm"];
    const instance = await WebAssembly.instantiate(module, go.importObject);
    const previous: unknown = Reflect.get(globalThis, "tnlWasm");
    let bridge: WasmBridge;
    let exited: Promise<void>;
    try {
      Reflect.deleteProperty(globalThis, "tnlWasm");
      exited = go.run(instance);
      void exited.catch(() => {});
      const registered: unknown = Reflect.get(globalThis, "tnlWasm");
      if (!isBridge(registered)) throw new TnlError("sdk.wasm_invalid");
      bridge = registered;
    } finally {
      if (previous === undefined) Reflect.deleteProperty(globalThis, "tnlWasm");
      else Reflect.set(globalThis, "tnlWasm", previous);
    }
    return { bridge, exited };
  } catch (error) {
    if (error instanceof TnlError) throw error;
    throw new TnlError("sdk.wasm_unavailable");
  }
}

export async function loadWasm(source: WebAssembly.Module | URL): Promise<WasmRuntime> {
  const [Go, selected] = await Promise.all([
    goConstructor(),
    source instanceof URL ? browserModule(source) : source,
  ]);
  return startWasm(selected, Go);
}
