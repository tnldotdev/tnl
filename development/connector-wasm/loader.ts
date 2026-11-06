import type { ConnectorBridge } from "./abi.ts";

interface GoRuntime {
  argv: string[];
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

type GoConstructor = new () => GoRuntime;

export interface ConnectorRuntime {
  bridge: ConnectorBridge;
  exited: Promise<void>;
  instantiateAndStartMs: number;
}

function hasPrepare(value: unknown): value is ConnectorBridge {
  return (
    typeof value === "object" &&
    value !== null &&
    "prepare" in value &&
    typeof value.prepare === "function"
  );
}

// load the unmodified wasm_exec.js copied from the pinned GOROOT before calling.
// go main registers the bridge synchronously before its first blocking wait.
export async function startConnectorWasm(module: WebAssembly.Module): Promise<ConnectorRuntime> {
  const globals = globalThis as typeof globalThis & {
    Go?: GoConstructor;
    tnlConnectorWasm?: unknown;
  };
  if (!globals.Go) throw new Error("load the pinned go wasm_exec.js runtime first");
  const go = new globals.Go();
  go.argv = ["connector-wasm"];
  const started = performance.now();
  const instance = await WebAssembly.instantiate(module, go.importObject);
  // registration is a synchronous rendezvous, not an isolate-global runtime.
  // no await occurs between clearing, starting, capturing, and restoring it, so
  // concurrent requests get their own go scheduler and callback references.
  const previous = globals.tnlConnectorWasm;
  let exited: Promise<void>;
  let bridge: ConnectorBridge;
  try {
    globals.tnlConnectorWasm = undefined;
    exited = go.run(instance);
    // callers may also await exited; prevent an unobserved rejection on setup failure.
    void exited.catch(() => {});
    if (!hasPrepare(globals.tnlConnectorWasm)) {
      throw new Error("go WASM did not register tnlConnectorWasm.prepare");
    }
    bridge = globals.tnlConnectorWasm;
  } finally {
    if (previous === undefined) delete globals.tnlConnectorWasm;
    else globals.tnlConnectorWasm = previous;
  }
  return {
    bridge,
    exited,
    instantiateAndStartMs: performance.now() - started,
  };
}
