import { describe, expect, it, vi } from "vitest";
import { startConnectorWasm } from "./loader.ts";

const emptyModule = new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));

describe("standard go runtime loader with fake Go (not WASM connector integration)", () => {
  it("requires wasm_exec.js rather than implementing a second runtime", async () => {
    vi.stubGlobal("Go", undefined);
    await expect(startConnectorWasm(emptyModule)).rejects.toThrow(
      "load the pinned go wasm_exec.js",
    );
  });

  it("starts the module and retrieves its synchronously registered bridge", async () => {
    const bridge = { prepare: vi.fn() };
    const run = vi.fn(async () => {
      vi.stubGlobal("tnlConnectorWasm", bridge);
    });
    vi.stubGlobal("tnlConnectorWasm", undefined);
    vi.stubGlobal(
      "Go",
      class {
        argv: string[] = [];
        importObject = {};
        run = run;
      },
    );
    const runtime = await startConnectorWasm(emptyModule);
    expect(run).toHaveBeenCalledOnce();
    expect(runtime.bridge).toBe(bridge);
    await runtime.exited;
    expect(Reflect.get(globalThis, "tnlConnectorWasm")).toBeUndefined();
    const second = await startConnectorWasm(emptyModule);
    expect(second.bridge).toBe(bridge);
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("atomically captures distinct bridges for concurrent request-local runtimes", async () => {
    const previous = { unrelated: true };
    const bridges = [{ prepare: vi.fn() }, { prepare: vi.fn() }];
    let count = 0;
    vi.stubGlobal("tnlConnectorWasm", previous);
    vi.stubGlobal(
      "Go",
      class {
        argv: string[] = [];
        importObject = {};
        async run(): Promise<void> {
          vi.stubGlobal("tnlConnectorWasm", bridges[count++]);
        }
      },
    );
    const [first, second] = await Promise.all([
      startConnectorWasm(emptyModule),
      startConnectorWasm(emptyModule),
    ]);
    expect(first.bridge).toBe(bridges[0]);
    expect(second.bridge).toBe(bridges[1]);
    expect(first.bridge).not.toBe(second.bridge);
    expect(Reflect.get(globalThis, "tnlConnectorWasm")).toBe(previous);
  });

  it("rejects a module that never registered the agreed ABI", async () => {
    vi.stubGlobal("tnlConnectorWasm", undefined);
    vi.stubGlobal(
      "Go",
      class {
        argv: string[] = [];
        importObject = {};
        async run(): Promise<void> {}
      },
    );
    await expect(startConnectorWasm(emptyModule)).rejects.toThrow("did not register");
  });
});
