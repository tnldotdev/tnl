import { afterEach, expect, test, vi } from "vitest";
import { compileWasm, startWasm } from "../../src/internal/connector/wasm_loader.js";

afterEach(() => vi.unstubAllGlobals());

test.each(["application/wasm", "application/octet-stream"])(
  "artifact compilation consumes one body without an unused fallback tee: %s",
  async (contentType) => {
    const response = new Response(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]), {
      headers: { "content-type": contentType },
    });
    const clone = vi.spyOn(response, "clone");
    const streaming = vi.spyOn(WebAssembly, "compileStreaming");
    const module = await compileWasm(response);
    expect(module).toBeInstanceOf(WebAssembly.Module);
    expect(clone).not.toHaveBeenCalled();
    expect(response.bodyUsed).toBe(true);
    expect(streaming).toHaveBeenCalledTimes(contentType === "application/wasm" ? 1 : 0);
  },
);

test("concurrent deployments capture private Go instances and restore the global rendezvous", async () => {
  const module = await WebAssembly.compile(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
  const previous = { another: "runtime" };
  vi.stubGlobal("tnlWasm", previous);
  const instances: MockGo[] = [];
  class MockGo {
    argv: string[] = [];
    importObject = {};
    readonly exited = Promise.withResolvers<void>();
    readonly bridge = {
      createDeployment: vi.fn(),
      publish: vi.fn(),
      enrollPublisher: vi.fn(),
      close: vi.fn(async () => this.exited.resolve()),
    };
    constructor() {
      instances.push(this);
    }
    run(_instance: WebAssembly.Instance): Promise<void> {
      Reflect.set(globalThis, "tnlWasm", this.bridge);
      return this.exited.promise;
    }
  }
  const [a, b] = await Promise.all([startWasm(module, MockGo), startWasm(module, MockGo)]);
  expect(instances).toHaveLength(2);
  expect(a.bridge).not.toBe(b.bridge);
  expect(Reflect.get(globalThis, "tnlWasm")).toBe(previous);
  expect(instances.map((go) => go.argv)).toEqual([["tnl-wasm"], ["tnl-wasm"]]);
  await a.bridge.close();
  await a.exited;
  expect(instances[1]?.bridge.close).not.toHaveBeenCalled();
  await b.bridge.close();
  await b.exited;
});

test("invalid Go registration and thrown startup errors expose no runtime input", async () => {
  const module = await WebAssembly.compile(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
  class InvalidGo {
    argv: string[] = [];
    importObject = {};
    run(): Promise<void> {
      Reflect.set(globalThis, "tnlWasm", { createDeployment: "private credential" });
      return Promise.resolve();
    }
  }
  await expect(startWasm(module, InvalidGo)).rejects.toMatchObject({ code: "sdk.wasm_invalid" });
  expect(Reflect.has(globalThis, "tnlWasm")).toBe(false);
  class FailedGo extends InvalidGo {
    override run(): Promise<void> {
      throw new Error("private credential");
    }
  }
  const failed = startWasm(module, FailedGo);
  await expect(failed).rejects.toMatchObject({
    code: "sdk.wasm_unavailable",
  });
  await expect(failed).rejects.not.toHaveProperty("cause");
});
