import "../../src/wasm/wasm_exec.js";
import { check, type PublisherFixture } from "./fixture.ts";

let installed = false;
let starts = 0;
export function runtimeStarts(): number {
  return starts;
}

// only the tnlwasmtest artifact accepts this private connector issuer. production
// trust is unchanged; go still owns identity, publication, certificate storage,
// tls, authorization and streams.
export function installPublisherFixtureHost(fixture: PublisherFixture): void {
  if (installed) return;
  const OriginalGo: unknown = Reflect.get(globalThis, "Go");
  check(typeof OriginalGo === "function", "packaged Go runtime was not loaded");
  const Go = OriginalGo;
  function FixtureGo() {
    const runtime: unknown = Reflect.construct(Go, []);
    check(
      typeof runtime === "object" &&
        runtime !== null &&
        "run" in runtime &&
        typeof runtime.run === "function",
      "invalid packaged Go runtime",
    );
    const run = runtime.run.bind(runtime);
    Reflect.set(runtime, "run", (instance: WebAssembly.Instance) => {
      const exited: unknown = run(instance);
      const bridge: unknown = Reflect.get(globalThis, "tnlWasm");
      check(
        typeof bridge === "object" &&
          bridge !== null &&
          "publish" in bridge &&
          typeof bridge.publish === "function" &&
          "createDeployment" in bridge &&
          typeof bridge.createDeployment === "function",
        "actual Go/WASM publisher bridge was not registered",
      );
      starts++;
      const create = bridge.createDeployment.bind(bridge);
      Reflect.set(
        bridge,
        "createDeployment",
        (options: unknown, host: unknown, ...rest: unknown[]) => {
          check(typeof host === "object" && host !== null, "invalid connector host");
          return create(
            options,
            { ...host, __tnlTestServiceRootPEM: fixture.service_root_pem },
            ...rest,
          );
        },
      );
      return exited;
    });
    return runtime;
  }
  Reflect.set(globalThis, "Go", FixtureGo);
  installed = true;
}
