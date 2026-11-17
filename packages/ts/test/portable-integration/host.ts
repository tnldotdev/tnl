import "../../dist/wasm/wasm_exec.js";
import { check, type PortableFixture } from "./fixture.ts";

let installed: PortableFixture | undefined;

// only the tnlwasmtest build accepts this private test host's disposable service
// CA. public createClient options and production trust stay unchanged; hostname
// checks, crypto, admission, and all stream operations still run in Go.
export function installFixtureHost(fixture: PortableFixture, fetcher?: typeof fetch): void {
  if (installed !== undefined) {
    check(
      installed.api_token === fixture.api_token &&
        installed.service_root_pem === fixture.service_root_pem,
      "one fixture host cannot mix independent topologies",
    );
    return;
  }
  const OriginalGo: unknown = Reflect.get(globalThis, "Go");
  check(typeof OriginalGo === "function", "the packaged Go runtime did not load");
  const Constructor = OriginalGo;
  function FixtureGo() {
    const runtime: unknown = Reflect.construct(Constructor, []);
    check(
      typeof runtime === "object" &&
        runtime !== null &&
        "run" in runtime &&
        typeof runtime.run === "function",
      "the packaged Go constructor returned an invalid runtime",
    );
    const run = runtime.run.bind(runtime);
    Reflect.set(runtime, "run", (instance: WebAssembly.Instance) => {
      const exited: unknown = run(instance);
      const bridge: unknown = Reflect.get(globalThis, "tnlWasm");
      check(
        typeof bridge === "object" &&
          bridge !== null &&
          "createDeployment" in bridge &&
          typeof bridge.createDeployment === "function",
        "the compiled Go connector did not register its real bridge",
      );
      const create = bridge.createDeployment.bind(bridge);
      Reflect.set(
        bridge,
        "createDeployment",
        (options: unknown, host: unknown, ...arguments_: unknown[]) => {
          check(typeof host === "object" && host !== null, "invalid SDK bridge host");
          return create(
            options,
            { ...host, __tnlTestServiceRootPEM: fixture.service_root_pem },
            ...arguments_,
          );
        },
      );
      return exited;
    });
    return runtime;
  }
  Reflect.set(globalThis, "Go", FixtureGo);
  if (fetcher !== undefined) Reflect.set(globalThis, "fetch", fetcher);
  installed = fixture;
}
