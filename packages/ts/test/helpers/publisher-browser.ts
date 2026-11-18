import { deployment, publish, response } from "../../src/browser.js";
import type { WasmPublisherHost } from "../../src/internal/connector/wasm_abi.js";

export async function exerciseBrowserPublication() {
  const exited = Promise.withResolvers<void>();
  const completed = Promise.withResolvers<void>();
  let restored: number[] | undefined;
  let applicationResponse: string | undefined;
  const scope = JSON.stringify({
    control_url: "https://control.example.test",
    team_id: "tm_fixture",
    publisher_identity_id: "pub_fixture",
  });
  let runClosed = false;
  window.publisherRuntimeForTest = {
    exited: exited.promise,
    bridge: {
      async createDeployment() {
        throw new Error("publishing must not require connector authority");
      },
      async publish(_encoded: string, host: WasmPublisherHost) {
        const release = await host.storage.lock(scope, "certificate", host.signal);
        try {
          const record = await host.storage.read(scope, "certificate", 64, host.signal);
          restored = Array.from(record ?? []);
          await host.storage.write(scope, "certificate", new Uint8Array([1, 2, 3]), host.signal);
          await host.storage.sync(scope, "certificate", host.signal);
        } finally {
          await release();
        }
        applicationResponse = await (
          await host.fetch(new Request("https://app.example.test/"))
        ).text();
        return {
          public: true,
          url: "https://app.example.test",
          ready: Promise.resolve(),
          closed: completed.promise,
          async close() {
            runClosed = true;
            completed.resolve();
          },
        };
      },
      async close() {
        if (!runClosed) throw new Error("go runtime exited before publication joined");
        exited.resolve();
      },
    },
  };
  const production = deployment("production", {
    project: "acme/shop",
    token: "private-fixture-credential",
  });
  const publication = await publish(production, () => response("browser handler"));
  await publication.close();
  await production.close();
  return { restored, applicationResponse };
}
