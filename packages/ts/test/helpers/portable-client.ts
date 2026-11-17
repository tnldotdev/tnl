// low-level lifecycle tests exercise the internal owner without a public runtime adapter.
import {
  createStreamClient,
  type StreamClientOptions,
} from "../../src/internal/connector/wasm_client.js";
import { loadWasm } from "../../src/internal/connector/wasm_loader.js";
import type { ServiceFacts } from "../../src/project.js";

export function createClient<const Services extends ServiceFacts = Record<never, never>>(
  options: StreamClientOptions<Services>,
) {
  return createStreamClient(options, (kind) =>
    loadWasm(
      new URL(
        kind === "publisher"
          ? "https://fixture.test/publisher.wasm"
          : "https://fixture.test/tnl.wasm",
      ),
    ),
  );
}
