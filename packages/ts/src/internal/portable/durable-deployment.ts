import { TnlError } from "../../errors.js";
import { createStreamClient } from "../connector/wasm_client.js";
import { loadWasm } from "../connector/wasm_loader.js";
import type { PublisherStorageHost } from "./storage-host.js";

// the durable owner supplies its persisted opaque credential and storage host.
// go validates authority; this adapter only decodes the private transport value.
export function durablePublisherDeployment(
  context: {
    readonly configuration: { readonly project: string; readonly deployment: string };
    readonly identity: Uint8Array;
    readonly storageHost: PublisherStorageHost;
    readonly signal: AbortSignal;
  },
  module: WebAssembly.Module,
) {
  let token: string;
  try {
    if (
      !(context.identity instanceof Uint8Array) ||
      context.identity.byteLength === 0 ||
      context.identity.byteLength > 32 << 10
    )
      throw new TnlError("sdk.configuration_invalid");
    token = new TextDecoder("utf-8", { fatal: true }).decode(context.identity);
  } catch {
    throw new TnlError("sdk.configuration_invalid");
  }
  return createStreamClient(
    { project: context.configuration.project, token },
    () => loadWasm(module),
    {
      storageHost: context.storageHost,
      signal: context.signal,
    },
  ).deployment(context.configuration.deployment);
}
