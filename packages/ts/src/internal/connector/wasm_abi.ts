import type { ServiceProtocol } from "../project/runtime.js";
import type { TnlFetch } from "../../project.js";
import type { PublisherStorageHost } from "../portable/storage-host.js";
import type { FetchHandler } from "../publisher/fetch_types.js";

// this is a binding boundary, not a second tunnel or credential protocol. go
// validates credentials and owns service selection, admission, tls, and renewal.
// cancellation rejects with name AbortError; other failures may carry a safe
// sdk error code. messages and causes are never forwarded by the ts binding.
export const WASM_CHUNK_BYTES = 64 * 1024;

export interface WasmDeploymentOptions {
  readonly project: string;
  readonly name: string;
  readonly credential?: string;
  readonly controlUrl?: string;
  readonly workload?: Readonly<{ name: string; sourceFingerprint: string }>;
  readonly services: readonly string[];
}

export interface WasmHost {
  readonly fetch: TnlFetch;
  readonly WebSocket: typeof globalThis.WebSocket;
  readonly assertion?: (signal: AbortSignal) => Promise<string>;
}

// one read and one write may run concurrently. close interrupts and joins them.
// no read or write crosses the boundary with more than WASM_CHUNK_BYTES.
export interface WasmByteStream {
  read(max: number): Promise<unknown>;
  write(bytes: Uint8Array): Promise<unknown>;
  closeWrite(): Promise<unknown>;
  close(): Promise<unknown>;
  startTls(): Promise<unknown>;
}

export interface WasmConnectionMetadata {
  readonly key: string;
  readonly protocol: ServiceProtocol;
  readonly hostname: string;
}

export interface WasmConnection {
  readonly metadata: unknown;
  open(signal: AbortSignal): Promise<unknown>;
  fetch(request: Request, signal: AbortSignal): Promise<unknown>;
  close(): Promise<unknown>;
}

export interface WasmDeployment {
  // repeated selection of the same binding returns its stable connection object.
  connect(name: string, signal: AbortSignal): Promise<unknown>;
  close(): Promise<unknown>;
}

export interface WasmPublisherHost {
  readonly fetch: FetchHandler;
  readonly controlFetch: TnlFetch;
  readonly storage: PublisherStorageHost;
  readonly signal: AbortSignal;
}

export interface WasmPublication {
  readonly url: unknown;
  readonly ready: PromiseLike<unknown>;
  readonly closed: PromiseLike<unknown>;
  close(): Promise<unknown>;
}

export interface WasmBridge {
  createDeployment?(
    options: WasmDeploymentOptions,
    host: WasmHost,
    signal: AbortSignal,
  ): Promise<unknown>;
  publish?(optionsJSON: string, host: WasmPublisherHost): Promise<unknown>;
  close(): Promise<unknown>;
}
