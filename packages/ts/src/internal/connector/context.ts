import { realpathSync } from "node:fs";
import type { TnlFetch } from "../../project.js";
import type { WorkloadConfiguration } from "./workload/provider.js";
import { TnlError } from "../../errors.js";
import type { OwnerIPC } from "./connection_ipc.js";

export interface NativeScope {
  readonly registry: string;
  readonly binary: string;
  readonly environment: Pick<
    NodeJS.ProcessEnv,
    "TNL_STATE_DIR" | "TNL_SERVER" | "TNL_CONNECTION_HANDLE"
  >;
  readonly requests: Map<string, Promise<unknown>>;
  open(file: string): Promise<OwnerIPC>;
  select(
    args: string[],
    input: unknown,
    name: string,
    assertion: string | undefined,
    options: { workload?: string; manifest?: string; requested_at: string },
  ): Promise<unknown>;
  entry?: { readonly file: string; readonly ipc: Promise<OwnerIPC> };
  selected?: { readonly file: string; readonly expiresAt: number };
}

export interface CachedIPC {
  readonly loading: Promise<OwnerIPC>;
  active: number;
  failed?: boolean;
  expiresAt?: number;
  timer?: ReturnType<typeof setTimeout>;
}

interface ConnectorContext {
  readonly scopes: Map<string, Promise<NativeScope>>;
  readonly selectedScopes: Map<string, Map<string, NativeScope>>;
  readonly fetches: Map<string, TnlFetch>;
  readonly external: Map<string, CachedIPC>;
  readonly workloads: Map<string, WorkloadConfiguration>;
}

declare global {
  var __tnlConnectorContextV1: ConnectorContext | undefined;
}

// this version describes the shared in-memory shape, not the native wire schema.
// independently loaded compatible SDK copies share waits, IPC, and cleanup.
export const context: ConnectorContext = (globalThis.__tnlConnectorContextV1 ??= {
  scopes: new Map(),
  selectedScopes: new Map(),
  fetches: new Map(),
  external: new Map(),
  workloads: new Map(),
});

export function contextKey(): string {
  try {
    return JSON.stringify([
      realpathSync(process.cwd()),
      process.env.TNL_STATE_DIR,
      process.env.TNL_SERVER,
      process.env.TNL_CONNECTION_HANDLE,
    ]);
  } catch {
    throw new TnlError("sdk.configuration_invalid");
  }
}
