import { realpathSync } from "node:fs";
import type { WorkloadConfiguration } from "./workload/provider.js";
import { TnlError } from "../../errors.js";
import type { OwnerIPC } from "./connection_ipc.js";
import type { SelectionOptions, WorkloadRequest } from "./workload/contract.js";

export interface NativeScope {
  readonly directory: string;
  readonly registry: string;
  readonly binary: string;
  readonly environment: Pick<
    NodeJS.ProcessEnv,
    "TNL_STATE_DIR" | "TNL_SERVER" | "TNL_CONNECTION_HANDLE"
  >;
  open(file: string): Promise<OwnerIPC>;
  select(
    args: string[],
    input: unknown,
    name: string,
    assertion: string | undefined,
    options: SelectionOptions,
  ): Promise<unknown>;
  workload(name: string, request: WorkloadRequest): Promise<unknown>;
  close?(): Promise<void>;
  entry?: { readonly file: string; readonly ipc: Promise<OwnerIPC> };
}

interface ConnectorContext {
  readonly workloads: Map<string, WorkloadConfiguration>;
}

declare global {
  var __tnlConnectorContextV2: ConnectorContext | undefined;
}

// copies share only workload setup. each deployment owns its IPC and cleanup.
export const context: ConnectorContext = (globalThis.__tnlConnectorContextV2 ??= {
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
