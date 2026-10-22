import { loadConnection } from "./internal/connector/connection_bridge.js";

/** install once in server setup; the callback reads the current request. */
export type WorkloadOptions = Readonly<
  { name: string } & (
    | { token: () => Promise<string>; tokenFile?: never }
    | { tokenFile: string; token?: never }
  )
>;

export function configureWorkload(options: WorkloadOptions): void {
  const { configureWorkload: configure } = loadConnection();
  configure(options);
}
