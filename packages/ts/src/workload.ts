import { createRequire } from "node:module";

/** install once in server setup; the callback reads the current request. */
export type WorkloadOptions = Readonly<
  { name: string } & (
    | { token: () => Promise<string>; tokenFile?: never }
    | { tokenFile: string; token?: never }
  )
>;

const loadConnection = createRequire(import.meta.url);
export function configureWorkload(options: WorkloadOptions): void {
  const { configureWorkload: configure } = loadConnection(
    "./internal/connection.cjs",
  ) as typeof import("./internal/connection.js");
  configure(options);
}
