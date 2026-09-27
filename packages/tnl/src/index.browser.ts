import { parseRuntimePayload } from "./internal/runtime.js";
import type { TnlRuntime } from "./index.js";

declare const process: { readonly env?: { readonly TNL_PROJECT_RUNTIME?: string } } | undefined;

const runtime = parseRuntimePayload(
  typeof process === "undefined" ? undefined : process.env?.TNL_PROJECT_RUNTIME,
);

/** Browser-safe project metadata; listener registration is server-only. */
export const tnl: TnlRuntime = Object.freeze({
  ...runtime,
  port: 3000,
  dev: runtime?.dev ?? false,
  async register(): Promise<void> {
    throw new Error("tnl.register is available only on a development server");
  },
});
