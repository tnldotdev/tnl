import type { TnlConfigInput } from "./config.gen.js";

export type * from "./config.gen.js";

/** Adds type checking to a version-1 tnl.config.ts configuration. */
export function defineConfig<const Config extends TnlConfigInput>(config: Config): Config {
  return config;
}
