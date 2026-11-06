import { createRequire } from "node:module";

const requireConnection = createRequire(import.meta.url);

/** import and require consumers share one lazily loaded ESM connection state. */
export function loadConnection(): typeof import("./connection.js") {
  return requireConnection("./connection.js") as typeof import("./connection.js");
}
