import { createRequire } from "node:module";

const requireConnection = createRequire(import.meta.url);

/** both server roots use one lazy CommonJS connection state. */
export function loadConnection(): typeof import("./connection.js") {
  return requireConnection("./connection.cjs") as typeof import("./connection.js");
}
