import * as connection from "../../src/internal/connector/connection.js";

/** coverage uses the source singleton in place of the built CommonJS bridge. */
export function loadConnection(): typeof connection {
  return connection;
}
