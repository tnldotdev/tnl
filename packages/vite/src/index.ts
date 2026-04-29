import { readDevEnvironment, registerTarget } from "@tnldotdev/dev";
import type { Plugin } from "vite";

export default function tnl(): Plugin {
  return {
    name: "tnl",
    apply: "serve",
    async config(userConfig = {}, configEnvironment) {
      const session = readDevEnvironment();
      if (
        session === null ||
        configEnvironment.command !== "serve" ||
        configEnvironment.isPreview === true
      ) {
        return undefined;
      }

      const server = userConfig.server ?? {};
      const port = session.port ?? server.port ?? 5173;
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error("Vite server.port must be between 1 and 65535 when used with tnl");
      }
      const allowedHosts = addAllowedHost(server.allowedHosts, session.hostname);
      await registerTarget("vite", port);
      return {
        server: {
          host: "127.0.0.1",
          port,
          strictPort: true,
          allowedHosts,
        },
      };
    },
  };
}

function addAllowedHost(
  allowedHosts: string[] | true | undefined,
  hostname: string,
): string[] | true {
  if (allowedHosts === true) {
    return true;
  }
  if (allowedHosts !== undefined && !Array.isArray(allowedHosts)) {
    throw new Error("Vite server.allowedHosts must be an array or true when used with tnl");
  }
  return [...new Set([...(allowedHosts ?? []), hostname])];
}
