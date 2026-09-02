import {
  publicTunnelEnvironment,
  readDevEnvironment,
  registerTarget,
  requestTunnelAssignment,
} from "@tnldotdev/dev";
import type { TnlOptionsInput, TnlTunnelAssignment } from "@tnldotdev/dev";
import type { Plugin } from "vite";

export type { TnlOptions, TnlOptionsContext, TnlOptionsInput, TnlWorktree } from "@tnldotdev/dev";

/**
 * Adds tnl support to the Vite development server. It does nothing during
 * builds, previews, or development started without `tnl dev`.
 */
export default function tnl(options: TnlOptionsInput = {}): Plugin {
  let assignment: TnlTunnelAssignment | null = null;
  let targetRegistered = false;
  return {
    name: "tnl",
    enforce: "post",
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
      assignment = await requestTunnelAssignment({ framework: "vite", options });
      if (assignment === null) {
        return undefined;
      }
      const result = {
        define: Object.fromEntries(
          Object.entries(publicTunnelEnvironment(assignment, "VITE_")).map(([name, value]) => [
            `import.meta.env.${name}`,
            JSON.stringify(value),
          ]),
        ),
        server: {
          host: "127.0.0.1",
          allowedHosts: addAllowedHost(server.allowedHosts, assignment.hostname),
        },
      };
      if (session.port !== undefined) {
        return {
          ...result,
          server: { ...result.server, port: session.port, strictPort: true },
        };
      }
      return result;
    },
    configureServer(server) {
      const configured = assignment;
      if (configured === null) {
        return;
      }
      if (server.httpServer === null) {
        throw new Error("Vite middleware mode cannot register a listening target with tnl dev");
      }
      const originalListen = server.listen.bind(server);
      server.listen = async (port, isRestart) => {
        const listening = await originalListen(port, isRestart);
        if (targetRegistered) {
          return listening;
        }
        const address = server.httpServer?.address();
        if (address === null || address === undefined || typeof address === "string") {
          await server.close();
          throw new Error("Vite did not report its listening port to tnl dev");
        }
        try {
          await registerTarget(configured, address.port);
          targetRegistered = true;
        } catch (error) {
          await server.close();
          throw error;
        }
        return listening;
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
