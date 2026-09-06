import {
  canonicalLoopbackTarget,
  readDevelopmentContext,
  registerLocalTarget,
  requestTunnelAssignment,
  runtimePayload,
  type TnlTunnelAssignment,
} from "./internal/dev.js";
import type { Plugin } from "vite";

const runtimeDefineName = "process.env.TNL_PROJECT_RUNTIME";

/** Adds tnl project metadata and safe `tnl dev` routing to a Vite development server. */
export default function tnl(...arguments_: never[]): Plugin {
  if (arguments_.length !== 0) {
    throw new Error("tnl() does not accept tunnel options; use project configuration");
  }
  let assignment: TnlTunnelAssignment | null = null;
  let localPortRegistered = false;
  return {
    name: "tnl",
    enforce: "post",
    apply: "serve",
    async config(userConfig = {}, configEnvironment) {
      assignment = null;
      localPortRegistered = false;
      if (configEnvironment.command !== "serve" || configEnvironment.isPreview === true) {
        return undefined;
      }

      const development = readDevelopmentContext();
      if (development.bootstrap === null) {
        if (development.localProject === null) {
          return undefined;
        }
        return runtimeDefine(runtimePayload(development.localProject, false));
      }

      const server = userConfig.server ?? {};
      validateAllowedHosts(server.allowedHosts);
      assignment = await requestTunnelAssignment("vite", development.bootstrap);
      const result = {
        ...runtimeDefine(runtimePayload(assignment.project, true)),
        server: {
          allowedHosts: addAllowedHost(server.allowedHosts, assignment.hostname),
        },
      };
      if (development.bootstrap.port === undefined) {
        return result;
      }
      return {
        ...result,
        server: {
          ...result.server,
          port: development.bootstrap.port,
          // Let Vite report a fallback listener so tnl can reject it with the target diagnostic.
          strictPort: false,
        },
      };
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
        if (localPortRegistered) {
          return listening;
        }
        const address = server.httpServer?.address();
        if (address === null || address === undefined || typeof address === "string") {
          await server.close();
          throw new Error("Vite did not report its listening port to tnl dev");
        }
        try {
          await registerLocalTarget(
            configured,
            canonicalLoopbackTarget(address.address, address.port),
          );
          localPortRegistered = true;
        } catch (error) {
          await server.close();
          throw error;
        }
        return listening;
      };
    },
  };
}

function runtimeDefine(payload: string) {
  return {
    define: {
      [runtimeDefineName]: JSON.stringify(payload),
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
  return [...new Set([...(allowedHosts ?? []), hostname])];
}

function validateAllowedHosts(value: string[] | true | undefined): void {
  if (value !== undefined && value !== true && !Array.isArray(value)) {
    throw new Error("Vite server.allowedHosts must be an array or true when used with tnl");
  }
}
