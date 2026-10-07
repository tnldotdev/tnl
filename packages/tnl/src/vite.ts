import {
  canonicalLoopbackTarget,
  readDevelopmentContext,
  registerLocalTarget,
  requestTunnelAssignment,
  runtimePayload,
  type TnlTunnelAssignment,
} from "./internal/dev.js";
import type { Plugin } from "vite";
import { TnlError, TnlCleanupError, classifyTnlError } from "./errors.js";

const runtimeDefineName = "process.env.TNL_PROJECT_RUNTIME";

/** Configures a Vite development server for `tnl dev` and adds project metadata. */
export default function tnl(...arguments_: never[]): Plugin {
  if (arguments_.length !== 0) {
    throw new TnlError("sdk.configuration_invalid");
  }
  let assignment: TnlTunnelAssignment | null = null;
  let registeredTarget: string | null = null;
  return {
    name: "tnl",
    enforce: "post",
    apply: "serve",
    async config(userConfig = {}, configEnvironment) {
      assignment = null;
      registeredTarget = null;
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
          // let Vite report a fallback listener so tnl can reject it with the target diagnostic.
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
        throw new TnlError("sdk.target_invalid");
      }
      const originalListen = server.listen.bind(server);
      server.listen = async (port, isRestart) => {
        let listening;
        try {
          listening = await originalListen(port, isRestart);
        } catch (error) {
          return await closeAfterFailure(server.close.bind(server), error);
        }
        try {
          const address = server.httpServer?.address();
          if (address === null || address === undefined || typeof address === "string") {
            throw new TnlError("sdk.listener_failed");
          }
          const target = canonicalLoopbackTarget(address.address, address.port);
          if (registeredTarget !== null) {
            if (registeredTarget !== target) {
              throw new TnlError("sdk.listener_failed");
            }
            return listening;
          }
          await registerLocalTarget(configured, target);
          registeredTarget = target;
        } catch (error) {
          return await closeAfterFailure(server.close.bind(server), error);
        }
        return listening;
      };
    },
  };
}

async function closeAfterFailure(close: () => Promise<void>, error: unknown): Promise<never> {
  try {
    await close();
  } catch (closeError) {
    throw new TnlCleanupError(error, closeError);
  }
  throw classifyTnlError(error, "sdk.listener_failed");
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
  if (
    value !== undefined &&
    value !== true &&
    (!Array.isArray(value) || !value.every((host) => typeof host === "string"))
  ) {
    throw new TnlError("sdk.configuration_invalid");
  }
}
