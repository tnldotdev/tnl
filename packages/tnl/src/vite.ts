import { canonicalLoopbackTarget, runtimePayload, serviceHostnames } from "./internal/dev.js";
import type { Plugin } from "vite";
import { TnlError, TnlCleanupError, classifyTnlError } from "./errors.js";
import { prepareService, type PrepareOptions, type PreparedService } from "./internal/app.js";

const runtimeDefineName = "process.env.TNL_PROJECT_RUNTIME";

/** configures a Vite development server to register its listener and add project metadata. */
export default function tnl(options: PrepareOptions = {}): Plugin {
  let assignment: PreparedService | null = null;
  return {
    name: "tnl",
    enforce: "post",
    apply: "serve",
    async config(userConfig = {}, configEnvironment) {
      assignment = null;
      if (configEnvironment.command !== "serve" || configEnvironment.isPreview === true) {
        return undefined;
      }

      const server = userConfig.server ?? {};
      validateAllowedHosts(server.allowedHosts);
      assignment = await prepareService(options, "vite");
      const result = {
        ...runtimeDefine(runtimePayload(assignment, true)),
        server: {
          allowedHosts: serviceHostnames({
            hostname: assignment.hostname,
            project: assignment,
            service: assignment.service,
          }).reduce<string[] | true>(
            (hosts, hostname) => addAllowedHost(hosts, hostname),
            server.allowedHosts ?? [],
          ),
        },
      };
      return result;
    },
    configureServer(server) {
      const configured = assignment;
      if (configured === null) {
        return;
      }
      if (server.httpServer === null) {
        throw new TnlError("sdk.target_invalid");
      }
      const listener = server.httpServer;
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
          canonicalLoopbackTarget(address.address, address.port);
          await configured.register(listener);
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
