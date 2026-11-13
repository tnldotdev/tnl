import { serviceHostnames, serializeRuntimePayload } from "./internal/project/runtime.js";
import { canonicalLoopbackTarget } from "./internal/publisher/target.js";
import type { Plugin } from "vite";
import { TnlError, TnlCleanupError, classifyTnlError } from "./errors.js";
import type { PreparedService } from "./internal/publisher/app.js";
import {
  closeFramework,
  frameworkOperation,
  frameworkOptions,
  localRuntimePayload,
  prepareFramework,
  type FrameworkOptions,
} from "./internal/publisher/framework.js";
import { operation } from "./internal/tracing.js";
import * as z from "zod";
import { parseValue } from "./internal/validation.js";

const runtimeDefineName = "process.env.TNL_PROJECT_RUNTIME";
const allowedHostsSchema = z.union([z.literal(true), z.array(z.string())]).optional();

/** configures a Vite development server to register its listener and add project metadata. */
export type { FrameworkOptions } from "./internal/publisher/framework.js";

export default function tnl(options: FrameworkOptions = {}): Plugin {
  let assignment: PreparedService | null = null;
  let preview: ReturnType<typeof frameworkOptions>["preview"] = "auto";
  return {
    name: "tnl",
    enforce: "post",
    apply: "serve",
    async config(userConfig = {}, configEnvironment) {
      assignment = null;
      if (configEnvironment.command !== "serve" || configEnvironment.isPreview === true) {
        return undefined;
      }
      preview = frameworkOptions(options).preview;
      if (preview === false) return runtimeDefine(localRuntimePayload);

      const server = userConfig.server ?? {};
      const allowedHosts = parseValue(
        allowedHostsSchema,
        server.allowedHosts,
        "sdk.configuration_invalid",
      );
      assignment = await operation("vite.prepare", () => prepareFramework(options, "vite"));
      if (assignment === null) return runtimeDefine(localRuntimePayload);
      const result = {
        ...runtimeDefine(serializeRuntimePayload(assignment, true)),
        server: {
          allowedHosts: serviceHostnames({
            hostname: assignment.hostname,
            project: assignment,
            service: assignment.service,
          }).reduce<string[] | true>(
            (hosts, hostname) => addAllowedHost(hosts, hostname),
            allowedHosts ?? [],
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
      server.listen = (port, isRestart) =>
        operation(isRestart === true ? "vite.restart" : "vite.register", async () => {
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
            await frameworkOperation(preview, async (signal) => {
              try {
                await configured.register(listener, signal);
              } catch (error) {
                await closeFramework(configured, error);
                throw error;
              }
            });
          } catch (error) {
            return await closeAfterFailure(server.close.bind(server), error);
          }
          return listening;
        });
    },
  };
}

async function closeAfterFailure(close: () => Promise<void>, error: unknown): Promise<never> {
  try {
    await operation("vite.cleanup", close);
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
