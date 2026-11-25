import { serviceHostnames, serializeRuntimePayload } from "./internal/project/runtime.js";
import { canonicalLoopbackTarget } from "./internal/publisher/target.js";
import { NODATA, NOTFOUND } from "node:dns";
import { Resolver } from "node:dns/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
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
const dnsHintBudget = 200;
const allowedHostsSchema = z.union([z.literal(true), z.array(z.string())]).optional();
const sdkWasmFiles = new Set(
  ["connector.wasm", "publisher.wasm"].map((name) =>
    fileURLToPath(new URL(`./wasm/${name}`, import.meta.url)),
  ),
);

/** configures a Vite development server to register its listener and add project metadata. */
export type { FrameworkOptions } from "./internal/publisher/framework.js";

export default function tnl(options: FrameworkOptions = {}): Plugin {
  let assignment: PreparedService | null = null;
  let preview: ReturnType<typeof frameworkOptions>["preview"] = "auto";
  let root: string;
  return {
    name: "tnl",
    enforce: "post",
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
    configResolved(config) {
      root = config.root;
    },
    generateBundle: {
      order: "post",
      handler(_options, bundle) {
        // vite can emit URL assets before tree shaking. keep only sdk wasm
        // files referenced by the final chunks, including lazy chunks.
        const referenced = new Set<string>();
        for (const chunk of Object.values(bundle)) {
          if (chunk.type === "asset") continue;
          if (chunk.viteMetadata === undefined) return;
          for (const asset of chunk.viteMetadata.importedAssets) referenced.add(asset);
        }
        for (const [file, asset] of Object.entries(bundle)) {
          if (
            asset.type === "asset" &&
            !referenced.has(file) &&
            asset.originalFileNames.length > 0 &&
            asset.originalFileNames.every((name) => sdkWasmFiles.has(resolve(root, name)))
          ) {
            delete bundle[file];
          }
        }
      },
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
      const { hostname, publicURL } = configured;
      const urlLine =
        publicURL !== undefined && (server.config.logLevel ?? "info") === "info"
          ? `  ➜  tnl:     ${publicURL}`
          : undefined;
      let announcement: { startup: boolean } | undefined;
      const originalPrintUrls = server.printUrls.bind(server);
      server.printUrls = () => {
        originalPrintUrls();
        if (announcement === undefined || urlLine === undefined) return;
        const { startup } = announcement;
        const printed = { startup: false };
        announcement = printed;
        if (!startup || hostname === undefined) {
          server.config.logger.info(urlLine);
          return;
        }
        void waitingForDns(hostname).then((waiting) => {
          if (announcement === printed && listener.listening) {
            server.config.logger.info(waiting ? `${urlLine} (waiting for DNS)` : urlLine);
          }
        });
      };
      const originalListen = server.listen.bind(server);
      server.listen = (port, isRestart) =>
        operation(isRestart === true ? "vite.restart" : "vite.register", async () => {
          announcement = undefined;
          let registered = false;
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
                registered = true;
              } catch (error) {
                await closeFramework(configured, error);
                throw error;
              }
            });
          } catch (error) {
            return await closeAfterFailure(server.close.bind(server), error);
          }
          if (registered && urlLine !== undefined) {
            const pending = { startup: true };
            announcement = pending;
            // vite prints startup urls immediately after listen. if a restart doesn't
            // print them, don't treat a later shortcut as startup.
            setImmediate(() => {
              pending.startup = false;
            }).unref();
          }
          return listening;
        });
    },
  };
}

async function waitingForDns(hostname: string): Promise<boolean> {
  try {
    const resolver = new Resolver({ tries: 1 });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const addresses = Promise.any(
        (["A", "AAAA"] as const).map(async (type) => resolver.resolve(hostname, type)),
      );
      return await Promise.race([
        // a positive answer in either family is enough. only two definite
        // negatives (NXDOMAIN or no data) justify the hint.
        addresses.then(
          () => false,
          (error: unknown) =>
            error instanceof AggregateError &&
            error.errors.every(
              (cause: unknown) =>
                cause instanceof Error &&
                "code" in cause &&
                (cause.code === NOTFOUND || cause.code === NODATA),
            ),
        ),
        new Promise<false>((resolve) => {
          timer = setTimeout(resolve, dnsHintBudget, false).unref();
        }),
      ]);
    } finally {
      clearTimeout(timer);
      resolver.cancel();
    }
  } catch {
    return false;
  }
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
