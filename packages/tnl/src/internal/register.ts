import { Server as HTTPSServer } from "node:https";
import {
  canonicalLoopbackTarget,
  readDevelopmentContext,
  registerLocalTarget,
  registrationTimeoutMilliseconds,
  requestTunnelAssignment,
} from "./dev.js";

export interface BunHTTPServer {
  readonly hostname?: string | undefined;
  readonly port?: number | undefined;
  readonly url: URL;
  stop(closeActiveConnections?: boolean): Promise<void> | void;
}

/** Small structural surface shared by Node HTTP servers, without Node types in browser declarations. */
export interface NodeHTTPServer {
  readonly listening: boolean;
  address(): unknown;
  once(event: "listening", listener: () => void): unknown;
  once(event: "error", listener: (error: Error) => void): unknown;
  once(event: "close", listener: () => void): unknown;
  off(event: "listening", listener: () => void): unknown;
  off(event: "error", listener: (error: Error) => void): unknown;
  off(event: "close", listener: () => void): unknown;
  close(callback?: (error?: Error) => void): unknown;
  closeAllConnections?(): void;
}

export type LocalHTTPServer = NodeHTTPServer | BunHTTPServer;

/** Registers a bound Node or Bun HTTP listener with this tnl dev invocation. */
export async function registerServer(server: LocalHTTPServer): Promise<void> {
  const { bootstrap } = readDevelopmentContext();
  if (bootstrap === null) return;
  try {
    const target = await listeningTarget(server);
    const framework = isBunServer(server) ? "bun" : "node";
    const assignment = await requestTunnelAssignment(framework, bootstrap);
    await registerLocalTarget(assignment, target);
  } catch (error) {
    try {
      await closeServer(server);
    } catch (closeError) {
      throw new AggregateError(
        [error, closeError],
        "tnl target registration and server cleanup failed",
        {
          cause: error,
        },
      );
    }
    throw error;
  }
}

async function listeningTarget(server: LocalHTTPServer): Promise<`http://${string}`> {
  if (isBunServer(server)) {
    const hostname = server.hostname ?? server.url.hostname;
    if (
      server.url.protocol !== "http:" ||
      typeof server.port !== "number" ||
      !Number.isInteger(server.port) ||
      typeof hostname !== "string"
    ) {
      throw new Error("Bun did not report a TCP listening address");
    }
    return canonicalLoopbackTarget(hostname, server.port);
  }
  if (server instanceof HTTPSServer) {
    throw new Error("tnl dev requires a local HTTP listener");
  }
  if (server.address() === null) {
    await new Promise<void>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout>;
      const cleanup = () => {
        clearTimeout(timer);
        server.off("listening", onListening);
        server.off("error", onError);
        server.off("close", onClose);
      };
      const onListening = () => {
        cleanup();
        resolve();
      };
      const onError = (error: Error) => {
        cleanup();
        reject(error);
      };
      const onClose = () => {
        cleanup();
        reject(new Error("Node listener closed before listening"));
      };
      server.once("listening", onListening);
      server.once("error", onError);
      server.once("close", onClose);
      timer = setTimeout(() => {
        cleanup();
        reject(new Error("Node listener did not start before registration timed out"));
      }, registrationTimeoutMilliseconds);
    });
  }
  const address = server.address();
  if (
    address === null ||
    typeof address !== "object" ||
    !("address" in address) ||
    !("port" in address) ||
    typeof address.address !== "string" ||
    typeof address.port !== "number"
  ) {
    throw new Error("Node did not report a TCP listening address");
  }
  return canonicalLoopbackTarget(address.address, address.port);
}

async function closeServer(server: LocalHTTPServer): Promise<void> {
  if (isBunServer(server)) {
    await server.stop(true);
    return;
  }
  if (server.listening) {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
      server.closeAllConnections?.();
    });
  }
}

function isBunServer(server: LocalHTTPServer): server is BunHTTPServer {
  return "stop" in server && typeof server.stop === "function";
}
