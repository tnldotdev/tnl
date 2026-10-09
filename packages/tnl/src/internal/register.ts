import { Server as HTTPSServer } from "node:https";
import { TnlError, TnlCleanupError, classifyTnlError } from "../errors.js";
import {
  canonicalListenerTarget,
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

export interface RegistrationOptions {
  /** hostname used to reach the listener, including for HTTPS certificate verification. */
  readonly targetHostname?: string;
}

/** Registers a bound Node or Bun HTTP listener with this tnl dev invocation. */
export async function registerServer(
  server: LocalHTTPServer,
  options: RegistrationOptions = {},
): Promise<void> {
  const { bootstrap } = readDevelopmentContext();
  if (bootstrap === null) return;
  try {
    const target = await listeningTarget(server, options);
    const framework = isBunServer(server) ? "bun" : "node";
    const assignment = await requestTunnelAssignment(framework, bootstrap);
    await registerLocalTarget(assignment, target);
  } catch (error) {
    try {
      await closeServer(server);
    } catch (closeError) {
      throw new TnlCleanupError(error, closeError);
    }
    throw classifyTnlError(error, "sdk.listener_failed");
  }
}

export async function listeningTarget(
  server: LocalHTTPServer,
  options: RegistrationOptions = {},
): Promise<`http://${string}` | `https://${string}`> {
  if (isBunServer(server)) {
    const hostname = server.hostname ?? server.url.hostname;
    if (
      (server.url.protocol !== "http:" && server.url.protocol !== "https:") ||
      typeof server.port !== "number" ||
      !Number.isInteger(server.port) ||
      typeof hostname !== "string"
    ) {
      throw new TnlError("sdk.target_invalid");
    }
    return canonicalListenerTarget(
      options.targetHostname ?? hostname,
      server.port,
      server.url.protocol === "https:" ? "https" : "http",
    );
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
        reject(new TnlError("sdk.listener_failed", { cause: error }));
      };
      const onClose = () => {
        cleanup();
        reject(new TnlError("sdk.listener_failed"));
      };
      server.once("listening", onListening);
      server.once("error", onError);
      server.once("close", onClose);
      timer = setTimeout(() => {
        cleanup();
        reject(new TnlError("sdk.listener_failed"));
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
    throw new TnlError("sdk.target_invalid");
  }
  return canonicalListenerTarget(
    options.targetHostname ?? address.address,
    address.port,
    server instanceof HTTPSServer ? "https" : "http",
  );
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

export function isBunServer(server: LocalHTTPServer): server is BunHTTPServer {
  return "stop" in server && typeof server.stop === "function";
}
